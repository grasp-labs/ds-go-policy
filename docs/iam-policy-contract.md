# IAM Policy Contract — `ds-go-policy`

Shared policy engine consumed by the Echo authz middleware (request gating) and by services (data filtering): CRN with region, statements, deny-wins. Runnable policy documents live in [`examples/`](examples/).

The security-critical logic (CRN matching, statement selection, effect resolution) has **exactly one** implementation here. It lives in its own module — **not** in `ds-go-echo-middleware`, since data filtering happens below the transport layer and must not import Echo.

## Repo layout

```text
ds-go-policy/
  policy/            # data model: Policy, Statement, Effect (JSON)
  crn/               # CRN parse / build / match (the resource-name analog)
  conditionkey/      # <service>:<name> condition-key grammar
  conditionoperator/ # shared names of the supported condition operators
  engine/          # evaluator: Decide (full) + Constrain (partial)
  adapter/
    sqlfilter/     # Constraints -> GORM/SQL WHERE
    pathfilter/    # Constraints -> filesystem path-prefix set
    (mongofilter/, s3filter/, … added as needed)
```

Dependency direction (no cycles, nothing imports Echo):

```text
ds-go-echo-middleware ─┐
                       ├─▶ ds-go-policy/engine ─▶ engine deps: policy, crn
services (repos) ──────┘        ▲
services' data layer ─▶ ds-go-policy/adapter/* ─┘
```

## `policy/` — the document

```go
package policy

type Effect string

const (
    Allow Effect = "allow"
    Deny  Effect = "deny"
)

type Statement struct {
    Sid        string     `json:"sid,omitempty"`
    Effect     Effect     `json:"effect"`
    Actions    []string   `json:"actions"`    // Compile: "{service}:{operation}", "{service}:*", "*"
    Resources  []string   `json:"resources"`  // CRN patterns
    Conditions Conditions `json:"conditions,omitempty"`
}

// Conditions is the IAM condition block: operator -> key -> values.
// Values unmarshal from a single string or an array. See "Conditions" below.
type Conditions map[string]map[string]Values
type Values []string

type Policy struct {
    ID         string      `json:"id"`
    Name       string      `json:"name,omitempty"` // human-readable name from the IAM service
    Version    string      `json:"version"`
    Statements []Statement `json:"statements"`
}
```

### Conditions

Evaluation ANDs across operators, ANDs across keys within an operator, and ORs
a key's values. Operators: `String*`, `Numeric*`, `Date*`, `Bool`,
`IpAddress`/`NotIpAddress`, `Null`, each with an optional `...IfExists` suffix.

Keys resolve three ways:

- **context key** (`status`) — read from `Request.Context`.
- **`resource.path[N]`** — the Nth path segment (0-based) of the request
  resource, answered by the engine from the resource itself, never the context.
  At `Constrain` time it defers to the adapter (`pathfilter` folds it into
  globs; `sqlfilter` maps it to a column like any residual key).
- **`<service>:<name>`** (`file:path_prefix:project`) — service-owned; the
  first colon splits the service from an opaque name. `conditionkey` validates
  the grammar at `Compile`; the service owns the allowlist and trusted mapping.

## `crn/` — the resource identity

```go
package crn

// crn:{tenant}:{scope}:{service}:{region}:{type}:{resource}
type CRN struct {
    Tenant   string
    Scope    string // secondary partition (owner id); empty when unowned
    Service  string
    Region   string // reserved; empty for now
    Type     string
    Resource string
}

func Parse(s string) (CRN, error)
func (c CRN) String() string

// Pattern is a CRN that may contain * (single segment) and ** (recursive, path-addressed).
type Pattern struct{ /* parsed form */ }

func ParsePattern(s string) (Pattern, error)
func (p Pattern) Matches(c CRN) bool
```

### The platform tenant — `aic`

`crn.PlatformTenant` (`"aic"`) is a reserved token in the tenant position. It
marks **platform-issued policies usable by all tenants**: in a concrete CRN it names a platform-owned resource;
in a pattern it is a placeholder for the requesting tenant and matches
resources of any tenant. The engine evaluates whatever policy set the caller
binds to a principal — restricting who may author `aic` patterns is the policy
management plane's responsibility. For list/query paths `engine.Constrain`
resolves the placeholder to the requesting tenant before emitting constraints,
so adapters only ever see concrete tenants.

## `engine/` — the security-critical core (two modes)

```go
package engine

import "…/policy"
import "…/crn"

// Request context for a concrete operation.
type Request struct {
    Action   string            // concrete "{service}:{operation}"
    Resource crn.CRN
    Context  map[string]string // attributes the service supplies for conditions
}

type Decision struct {
    Allowed bool
    Reason  string // matched Sid or a fallback reason
}

// --- Mode 1: full evaluation (PEP for request gating) ---
// Deny-wins, default-deny. A malformed or wildcard action is implicitly denied.
// Used by ds-go-echo-middleware.
func Decide(policies []policy.Policy, r Request) Decision

// --- Mode 2: partial evaluation (emit a filter for list/query paths) ---
// No concrete resource: given a concrete action and the requesting tenant,
// reduce the policy set to the allow/deny resource patterns (+ conditions) that
// survive for this principal.
type ResourceMatch struct {
    Pattern    crn.Pattern
    Conditions policy.Conditions
}

type Constraints struct {
    Allow []ResourceMatch
    Deny  []ResourceMatch // must be subtracted by the adapter (deny-wins)
}

// Invalid policies or non-concrete actions return empty constraints.
// tenant scopes the list/query; foreign-tenant patterns are dropped and the
// platform placeholder resolves to it. context resolves known conditions up
// front; unresolved conditions stay attached for the adapter.
func Constrain(policies []policy.Policy, action, tenant string, context map[string]string) Constraints
```

The caller resolves which policies apply to the principal (via the IAM binding / `map_group_policy`) and passes them in — the engine stays a pure function of `(policies, request)`, which makes it trivial to unit-test and impossible to couple to storage.

## `adapter/*` — the non-shareable last mile

Each adapter turns `Constraints` into one storage's filter. It needs a mapping
from CRN fields to that store's columns/paths, so the service provides it. For
residual SQL conditions, both the trusted column/expression and the exact
operator must be configured; an `IfExists` variant is separate, and missing or
inexpressible entries fail closed:

```go
package sqlfilter

// Maps CRN segments to columns for one table.
type Mapping struct {
    Service                    string              // required table service; must not be "*"
    Tenant, Scope, Region, Type string              // column names (Scope -> owner_id/owners)
    TenantAnswered             bool                // tenant enforced outside the filter (platform-published tables)
    Fixed                      map[Segment]string  // per-table constants; use "" for an absent segment
    Resource                   ResourceColumn      // id column and/or path column
    Conditions                map[string]string   // residual condition key -> trusted column/expression
    AllowedConditionOperators map[string][]string // allowed operators for each residual key
}

// Where returns a clause you AND into the query. Do not run the query on error.
func Where(c engine.Constraints, m Mapping) (sql string, args []any, err error)
```

`TenantAnswered` is safe only when the caller has independently established
that every retained match applies to the table's tenant projection. `Constrain`
alone is insufficient because it makes platform-placeholder and explicit
caller-tenant patterns indistinguishable. The service must still add its own
row-visibility predicate.

```go
package pathfilter

// Allowed/denied path globs derived from path-addressed CRNs,
// for filesystem walkers / object-store prefixing.
// Residual resource.path[N] StringEquals conditions are folded into the
// globs (one pinned glob per allowed value); any other residual condition
// fails closed with ErrUnsupportedCondition.
func Prefixes(c engine.Constraints) (allow, deny []string, err error)
```

## The contract that keeps it safe

- `policy` + `crn` + `engine` have **zero** storage/HTTP deps and are the only place matching/effect logic exists.
- `Decide` and `Constrain` share the same matcher, so a request decision and a list filter can never disagree.
- Adapters may only *narrow* — they consume `Constraints` and must subtract `Deny`; they never re-interpret policy.

## Build order

1. `policy` + `crn` + `engine.Decide` — unblocks the middleware.
2. `engine.Constrain` + `adapter/sqlfilter` — the IAM service itself is relational.
3. Further adapters (`pathfilter`, etc.) as services need them.
