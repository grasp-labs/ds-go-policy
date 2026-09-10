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
func (p Pattern) Matches(c CRN, requestTenant string) bool
```

### Reserved tenant tokens — `aic` and `self`

The tenant position carries two reserved tokens.

`crn.PlatformTenant` (`"aic"`) names **platform-owned resources** in both
positions: a concrete `crn:aic:...` is a platform-owned resource, and an `aic`
pattern matches only platform-owned rows (never another tenant's). It is never
rewritten.

`crn.CallerTenant` (`"self"`) stands for **the requesting tenant** and is valid
in a pattern only — a concrete CRN is a real identity, so `crn.Parse` rejects
`self`. A `self` pattern matches resources whose tenant equals the caller's.

| pattern tenant | `Decide` matches                           | `Constrain` keeps                       |
| -------------- | ------------------------------------------ | --------------------------------------- |
| concrete UUID  | resources of that tenant                   | only when it equals the request tenant  |
| `aic`          | platform-owned resources only              | as-is, unrewritten, for the adapter     |
| `self`         | resources whose tenant equals the caller's | rewritten to the request tenant         |

The engine evaluates whatever policy set the caller binds to a principal —
restricting who may author `aic`/`self` patterns is the policy management
plane's responsibility. `Decide` matches `self` against `Request.Tenant`; for
list/query paths `engine.Constrain` rewrites `self` to the requesting tenant and
keeps `aic` for the adapter to bind to a platform-owned id.

## `engine/` — the security-critical core (two modes)

```go
package engine

import "…/policy"
import "…/crn"

// Request context for a concrete operation.
type Request struct {
    Action   string            // concrete "{service}:{operation}"
    Resource crn.CRN
    Tenant   string            // caller's tenant; matched by "self" patterns
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
// tenant scopes the list/query; foreign-tenant patterns are dropped, a "self"
// pattern is rewritten to it, and an "aic" pattern is kept unrewritten for the
// adapter. context resolves known conditions up front; unresolved conditions
// stay attached for the adapter.
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
    TenantAnswered             bool                // tenant enforced outside the filter (escape hatch)
    PublicRows                 bool                // reads: OR issuer = 'public'; also admits "aic" patterns
    Fixed                      map[Segment]string  // per-table constants; use "" for an absent segment
    Resource                   ResourceColumn      // id column and/or path column
    Conditions                map[string]string   // residual condition key -> trusted column/expression
    AllowedConditionOperators map[string][]string // allowed operators for each residual key
}

// Where returns a clause you AND into the query. Do not run the query on error.
func Where(c engine.Constraints, m Mapping) (sql string, args []any, err error)
```

`PublicRows` declares that the mapping reads a platform-published table: any
principal already holding the action reads its published rows, no statement
required. The fixed `issuer = 'public'` marker is OR-ed onto the allow clause —
every platform-published table marks its rows by that convention, so no per-table
configuration is needed — which widens an existing grant and never creates one (an
empty allow still yields `1=0`). The caller's own id/condition filters stay inside
the caller's group and never narrow published rows, and an `aic` deny still
subtracts them.

The flag is also what admits an `aic` pattern at all. That pattern is the one
shape which does not bind the mapping's tenant column, emitting the marker
instead, so a mapping without the flag drops it as it drops a pattern for another
tenant. **A write mapping leaves the flag off; no policy can then reach
platform-published rows through a write filter.** The platform writes its own rows
by ownership, through an ordinary `self` or concrete-tenant pattern. On a read
mapping an `aic` allow adds nothing to the marker and stays out of the clause,
counting only as a grant on the table.

> **Trust invariant — `issuer = 'public'` is trusted.** The filter authorizes a
> row to every principal *because the row asserts `issuer = 'public'`*. It does
> not verify ownership. The soundness of cross-tenant isolation therefore rests
> entirely on the write path, and every API that writes a platform-published
> table **MUST GUARANTEE**:
>
> 1. Only the platform tenant can set `issuer = 'public'`. A request from any
>    other tenant that attempts to set it MUST be rejected. The write guard
>    should compare against `sqlfilter.PlatformIssuerColumn` /
>    `sqlfilter.PlatformIssuerPublic` (the same constants the read filter trusts)
>    so the two cannot drift.
> 2. When `issuer = 'public'` is set, the row is platform-owned — its `tenant_id`
>    (owner) is the platform tenant id.
> 3. Neither field is writable after creation: an update preserves the stored
>    `tenant_id` and `issuer` rather than restamping them from the request, so an
>    authorized edit of a published row cannot move it to another tenant or
>    unpublish it.
>
> If any write path violates (1), a tenant can publish its own row to every other
> tenant — a cross-tenant read leak the policy engine cannot detect, because by
> the time the filter runs the row already claims to be public. This guarantee is
> a hard, tested requirement of each service, not a convention. It is the price
> of expressing public visibility as a row attribute instead of ownership;
> binding to `tenant_id = <platform id>` would move the trust to system-assigned
> ownership, but requires the platform id to be configured per table.

Two further constraints follow from the fixed predicate: every table that can
receive an `aic` grant must have an `issuer` column (a missing column is a
runtime error, fail-closed), and the marker column/value (`issuer` / `'public'`)
is unqualified, so callers that alias or JOIN the table must keep `issuer`
unambiguous.

`TenantAnswered` is the escape hatch for a projection whose tenant scoping is
enforced outside the filter: it emits no tenant predicate and is safe only when
the caller has independently established that every retained match applies to the
table's projection. The service must still add its own row-visibility predicate.

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
