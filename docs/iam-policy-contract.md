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

### The reserved tenant token — `aic`

The tenant position carries exactly one reserved token, and it expresses tenancy
only. See [ADR 0001](adr/0001-tenancy-and-published-rows.md).

`crn.PlatformTenant` (`"aic"`) stands for **the requesting tenant**. It is valid
in a pattern only — a concrete CRN is a real resource identity, whose tenant is a
real tenant — so `crn.Parse` and `crn.Build` reject it. This is what lets the
platform issue one document that every tenant binds to its own groups and that
grants each of them their own resources.

| pattern tenant | `Decide` matches                           | `Constrain` keeps                      |
| -------------- | ------------------------------------------ | -------------------------------------- |
| concrete UUID  | resources of that tenant                   | only when it equals the request tenant |
| `aic`          | resources whose tenant equals the caller's | resolved to the request tenant         |

Both paths enforce one invariant: **a policy can only reach resources of the
tenant the request is made for.** A pattern naming any other tenant is dropped
before matching, so adapters only ever see the request tenant.

There is deliberately no token for platform-published rows. Publication is the
grant for those, and it is a marker on the row — see `Mapping.Published` and
`Request.ResourcePublished` below.

The engine evaluates whatever policy set the caller binds to a principal;
restricting who may author `aic` patterns is the policy management plane's
responsibility.

## `engine/` — the security-critical core (two modes)

```go
package engine

import "…/policy"
import "…/crn"

// Request context for a concrete operation.
type Request struct {
    Action   string            // concrete "{service}:{operation}"
    Resource crn.CRN
    Tenant   string            // caller's tenant, from verified claims; bounds every pattern
    ResourcePublished bool     // the row carries the platform's published marker
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
// tenant scopes the list/query: foreign-tenant patterns are dropped and an "aic"
// pattern is resolved to it, so every emitted pattern carries this tenant.
// context resolves known conditions up front; unresolved conditions stay
// attached for the adapter.
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
    Published                  Published           // reads: marker column+value OR-ed onto the allow
    Fixed                      map[Segment]string  // per-table constants; use "" for an absent segment
    Resource                   ResourceColumn      // id column and/or path column
    Conditions                map[string]string   // residual condition key -> trusted column/expression
    AllowedConditionOperators map[string][]string // allowed operators for each residual key
}

// Where returns a clause you AND into the query. Do not run the query on error.
func Where(c engine.Constraints, m Mapping) (sql string, args []any, err error)
```

`Published` declares that the mapping reads a table the platform publishes rows
into: any principal already holding the action reads those rows, no statement
required. The marker is OR-ed onto the allow clause, so it widens an existing
grant and never creates one — an empty allow still yields `1=0`, and a principal
with no grant gets 403 rather than the catalog.

The column is per-table rather than a package constant so it can be qualified,
which matters as soon as a query aliases or joins the table.

The caller's own id and condition filters stay inside the caller's group and never
narrow published rows. Denies cannot reach them either, and that follows from the
grammar rather than being a separate rule: every pattern carries the caller's
tenant, so every deny group contains `tenant = <caller>`, and a published row
belongs to the platform. The marker is all-or-nothing by design — withholding the
catalog from a principal means withholding the action. (`TenantAnswered` emits no
tenant predicate and so lifts this; do not combine it with a published table.)

**A write mapping leaves `Published` unset, and the tenant column does the rest:**
every pattern is bound to the caller, and a published row is the platform's, so no
policy shape reaches it. The platform edits its own published rows because it owns
them.

On the single-resource path, `Request.ResourcePublished` plays the same role: the
service reads the marker off the loaded row, and it satisfies the resource test of
an allow whose action already matches. Without it `Decide` would refuse a row that
`Constrain` returns.

> **Trust invariant — `issuer = 'public'` is trusted.** The filter authorizes a
> row to every principal *because the row asserts `issuer = 'public'`*. It does
> not verify ownership. The soundness of cross-tenant isolation therefore rests
> entirely on the write path, and every API that writes a platform-published
> table **MUST GUARANTEE**:
>
> 1. Only the platform tenant can set the marker. A request from any other tenant
>    that attempts to set it MUST be rejected. The write guard should read the
>    column and value from the same `sqlfilter.Published` the read mapping
>    declares, so the two cannot drift, and it belongs in one central place — a
>    single service that lets a tenant set the marker publishes that tenant's row
>    to every other tenant.
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

One further constraint: a mapping that sets `Published` must name a column the
table actually has, since a missing column is a runtime error (fail-closed).

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
