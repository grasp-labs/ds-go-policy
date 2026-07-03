# IAM Policy Contract — `ds-go-policy`

Shared policy engine consumed by the Echo authz middleware (request gating) and by services (data filtering). It maps 1:1 onto [`policies.md`](policies.md): CRN with region, statements, deny-wins.

The security-critical logic (CRN matching, statement selection, effect resolution) has **exactly one** implementation here. It lives in its own module — **not** in `ds-go-echo-middleware`, since data filtering happens below the transport layer and must not import Echo.

## Repo layout

```text
ds-go-policy/
  policy/          # data model: Policy, Statement, Effect (JSON = policies.md)
  crn/             # CRN parse / build / match (the ARN analog)
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

## `policy/` — the document (mirrors `policies.md`)

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
    Actions    []string   `json:"actions"`    // "file:getFile", "file:*", "*"
    Resources  []string   `json:"resources"`  // CRN patterns
    Conditions Conditions `json:"conditions,omitempty"`
}

// Conditions mirrors the AWS IAM condition block: operator -> key -> values.
// Values unmarshal from a single string or an array of strings. Evaluation
// (engine): operators AND, keys AND, a key's values OR. Supported operators
// include String*, Numeric*, Date*, Bool, IpAddress/NotIpAddress, Null, and
// the "...IfExists" suffix.
type Conditions map[string]map[string]Values
type Values []string

type Policy struct {
    ID         string      `json:"id"`
    TenantID   string      `json:"tenant_id"`
    Version    string      `json:"version"`
    Statements []Statement `json:"statements"`
}
```

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

## `engine/` — the security-critical core (two modes)

```go
package engine

import "…/policy"
import "…/crn"

// Request context for a concrete operation.
type Request struct {
    Action   string            // "{service}:{operationId}"
    Resource crn.CRN
    Context  map[string]string // attributes the service supplies for conditions
}

type Decision struct {
    Allowed bool
    Reason  string // matched sid / "implicit deny"
}

// --- Mode 1: full evaluation (PEP for request gating) ---
// Deny-wins, default-deny. Used by ds-go-echo-middleware.
func Decide(policies []policy.Policy, r Request) Decision

// --- Mode 2: partial evaluation (emit a filter for list/query paths) ---
// No concrete resource: given an action, reduce the policy set to the
// allow/deny resource patterns (+ conditions) that survive for this principal.
type ResourceMatch struct {
    Pattern    crn.Pattern
    Conditions policy.Conditions
}

type Constraints struct {
    Allow []ResourceMatch
    Deny  []ResourceMatch // must be subtracted by the adapter (deny-wins)
}

// context resolves principal/request conditions up front; conditions on
// resource attributes not present in context stay attached for the adapter.
func Constrain(policies []policy.Policy, action string, context map[string]string) Constraints
```

The caller resolves which policies apply to the principal (via the IAM binding / `map_group_policy`) and passes them in — the engine stays a pure function of `(policies, request)`, which makes it trivial to unit-test and impossible to couple to storage.

## `adapter/*` — the non-shareable last mile

Each adapter turns `Constraints` into one storage's filter. It needs a mapping from CRN fields to that store's columns/paths, so the service provides it:

```go
package sqlfilter

// Maps CRN segments to columns for one table.
type Mapping struct {
    Tenant, Scope, Region, Type string // column names (Scope -> owner_id/owners)
    Resource   ResourceColumn          // id column and/or path column
    Conditions map[string]string       // residual condition key -> column (e.g. "department" -> "dept")
}

// Where returns a clause you AND into the query (GORM-friendly).
func Where(c engine.Constraints, m Mapping) (sql string, args []any, err error)
```

```go
package pathfilter

// Allowed/denied path globs derived from path-addressed CRNs,
// for filesystem walkers / object-store prefixing.
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
