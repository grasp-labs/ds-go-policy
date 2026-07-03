# ds-go-policy

![Build](https://github.com/grasp-labs/ds-go-policy/actions/workflows/ci.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/grasp-labs/ds-go-policy)](https://goreportcard.com/report/github.com/grasp-labs/ds-go-policy)
[![codecov](https://codecov.io/gh/grasp-labs/ds-go-policy/branch/main/graph/badge.svg)](https://codecov.io/gh/grasp-labs/ds-go-policy)
[![GitHub release](https://img.shields.io/github/v/release/grasp-labs/ds-go-policy)](https://github.com/grasp-labs/ds-go-policy/releases)
![License](https://img.shields.io/github/license/grasp-labs/ds-go-policy?cacheSeconds=60)

A small, dependency-light IAM policy engine for Go. It answers two questions from
the same policy documents:

- **Can this principal perform this action on this resource?** (request gating)
- **Which resources may this principal see?** (a filter for list/query paths)

The security-critical logic — resource matching, statement selection, and
deny-wins resolution — has **exactly one** implementation here, so a request
decision and a list filter can never disagree.

## Design principles

- **Pure functions.** The engine is a function of `(policies, request)`. The
  caller resolves which policies apply to a principal and passes them in; the
  engine has no storage, HTTP, or transport dependencies.
- **Deny-wins, default-deny.** Any matching `deny` overrides every `allow`, and
  nothing is permitted unless explicitly allowed.
- **Fail closed.** Policies are validated and compiled up front; malformed
  effects, unparseable resource patterns, and unknown condition operators are
  rejected rather than silently skipped.
- **Familiar semantics** for actions, resource wildcards, and condition
  operators, adapted to Commons's CRN resource identity.

## Packages

| Package                  | Responsibility                                                        |
| ------------------------ | -------------------------------------------------------------------- |
| `policy`                 | Data model: `Policy`, `Statement`, `Effect`, `Conditions` (JSON).    |
| `crn`                    | Resource identity: parse / build / match CRNs and CRN patterns.      |
| `engine`                 | Evaluator: `Decide` (full) and `Constrain` (partial).               |
| `adapter/sqlfilter`      | `Constraints` → SQL `WHERE` clause.                                  |
| `adapter/pathfilter`     | `Constraints` → filesystem / object-store path globs.               |

Dependency direction is acyclic: `adapter/* → engine → {policy, crn}`. Nothing
imports transport or storage.

## Installation

```bash
go get github.com/grasp-labs/ds-go/policy
```

Requires Go 1.26+.

## Quick start

### Gate a request (`Decide`)

```go
import (
	"github.com/grasp-labs/ds-go/policy/crn"
	"github.com/grasp-labs/ds-go/policy/engine"
	"github.com/grasp-labs/ds-go/policy/policy"
)

// The concrete resource being acted on.
resource, err := crn.Build(tenantID, ownerID, "file", "", "file", "projectx/app.json")
if err != nil {
	// invalid CRN input
}

decision := engine.Decide(policies, engine.Request{
	Action:   "file:updateFile", // "{service}:{operationId}"
	Resource: resource,
	Context:  map[string]string{"tag.classification": "internal"},
})

if !decision.Allowed {
	// deny: decision.Reason is the matching statement Sid or "implicit deny"
}
```

For a hot path, compile once and reuse:

```go
compiled, err := engine.Compile(policies) // validates + pre-parses patterns
if err != nil {
	// reject the policy set
}
decision := compiled.Decide(req)
```

### Filter a list/query (`Constrain`)

For a list or search there is no concrete resource, so instead of a yes/no the
engine reduces the policy set to the resource patterns that survive for this
principal, and an adapter turns them into a storage filter. Conditions are split
by where their data lives:

- **Attributes already known for the request** (e.g. the target `environment`
  in the config policy) are passed in the `context` and resolved up front — a
  statement whose context condition fails is dropped.
- **Resource attributes** (e.g. the file's `status`, stored on each row) are
  *not* in the context, so they stay attached to the pattern and the adapter
  turns them into predicates via `Mapping.Conditions`.

Take the file-access policy from [`docs/examples/`](./docs/examples/file-access.json):
it allows `file:listFiles` over the whole tree where `status = "active"`, and
denies everything under `projectx/secrets/`. Constraining it for a `listFiles`
request yields a `WHERE` clause that narrows the query to exactly what the
principal may see:

```go
import "github.com/grasp-labs/ds-go/policy/adapter/sqlfilter"

// policies for the principal (see docs/examples/file-access.json):
//   allow file:listFiles on **                 where status = "active"
//   deny  *              on projectx/secrets/**
cons := engine.Constrain(policies, "file:listFiles", nil)

where, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
	Tenant:     "tenant_id",
	Type:       "type",
	Resource:   sqlfilter.ResourceColumn{Path: "path"},
	Conditions: map[string]string{"status": "status"}, // resource attribute -> column
})
if err != nil {
	// a residual condition or pattern the adapter can't express: fail closed
}

// where:
//   (tenant_id = ? AND type = ? AND status = ?)
//   AND NOT (tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\'))
// args:
//   [tenantID, "file", "active", tenantID, "file", "projectx/secrets", "projectx/secrets/%"]

db.Where(where, args...).Find(&files)
```

The context side works the same way: the config policy's `plan-write-staging-only`
statement only applies when `environment` is `staging`, so a caller passes
`map[string]string{"environment": "staging"}` and the statement is kept or
dropped before any SQL is generated.

## Concepts

### CRN — resource identity

A CRN names a resource:

```text
crn:{tenant}:{scope}:{service}:{region}:{type}:{resource}
```

- `tenant` is always a UUID (tenant isolation — never a wildcard).
- `resource` is an S3-style relative path (no leading/trailing `/`); it may
  contain `:` since it is the final field.

`crn.Parse` validates a serialized CRN; `crn.Build` constructs a canonical one
(stripping leading/trailing slashes from the resource).

### Patterns — `*` and `**`

A `Pattern` is a CRN whose fields may be wildcards:

- `*` — matches exactly **one** segment (one flat field, or one path element).
- `**` — matches **zero or more** path segments (resource path only).

| Pattern            | Matches                                  | Does not match          |
| ------------------ | ---------------------------------------- | ----------------------- |
| `projectx/*`       | `projectx/app.json`                      | `projectx/sub/app.json` |
| `projectx/**`      | `projectx`, `projectx/sub/app.json`      | `other/app.json`        |

Matching is whole-segment and linear-time (no backtracking).

### Policies & statements

A `Policy` carries `Statement`s; each has an `Effect` (`allow`/`deny`), a list of
`Actions`, a list of resource CRN patterns, and optional `Conditions`. Actions
support `"service:operation"`, `"service:*"`, and `"*"`.

### Conditions

Conditions follow the `operator → key → values` shape. Operators AND together,
keys within an operator AND, and a key's values OR. Values may be a single string
or an array.

```json
"conditions": {
  "StringEquals":    { "status": ["active", "archived"] },
  "StringNotEquals": { "tag.classification": "restricted" }
}
```

Supported operators: `String*` (`Equals`, `NotEquals`, `EqualsIgnoreCase`,
`Like`, …), `Numeric*`, `Date*` (RFC 3339), `Bool`, `IpAddress` / `NotIpAddress`,
`Null`, and the `...IfExists` suffix. Keys are matched against the attributes the
service supplies in `Request.Context`.

## Examples

Runnable policy documents live in [`docs/examples/`](./docs/examples), modeled on
the DS-file and Config APIs. They are loaded and evaluated by the test suite, so
they stay in sync with the implementation. See the full design contract in
[`docs/iam-policy-contract.md`](./docs/iam-policy-contract.md).

## Testing

```bash
go test ./...
```

## License

Apache 2.0 — see [LICENSE](./LICENSE).
