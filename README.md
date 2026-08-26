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
- **Fail closed.** `Compile` rejects malformed policies, action and resource
  patterns, and conditions rather than silently skipping them.
- **Familiar semantics** for actions, resource wildcards, and condition
operators, adapted to Commons's CRN resource identity.



## Packages


| Package              | Responsibility                                                    |
| -------------------- | ----------------------------------------------------------------- |
| `policy`             | Data model: `Policy`, `Statement`, `Effect`, `Conditions` (JSON). |
| `crn`                | Resource identity: parse / build / match CRNs and CRN patterns.   |
| `conditionkey`       | Build and parse service-owned condition keys.                     |
| `conditionoperator`  | Shared names of the supported condition operators.                |
| `engine`             | Evaluator: `Decide` (full) and `Constrain` (partial).             |
| `adapter/sqlfilter`  | `Constraints` → SQL `WHERE` clause.                               |
| `adapter/pathfilter` | `Constraints` → filesystem / object-store path globs.             |


Dependency direction is acyclic:
`adapter/* → engine → {policy, crn, conditionkey, conditionoperator}`. Nothing
imports transport or storage.

## Installation

```bash
go get github.com/grasp-labs/ds-go-policy
```

Requires Go 1.26+.

## Quick start



### Gate a request (`Decide`)

```go
import (
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

// The concrete resource being acted on.
resource, err := crn.Build(tenantID, ownerID, "file", "", "file", "projectx/app.json")
if err != nil {
	// invalid CRN input
}

decision := engine.Decide(policies, engine.Request{
	Action:   "file:updateFile", // "{service}:{operation}"
	Resource: resource,
	Context:  map[string]string{"tag.classification": "internal"},
})

if !decision.Allowed {
	// deny: decision.Reason is the matching Sid or a fallback reason
}
```

`Decide` is a one-liner: compile, then evaluate. If the policies are
malformed it denies (fail closed) and you never see the compile error. Fine
for tests and one-off checks.

When the same policies will be reused — or you need to know *why* they
failed to load — compile once and keep the result:

```go
compiled, err := engine.Compile(policies) // once, when policies are fetched
if err != nil {
	// reject the policy set
}

// then, per request:
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
  *not* in the context, so they stay attached to the pattern. `sqlfilter`
  requires both a trusted column/expression in `Mapping.Conditions` and the
  exact operator in `Mapping.AllowedConditionOperators`; missing entries fail
  closed, and an `IfExists` variant must be allowed separately.

`sqlfilter.Mapping.Service` is required and identifies the table's resource
service.

Take the file-access policy from [`docs/examples/file-access.json`](./docs/examples/file-access.json):
it allows `file:listFiles` over the whole tree where `status` is `"active"` or
`"archived"` (a key's values OR together), and denies everything under
`projectx/secrets/`. Constraining it for a `listFiles` request yields a `WHERE`
clause that narrows the query to exactly what the principal may see:

```go
import (
	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/conditionoperator"
)

// policies for the principal (see docs/examples/file-access.json):
//   allow file:listFiles on **                 where status in {"active", "archived"}
//   deny  *              on projectx/secrets/**
cons := engine.Constrain(policies, "file:listFiles", tenantID, nil)

where, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
	Service:    "file",
	Tenant:     "tenant_id",
	Type:       "type",
	Resource:   sqlfilter.ResourceColumn{Path: "path"},
	Fixed:      map[sqlfilter.Segment]string{sqlfilter.SegmentRegion: ""},
	Conditions: map[string]string{"status": "status"},
	AllowedConditionOperators: map[string][]string{
		"status": {conditionoperator.StringEquals},
	},
})
if err != nil {
	// Do not run the query without an authorization filter.
	return err
}

// where:
//   (tenant_id = ? AND type = ? AND status IN (?, ?))
//   AND ((tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\')) IS NOT TRUE)
// args:
//   [tenantID, "file", "active", "archived", tenantID, "file", "projectx/secrets", "projectx/secrets/%"]

db.Where(where, args...).Find(&files)
```

Some CRN fields are not columns on this table — they are implied by the
table itself. A `groups` table has no `type` column (every row is a group);
`scope` and `region` may be unused. Put those constants in `Mapping.Fixed`,
using `""` for an absent dimension, instead of a column.

Then a resource pattern is checked against those constants before any SQL
is built:

- it names this table (`type` is `group`) → no extra `WHERE` for that field
- it names another table (`type` is `role`) → this query sees nothing from
  that pattern (an allow grants nothing here; a deny denies nothing here)

```go
// groupCons contains constraints for the group-list operation.
where, args, err := sqlfilter.Where(groupCons, sqlfilter.Mapping{
	Service: "iam",
	Tenant: "tenant_id",
	Fixed: map[sqlfilter.Segment]string{
		sqlfilter.SegmentScope:  "",
		sqlfilter.SegmentRegion: "",
		sqlfilter.SegmentType:   "group",
	},
	Resource: sqlfilter.ResourceColumn{ID: "id"},
})
if err != nil {
	return err
}
// crn:{tenant}::iam::group:{id}  ->  tenant_id = ? AND id = ?
// crn:{tenant}::iam::role:*      ->  selects nothing here (it's the roles table's grant)
```

A platform-published table (managed policies, a global catalog) is different:
the pattern's tenant is *who may use the grant*, not *who owns the row*. A
`tenant_id = ?` clause would hide every public row. Use `TenantAnswered` only
after independently establishing that the retained grants apply to this
published tenant projection; the service must also add its own visibility
predicate:

```go
// publishedCons contains only grants established for this projection.
where, args, err := sqlfilter.Where(publishedCons, sqlfilter.Mapping{
	Service:        "iam",
	TenantAnswered: true,
	Fixed: map[sqlfilter.Segment]string{
		sqlfilter.SegmentScope:  "",
		sqlfilter.SegmentRegion: "",
		sqlfilter.SegmentType:   "managed_policy",
	},
	Resource: sqlfilter.ResourceColumn{ID: "id"},
})
if err != nil {
	return err
}
// where: 1=1  — the grant covers the table; tenant is not a row filter
db.Where(where, args...).Where("owner = ?", crn.PlatformTenant).Find(&policies)
```

The context side works the same way: the config policy's `plan-write-staging-only`
statement only applies when `environment` is `staging`, so a caller passes
`map[string]string{"environment": "staging"}` and the statement is kept or
dropped before any SQL is generated.

For path-addressed stores (filesystem walkers, object-store prefixing) the
`pathfilter` adapter produces allow/deny globs instead. It also folds
`resource.path[N]` segment conditions (see [Conditions](#conditions)) directly
into the globs — the partitioned-listing policy from
[`docs/examples/inbound-partitions.json`](./docs/examples/inbound-partitions.json)
becomes one glob per allowed partition:

```go
import "github.com/grasp-labs/ds-go-policy/adapter/pathfilter"

// policy (see docs/examples/inbound-partitions.json):
//   allow file:listFiles on files/inbound/** where resource.path[2] in {"123456789", "23456788"}
cons := engine.Constrain(policies, "file:listFiles", tenantID, nil)

allow, deny, err := pathfilter.Prefixes(cons)
// allow: ["files/inbound/123456789/**", "files/inbound/23456788/**"]
// deny:  [] — the caller must always subtract deny globs (deny-wins)
```

Any other residual condition (e.g. a `status` stored on rows, not in the path)
is not expressible as a glob, and `Prefixes` fails closed with
`ErrUnsupportedCondition`.

## Concepts



### CRN — resource identity

A CRN names a resource:

```text
crn:{tenant}:{scope}:{service}:{region}:{type}:{resource}
```

- `tenant` is a UUID (tenant isolation — never a wildcard), or the reserved
platform token `aic` (see below).
- `resource` is an S3-style relative path (no leading/trailing `/`); it may
contain `:` since it is the final field.

### The platform tenant — `aic`

`aic` is a reserved token in the tenant position for **platform-issued
policies usable by all tenants** (`crn.PlatformTenant`):

- In a **concrete CRN**, `aic` names a platform-owned resource.
- In a **resource pattern**, `aic` is a placeholder for the requesting tenant:
the pattern matches resources of *any* tenant, so one platform-issued document
(a managed allow, or a guardrail deny) applies to every tenant it is bound to.
- The engine evaluates whatever policy set the caller binds to a principal;
restricting who may *author* `crn:aic:...` patterns is the responsibility of
the policy management plane that issues and stores policies.

```json
{
  "id": "aic-managed-guardrail",
  "statements": [{
    "sid": "aic-protect-secrets",
    "effect": "deny",
    "actions": ["*"],
    "resources": ["crn:aic:*:file::file:**/secrets/**"]
  }]
}
```

For list/query paths, `engine.Constrain` takes the requesting tenant (the same
fact `Decide` reads from `Request.Resource`) and resolves the placeholder to it
before emitting constraints — adapters only ever see concrete tenants and never
interpret policy.

`crn.Parse` validates a serialized CRN; `crn.Build` constructs a canonical one
(stripping leading/trailing slashes from the resource).

### Patterns — `*` and `**`

A `Pattern` is a CRN whose fields may be wildcards:

- `*` — matches exactly **one** segment (one flat field, or one path element).
- `**` — matches **zero or more** path segments (resource path only).


| Pattern       | Matches                             | Does not match          |
| ------------- | ----------------------------------- | ----------------------- |
| `projectx/*`  | `projectx/app.json`                 | `projectx/sub/app.json` |
| `projectx/**` | `projectx`, `projectx/sub/app.json` | `other/app.json`        |


Matching is whole-segment and linear-time (no backtracking).

### Policies & statements

A `Policy` carries `Statement`s; each has an `Effect` (`allow`/`deny`), a list of
`Actions`, a list of resource CRN patterns, and optional `Conditions`. Actions
support `"service:operation"`, `"service:*"`, and `"*"`; `Compile` rejects any
other action pattern. Request actions must be concrete: `Decide` implicitly
denies invalid values, while `Constrain` returns empty constraints. Actions and
resource patterns are matched independently; any relationship between their
service names belongs to the calling service's authorization contract.

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

Service-owned keys use the `<service>:<name>` grammar (first colon splits the
service from an opaque name), e.g. `file:path_prefix:project`. Compilation
validates the grammar; the service still owns the allowlist and the mapping to
trusted data — never derive a storage identifier from a parsed key. The
`conditionkey` package builds and parses that form; see
[`docs/examples/inbound-country.json`](./docs/examples/inbound-country.json).

One key namespace is reserved: `resource.path[N]` resolves to the Nth segment
(0-based) of the request resource's path, taken from the resource itself —
never from the context, so it cannot be spoofed. This pins a path partition to
a value set without enumerating one resource pattern per value:

```json
"resources": ["crn:<tenant>:*:file::file:files/inbound/**"],
"conditions": { "StringEquals": { "resource.path[2]": ["123456789", "23456788"] } }
```

At list time (`Constrain`) there is no concrete resource, so `resource.path[N]`
conditions stay attached to the pattern and the adapter enforces them.
`pathfilter` folds them into the globs; `sqlfilter` maps them through
`Mapping.Conditions`, requires `StringEquals` in
`Mapping.AllowedConditionOperators`, and renders an `IN` list.

## Examples

Runnable policy documents live in [`docs/examples/`](./docs/examples), modeled on
the DS-file and Config APIs. They are loaded and evaluated by the test suite, so
they stay in sync with the implementation. See the full design contract in
[`docs/iam-policy-contract.md`](./docs/iam-policy-contract.md).

## Testing

```bash
go test ./...
```

## Releasing

Pushing a `v*.*.*` tag creates the GitHub release with auto-generated notes
and publishes the artifact reference to ds-coordination:

```bash
git tag v1.3.0 && git push --tags
```

## License

Apache 2.0 — see [LICENSE](./LICENSE).
