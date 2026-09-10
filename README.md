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
	Tenant:   tenantID, // the caller's tenant; matched by "self" patterns
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

A platform-published table (a managed catalog like `dataset`) holds rows the
platform owns. Only the platform tenant may publish them, and by convention every
such table marks them with `issuer = 'public'`. `PublicRows` declares that a
mapping reads such a table: its published rows are then readable by every
principal that already holds the action, so no policy has to name them.

Requiring every policy to carry an `aic` statement instead would be a footgun —
a tenant whose only grant pins one of its own datasets would silently lose the
published rows, because that pattern narrows to a single id:

```go
// cons: allow config:listDataset on crn:self:*:config::dataset:*, owner_id = ownerA
cons := engine.Constrain(policies, "config:listDataset", tenantID, nil)

where, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
	Service:    "config",
	Tenant:     "dataset.tenant_id",
	PublicRows: true,
	Fixed: map[sqlfilter.Segment]string{
		sqlfilter.SegmentScope:  "",
		sqlfilter.SegmentRegion: "",
		sqlfilter.SegmentType:   "dataset",
	},
	Resource:   sqlfilter.ResourceColumn{ID: "dataset.id"},
	Conditions: map[string]string{"owner_id": "dataset.owner_id"},
	AllowedConditionOperators: map[string][]string{
		"owner_id": {conditionoperator.StringEquals},
	},
})
if err != nil {
	return err
}
// where: (dataset.tenant_id = ? AND dataset.owner_id = ?) OR issuer = 'public'
// args:  [tenantID, "ownerA"]
```

The caller's `owner_id`/`id`/`status` filters live only inside their own group, so
the published rows are never narrowed by them (this matters on list endpoints).
The flag widens an existing grant and never creates one: with no applicable allow
for the action the clause is still `1=0`, and a platform-issued (`aic`) deny still
subtracts published rows — that is how the platform withdraws one of them.

`PublicRows` is also what admits an `aic` pattern at all. It is the one pattern
shape that does not bind the tenant column — it emits the fixed `issuer = 'public'`
predicate instead — so a mapping without the flag drops it, the way it drops a
pattern for another tenant or another service. **A write filter therefore leaves
the flag off, and then no policy, however it names those rows, can update or
delete what the platform published.** The platform itself is unaffected: it owns
those rows, so an ordinary `self` or concrete-tenant pattern binds them by tenant
column. On a read mapping an `aic` allow selects nothing the marker does not
already select, so it stays out of the clause and counts only as a grant on the
table — a principal whose sole grant for the action is the platform's bound public
policy reads the published rows and nothing else.

`TenantAnswered` remains the escape hatch for a projection whose tenant scoping
is enforced outside the filter — it emits no tenant predicate at all. Use it only
after independently establishing that the retained grants apply to this
projection, and add the service's own visibility predicate:

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

- `tenant` is a UUID (tenant isolation — never a wildcard), or one of the two
reserved tokens `aic` (platform-owned) and `self` (the requesting tenant, in a
pattern only — see below).
- `resource` is an S3-style relative path (no leading/trailing `/`); it may
contain `:` since it is the final field.

### The platform tenant — `aic`

The tenant position carries two reserved tokens with distinct meanings. `aic`
(`crn.PlatformTenant`) names platform-owned resources; `self`
(`crn.CallerTenant`) stands for the requesting tenant. Keeping them separate is
what lets one platform-issued document grant every tenant read access to a
shared table *without* also granting cross-tenant access to private rows.

| pattern tenant  | `Decide` matches                             | `Constrain` keeps                              |
| --------------- | -------------------------------------------- | ---------------------------------------------- |
| concrete UUID   | resources of that tenant                     | only when it equals the request tenant         |
| `aic`           | platform-owned resources only                | as-is, unrewritten, for the adapter            |
| `self`          | resources whose tenant equals the caller's   | rewritten to the request tenant                |

- `self` is valid in a **resource pattern only**. A concrete CRN is a real
resource identity, so `crn.Parse` rejects `self` there — an identity can't be
"self".
- `aic` is exact in both positions: a concrete `crn:aic:...` is a platform-owned
resource, and an `aic` pattern matches only those platform-owned rows (never
another tenant's).
- The engine evaluates whatever policy set the caller binds to a principal;
restricting who may *author* `crn:aic:...` or `crn:self:...` patterns is the
responsibility of the policy management plane that issues and stores policies.

Public visibility is then a single platform-issued statement, bound to every
principal, and nothing else:

```json
{
  "id": "aic-public-datasets",
  "statements": [{
    "sid": "aic-list-public-datasets",
    "effect": "allow",
    "actions": ["config:listDataset"],
    "resources": ["crn:aic:*:config::dataset:*"]
  }]
}
```

A caller's own grant uses `self`, which matches (and, at list time, is rewritten
to) their own tenant:

```json
{
  "id": "own-datasets",
  "statements": [{
    "sid": "own-datasets",
    "effect": "allow",
    "actions": ["config:listDataset"],
    "resources": ["crn:self:*:config::dataset:*"]
  }]
}
```

For request gating, `Compiled.Decide` matches `self` against `Request.Tenant`
(the caller's tenant, distinct from `Request.Resource.Tenant`, which owns the
resource acted on). For list/query paths, `engine.Constrain` takes the
requesting tenant, rewrites `self` to it, and keeps `aic` unrewritten so the
adapter can bind it to the table's platform-owned id — adapters only ever see a
concrete tenant or the `aic` token, and never interpret policy.

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
