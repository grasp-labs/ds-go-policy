# ADR 0001 — Tenancy and platform-published rows

Status: accepted

## Context

Two things must be expressible without redundancy:

1. The platform tenant issues **one** policy document that every tenant can bind
   to its own groups, granting access to *that* tenant's resources.
2. The platform tenant publishes **data** (a dataset, a linked service) that
   every tenant may read.

These are unrelated, and the CRN tenant segment had come to carry both. A single
token meaning "platform" was read as "the consuming tenant" in one release line
and "platform-owned rows only" in another, so a managed policy silently granted
nothing but published rows.

## Decision

**1. The tenant segment expresses tenancy only.** Two forms:

| form | meaning |
| ---- | ------- |
| placeholder | the requesting tenant |
| concrete UUID | that tenant, a deliberate cross-tenant grant |

Never a wildcard — the tenant is the isolation boundary. There is no token for
"platform-owned rows".

**2. The engine resolves the placeholder, not the issuer.** It resolves against
the tenant in the verified claims, at the point of evaluation. IAM stores and
serves documents verbatim.

Resolving at the issuer would render the placeholder as a concrete UUID, making
it indistinguishable from a deliberate cross-tenant grant — a distinction no
consumer could then recover or enforce. It would also make a document
tenant-varying, so every cache and validator over it has to key on tenant.

**3. Both evaluation paths drop patterns whose tenant is not the requesting
tenant.** One invariant, `Decide` and `Constrain` alike.

**4. Publication is the grant; no policy names published rows.** A row marked
`issuer = 'public'` is readable by every tenant, and the marker is binary — all
tenants or none. Selective sharing must not use the marker; it belongs to the
entitlement gate, not to policy.

Consequently a read mapping widens with the marker and a write mapping does not.
Only the owner writes, so the platform maintains its published rows because it
owns them, and no tenant can reach them through any policy shape.

**5. Widening never creates a grant.** No applicable allow means the filter is
closed, and closed means 403 — never "published rows only".

**6. Both evaluation paths widen the same way.** `Decide` takes the row's marker
as an input (`Request.ResourcePublished`, read off the row by the service) and
treats it exactly as the filter treats the marker column: it satisfies the
resource test of an allow whose action already matches. Without this the
single-resource path would deny a published row the list path returns.

## Filter algebra

```
read   (<allow over the caller's own rows>) OR <marker>
write  <allow over the caller's own rows>
none   1=0  → 403
```

Narrowing *inside* an allow — an id, an owner, a condition — applies to the
caller's own rows only. A grant over `department=finance` says which of *your*
datasets are visible and says nothing about the shared catalog.

Published rows are also beyond the reach of a deny, and this follows from the
grammar rather than being a separate rule: every pattern carries the caller's
tenant, so every deny group contains `tenant = <caller>`, and a published row
belongs to the platform. There is deliberately no way to write "all published
rows except this one" — the marker is all-or-nothing, so withholding the catalog
from a principal means withholding the action.

The one exception is `TenantAnswered`, which emits no tenant predicate and so lets
a deny reach published rows. It is an escape hatch for projections that scope
tenancy themselves, and it should not be used for an ordinary published table.

## Changes this requires

- `crn` — one placeholder token; delete the "platform-owned rows" meaning, and
  reject the token in a concrete CRN.
- `engine.Decide` — drop patterns whose tenant is not the requesting tenant, and
  honour `Request.ResourcePublished`.
- `adapter/sqlfilter` — drop the placeholder→marker pattern mapping; take the
  marker column and value from `Mapping` (it was a hardcoded, unqualified
  `issuer = 'public'`, which breaks under aliases and JOINs); remove the
  public-grant escape so an empty allow is always `1=0`.

Still open: emitting `UNION ALL` over two indexed scans rather than the marker
`OR`, which cannot use a single index. This is a planner concern, not a semantic
one, and the clause shape above is what callers depend on.

## Appendix — one policy, end to end

### 1. The platform issues it

`POST /policy/` to ds-iam, as the platform tenant:

```json
{
  "name": "ConfigFullAccess",
  "issuer": "public",
  "status": "active",
  "version": "1.0.0",
  "statements": [
    {
      "sid": "ConfigFullAccess",
      "effect": "allow",
      "actions": ["config:*"],
      "resources": ["crn:aic:*:config::*:**"]
    }
  ]
}
```

IAM validates shape only — every resource must parse as a CRN pattern and the
document must compile. It stores `tenant_id` from the caller's claims and
`issuer: "public"` (which only the platform tenant may set), and the statements
verbatim. Ownership lives in those two columns; the resources say nothing about
who owns the policy.

A tenant then binds it to one of its own groups, and a principal is a member of
that group.

### 2. ds-iam returns it

`GET /principal/user:alice@example.com/policies/` walks memberships → groups →
bindings → active policies, tenant-owned or public, and returns the documents
unchanged:

```json
{
  "principal_id": "user:alice@example.com",
  "policies": [
    {
      "id": "3b313457-…",
      "name": "ConfigFullAccess",
      "version": "1.0.0",
      "statements": [
        {
          "sid": "ConfigFullAccess",
          "effect": "allow",
          "actions": ["config:*"],
          "resources": ["crn:aic:*:config::*:**"]
        }
      ]
    }
  ]
}
```

The placeholder is still there. The IAM middleware in ds-config caches this per
(tenant, principal) and compiles it.

### 3. ds-go-policy interprets it

`GET /dataset/` in ds-config asks its guard for `config:listDataset`, and the
engine partially evaluates — it does not test rows:

- `config:*` matches the action.
- The pattern's tenant is the placeholder, so it resolves to the requesting
  tenant `T`. A pattern naming any other tenant would be dropped here.

leaving one allow pattern and no denies:

```
crn:T:*:config::*:**
```

### 4. The adapter converts it to SQL

Against the dataset mapping — `tenant_id`, `owner_id`, `id`, region fixed empty,
type fixed `dataset`, published rows readable:

| segment | pattern | predicate |
| ------- | ------- | --------- |
| tenant | `T` | `dataset.tenant_id = ?` |
| scope | `*` | none |
| service | `config` | agrees with the table |
| region | *(empty)* | agrees with the fixed value |
| type | `*` | none |
| resource | `**` | none |

The allow clause is `dataset.tenant_id = ?`; the read mapping widens it:

```sql
(dataset.tenant_id = ? ) OR dataset.issuer = 'public'
```

### 5. The handler runs it

The clause is parenthesised and ANDed with the request's own filters and
pagination, so a `?name=…` narrows the published rows too:

```sql
SELECT * FROM datasets
WHERE ((dataset.tenant_id = ?) OR dataset.issuer = 'public')
  AND name = ?
ORDER BY created_at DESC
LIMIT 500 OFFSET 0
```

The principal sees its own tenant's datasets plus the platform's published ones,
from one stored document, with no statement mentioning published rows. Had the
policy granted no `config:listDataset` at all, the filter would have been `1=0`
and the request a 403.
