# Policy examples

Runnable policy documents for `ds-go-policy`, modeled on real Grasp APIs. Each
`*.json` file is loaded and evaluated by tests in `engine/` (`TestExample_*`),
so the examples stay in sync with the implementation.

## What a policy looks like

A policy is a list of statements. A statement grants (`allow`) or blocks
(`deny`) a set of `actions` on a set of `resources`, optionally gated by
`conditions`:

```json
{
  "id": "pol-file-access",
  "version": "1.0.0",
  "statements": [
    {
      "sid": "read-active-files",
      "effect": "allow",
      "actions": ["file:getFile", "file:listFiles"],
      "resources": ["crn:<tenant>:*:file::file:**"],
      "conditions": {
        "StringEquals": { "status": ["active", "archived"] }
      }
    }
  ]
}
```

| Field         | Value                                                                  |
| ------------- | ---------------------------------------------------------------------- |
| `effect`      | `allow` or `deny`.                                                     |
| `actions`     | `"{service}:{operation}"`, `"{service}:*"`, or `"*"`.                |
| `resources`   | CRN patterns; `*` matches one segment, `**` a whole path tail.         |
| `conditions`  | optional `operator → key → values`; omit to match unconditionally.    |
| `sid`         | statement label, returned as the decision reason.                     |

A CRN is `crn:{tenant}:{scope}:{service}:{region}:{type}:{resource}`. In these
examples `scope` is `*` and `region` is empty; DS-file uses `service`/`type`
`file` with the file path as `resource`, Config uses `service` `config` with
the resource kind (`plan`, `invoice`, …) as `type` and the id as `resource`.

## How it is enforced

- **default-deny** — a request is denied unless some `allow` matches it.
- **deny-wins** — any matching `deny` overrides every `allow`.
- **a statement matches** when one of its `actions`, one of its `resources`,
  and *all* of its `conditions` match the request.
- **conditions** — operators AND, keys within an operator AND, a key's values
  OR. Keys resolve three ways:
  - a plain key (`status`) is read from `Request.Context`;
  - `resource.path[N]` is the Nth path segment (0-based) of the resource
    itself — answered by the engine, never spoofable via context;
  - `<service>:<name>` (`file:path_prefix:project`) is service-owned: the
    service resolves it from trusted data into the context.

## `file-access.json`

1. **`read-active-files`** — read (`getFile`/`listFiles`/`getFileContent`/`search`)
   on any file, only when `status` is `active` or `archived` (a key's values OR
   together).
2. **`write-projectx-unless-restricted`** — writes under `projectx/**`, unless
   the file's `tag.classification` is `restricted`.
3. **`protect-projectx-secrets`** — deny every action on `projectx/secrets/**`
   (deny-wins).

## `platform-guardrail.json`

A **platform-issued** policy bound to every principal. Its pattern uses the
reserved token `self` (`crn.CallerTenant`), which stands for the requesting
tenant, so the one document guards each tenant's own resources without reaching
across tenants.

1. **`aic-protect-secrets`** — deny every action on any `**/secrets/**` path in
   the caller's own tenant (a guardrail that overrides tenant allows, deny-wins).

> The two reserved tenant tokens are distinct: `self` is the requesting tenant
> (valid in a pattern only), while `aic` (`crn.PlatformTenant`) names
> platform-owned resources — an `aic` pattern matches only platform-owned rows,
> never another tenant's. See the "platform tenant" section of the top-level
> [`README`](../../README.md) for the full table.

## `inbound-partitions.json`

Path-partitioned data (`files/inbound/{org_number}/...`) pinned to a value set
with one pattern instead of one resource pattern per partition.

1. **`inbound-by-org`** — read/list under `files/inbound/**`, only when the
   partition segment (`resource.path[2]`) is one of the listed org numbers.
   For listing, `pathfilter` folds the condition into one glob per org
   (`files/inbound/123456789/**`, …); `sqlfilter` renders it as an `IN` clause
   using both `Mapping.Conditions` and `Mapping.AllowedConditionOperators`.

## `inbound-country.json`

A **service-owned condition key** in `<service>:<name>` form
(`inbound:customer:country_code`). The Inbound service resolves it from trusted
customer data into `Request.Context`; the engine then matches it like any other
key. Compilation validates the grammar, but the service still owns the
allowlist and the mapping to storage.

1. **`inbound-nordic-only`** — read/list under `files/inbound/**`, only when the
   customer's `country_code` is one of `NO`/`SE`/`DK`.

## `config-billing.json`

1. **`billing-read`** — billing list/get across all Config resources.
2. **`plan-write-staging-only`** — create/update/delete `plan`, only when
   `environment` is `staging`.
3. **`no-invoice-generation`** — deny `config:generateInvoice`.

## `dataset-owner-grant.json` + `platform-public-datasets.json`

The core v1.4.0 scenario for a platform-published table (`dataset`), modeled as
**two separate documents** — public visibility is not copied into every user's
policy.

- **`dataset-owner-grant.json`** — the caller's *own* policy.
  1. **`own-single-dataset`** — list/get one specific dataset owned by the
     caller's tenant (a concrete tenant UUID + concrete id).
- **`platform-public-datasets.json`** — a single **platform-issued** policy the
  IAM binding layer attaches to *every* principal (like `platform-guardrail.json`).
  1. **`public-datasets`** — list/get every **public** dataset, addressed by the
     platform token `aic` (`crn.PlatformTenant`); rows an issuer published for all.

The engine composes whatever policy set the caller resolves for a principal, so
these two documents combine at evaluation time. At list time `sqlfilter.Where`
yields the union — the caller's own row OR all public rows (marked by the fixed
`issuer = 'public'` convention) — and nothing from another tenant:

```sql
(tenant_id = ? AND id = ?)   -- the caller's granted dataset
  OR (issuer = 'public')      -- every public/platform-owned dataset
```

The caller's own `id`/`status`/etc. filters stay inside the first group, so they
never narrow the public rows (important for list endpoints).
