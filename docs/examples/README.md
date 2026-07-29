# Policy examples

Runnable policy documents for `ds-go-policy`, modeled on real Grasp APIs. Each
`*.json` file is loaded and evaluated by tests in `engine/` (`TestExample_*`),
so the examples stay in sync with the implementation.

## Anatomy

- **Action** — `"{service}:{operationId}"` from the service's OpenAPI, e.g.
  `file:getFile`. Wildcards: `"file:*"` and `"*"`.
- **Resource** — a CRN
  `crn:{tenant}:{scope}:{service}:{region}:{type}:{resource}`. Patterns may use
  `*` (one segment) and `**` (recursive, resource path only).
- **Conditions** — `operator → key → values`; operators AND, keys AND, a key's
  values OR. Keys are matched against the attributes the service supplies in
  `engine.Request.Context`.

### CRN conventions

| API      | `service` | `type`                                    | `resource`  |
| -------- | --------- | ----------------------------------------- | ----------- |
| DS-file  | `file`    | `file`                                    | `file_path` |
| Config   | `config`  | resource kind (`plan`, `invoice`, `model`, …) | resource `id` |

`scope` is the owning subject/partition (`*` in these examples); `region` is
currently empty.

## `file-access.json`

1. **`read-active-files`** — read (`getFile`/`listFiles`/`getFileContent`/`search`)
   on any file, only when `status` is `active`.
2. **`write-projectx-unless-restricted`** — writes under `projectx/**`, unless
   the file's `tag.classification` is `restricted`.
3. **`protect-projectx-secrets`** — deny every action on `projectx/secrets/**`
   (deny-wins).

## `platform-guardrail.json`

A **platform-issued** policy: its patterns use the reserved platform token
`aic` (`crn.PlatformTenant`) as a placeholder for the requesting tenant, so the
one document applies to every tenant it is bound to.

1. **`aic-protect-secrets`** — deny every action on any `**/secrets/**` path,
   in any tenant (a guardrail that overrides tenant allows, deny-wins).

## `config-billing.json`

1. **`billing-read`** — billing list/get across all Config resources.
2. **`plan-write-staging-only`** — create/update/delete `plan`, only when
   `environment` is `staging`.
3. **`no-invoice-generation`** — deny `config:generateInvoice`.
