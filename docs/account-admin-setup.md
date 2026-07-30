# Account-admin setup

## What needs what

| Operation | When | Privilege |
|---|---|---|
| Read `system.access.audit`, enrich, propose | always | workspace read on the audit table |
| **Resolve identities** (SCIM `users`/`service_principals` list) | `scoping_mode` includes identity | **account admin** |
| **Apply a CBI policy** (`network_policies.*_rpc`) | gated apply cell, `apply_policy=true` | **account admin** |

Pure analysis, and IP-only / destination-only proposals you don't apply from the notebook, need
**no** account-level privilege. A workspace PAT is **not** sufficient for account-level calls.

## Recommended: account-admin service principal (OAuth M2M)

1. **Create a service principal** and grant it the **account admin** role:
   Account console → *User management* → *Service principals* → (create) → *Roles* → Account admin.
2. **Generate an OAuth secret** for it — note the `client_id` and the secret (shown once).
3. **Store the secret in a Databricks secret scope** (never hardcode):
   ```bash
   databricks secrets create-scope cbi_advisor
   databricks secrets put-secret cbi_advisor account_sp_secret
   ```
4. **Set the notebook widgets** (group 4):
   - `4a account_id` — your Databricks account id
   - `4b account_host` — e.g. `https://accounts.cloud.databricks.com`
     (Azure: `https://accounts.azuredatabricks.net`; GCP: `https://accounts.gcp.databricks.com`)
   - `4c account_sp_client_id` — the SP's client_id
   - `4d account_secret_scope` — `cbi_advisor`
   - `4e account_secret_key` — `account_sp_secret`

`_account_client()` then builds `AccountClient(host, account_id, client_id, client_secret=<secret>)`.

## Ambient fallback

If widgets 4c–4e are blank, the notebook falls back to `AccountClient(host, account_id)` /
`AccountClient()`, relying on the runtime's ambient account credentials (e.g. an account-admin
OAuth profile in `~/.databrickscfg`). Fine for interactive local use by an account admin; the SP
route is preferred for repeatable / job runs.

## Least privilege note

There is no finer-grained role than account admin for these APIs today. If that's too broad for a
customer, stop at **suggest + JSON preview** and have their account admin apply the printed policy
themselves — the notebook's preview cell emits the exact object.
