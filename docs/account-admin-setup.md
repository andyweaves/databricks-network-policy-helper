# Account-admin setup

## What needs what

| Operation | When | Privilege |
|---|---|---|
| Read `system.access.audit` / `outbound_network`, enrich, propose | always | workspace read on the system tables |
| **Resolve identities** (SCIM `users`/`service_principals` list) | ingress `--scoping-mode` includes identity | **account admin** |
| **Apply a policy** (`network_policies.*_rpc`) | gated apply, `--create-policy` | **account admin** |

Pure analysis, and IP-only / destination-only proposals you don't apply, need **no** account-level
privilege — just workspace read and a SQL warehouse. A workspace PAT is **not** sufficient for
account-level calls.

## Authentication model

`dbx-nwp-helper` uses the Databricks SDK's **unified auth**. Workspace calls (analysis, warehouse
management, reading the IP ACL) resolve credentials from a `--profile` in `~/.databrickscfg`,
`DATABRICKS_*` environment variables, or an OAuth session. Account-level calls additionally need
`--account-id <numeric id>` (not reliably discoverable from a workspace) and account-admin
credentials resolvable for the account host.

Find the account id in the Account console (top-right user menu) or in the account console URL after
`/account/`. Set the account host with `--account-host` for Azure
(`https://accounts.azuredatabricks.net`) or GCP (`https://accounts.gcp.databricks.com`).

## Recommended: account-admin service principal (OAuth M2M)

1. **Create a service principal** and grant it the **account admin** role:
   Account console → *User management* → *Service principals* → (create) → *Roles* → Account admin.
2. **Generate an OAuth secret** for it — note the `client_id` and the secret (shown once).
3. **Configure a profile** in `~/.databrickscfg` that authenticates as that SP, e.g.:
   ```ini
   [np-helper-account]
   host          = https://accounts.cloud.databricks.com
   account_id    = <your-account-id>
   client_id     = <sp-client-id>
   client_secret = <sp-oauth-secret>
   ```
   Then run with `--profile np-helper-account --account-id <your-account-id>`. (Prefer a secret
   manager / env var over a plaintext secret in the config where your setup allows it.)

For interactive use by an account admin, a `databricks auth login` OAuth profile also works — the SDK
resolves it the same way.

## Least privilege note

There is no finer-grained role than account admin for these APIs today. If that's too broad for a
customer, stop at **propose-only** (omit `--create-policy`) and have their account admin apply the
printed JSON policy themselves — the preview emits the exact object that would be sent.
