# Databricks CBI Helper

Turn real `system.access.audit` traffic into a proposed **Context-Based Ingress (CBI)** allow-list
for a Databricks **account network policy** — enriched with open threat-intelligence and
cloud-provider IP ranges, optionally scoped by destination and identity, and applied safely
dry-run-first.

It answers: *who connects to this workspace, from where, and what should the inbound allow-list be?*

## What it does

1. Analyses the last N days of `system.access.audit` — request surfaces, per-principal network
   diversity, and the **public source IPs** carrying successful traffic.
2. Enriches candidate IPs with:
   - **Threat intelligence** (Spamhaus DROP, Tor, FireHOL, IPsum, DShield, CINS) — flags IPs
     already talking to your workspace that appear on a blocklist.
   - **Cloud-provider ranges** (AWS, GCP, Oracle, Azure — official feeds) — flags cloud-owned IPs.
   - **Databricks-owned ranges** (official `databricks.com/networking/v1/ip-ranges.json`, all 3
     clouds) — flags Databricks' own control-plane / serverless IPs so they're excluded, not
     allow-listed.
   - **RDAP** ownership — names the owning org and its full assigned range.
3. Proposes CIDR framings per owner group — `minimal` / `optimal` / `maximum` — annotated with the
   enrichment, ranked, with known-bad / cloud-owned groups flagged for review.
4. Optionally scopes rules by **destination** (Apps / Lakebase) and **identity** (specific users /
   service principals).
5. Optionally writes the result into the network policy via the Databricks SDK, in **`dry_run`**
   (log-only) or **`enforce`** (blocking) mode — both gated behind explicit, mode-specific
   confirmation.

## Safety model

- Default `policy_mode` is **`dry_run`** — writes the log-only `ingress_dry_run` block and **blocks
  nothing**. Validate here first.
- **`enforce` mode writes the enforced `ingress` block and CAN lock users out** if the allow-list
  is incomplete. It requires a distinct confirm phrase (`APPLY ENFORCE`).
- The CBI policy schema is **IPv4-only**; IPv6 is analysed but never put in a policy.
- Nothing is written unless you set `apply_policy=true` **and** type the mode's confirm phrase.

## Quick start

1. **Deploy the notebook** into a workspace:
   ```bash
   python scripts/deploy_notebook.py --profile <cli-profile> --overwrite
   ```
   (Imports `notebooks/audit_log_cbi.py` to `/Users/<you>/audit_log_cbi`; pass `--path` to change.)
2. **Open it**, set the widgets at the top (all decisions live there), and run top to bottom.
3. **Review** the suggestions and the JSON preview.
4. **Apply** only with intent — start in `dry_run`, review the logs, then re-run in `enforce`.

## Permissions

- Analysis / enrichment: workspace read on `system.access.audit`.
- **Applying a policy, or identity scoping: account admin** (recommended: an account-admin service
  principal via OAuth M2M with its secret in a secret scope). See
  [`docs/account-admin-setup.md`](docs/account-admin-setup.md).

## Layout

| Path | What |
|---|---|
| `notebooks/audit_log_cbi.py` | The analysis + proposal + apply notebook (the engine). |
| `notebooks/install_skill.py` | Installs the Genie Code skill into your user skills directory. |
| `scripts/deploy_notebook.py` | Import/update the notebook into a workspace via the CLI. |
| `docs/threat-intel-feeds.md` | The enrichment feeds, what each represents, licensing. |
| `docs/cbi-sdk-schema.md` | The verified `AccountNetworkPolicy` SDK object model. |
| `docs/account-admin-setup.md` | Account-admin service-principal + secret-scope setup. |
| `docs/egress-fqdns.md` | External hosts to allow when behind egress controls / SEG. |
| `genie/genie-space-spec.md` | Spec for a backing AI/BI Genie space (build once tables persist). |
| `.assistant/skills/cbi-helper/` | Databricks Genie Code skill wrapping this workflow. |

## Databricks Genie Code skill

`.assistant/skills/cbi-helper/SKILL.md` is a [Databricks Genie Code
skill](https://docs.databricks.com/aws/en/genie-code/skills) that teaches the coding agent to run
this workflow. Genie Code discovers per-user skills under `/Users/<you>/.assistant/skills/`.

**Easiest install:** run **`notebooks/install_skill.py`** from the repo / git-folder checkout — it
copies the `cbi-helper` skill into your user skills directory for you (defaults to the user scope;
a `workspace` scope option exists for account-wide install if you have permission). Alternatively,
copy the `.assistant/skills/cbi-helper` folder there by hand.

Once installed, Genie Code picks it up next time you use it; invoke it explicitly with
`@cbi-helper` in chat.

## Genie space

`genie/genie-space-spec.md` specifies a Genie space over the audit + enrichment tables so operators
can ask questions in natural language ("which external IPs hit the workspace and are any on a
blocklist?"). Build it **after** persisting the enrichment tables to a stable schema (set the
notebook's `enrichment_schema` widget) — don't build over temp views.

## Notes & caveats

- Requires `databricks-sdk>=0.113.0` for the CBI dataclasses — the notebook pins and restarts to
  ensure this on serverless / older runtimes.
