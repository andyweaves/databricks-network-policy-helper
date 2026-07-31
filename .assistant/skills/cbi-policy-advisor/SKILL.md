---
name: cbi-policy-advisor
description: Suggest and optionally apply Databricks Context-Based Ingress (CBI) network-policy allow-lists from real audit-log traffic. Use when the user wants to build/suggest a context-based ingress policy, tighten inbound network access, allow-list source IPs, analyse who connects to a workspace and from where, or turn system.access.audit logs into a CBI / account network-policy proposal. Analyses public source IPs carrying successful traffic, enriches them with open threat-intelligence and cloud-provider ranges plus RDAP ownership, proposes minimal/optimal/maximum CIDR framings optionally scoped by destination (Apps/Lakebase) and identity (users/SPs), and can write the result into a network policy's dry-run (log-only) or enforced ingress block via the Databricks SDK.
---

# CBI Policy Advisor

Turn real `system.access.audit` traffic into a proposed **Context-Based Ingress (CBI)** allow-list
for a Databricks **account network policy**, with threat-intel + cloud-range enrichment, optional
destination/identity scoping, and a safe dry-run-first apply path.

The engine is the notebook `notebooks/audit_log_cbi.py` at the repo root. This skill helps deploy it,
run it with sensible parameters, and review/apply a policy responsibly. Paths below are relative to
this skill folder (`.assistant/skills/cbi-policy-advisor/`).

## When to use

The user wants to: suggest/build a CBI or ingress allow-list; see which public IPs / identities
connect to a workspace and from where; tighten inbound network access from observed traffic; or
trial an ingress policy in dry-run before enforcing.

## Safety model — read first

- The notebook's default `policy_mode` is **`dry_run`** — writes the log-only `ingress_dry_run`
  block and **blocks nothing**. Always propose and validate here first.
- **`enforce` mode writes the enforced `ingress` block and CAN lock users (and the operator) out**
  if the allow-list is incomplete. It needs a distinct confirm phrase (`APPLY ENFORCE`).
- Never set `apply_policy=true` on the user's behalf without explicit, current confirmation of the
  mode and the exact CIDRs. Show the JSON preview first.
- The CBI policy schema is **IPv4-only**; IPv6 is analysed but never put in a policy.

## Workflow

1. **Authenticate.** Analysis needs only workspace read on `system.access.audit`. **Applying a
   policy, or identity scoping, needs an account admin** — recommended: an account-admin service
   principal via OAuth M2M with its secret in a secret scope. See `../../../docs/account-admin-setup.md`.
2. **Deploy the notebook** into the workspace:
   `python ../../../scripts/deploy_notebook.py --profile <cli-profile> --overwrite`
   (imports `notebooks/audit_log_cbi.py`; pass `--path` to choose the destination).
3. **Set parameters** — every decision is a widget at the top of the notebook (see its
   "Parameters & decisions" table). Key ones: `lookback_days`, `min_events`, `threat_feeds`,
   `scoping_mode`, `policy_framing`, `policy_mode`, and the account-auth group (auto-detected when
   left blank).
4. **Run analysis** — surface summary, per-principal network diversity, the frequent-public-IP
   candidate set, a ⚠️ threat-match table (investigate these regardless of the allow-list), and the
   ranked CIDR suggestions.
5. **Review the proposal** — the JSON preview shows the exact block that would be sent. Confirm the
   framing, scoping and mode with the user.
6. **Apply (gated)** — only with explicit go-ahead: set `apply_policy=true` and the mode's confirm
   phrase. Default to `dry_run`; promote to `enforce` only after dry-run logs look right.

## CIDR framings (`policy_framing`)

- `minimal` — one `/32` per observed IP (tightest).
- `optimal` — collapse adjacent addresses (**default**).
- `maximum` — the full RDAP-assigned range (needs `enable_rdap=true`).

## Scoping modes (`scoping_mode`)

- `ip_only` (default) — one rule: these CIDRs, all destinations, all identities.
- `ip_and_destination` — scope groups whose traffic maps cleanly to Apps or Lakebase.
- `ip_and_identity` — scope to the specific users/SPs seen (resolves emails→numeric ids via account
  SCIM; account admin required). Groups are **not** supported — only users and service principals.
- `ip_identity_and_destination` — both.

## Flagged groups

Threat/cloud-flagged groups are **kept and clearly flagged** by default (`exclude_flagged=false`).
Set `exclude_flagged=true` to hold them out of the proposal automatically. A threat-intel match on
an IP already reaching the workspace warrants investigation regardless of the allow-list.

## References (relative to this skill)

- `../../../docs/threat-intel-feeds.md` — the enrichment feeds, what each represents, licensing.
- `../../../docs/cbi-sdk-schema.md` — the verified `AccountNetworkPolicy` SDK object model.
- `../../../docs/account-admin-setup.md` — account-admin SP + secret-scope setup.
- `../../../docs/egress-fqdns.md` — external hosts to allow when behind egress controls / SEG.
- `../../../genie/genie-space-spec.md` — spec for a backing AI/BI Genie space (build once tables persist).

## Engine & helper (repo root)

- `../../../notebooks/audit_log_cbi.py` — the analysis + proposal + apply notebook (source of truth).
- `../../../scripts/deploy_notebook.py` — import/update the notebook into a workspace via the CLI.
