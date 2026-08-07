---
name: ingress-helper
description: Suggest and optionally apply Databricks Context-Based Ingress (CBI) network-policy allow-lists from real audit-log traffic. Use when the user wants to build/suggest a context-based ingress policy, tighten inbound network access, allow-list source IPs, analyse who connects to a workspace and from where, or turn system.access.audit logs into a CBI / account network-policy proposal. Analyses public source IPs carrying successful traffic, enriches them with open threat-intelligence and cloud-provider ranges plus RDAP ownership, proposes minimal/optimal/maximum CIDR framings optionally scoped by destination (Apps/Lakebase) and identity (users/SPs), and can write the result into a network policy's dry-run (log-only) or enforced ingress block via the Databricks SDK.
---

# Context-Based Ingress (CBI) Helper

Turn real `system.access.audit` traffic into a proposed **Context-Based Ingress (CBI)** allow-list
for a Databricks **account network policy**, with threat-intel + cloud-range enrichment, optional
destination/identity scoping, and a safe dry-run-first apply path.

The engine is the notebook `notebooks/ingress_policy_helper.py` at the repo root. This skill helps
deploy it, run it with sensible parameters, and review/apply a policy responsibly. Paths below are
relative to this skill folder (`.assistant/skills/ingress-helper/`).

For **egress** (outbound allow-lists) use `egress-helper`. To end up with a combined ingress + egress
policy, run one helper with `policy_action=create_new`, then the other with
`policy_action=add_to_existing` pointed at the policy id the first one created.

## When to use

The user wants to: suggest/build a CBI or ingress allow-list; see which public IPs / identities
connect to a workspace and from where; tighten inbound network access from observed traffic; or
trial an ingress policy in dry-run before enforcing.

## Safety model — read first

- The notebook's default `policy_mode` is **`dry_run`** — writes the log-only `ingress_dry_run`
  block and **blocks nothing**. Always propose and validate here first.
- **`enforce` mode writes the enforced `ingress` block and CAN lock users (and the operator) out**
  if the allow-list is incomplete. Keep `policy_mode=dry_run` until the logs look right.
- Never set `create_policy=true` on the user's behalf without explicit, current confirmation of the
  mode and the exact CIDRs. Show the JSON preview first.
- The CBI policy schema is **IPv4-only**; IPv6 is analysed but never put in a policy.

## Workflow

1. **Authenticate.** Analysis needs only workspace read on `system.access.audit`. **Applying a
   policy, or identity scoping, needs an account admin** — recommended: an account-admin service
   principal via OAuth M2M with its secret in a secret scope. See `docs/account-admin-setup.md`.
2. **Deploy the notebook** into the workspace:
   `python scripts/deploy_notebook.py --profile <cli-profile> --overwrite`
   (imports `notebooks/ingress_policy_helper.py`; pass `--path` to choose the destination).
3. **Set parameters** — every decision is a widget at the top of the notebook (see its
   "Parameters & decisions" table). Key ones: `lookback_days`, `min_events`, `threat_feeds`,
   `scoping_mode`, `policy_framing`, `policy_mode`, and the account-auth group (auto-detected when
   left blank).
4. **Run analysis** — surface summary, per-principal network diversity, the frequent-public-IP
   candidate set, a ⚠️ threat-match table (investigate these regardless of the allow-list), and the
   ranked CIDR suggestions.
5. **Review the proposal** — the JSON preview shows the exact block that would be sent. Confirm the
   framing, scoping and mode with the user.
6. **Create (gated)** — only with explicit go-ahead: set `create_policy=true` (and `auto_assign` to
   bind the workspace(s)). Default to `dry_run`; promote to `enforce` only after dry-run logs look
   right.

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

## Policy scope (`policy_scope`) & limits

- `single` (default) — one policy across all workspaces.
- `per_workspace` — a tailored policy per workspace + a recommended workspace→policy assignment
  table. Policies are named `<name_prefix>-ws-<id>`; single scope is just `<name_prefix>`.
  Audit `workspace_id = 0` is account-level, excluded unless `include_account_level=true`.

Applying is governed by a few widgets: **`create_policy`** is the master switch (nothing is written
unless true); **`policy_action`** chooses `create_new` (a fresh policy named from `name_prefix`) or
`add_to_existing` (update the policy in **`existing_policy_id`**, replacing only its ingress block and
leaving its egress + everything else intact — requires `policy_scope=single`); **`auto_assign`** binds
the workspace(s). `add_to_existing` is how you layer ingress onto a policy the egress helper already
created (and vice-versa) for a combined policy. On `create_new` the basic egress block is set from
`egress_policy`: `allow_all` (FULL_ACCESS), `dry_run` (restricted, log-only for all products), or
`restricted` (enforced — configure allowed destinations yourself afterwards); `add_to_existing` keeps
the target's egress untouched.

## Existing IP access list & denied requests

If the workspace has an **IP access list** (ACL), `ip_acl_handling` (widget 3f) controls it:
- `migrate_and_enrich` (default) — recreate the ACL as CBI rules **and** add traffic-derived rules.
- `migrate` — recreate the ACL exactly (ALLOW → allow rules, BLOCK → deny rules), no traffic rules.
- `ignore` — traffic-derived rules only.

The notebook also surfaces requests **currently being denied** by the ACL (`action_name =
'IpAccessDenied'` / HTTP 403) as review signal. Set `deny_denied_ips=true` (widget 3g) to also turn
those source IPs into explicit CBI deny rules.

The notebook knows the Databricks network-policy limits and **warns + auto-caps** to keep proposals
valid: **50 ingress rules, 2000 CIDR blocks, 100 identities per policy; 1000 policies per account**.

## Flagged groups & threat-intel deny rules

Threat-intel and cloud-provider-owned groups are **always excluded** from proposed allow rules — an
allow-list must never include a known-bad or cloud-provider range. Threat matches still appear in the
⚠️ threat-match table for investigation (traffic from a flagged IP already reaching the workspace may
mean a compromised identity).

**Databricks-owned** IPs are the exception and take **precedence**: Databricks' own control-plane /
serverless IPs (identified from the official `databricks.com/networking/v1/ip-ranges.json` feed, all
three clouds) are **auto-added to the allow-list** in their own unscoped rule — they're the platform
reaching in, so leaving them out would lock the control plane out under an enforced policy. This
overrides the cloud-provider flag (a Databricks IP is also an AWS/Azure/GCP IP).

Separately, the `threat_deny_rules` widget can add **deny rules** built from the threat-intel table,
independent of the allow-list: `off` (none), `matched_only` (deny only threat CIDRs that matched
observed traffic), or `all` (deny entire feeds regardless of matches — one deny rule per feed).

When the deny list exceeds the `MAX_DENY_CIDRS` cap, it is **prioritised, not skipped**: keep
confidence-1 entries (drop confidence-2), put `attacker_subnet` ranges first, then take the top N to
fit — and report how many CIDRs are included vs excluded. (Selection order is preserved so the hard
2000-CIDR-per-policy limit also trims the lowest-priority entries first.)

CBI `RESTRICTED_ACCESS` is **default-deny** (deny rules are exceptions to allow rules). If a policy
would end up with deny rules but **no** allow rules, a catch-all allow (all public IPs) is added
automatically so non-denied traffic is still permitted — otherwise everything would be blocked.

## Source repo

This skill wraps the **databricks-network-policy-helper** repo
(`https://github.com/andyweaves/databricks-network-policy-helper`). The paths below are relative to that repo
root. If this skill was copied out of the repo (e.g. into `/Users/<you>/.assistant/skills/`), find
those files back in the repo / the git folder it was installed from.

## References

- `docs/threat-intel-feeds.md` — the enrichment feeds, what each represents, licensing.
- `docs/cbi-sdk-schema.md` — the verified `AccountNetworkPolicy` SDK object model.
- `docs/account-admin-setup.md` — account-admin SP + secret-scope setup.

## Engine & helper (repo root)

- `notebooks/ingress_policy_helper.py` — the analysis + proposal + apply notebook (source of truth).
- `scripts/deploy_notebook.py` — import/update the notebook into a workspace via the CLI.
