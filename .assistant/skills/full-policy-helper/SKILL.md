---
name: full-policy-helper
description: Build a complete Databricks account network policy — both ingress (CBI) and egress (SEG) — from observed traffic, in one go. Use when the user wants a full network policy from scratch, both inbound and outbound rules, or to combine the ingress and egress helpers into a single policy. Runs the ingress (audit_log_cbi) and egress (egress_policy_helper) analyses, merges their rules per workspace target, and creates one policy each (dry-run or enforce).
---

# Full Network Policy Helper (ingress + egress)

Combines the **ingress** (CBI, from `system.access.audit` source IPs) and **egress** (SEG, from
`system.access.outbound_network` destinations) helpers into a single account network policy. The
engine is `notebooks/full_policy_helper.py` in the databricks-network-policy-helper repo.

Use `cbi-helper` or `egress-helper` alone if you only need one direction.

## How it works

1. Installs the SDK + restarts **once**, then sets `_COMBINED_RUN = True`.
2. `%run`s `audit_log_cbi` and `egress_policy_helper` — both in **propose-only** mode (they build
   their rule structures but skip their own restart and create cells because `_COMBINED_RUN` is set).
3. **Merges** per policy target: the ingress block (into `ingress` or `ingress_dry_run` per
   `policy_mode`) + the egress block go onto one `AccountNetworkPolicy`.
4. Gated create (`create_policy` / `auto_assign`) creates each merged policy and binds workspaces.

## Options

All the ingress and egress widgets apply (set them in the widget bar) — e.g. `lookback_days`,
`threat_feeds`, `scoping_mode`, `ip_acl_handling`, `block_threat_domains`, `policy_mode`,
`name_prefix`, and the account-auth group. **Set `policy_scope` once** (single / per_workspace) — both
directions read it, so their targets line up. The combiner adds only the final `create_policy` (Z1)
and `auto_assign` (Z2) gate.

## Safety

Nothing is written unless `create_policy=true`. `policy_mode=dry_run` (default) writes log-only
ingress + dry-run egress. `enforce` blocks both non-matching source IPs *and* egress not on the
allow-list — validate in dry_run first, and verify inbound + outbound still work after enforcing.

## Notes

- Policy names match the ingress helper's (`<name_prefix>` single, `<name_prefix>-ws-<id>`
  per_workspace), so an ingress-only run and a combined run land on the **same** policy — the
  combiner just adds the egress block.
- Merged create is get-or-update: it sets the ingress target block and egress on the live policy,
  leaving any block it didn't touch intact.
- Requires an account admin (same account-auth widgets as the child notebooks). See
  `docs/account-admin-setup.md`.
