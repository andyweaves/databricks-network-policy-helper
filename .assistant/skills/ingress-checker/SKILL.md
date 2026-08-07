---
name: ingress-checker
description: Review how a running Databricks ingress (CBI) network policy is performing and recommend rules to add, from system.access.inbound_network. Use when the user wants to check/review/audit an existing ingress or context-based-ingress policy, see what their inbound network policy is denying or blocking, evaluate dry-run ingress denials, find legitimate traffic a policy is blocking, or get recommendations for ingress allow rules to add. Read-only: reads denied inbound requests over a lookback window, splits enforced (DENY) vs dry-run (DENY_DRY_RUN) denials, flags source IPs against open threat-intel feeds, and produces ADD-candidate and working-as-intended tables. Never creates or modifies a policy.
---

# Ingress Policy Checker (review a running CBI policy)

Read-only review of an **already-running** ingress (context-based ingress / CBI) network policy. The
engine is `notebooks/ingress_policy_checker.py` in the databricks-network-policy-helper repo.

It answers: *is my ingress policy denying the right things, and what legitimate traffic is it (or
would it be) blocking that I should allow-list?*

To **build/apply** an ingress policy use `ingress-helper`; for egress review use `egress-checker`; to
review both directions at once use `full-policy-checker`.

## When to use

The user wants to: review/check/audit a running ingress policy, see what it's denying, understand
dry-run ingress denials before enforcing, find legitimate inbound traffic being blocked, or get
recommendations for allow rules to add. **Not** for building a policy from scratch (use
`ingress-helper`) or migrating an IP ACL (use `ip-acl-migration`).

## What it does

1. Reads `system.access.inbound_network` over `lookback_days`. **This table records only denied
   inbound requests** — hard denials (`DENY`, enforced) and dry-run would-be-denials
   (`DENY_DRY_RUN`). Empty = no policy assigned/logging, or nothing was denied.
2. Aggregates denials by source IP, keeping matched `rule_label`, `request_path`, identity and
   workspace so you can judge whether each denial is legitimate.
3. Flags each source IP against a compact, high-signal subset of the open threat-intel feeds the
   ingress helper uses (Spamhaus DROP, FireHOL level1, IPsum ≥3-list, DShield, CINS, Tor).
4. Produces two review tables:
   - **ADD candidates** — un-flagged denied sources = legitimate access being blocked (or would be
     under enforcement). Candidate allow rules.
   - **Working as intended** — flagged / threat-intel denied sources = the policy keeping bad actors
     out. No action.

## What it does NOT do

- **No removals.** `inbound_network` logs only *denied* traffic, never *allowed* traffic, so it can't
  see which allow rules are unused. Allow-rule pruning needs `system.access.audit`; the checker says
  so rather than guess.
- **No writes.** It never creates, updates, or assigns a policy. Take the ADD candidates to
  `ingress-helper` (or your change process).

## Options (widgets)

- `lookback_days`, `min_events`, `workspace_id_filter` (blank = all workspaces the reader can see)
- `flag_threat_intel` (default true; set false to skip all outbound feed fetches on an egress-locked
  cluster — every IP is then treated as un-flagged and the review still works)

## Notes

- Needs read access to `system.access.inbound_network` (no account admin required — it only reads).
- If all denials are dry-run, the policy is in preview and blocking nothing yet: add the ADD
  candidates first, then switch to enforce once the remaining dry-run denials are only bad actors.
