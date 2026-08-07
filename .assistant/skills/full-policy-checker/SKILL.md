---
name: full-policy-checker
description: Review how a running Databricks account network policy is performing across both ingress (CBI) and egress (SEG) at once, and recommend rules to add. Use when the user wants to check/review/audit a full network policy, review both inbound and outbound denials together, get a combined policy-health summary, or evaluate a dry-run policy before enforcing. Read-only: runs the ingress and egress checkers over system.access.inbound_network and system.access.outbound_network, then prints a combined summary of denials, ADD candidates, and blocked-as-intended per direction. Never creates or modifies a policy.
---

# Full Policy Checker (review a running ingress + egress policy)

Read-only combined review of an **already-running** account network policy across both directions.
The engine is `notebooks/full_policy_checker.py` in the databricks-network-policy-helper repo.

It answers: *how is my whole network policy performing — what's it denying inbound and outbound, and
what legitimate traffic should I allow-list before (or now that) it's enforced?*

Use `ingress-checker` or `egress-checker` alone if you only care about one direction. To **build**
a full policy use `full-policy-helper`.

## How it works

1. `%run`s `ingress_policy_checker` (reads `system.access.inbound_network`) and captures its results.
2. `%run`s `egress_policy_checker` (reads `system.access.outbound_network`) and captures its results.
3. Prints a **combined policy-health summary** — per direction: denied entities, enforced vs dry-run
   denial counts, ADD candidates, and blocked-as-intended.

## What it does NOT do

- **No removals.** The network system tables log only *denied* traffic, not *allowed* traffic, so
  unused allow rules aren't visible from here.
- **No writes.** Like the checkers it runs, it never creates, updates, or assigns a policy. Take the
  ADD candidates to `full-policy-helper` (or your change process).

## Options

All the ingress and egress checker widgets apply (set them in the widget bar): `lookback_days`,
`min_events`, `workspace_id_filter`, `source_type_filter`, `flag_threat_intel`, `flag_threat_domains`.

## Notes

- Needs read access to `system.access.inbound_network` and `system.access.outbound_network` (no
  account admin required — it only reads).
- If all denials across both directions are dry-run, the policy is in preview and blocking nothing
  yet — work through the ADD candidates in each checker, then move to enforce.
