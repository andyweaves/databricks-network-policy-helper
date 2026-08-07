---
name: egress-checker
description: Review how a running Databricks serverless egress (SEG) network policy is performing and recommend destinations to add, from system.access.outbound_network. Use when the user wants to check/review/audit an existing egress policy, see what their outbound network policy is denying or blocking, evaluate dry-run egress denials, find legitimate egress a policy is blocking, or get recommendations for egress allow rules to add. Read-only: reads denied egress over a lookback window, splits enforced (DROP) vs dry-run (DRY_RUN_DENIAL) denials, classifies storage vs internet FQDNs, flags FQDNs against abuse.ch ThreatFox, and produces ADD-candidate and flagged-denial tables. Never creates or modifies a policy.
---

# Egress Policy Checker (review a running SEG policy)

Read-only review of an **already-running** serverless egress (SEG) network policy. The engine is
`notebooks/egress_policy_checker.py` in the databricks-network-policy-helper repo.

It answers: *is my egress policy blocking the right things, and what legitimate outbound traffic is
it (or would it be) blocking that I should allow-list?*

To **build/apply** an egress policy use `egress-helper`; for ingress review use `ingress-checker`; to
review both directions at once use `full-policy-checker`.

## When to use

The user wants to: review/check/audit a running egress policy, see what it's denying, understand
dry-run egress denials before enforcing, find legitimate egress being blocked, or get recommendations
for egress allow rules to add. **Not** for building an egress policy from scratch (use
`egress-helper`).

## What it does

1. Reads `system.access.outbound_network` over `lookback_days`. **This table records only denied
   egress** — hard denials (`DROP`, enforced) and dry-run would-be-denials (`DRY_RUN_DENIAL`).
   Empty = no egress policy logging (stand one up in dry_run first), or nothing was denied.
2. Classifies each denied destination the same way `egress-helper` does — S3 / GCS / Azure storage
   vs internet FQDN; bare `s3.<region>.amazonaws.com` is noted as too broad to allow-list.
3. Flags denied internet FQDNs against the abuse.ch ThreatFox botnet-C2 domain feed.
4. Produces two review tables:
   - **ADD candidates** — un-flagged denied destinations = legitimate egress being blocked (or would
     be under enforcement). Candidate allow rules.
   - **Flagged denials** — destinations on ThreatFox = the policy blocking known-bad egress. Do NOT
     add these.

## What it does NOT do

- **No removals.** `outbound_network` logs only *denied* egress, never *allowed* egress, so it can't
  see which allow rules are unused. The checker says so rather than guess.
- **No writes.** It never creates, updates, or assigns a policy. Take the ADD candidates to
  `egress-helper` (or your change process).

## Exfil note

The RESTRICTED_ACCESS allow-list is the real control against data exfiltration — a novel attacker
host is on no feed but is still blocked by default-deny. A ThreatFox-flagged denial is a bonus
signal, not the protection.

## Options (widgets)

- `lookback_days`, `min_events`, `source_type_filter` (blank = all `network_source_type`s)
- `flag_threat_domains` (default true; set false to skip the ThreatFox fetch on an egress-locked
  cluster — every FQDN is then treated as un-flagged and the review still works)

## Notes

- Needs read access to `system.access.outbound_network` (no account admin required — it only reads).
- If all denials are dry-run, the policy is in preview and blocking nothing yet: add the ADD
  candidates first, then switch to enforce once the remaining dry-run denials are only bad hosts.
