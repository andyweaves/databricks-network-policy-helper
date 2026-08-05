---
name: egress-helper
description: Propose and apply a Databricks serverless egress (SEG) network-policy allow-list from observed outbound traffic in system.access.outbound_network. Use when the user wants to build/suggest an egress policy, allow-list outbound destinations, control serverless egress, turn dry-run egress denials into an allow-list, or block known-bad domains. Classifies observed destinations into storage (S3/GCS/Azure) and internet FQDNs, shows what it would allow for review, and can create the egress policy (dry-run or enforce) and optionally block threat-intel domains.
---

# Egress Policy Helper (serverless egress / SEG)

Builds a Databricks **account network policy egress** allow-list from observed outbound traffic. The
engine is `notebooks/egress_policy_helper.py` in the databricks-network-policy-helper repo.

For **ingress** (source-IP allow-lists) use `cbi-helper`; to build a full ingress+egress policy in
one go, use `full-policy-helper` (if present).

## The dry-run-observe loop (important)

`system.access.outbound_network` records only **denied** egress — including **`DRY_RUN_DENIAL`**
(would-be-denials under a dry-run policy). So the workflow is:
1. Stand up an egress policy in **dry_run** (RESTRICTED_ACCESS, log-only) — blocks nothing.
2. Let it observe; the table logs every destination that *would* be denied = your egress footprint.
3. Run this helper to turn those destinations into a real allow-list.

If the table is empty, no egress policy is logging yet — start with step 1.

## What it does

1. Reads `outbound_network` over `lookback_days` (optional `network_source_type` filter).
2. Classifies each destination by host shape:
   - **S3** `<bucket>.s3.<region>.amazonaws.com` → storage rule (bucket + region from the host).
   - **GCS** `[<bucket>.]storage.googleapis.com` → storage rule.
   - **Azure** `<account>.<blob|dfs|file>.core.windows.net` → storage rule (account + service).
   - Bare `s3.<region>.amazonaws.com` (no bucket) → **skipped** (too broad to be a useful rule).
   - Everything else → **internet FQDN** allow rule.
3. Optional RDAP owner lookup on internet FQDNs (context).
4. **Review tables** (internet + per-cloud storage) — confirm before creating.
5. Optional **threat-intel domain blocking** (`block_threat_domains`: off / matched_only / all) →
   `blocked_internet_destinations` (FQDN-only, enforced in any mode, takes precedence over allows).
   Feed: malware-filter "online malicious domains" (abuse.ch URLhaus, deduped to FQDNs; free, no
   key). `matched_only` (block observed FQDNs on the feed) is the sensible default given the
   100-FQDN cap.
6. Gated create: `create_policy` creates/updates the egress block; `auto_assign` binds this workspace.

## Options (widgets)

- `lookback_days`, `min_events`, `source_type_filter`
- `enable_rdap`
- `name_prefix`, `policy_mode` (**dry_run** default / enforce), `policy_scope` (single / per_workspace), `block_threat_domains`
- Account auth (`account_id` + optional SP client_id / secret scope+key) — **account admin required**
  to create/assign. See `docs/account-admin-setup.md`.
- `create_policy` (gate), `auto_assign`

## Limits & safety

Egress policy limits: 100 internet destinations, 100 storage destinations per policy (the notebook
warns + caps). Nothing is written unless `create_policy=true`. `policy_mode=dry_run` (default) is
log-only; `enforce` blocks egress not on the allow-list — validate in dry_run first.

## Notes

- The egress block replaces only the policy's `egress`; `ingress` / `ingress_dry_run` are untouched.
- S3 same-region-as-metastore buckets are auto-permitted by Databricks; cross-region ones must be
  listed — which is what this proposes.
- Storage destinations are IPv4/host based; the CBI egress schema is documented at
  `docs/cbi-sdk-schema.md`.
