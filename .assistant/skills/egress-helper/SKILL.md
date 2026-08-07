---
name: egress-helper
description: Propose and apply a Databricks serverless egress (SEG) network-policy allow-list from observed outbound traffic in system.access.outbound_network. Use when the user wants to build/suggest an egress policy, allow-list outbound destinations, control serverless egress, turn dry-run egress denials into an allow-list, or block known-bad domains. Classifies observed destinations into storage (S3/GCS/Azure) and internet FQDNs, shows what it would allow for review, and can create the egress policy (dry-run or enforce) and optionally block threat-intel domains.
---

# Egress Policy Helper (serverless egress / SEG)

Builds a Databricks **account network policy egress** allow-list from observed outbound traffic. The
engine is `notebooks/egress_policy_helper.py` in the databricks-network-policy-helper repo.

For **ingress** (source-IP allow-lists) use `ingress-helper`. To end up with a combined ingress +
egress policy, run one helper with `policy_action=create_new`, then the other with
`policy_action=add_to_existing` pointed at the policy id the first one created.

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
3. Optional cloud-owner lookup on internet FQDNs — resolve the IP (audit-log `rdata` first, else
   DNS) and match it **offline** against the AWS/GCP/Azure/Databricks published ranges (no per-IP
   RDAP, which is unreliable from an egress-restricted cluster). Shows `resolved_ip` + `hosting_owner`
   (the cloud, or "non-cloud / unknown", or "DNS resolution failed - check egress control"). Context only.
4. **Review tables** (internet + per-cloud storage) — confirm before creating.
5. Optional **threat-intel domain blocking** (`block_threat_domains`: off / matched_only / all) →
   `blocked_internet_destinations` (FQDN-only, enforced in any mode, takes precedence over allows).
   Feed (`threat_feed`, free/no key): `threatfox` — abuse.ch ThreatFox botnet-C2 IOCs, the best fit
   for the exfil use case since these are attacker-controlled command-and-control hosts. (URLhaus was
   dropped: its entries are 100% malware-*download* hosts — payload delivery, the wrong direction —
   and its C2-tagged slice is almost all IP literals, leaving ~a dozen FQDNs a FQDN-only block list
   could use.) `matched_only` (block only observed FQDNs that appear on the feed) is the sensible
   default given the 100-FQDN cap.

   > **What actually stops data exfiltration** (e.g. a LiteLLM-style credential/data leak to an
   > attacker server) is the RESTRICTED_ACCESS allow-list itself: with egress enforced, traffic to
   > any destination *not* on the allow-list is blocked, including the attacker's. The threat-intel
   > domain block list is a **secondary** layer — it catches known-bad hosts explicitly, but the
   > allow-list is the control that matters. Don't rely on the block feed as your primary defence.
6. Gated create: `create_policy` writes the egress block; `policy_action` chooses a new policy or an
   existing one; `auto_assign` binds the workspace.

## Options (widgets)

- `lookback_days`, `min_events`, `source_type_filter`
- `enable_rdap`
- `name_prefix`, `policy_mode` (**dry_run** default / enforce), `policy_scope` (single / per_workspace), `block_threat_domains`
- Account auth (`account_id` + optional SP client_id / secret scope+key) — **account admin required**
  to create/assign. See `docs/account-admin-setup.md`.
- `create_policy` (gate), `policy_action` (`create_new` / `add_to_existing`), `existing_policy_id`,
  `auto_assign`. `add_to_existing` updates only the egress block of the supplied policy id (leaving
  its ingress intact) and requires `policy_scope=single` — this is how you combine with the ingress
  helper: run one with `create_new`, then the other with `add_to_existing` on the same policy id.

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
