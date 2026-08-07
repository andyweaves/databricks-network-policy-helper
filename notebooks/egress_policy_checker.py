# Databricks notebook source
# MAGIC %md
# MAGIC # Egress Policy Checker (read-only review of a running SEG policy)
# MAGIC
# MAGIC Reviews how an **already-running** serverless egress (SEG) network policy is performing, from
# MAGIC `system.access.outbound_network`, and recommends **destinations to add** to the allow-list. It
# MAGIC writes **nothing** — use `egress_policy_helper` to actually build/apply a policy.
# MAGIC
# MAGIC It:
# MAGIC 1. Reads `system.access.outbound_network` over a lookback window. **This table records only
# MAGIC    denied egress** — both hard denials (`DROP`, enforced mode) and **dry-run** would-be-denials
# MAGIC    (`DRY_RUN_DENIAL`). Nothing here means no egress policy is logging, or it denied nothing.
# MAGIC 2. Classifies each denied destination: **storage** (S3 / GCS / Azure) vs **internet FQDN**
# MAGIC    (same rules as `egress_policy_helper`).
# MAGIC 3. Flags internet FQDNs against a threat-intel domain feed (abuse.ch ThreatFox botnet-C2).
# MAGIC 4. Produces two review tables:
# MAGIC    - **ADD candidates** — denied destinations that are *not* on the threat feed = legitimate
# MAGIC      egress the policy is (or, in dry-run, would be) blocking. Candidate allow rules.
# MAGIC    - **Flagged denials** — denied destinations that *are* on the threat feed = the policy
# MAGIC      correctly blocking known-bad egress (or would, once enforced). Do **not** add these.
# MAGIC
# MAGIC > **On removing rules:** this table logs only *denied* egress, never *allowed* egress, so it
# MAGIC > can't tell you which existing allow rules are unused. This checker deliberately doesn't guess
# MAGIC > at removals.
# MAGIC
# MAGIC > **Exfil reminder:** the RESTRICTED_ACCESS allow-list is what actually stops data exfiltration
# MAGIC > (a novel attacker host is on no feed but is still blocked by default-deny). A flagged denial is
# MAGIC > a bonus signal, not the control.
# MAGIC
# MAGIC > ✋ **Read-only.** No widgets create or modify anything.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parameters

# COMMAND ----------

# DBTITLE 1,Widgets
# Read-only review knobs. No account auth, no create/apply — this notebook only reads system tables.
dbutils.widgets.text("lookback_days", "30", "1a. Lookback (days)")
dbutils.widgets.text("min_events", "1", "1b. Min events per destination")
# outbound_network network_source_type values: DBSQL, General Compute, MLServing, ML Build, Apps,
# DLT, ... Leave blank for all.
dbutils.widgets.text("source_type_filter", "", "1c. network_source_type filter (blank=all)")
# Flag denied internet FQDNs against abuse.ch ThreatFox (botnet C2). Free, no API key. Turn off to
# skip the outbound feed fetch (e.g. on a fully egress-locked cluster).
dbutils.widgets.dropdown("flag_threat_domains", "true", ["true", "false"], "2a. Flag threat-intel domains")

LOOKBACK_DAYS = int(dbutils.widgets.get("lookback_days") or "30")
MIN_EVENTS = int(dbutils.widgets.get("min_events") or "1")
SOURCE_TYPE_FILTER = dbutils.widgets.get("source_type_filter").strip()
FLAG_THREAT_DOMAINS = dbutils.widgets.get("flag_threat_domains") == "true"

print(f"lookback_days={LOOKBACK_DAYS} min_events={MIN_EVENTS} "
      f"source_type_filter={SOURCE_TYPE_FILTER or '(all)'} flag_threat_domains={FLAG_THREAT_DOMAINS}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Read denied egress destinations
# MAGIC
# MAGIC `system.access.outbound_network` records denied egress. `access_type` distinguishes `DROP`
# MAGIC (blocked now, enforced mode) from `DRY_RUN_DENIAL` (would be blocked — the policy is in
# MAGIC dry-run). Storage often surfaces as `DNS` events whose `domain_name` is an S3/GCS/Azure host,
# MAGIC so we coalesce the destination the same way `egress_policy_helper` does.

# COMMAND ----------

# DBTITLE 1,Aggregate denied destinations
_src_filter = f"AND network_source_type = '{SOURCE_TYPE_FILTER}'" if SOURCE_TYPE_FILTER else ""

denied_sdf = spark.sql(f"""
    SELECT
      COALESCE(dns_event.domain_name, storage_event.hostname, destination) AS destination,
      destination_type,
      COUNT(*) AS events,
      sort_array(collect_set(access_type)) AS access_types,
      SUM(CASE WHEN access_type = 'DROP' THEN 1 ELSE 0 END) AS enforced_denials,
      SUM(CASE WHEN access_type = 'DRY_RUN_DENIAL' THEN 1 ELSE 0 END) AS dry_run_denials,
      sort_array(collect_set(network_source_type)) AS source_types,
      sort_array(collect_set(workspace_id)) AS workspace_ids,
      MIN(event_time) AS first_seen,
      MAX(event_time) AS last_seen
    FROM system.access.outbound_network
    WHERE event_time >= current_date() - INTERVAL {LOOKBACK_DAYS} DAYS
      AND access_type IN ('DROP', 'DRY_RUN_DENIAL')
      AND COALESCE(dns_event.domain_name, storage_event.hostname, destination) IS NOT NULL
      {_src_filter}
    GROUP BY 1, 2
    HAVING COUNT(*) >= {MIN_EVENTS}
    ORDER BY events DESC
""")

_n = denied_sdf.count()
print(f"distinct denied egress destinations (>= {MIN_EVENTS} events, last {LOOKBACK_DAYS}d): {_n:,}")
if _n == 0:
    print(
        "No denied egress in this window. Either no egress policy is logging (stand one up in "
        "dry_run — restricted, log-only — so it records would-be-denials), or it denied nothing."
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Classify destinations (storage vs internet FQDN)
# MAGIC
# MAGIC Same host-shape rules as `egress_policy_helper`: S3 / GCS / Azure storage hosts vs internet
# MAGIC FQDNs; bare `s3.<region>.amazonaws.com` (no bucket) is too broad to be a useful rule and is
# MAGIC noted separately.

# COMMAND ----------

# DBTITLE 1,Classify each denied destination
import re

_S3_VH = re.compile(r'^(?P<bucket>[a-z0-9.\-]+)\.s3[.\-](?:(?P<region>[a-z0-9\-]+)\.)?amazonaws\.com$', re.I)
_S3_BARE = re.compile(r'^s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com$', re.I)
_GCS = re.compile(r'^(?:(?P<bucket>[a-z0-9._\-]+)\.)?storage\.googleapis\.com$', re.I)
_AZ = re.compile(r'^(?P<acct>[a-z0-9]+)\.(?P<svc>blob|dfs|file)\.core\.windows\.net$', re.I)


def _classify(host):
    """Return (kind, detail). kind in {s3, gcs, azure, bare_s3, internet}."""
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return "bare_s3", ""
    m = _S3_VH.match(h)
    if m and m.group("bucket") != "s3":
        region = m.group("region") or "?"
        return "s3", f"bucket={m.group('bucket')} region={region}"
    if _S3_BARE.match(h):
        return "bare_s3", h
    g = _GCS.match(h)
    if g and g.group("bucket"):
        return "gcs", f"bucket={g.group('bucket')}"
    a = _AZ.match(h)
    if a:
        return "azure", f"account={a.group('acct')} service={a.group('svc')}"
    return "internet", h

# COMMAND ----------

# MAGIC %md
# MAGIC ## Threat-intel domain flag (abuse.ch ThreatFox)
# MAGIC
# MAGIC Downloads the abuse.ch ThreatFox botnet-C2 hostfile and flags any denied **internet FQDN** that
# MAGIC appears on it. Free, no API key. If `flag_threat_domains=false` (or the fetch fails on an
# MAGIC egress-locked cluster) every FQDN is treated as un-flagged — the review still works.

# COMMAND ----------

# DBTITLE 1,Load ThreatFox domains
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_FEED_TIMEOUT = 45
_FEED_UA = "Databricks-Network-Policy-Checker"
_THREATFOX_URL = "https://threatfox.abuse.ch/downloads/hostfile/"

_threat_domains = set()
if FLAG_THREAT_DOMAINS and _n:
    try:
        _req = Request(_THREATFOX_URL, headers={"User-Agent": _FEED_UA})
        with urlopen(_req, timeout=_FEED_TIMEOUT) as _resp:
            _text = _resp.read().decode("utf-8", errors="replace")
        for _line in _text.splitlines():
            _s = _line.strip()
            if not _s or _s.startswith(("#", "!", "[")):
                continue
            _parts = _s.split()  # '0.0.0.0 host' / '127.0.0.1 host'
            if len(_parts) == 2:
                _threat_domains.add(_parts[1].lower())
        print(f"ThreatFox domains loaded: {len(_threat_domains):,}")
    except (HTTPError, URLError, TimeoutError, OSError) as _e:
        print(f"  ! ThreatFox fetch failed ({_e}); all FQDNs treated as un-flagged.")
elif not FLAG_THREAT_DOMAINS:
    print("flag_threat_domains=false — skipping feed download; all FQDNs treated as un-flagged.")


def _flag_domain(fqdn):
    return bool(_threat_domains) and fqdn.lower() in _threat_domains

# COMMAND ----------

# MAGIC %md
# MAGIC ## Review: what the policy is denying
# MAGIC
# MAGIC Splits denied destinations into **ADD candidates** (legitimate egress being blocked, or would
# MAGIC be) and **flagged denials** (on the threat feed — the policy blocking known-bad egress).
# MAGIC `mode` tells you whether each denial is live (`DROP`, enforced) or a dry-run preview.

# COMMAND ----------

# DBTITLE 1,Build + display review tables
import pandas as pd


def _as_list(v):
    if v is None:
        return []
    if hasattr(v, "tolist"):
        v = v.tolist()
    elif not isinstance(v, (list, tuple)):
        v = [v]
    return [x for x in v if x is not None and x != ""]


def _mode(access_types):
    o = set(_as_list(access_types))
    if o == {"DROP"}:
        return "enforced (blocked now)"
    if o == {"DRY_RUN_DENIAL"}:
        return "dry-run (would block)"
    return "mixed (enforced + dry-run)"


_rows = []
for r in denied_sdf.toPandas().itertuples(index=False):
    kind, detail = _classify(r.destination)
    is_internet = kind == "internet"
    flagged = _flag_domain(r.destination) if is_internet else False
    _rows.append({
        "destination": r.destination,
        "kind": kind,
        "detail": detail,
        "events": int(r.events),
        "enforced_denials": int(r.enforced_denials),
        "dry_run_denials": int(r.dry_run_denials),
        "mode": _mode(r.access_types),
        "threat_intel": "threatfox" if flagged else "",
        "flagged": flagged,
        "bare_s3": kind == "bare_s3",
        "source_types": ", ".join(_as_list(r.source_types)),
        "workspace_ids": ", ".join(str(w) for w in _as_list(r.workspace_ids)),
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
    })

review_df = pd.DataFrame(_rows)

if review_df.empty:
    print("Nothing to review — no denied egress in this window.")
    add_candidates = flagged_denials = review_df
else:
    # ADD candidates: un-flagged and specific enough to become a rule (drop bare/path-style S3).
    add_candidates = (review_df[~review_df["flagged"] & ~review_df["bare_s3"]]
                      .drop(columns=["flagged", "bare_s3"]).reset_index(drop=True))
    flagged_denials = (review_df[review_df["flagged"]]
                       .drop(columns=["flagged", "bare_s3"]).reset_index(drop=True))
    _n_bare = int(review_df["bare_s3"].sum())
    print(f"ADD candidates (un-flagged denied destinations — likely legitimate): {len(add_candidates):,}")
    print(f"Flagged denials (on ThreatFox — blocked as intended):                {len(flagged_denials):,}")
    if _n_bare:
        print(f"({_n_bare} bare/path-style S3 endpoint(s) excluded from ADD — too broad to be a rule.)")

# COMMAND ----------

# DBTITLE 1,ADD candidates — egress rules to consider adding
if review_df.empty:
    print("No denied egress to review.")
elif add_candidates.empty:
    print("No un-flagged denials to add. Either everything denied is on the threat feed (good), or "
          "only bare/path-style S3 endpoints were seen (too broad to allow-list).")
else:
    print("Denied destinations from un-flagged hosts — legitimate egress the policy is blocking (or "
          "would block in dry-run). Review each: if legitimate, add it via egress_policy_helper. If "
          "these are dry-run denials, add them BEFORE switching to enforce or you'll break this egress.")
    display(add_candidates)

# COMMAND ----------

# DBTITLE 1,Flagged denials — known-bad egress the policy is blocking
if review_df.empty or flagged_denials.empty:
    print("No denials of ThreatFox-flagged destinations in this window.")
else:
    print("Denied destinations on the ThreatFox botnet-C2 feed — the policy is correctly blocking "
          "these (or would, once enforced). Do NOT add them; useful as evidence the policy works.")
    display(flagged_denials)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary

# COMMAND ----------

# DBTITLE 1,Recommendations
if review_df.empty:
    print("No denied egress in the lookback window — nothing to recommend.")
else:
    _enforced = int(review_df["enforced_denials"].sum())
    _dry = int(review_df["dry_run_denials"].sum())
    print(f"Reviewed {len(review_df):,} denied destination(s) over the last {LOOKBACK_DAYS} day(s): "
          f"{_enforced:,} enforced denial event(s), {_dry:,} dry-run denial event(s).\n")
    print(f"• ADD: {len(add_candidates):,} un-flagged destination(s) look legitimate — consider adding "
          f"allow rules (via egress_policy_helper) so they aren't blocked.")
    print(f"• KEEP: {len(flagged_denials):,} flagged destination(s) are being blocked as intended.")
    print("• REMOVE: not assessed — outbound_network logs only denials, not allowed egress, so unused "
          "allow rules aren't visible here.")
    if _dry and not _enforced:
        print("\nℹ️  All denials are dry-run — the policy is in preview and blocking nothing yet. Add "
              "the ADD candidates, then switch to enforce when the dry-run denials are only bad hosts.")
    print("\nThis notebook made no changes.")
