# Databricks notebook source
# MAGIC %md
# MAGIC # Ingress Policy Checker (read-only review of a running CBI policy)
# MAGIC
# MAGIC Reviews how an **already-running** ingress (context-based ingress / CBI) network policy is
# MAGIC performing, from `system.access.inbound_network`, and recommends **rules to add**. It writes
# MAGIC **nothing** — use `ingress_policy_helper` to actually build/apply a policy.
# MAGIC
# MAGIC It:
# MAGIC 1. Reads `system.access.inbound_network` over a lookback window. **This table records only
# MAGIC    denied inbound requests** — both hard denials (`DENY`, enforced mode) and **dry-run**
# MAGIC    would-be-denials (`DENY_DRY_RUN`). Nothing here means either no policy is assigned/logging,
# MAGIC    or the policy denied nothing in the window.
# MAGIC 2. Groups the denied requests by source IP, matched `rule_label`, `request_path` and identity.
# MAGIC 3. Flags each source IP against open threat-intel feeds (compact, high-signal subset).
# MAGIC 4. Produces two review tables:
# MAGIC    - **ADD candidates** — denied traffic from *un-flagged* sources = legitimate access the
# MAGIC      policy is (or, in dry-run, would be) blocking. These are your candidate allow rules.
# MAGIC    - **Working as intended** — denied traffic from *flagged / threat-intel* sources = the
# MAGIC      policy correctly keeping bad actors out (or would, once enforced).
# MAGIC
# MAGIC > **On removing rules:** this table logs only *denied* traffic, never *allowed* traffic, so it
# MAGIC > can't tell you which existing allow rules are unused. Allow-rule pruning needs different data
# MAGIC > (e.g. `system.access.audit`); this checker deliberately doesn't guess at removals.
# MAGIC
# MAGIC > ✋ **Read-only.** No widgets create or modify anything. Take the ADD candidates to
# MAGIC > `ingress_policy_helper` (or your change process) to actually update the policy.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parameters

# COMMAND ----------

# DBTITLE 1,Widgets
# Read-only review knobs. No account auth, no create/apply — this notebook only reads system tables.
dbutils.widgets.text("lookback_days", "30", "1a. Lookback (days)")
dbutils.widgets.text("min_events", "1", "1b. Min events per source IP")
# Restrict to one workspace's events, or leave blank for every workspace in the account the caller
# can see. inbound_network is account-wide (subject to the reader's grants).
dbutils.widgets.text("workspace_id_filter", "", "1c. workspace_id filter (blank=all)")
# Compact high-signal threat-intel flag so ADD candidates never surface a known-bad IP. Free feeds,
# no API key. Turn off to skip all outbound feed fetches (e.g. on a fully egress-locked cluster).
dbutils.widgets.dropdown("flag_threat_intel", "true", ["true", "false"], "2a. Flag threat-intel IPs")

LOOKBACK_DAYS = int(dbutils.widgets.get("lookback_days") or "30")
MIN_EVENTS = int(dbutils.widgets.get("min_events") or "1")
WORKSPACE_ID_FILTER = dbutils.widgets.get("workspace_id_filter").strip()
FLAG_THREAT_INTEL = dbutils.widgets.get("flag_threat_intel") == "true"

print(f"lookback_days={LOOKBACK_DAYS} min_events={MIN_EVENTS} "
      f"workspace_id_filter={WORKSPACE_ID_FILTER or '(all)'} flag_threat_intel={FLAG_THREAT_INTEL}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Read denied inbound requests
# MAGIC
# MAGIC `system.access.inbound_network` records denied inbound requests. `policy_outcome` distinguishes
# MAGIC `DENY` (blocked now, enforced mode) from `DENY_DRY_RUN` (would be blocked — the policy is in
# MAGIC dry-run). We group by source IP and keep the matched rule labels, request paths and identities
# MAGIC so you can see *what* is being denied and decide whether it's legitimate.

# COMMAND ----------

# DBTITLE 1,Aggregate denials by source IP
_ws_filter = f"AND workspace_id = '{WORKSPACE_ID_FILTER}'" if WORKSPACE_ID_FILTER else ""

denied_sdf = spark.sql(f"""
    SELECT
      source.ip AS source_ip,
      COUNT(*) AS events,
      sort_array(collect_set(policy_outcome)) AS outcomes,
      SUM(CASE WHEN policy_outcome = 'DENY' THEN 1 ELSE 0 END) AS enforced_denials,
      SUM(CASE WHEN policy_outcome = 'DENY_DRY_RUN' THEN 1 ELSE 0 END) AS dry_run_denials,
      sort_array(collect_set(rule_label)) AS matched_rules,
      sort_array(collect_set(request_path)) AS request_paths,
      sort_array(collect_set(authenticated_as)) AS identities,
      sort_array(collect_set(workspace_id)) AS workspace_ids,
      MIN(event_time) AS first_seen,
      MAX(event_time) AS last_seen
    FROM system.access.inbound_network
    WHERE event_time >= current_date() - INTERVAL {LOOKBACK_DAYS} DAYS
      AND policy_outcome IN ('DENY', 'DENY_DRY_RUN')
      AND source.ip IS NOT NULL
      {_ws_filter}
    GROUP BY source.ip
    HAVING COUNT(*) >= {MIN_EVENTS}
    ORDER BY events DESC
""")

_n_sources = denied_sdf.count()
print(f"distinct denied source IPs (>= {MIN_EVENTS} events, last {LOOKBACK_DAYS}d): {_n_sources:,}")
if _n_sources == 0:
    print(
        "No denied inbound requests in this window. Either no ingress policy is assigned/logging on "
        "the target workspace(s), or the policy denied nothing. If you expect denials, confirm a "
        "policy is assigned (dry-run is enough to log) and widen the lookback."
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Threat-intel flag (compact, high-signal)
# MAGIC
# MAGIC Downloads a small, high-signal subset of the open feeds the ingress helper uses (Spamhaus DROP,
# MAGIC FireHOL level1, IPsum ≥3-list, DShield, CINS, Tor) and flags any denied source IP that appears
# MAGIC on one. Free, no API key. If `flag_threat_intel=false` (or a fetch fails on an egress-locked
# MAGIC cluster) every IP is treated as un-flagged — the review still works, just without the flag.

# COMMAND ----------

# DBTITLE 1,Load threat-intel ranges + flag sources
import ipaddress
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_FEED_TIMEOUT = 30
_FEED_UA = "Databricks-Network-Policy-Checker"

# (url, parser) — each parser turns the feed body into an iterable of CIDR strings. High-signal
# subset of ingress_policy_helper's feeds; see docs/threat-intel-feeds.md for the full catalogue.
_THREAT_FEEDS = {
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop_v4.json",
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "dshield": "https://feeds.dshield.org/block.txt",
    "cins": "https://cinsscore.com/list/ci-badguys.txt",
    "tor_exit": "https://check.torproject.org/torbulkexitlist",
}
_IPSUM_MIN_LISTS = 3


def _http_text(url):
    try:
        req = Request(url, headers={"User-Agent": _FEED_UA, "Accept": "*/*"})
        with urlopen(req, timeout=_FEED_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        print(f"  ! feed fetch failed for {url}: {e}")
        return None


def _valid_cidr(value):
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except (ValueError, AttributeError):
        return None


def _parse_feed(key, text):
    """Yield (cidr, feed) rows from a feed body. Import json lazily; keep parsing lenient."""
    import json as _json
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if key == "spamhaus_drop":
            if not s.startswith("{"):
                continue
            try:
                cidr = _valid_cidr(_json.loads(s).get("cidr", ""))
            except _json.JSONDecodeError:
                cidr = None
        elif key == "ipsum":
            parts = s.split()
            cidr = _valid_cidr(f"{parts[0]}/32") if len(parts) >= 2 and parts[1].isdigit() \
                and int(parts[1]) >= _IPSUM_MIN_LISTS else None
        elif key == "dshield":
            parts = s.split("\t")
            cidr = _valid_cidr(f"{parts[0]}/{parts[2]}") if len(parts) >= 3 and parts[2].isdigit() else None
        elif key == "tor_exit":
            cidr = _valid_cidr(f"{s}/32" if ":" not in s else f"{s}/128")
        else:  # firehol_level1, cins — bare IP or CIDR per line
            cidr = _valid_cidr(s if "/" in s else f"{s}/32")
        if cidr:
            yield cidr, key


# Build a list of (network, feed) once, then test each denied source IP against it. The feeds are
# small enough (tens of thousands of nets) to check in-driver for the handful of denied sources.
_threat_nets = []
if FLAG_THREAT_INTEL and _n_sources:
    for _key, _url in _THREAT_FEEDS.items():
        _body = _http_text(_url)
        if not _body:
            continue
        _added = 0
        for _cidr, _feed in _parse_feed(_key, _body):
            try:
                _threat_nets.append((ipaddress.ip_network(_cidr), _feed))
                _added += 1
            except ValueError:
                pass
        print(f"  {_key}: {_added:,} ranges")
    print(f"threat-intel ranges loaded: {len(_threat_nets):,}")
elif not FLAG_THREAT_INTEL:
    print("flag_threat_intel=false — skipping feed download; all sources treated as un-flagged.")


def _flag_ip(ip_str):
    """Return a sorted list of feeds flagging this IP (empty = clean/unknown)."""
    if not _threat_nets:
        return []
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return []
    hits = {feed for net, feed in _threat_nets if ip in net}
    return sorted(hits)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Review: what the policy is denying
# MAGIC
# MAGIC Splits the denied source IPs into **ADD candidates** (un-flagged — legitimate access being
# MAGIC blocked, or would be under enforcement) and **working as intended** (flagged / threat-intel —
# MAGIC the policy keeping bad actors out). `mode` tells you whether each denial is live (`DENY`,
# MAGIC enforced) or a dry-run preview (`DENY_DRY_RUN`).

# COMMAND ----------

# DBTITLE 1,Build + display review tables
import pandas as pd


def _as_list(v):
    """Spark arrays arrive as numpy arrays via toPandas; normalise to a plain list."""
    if v is None:
        return []
    return list(v)


def _mode(outcomes):
    o = set(_as_list(outcomes))
    if o == {"DENY"}:
        return "enforced (blocked now)"
    if o == {"DENY_DRY_RUN"}:
        return "dry-run (would block)"
    return "mixed (enforced + dry-run)"


_rows = []
for r in denied_sdf.toPandas().itertuples(index=False):
    feeds = _flag_ip(r.source_ip)
    _rows.append({
        "source_ip": r.source_ip,
        "events": int(r.events),
        "enforced_denials": int(r.enforced_denials),
        "dry_run_denials": int(r.dry_run_denials),
        "mode": _mode(r.outcomes),
        "threat_intel": ", ".join(feeds) if feeds else "",
        "flagged": bool(feeds),
        "matched_rules": ", ".join(_as_list(r.matched_rules)),
        "request_paths": ", ".join(_as_list(r.request_paths)),
        "identities": ", ".join(_as_list(r.identities)),
        "workspace_ids": ", ".join(str(w) for w in _as_list(r.workspace_ids)),
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
    })

review_df = pd.DataFrame(_rows)

if review_df.empty:
    print("Nothing to review — no denied inbound requests in this window.")
    add_candidates = working_as_intended = review_df
else:
    add_candidates = review_df[~review_df["flagged"]].drop(columns=["flagged"]).reset_index(drop=True)
    working_as_intended = review_df[review_df["flagged"]].drop(columns=["flagged"]).reset_index(drop=True)

    print(f"ADD candidates (un-flagged denied sources — likely legitimate): {len(add_candidates):,}")
    print(f"Working as intended (flagged/threat-intel denied sources):      {len(working_as_intended):,}")

# COMMAND ----------

# DBTITLE 1,ADD candidates — allow rules to consider adding
if review_df.empty:
    print("No denied inbound requests to review.")
elif add_candidates.empty:
    print("No un-flagged denials — nothing obvious to add. Every denied source is on a threat feed "
          "(see the next table), which means the policy is doing its job.")
else:
    print("Un-flagged source IPs the policy is denying (or would deny in dry-run). Review each: if "
          "legitimate, add it as an allow rule via ingress_policy_helper. If it's dry-run, add "
          "these BEFORE switching the policy to enforce, or you'll lock this traffic out.")
    display(add_candidates)

# COMMAND ----------

# DBTITLE 1,Working as intended — denials of flagged sources
if review_df.empty or working_as_intended.empty:
    print("No denials of threat-intel-flagged sources in this window.")
else:
    print("Denied source IPs that appear on a threat-intel feed — the policy is correctly keeping "
          "these out (or would, once enforced). No action needed; useful as evidence the policy works.")
    display(working_as_intended)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary

# COMMAND ----------

# DBTITLE 1,Recommendations
if review_df.empty:
    print("No denied inbound traffic in the lookback window — nothing to recommend.")
else:
    _enforced = int(review_df["enforced_denials"].sum())
    _dry = int(review_df["dry_run_denials"].sum())
    print(f"Reviewed {len(review_df):,} denied source IP(s) over the last {LOOKBACK_DAYS} day(s): "
          f"{_enforced:,} enforced denial event(s), {_dry:,} dry-run denial event(s).\n")
    print(f"• ADD: {len(add_candidates):,} un-flagged source(s) look legitimate — consider adding "
          f"allow rules (via ingress_policy_helper) so they aren't blocked.")
    print(f"• KEEP: {len(working_as_intended):,} flagged source(s) are being denied as intended.")
    print("• REMOVE: not assessed — inbound_network logs only denials, not allowed traffic, so unused "
          "allow rules aren't visible here. Use system.access.audit for allow-rule usage.")
    if _dry and not _enforced:
        print("\nℹ️  All denials are dry-run — the policy is in preview and blocking nothing yet. Add "
              "the ADD candidates, then switch to enforce when the dry-run denials are only bad actors.")
    print("\nThis notebook made no changes.")
