# Databricks notebook source
# MAGIC %md
# MAGIC # Egress Policy Helper (serverless egress / SEG)
# MAGIC
# MAGIC Proposes a Databricks **account network policy egress** allow-list from observed outbound
# MAGIC traffic in `system.access.outbound_network`, and (optionally) blocks known-bad domains.
# MAGIC
# MAGIC It:
# MAGIC 1. Reads `system.access.outbound_network` over a lookback window. **This table only records
# MAGIC    egress that a policy denied** — including **dry-run** would-be-denials. So the intended flow
# MAGIC    is: put an egress policy in **dry_run** (restricted, log-only), let it observe, then run this
# MAGIC    to turn the observed destinations into a real allow-list.
# MAGIC 2. Classifies each distinct destination: **storage** (S3 / GCS / Azure) vs **internet FQDN**.
# MAGIC 3. Enriches internet FQDNs with their hosting owner (resolve IP → RDAP the IP; optional).
# MAGIC 4. Shows what it would allow (review tables) — you confirm.
# MAGIC 5. Optionally creates the egress policy via the SDK, and can add **threat-intel domain blocks**.
# MAGIC
# MAGIC > ⚠️ Nothing is written unless `create_policy=true`. `policy_mode=dry_run` (default) is log-only.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Install a current Databricks SDK

# COMMAND ----------

# DBTITLE 1,Install dependencies from requirements.txt
# MAGIC %pip install --quiet -r ../requirements.txt

# COMMAND ----------

# DBTITLE 1,Restart Python
# Skip when running under the combiner (full_policy_helper), which installs + restarts once itself.
if not globals().get("_COMBINED_RUN", False):
    dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parameters

# COMMAND ----------

# DBTITLE 1,Widgets
dbutils.widgets.text("lookback_days", "30", "1a. Lookback (days)")
dbutils.widgets.text("min_events", "1", "1b. Min events per destination")
# outbound_network network_source_type values: DBSQL, General Compute, MLServing, ML Build, Apps,
# DLT, ... Leave blank for all.
dbutils.widgets.text("source_type_filter", "", "1c. network_source_type filter (blank=all)")

# --- Enrichment ---
dbutils.widgets.dropdown("enable_rdap", "true", ["true", "false"], "2a. Hosting-owner lookup (FQDNs)?")

# --- Policy shape ---
dbutils.widgets.text("name_prefix", "cbi-helper", "3a. Name prefix for policy/rules")
dbutils.widgets.dropdown("policy_mode", "dry_run", ["dry_run", "enforce"], "3b. Egress policy mode")
# single = one egress policy from all observed traffic; per_workspace = a tailored policy per
# workspace_id seen in the logs.
dbutils.widgets.dropdown("policy_scope", "single", ["single", "per_workspace"], "3b2. Policy scope")
# Threat-intel domain blocking: off | matched_only (block observed FQDNs that hit a feed) |
# all (block the whole suspicious-domain feed). Independent of the allow-list.
dbutils.widgets.dropdown(
    "block_threat_domains", "off", ["off", "matched_only", "all"], "3c. Block threat-intel domains"
)
# Which threat-domain feed to use (all free, no key): threatfox = abuse.ch ThreatFox (~49k;
# C2/botnet/phishing/distribution); urlhaus = abuse.ch URLhaus online (~500; distribution only,
# very high-signal); hagezi_tif = HaGeZi TIF medium (~370k; broadest, higher false-positive risk).
dbutils.widgets.dropdown(
    "threat_feed", "threatfox", ["threatfox", "urlhaus", "hagezi_tif"], "3d. Threat-domain feed"
)

# --- Account authentication (account-level; needed to create the policy) ---
dbutils.widgets.text("account_id", "", "4a. Databricks account_id")
dbutils.widgets.text("account_host", "https://accounts.cloud.databricks.com", "4b. Account console host")
dbutils.widgets.text("account_sp_client_id", "", "4c. Account admin SP client_id")
dbutils.widgets.text("account_secret_scope", "", "4d. Secret scope holding SP secret")
dbutils.widgets.text("account_secret_key", "", "4e. Secret key for SP secret")

# --- Create (gated) ---
dbutils.widgets.dropdown("create_policy", "false", ["true", "false"], "5a. Create the policy?")
dbutils.widgets.dropdown("auto_assign", "false", ["true", "false"], "5b. Auto-assign to this workspace?")

LOOKBACK_DAYS = int(dbutils.widgets.get("lookback_days"))
MIN_EVENTS = int(dbutils.widgets.get("min_events"))
SOURCE_TYPE_FILTER = dbutils.widgets.get("source_type_filter").strip()
ENABLE_RDAP = dbutils.widgets.get("enable_rdap") == "true"
NAME_PREFIX = dbutils.widgets.get("name_prefix").strip() or "cbi-helper"
POLICY_MODE = dbutils.widgets.get("policy_mode")
POLICY_SCOPE = dbutils.widgets.get("policy_scope")  # single | per_workspace
BLOCK_THREAT_DOMAINS = dbutils.widgets.get("block_threat_domains")  # off | matched_only | all
THREAT_FEED = dbutils.widgets.get("threat_feed")  # threatfox | urlhaus | hagezi_tif
ACCOUNT_ID = dbutils.widgets.get("account_id").strip()
ACCOUNT_HOST = dbutils.widgets.get("account_host").strip() or "https://accounts.cloud.databricks.com"
ACCOUNT_SP_CLIENT_ID = dbutils.widgets.get("account_sp_client_id").strip()
ACCOUNT_SECRET_SCOPE = dbutils.widgets.get("account_secret_scope").strip()
ACCOUNT_SECRET_KEY = dbutils.widgets.get("account_secret_key").strip()
CREATE_POLICY = dbutils.widgets.get("create_policy") == "true"
AUTO_ASSIGN = dbutils.widgets.get("auto_assign") == "true"

# Databricks egress policy limits (warn + cap so proposals stay valid).
MAX_INTERNET_DESTINATIONS = 100     # FQDNs (allow or block) per policy
MAX_STORAGE_DESTINATIONS = 100      # storage destinations per policy
MAX_POLICY_ID_LEN = 30

print(f"lookback_days={LOOKBACK_DAYS} min_events={MIN_EVENTS} source_filter={SOURCE_TYPE_FILTER or '(all)'} "
      f"| policy_scope={POLICY_SCOPE} policy_mode={POLICY_MODE} "
      f"block_threat_domains={BLOCK_THREAT_DOMAINS} threat_feed={THREAT_FEED}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Read observed egress destinations
# MAGIC
# MAGIC `system.access.outbound_network` records **denied** egress (incl. `DRY_RUN_DENIAL`). Each row's
# MAGIC `destination_type` is `DNS`, `STORAGE`, or `IP`. Storage often surfaces as **DNS** events whose
# MAGIC `domain_name` is an S3/GCS/Azure host — we classify by domain shape below. Empty table = no
# MAGIC egress policy is logging yet (stand one up in dry_run first).

# COMMAND ----------

# DBTITLE 1,observed_egress
import pandas as pd

_src_filter = f"AND network_source_type = '{SOURCE_TYPE_FILTER}'" if SOURCE_TYPE_FILTER else ""

observed_egress = spark.sql(
    f"""
    SELECT
      COALESCE(dns_event.domain_name, storage_event.hostname, destination) AS destination,
      destination_type,
      COUNT(*) AS events,
      COUNT(DISTINCT access_type) AS distinct_access_types,
      sort_array(collect_set(access_type)) AS access_types,
      sort_array(collect_set(network_source_type)) AS source_types,
      sort_array(collect_set(workspace_id)) AS workspace_ids,
      -- resolved IPs already recorded in the DNS event (flatten the per-row rdata arrays)
      sort_array(array_distinct(flatten(collect_list(dns_event.rdata)))) AS resolved_ips,
      MIN(event_time) AS first_seen,
      MAX(event_time) AS last_seen
    FROM system.access.outbound_network
    WHERE event_time >= current_date() - INTERVAL {LOOKBACK_DAYS} DAYS
      {_src_filter}
      AND COALESCE(dns_event.domain_name, storage_event.hostname, destination) IS NOT NULL
    GROUP BY 1, 2
    HAVING COUNT(*) >= {MIN_EVENTS}
    ORDER BY events DESC
    """
)
observed_egress.createOrReplaceTempView("observed_egress")
_n = observed_egress.count()
print(f"distinct observed egress destinations (>= {MIN_EVENTS} events): {_n:,}")
if _n == 0:
    print("Table is empty for this window. Put an egress policy in dry_run (restricted, log-only) so "
          "it logs would-be-denials, then re-run.")
display(observed_egress)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Classify destinations (storage vs internet FQDN)
# MAGIC
# MAGIC Regex-classifies each destination host:
# MAGIC - **S3** `<bucket>.s3.<region>.amazonaws.com` → storage rule (bucket + region from the host).
# MAGIC - **GCS** `[<bucket>.]storage.googleapis.com` → storage rule.
# MAGIC - **Azure** `<account>.<blob|dfs|file>.core.windows.net` → storage rule (account + service).
# MAGIC - Bare `s3.<region>.amazonaws.com` (no bucket) → **skipped** (too broad to be a useful rule).
# MAGIC - Everything else → **internet FQDN** allow rule.

# COMMAND ----------

# DBTITLE 1,Classify
import re

_S3_VH = re.compile(r'^(?P<bucket>[a-z0-9.\-]+)\.s3[.\-](?:(?P<region>[a-z0-9\-]+)\.)?amazonaws\.com$', re.I)
_S3_BARE = re.compile(r'^s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com$', re.I)
_GCS = re.compile(r'^(?:(?P<bucket>[a-z0-9._\-]+)\.)?storage\.googleapis\.com$', re.I)
_AZ = re.compile(r'^(?P<acct>[a-z0-9]+)\.(?P<svc>blob|dfs|file)\.core\.windows\.net$', re.I)


def _classify(host):
    """Return (kind, dict). kind in {s3, gcs, azure, skip_bare_s3, internet}."""
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return "skip_bare_s3", {}
    m = _S3_VH.match(h)
    if m and m.group("bucket") != "s3":
        return "s3", {"bucket": m.group("bucket"), "region": m.group("region")}
    if _S3_BARE.match(h):
        return "skip_bare_s3", {"host": h}
    g = _GCS.match(h)
    if g and g.group("bucket"):
        return "gcs", {"bucket": g.group("bucket")}
    a = _AZ.match(h)
    if a:
        return "azure", {"account": a.group("acct"), "service": a.group("svc")}
    return "internet", {"fqdn": h}


import numpy as np
from collections import defaultdict

ALL_WORKSPACES = "__ALL__"  # policy_target sentinel for a single all-workspaces policy


def _as_list(v):
    """Coerce a Spark array<> column (numpy array after toPandas) to a clean Python list."""
    if v is None:
        return []
    if hasattr(v, "tolist"):
        v = v.tolist()
    elif not isinstance(v, (list, tuple)):
        v = [v]
    return [x for x in v if x is not None and x != ""]


def _new_target():
    return {"s3": {}, "gcs": {}, "azure": {}, "internet": {}}


# Bucket classified destinations per policy target. single -> one ALL_WORKSPACES target; per_workspace
# -> each destination fans out to the workspace_ids it was observed in.
targets = defaultdict(_new_target)
fqdn_resolved_ips = {}  # fqdn -> [resolved IPs from dns_event.rdata] (used to skip a DNS lookup later)
skipped_bare_s3 = 0
for r in observed_egress.toPandas().to_dict(orient="records"):
    kind, info = _classify(r["destination"])
    events = int(r["events"])
    if kind == "s3" and info.get("region"):
        key, bucketname = ("s3", (info["bucket"], info["region"]))
    elif kind == "gcs":
        key, bucketname = ("gcs", info["bucket"])
    elif kind == "azure":
        key, bucketname = ("azure", (info["account"], info["service"]))
    elif kind == "internet":
        key, bucketname = ("internet", info["fqdn"])
        ips = fqdn_resolved_ips.setdefault(info["fqdn"], [])
        for ip in _as_list(r.get("resolved_ips")):
            if ip not in ips:
                ips.append(ip)
    else:
        skipped_bare_s3 += 1
        continue
    if POLICY_SCOPE == "per_workspace":
        tgts = [int(w) for w in _as_list(r.get("workspace_ids"))] or [ALL_WORKSPACES]
    else:
        tgts = [ALL_WORKSPACES]
    for t in tgts:
        d = targets[t][key]
        d[bucketname] = d.get(bucketname, 0) + events

if not targets:
    targets[ALL_WORKSPACES] = _new_target()

_tot = lambda k: sum(len(targets[t][k]) for t in targets)  # noqa: E731 - compact roll-up for logging
print(f"policy_scope={POLICY_SCOPE}: {len(targets)} policy target(s). Across all: "
      f"{_tot('s3')} S3, {_tot('gcs')} GCS, {_tot('azure')} Azure storage, {_tot('internet')} internet FQDNs; "
      f"skipped {skipped_bare_s3} bare/path-style S3 endpoint(s).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Hosting-owner lookup for internet FQDNs (optional)
# MAGIC
# MAGIC For review context — **who hosts each domain** (e.g. GitHub, Fastly, Amazon). We resolve the
# MAGIC FQDN to an IP, then RDAP the IP for the owning org. RDAP-on-domain is avoided: it only yields
# MAGIC the registrar (e.g. MarkMonitor) and the registrant is usually GDPR-redacted. The resolved IP
# MAGIC often comes free from the audit log (`dns_event.rdata`) — we only DNS-resolve when it doesn't.
# MAGIC One lookup per distinct FQDN (widget `2a`).

# COMMAND ----------

# DBTITLE 1,Resolve FQDN -> IP -> hosting owner (RDAP)
import json
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_RDAP_TIMEOUT, _RDAP_RETRIES, _UA = 8, 2, "Databricks-CBI-Helper"


def _resolve_ip(fqdn):
    """First IP for an FQDN — prefer the one already in the audit log (dns_event.rdata), else DNS."""
    for ip in fqdn_resolved_ips.get(fqdn, []):
        return ip
    try:
        return socket.gethostbyname(fqdn)
    except OSError:
        return None


def _rdap_ip_owner(ip):
    """Owning org for an IP via rdap.org (follows the redirect to the RIR). None on failure."""
    for _ in range(_RDAP_RETRIES):
        try:
            req = Request(f"https://rdap.org/ip/{ip}",
                          headers={"Accept": "application/rdap+json", "User-Agent": _UA})
            with urlopen(req, timeout=_RDAP_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            for entity in payload.get("entities", []) or []:
                vcard = entity.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for fld in vcard[1]:
                        if len(fld) >= 4 and fld[0] == "fn" and fld[3]:
                            return payload.get("name") or fld[3]
            return payload.get("name") or payload.get("handle")
        except (HTTPError, URLError, TimeoutError, ValueError):
            time.sleep(0.5)
    return None


def _union(key):
    """Merge a destination dict (s3/gcs/azure/internet) across all policy targets, summing events."""
    merged = {}
    for t in targets:
        for k, n in targets[t][key].items():
            merged[k] = merged.get(k, 0) + n
    return merged


all_internet_fqdns = _union("internet")

fqdn_ip = {}       # fqdn -> resolved IP
fqdn_owner = {}    # fqdn -> hosting org (from IP RDAP)
if ENABLE_RDAP and all_internet_fqdns:
    _ip_owner_cache = {}
    for fqdn in all_internet_fqdns:
        ip = _resolve_ip(fqdn)
        fqdn_ip[fqdn] = ip
        if ip:
            if ip not in _ip_owner_cache:
                _ip_owner_cache[ip] = _rdap_ip_owner(ip)
                time.sleep(0.1)
            fqdn_owner[fqdn] = _ip_owner_cache[ip]
    print(f"Hosting owner resolved for {sum(1 for v in fqdn_owner.values() if v)} of "
          f"{len(all_internet_fqdns)} FQDN(s) "
          f"({sum(1 for f in all_internet_fqdns if fqdn_resolved_ips.get(f))} had IPs from the audit log).")
else:
    print("Owner lookup off or no FQDNs.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Review — proposed egress allow-list
# MAGIC
# MAGIC What the helper would allow. Review before creating. Storage tables carry the fields the CBI
# MAGIC egress policy needs (S3 bucket+region, GCS bucket, Azure account+service).

# COMMAND ----------

# DBTITLE 1,Review tables
# Review shows the combined picture across all targets. In per_workspace scope the per-target
# breakdown is printed in the build step below.
_u_s3, _u_gcs, _u_azure = _union("s3"), _union("gcs"), _union("azure")
internet_pdf = pd.DataFrame(
    [{"fqdn": f, "events": n, "resolved_ip": fqdn_ip.get(f), "hosting_owner": fqdn_owner.get(f)}
     for f, n in sorted(all_internet_fqdns.items(), key=lambda kv: kv[1], reverse=True)]
)
s3_pdf = pd.DataFrame(
    [{"bucket": b, "region": reg, "events": n} for (b, reg), n in sorted(
        _u_s3.items(), key=lambda kv: kv[1], reverse=True)]
)
gcs_pdf = pd.DataFrame([{"bucket": b, "events": n} for b, n in sorted(
    _u_gcs.items(), key=lambda kv: kv[1], reverse=True)])
azure_pdf = pd.DataFrame(
    [{"account": acct, "service": svc, "events": n} for (acct, svc), n in sorted(
        _u_azure.items(), key=lambda kv: kv[1], reverse=True)]
)

print(f"Internet FQDNs: {len(internet_pdf)} | S3: {len(s3_pdf)} | GCS: {len(gcs_pdf)} | Azure: {len(azure_pdf)}"
      f"  (combined across {len(targets)} target(s))")
for name, pdf in [("Internet FQDNs", internet_pdf), ("AWS S3", s3_pdf),
                  ("GCS", gcs_pdf), ("Azure storage", azure_pdf)]:
    if not pdf.empty:
        print(f"\n=== {name} ===")
        display(pdf)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Threat-intel domain block list (optional)
# MAGIC
# MAGIC `block_threat_domains` (widget `3c`): `off` (none); `matched_only` (block observed FQDNs that
# MAGIC appear on a suspicious-domain feed); `all` (block the whole feed, capped). Blocked destinations
# MAGIC are enforced in any mode and take precedence over allows — a lightweight way to block known-bad
# MAGIC domains. The feed is chosen by widget `3d` (`threat_feed`); all are free and need no API key.

# COMMAND ----------

# DBTITLE 1,Build blocked domains
# Threat-domain feed registry — each entry is (url, line->host parser). All free, no key.
#  - threatfox   : abuse.ch ThreatFox hostfile (~49k; C2/botnet/phishing/distribution). '0.0.0.0 host'.
#  - urlhaus     : malware-filter URLhaus online domains (~500; distribution only, very high-signal).
#  - hagezi_tif  : HaGeZi TIF medium (~370k; broadest — malware+scam+spam, higher false-positive risk).
#    Adblock syntax: '||host^'.
def _host_plain(line):
    return line.strip().lower()


def _host_hostfile(line):  # '0.0.0.0 host' / '127.0.0.1 host'
    parts = line.split()
    return parts[1].lower() if len(parts) == 2 else ""


def _host_adblock(line):  # '||host^'
    m = re.match(r'^\|\|([^/^]+)\^', line.strip())
    return m.group(1).lower() if m else ""


THREAT_FEEDS = {
    "threatfox": ("https://threatfox.abuse.ch/downloads/hostfile/", _host_hostfile),
    "urlhaus": ("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt", _host_plain),
    "hagezi_tif": ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt", _host_adblock),
}


def _load_threat_domains(feed_key):
    """Distinct malicious FQDNs from the selected feed. IP literals and non-hosts are dropped
    (blocked destinations are FQDN-only). Best-effort — empty set on any fetch failure."""
    import ipaddress as _ip
    url, parse = THREAT_FEEDS[feed_key]
    domains = set()
    try:
        req = Request(url, headers={"User-Agent": _UA})
        with urlopen(req, timeout=45) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith(("#", "!", "[")):
                continue
            host = parse(s)
            if not host or "." not in host:
                continue
            try:
                _ip.ip_address(host)  # IP literal — not a valid FQDN block target
                continue
            except ValueError:
                pass
            domains.add(host)
    except Exception as e:  # noqa: BLE001
        print(f"  ! could not fetch threat-domain feed '{feed_key}': {e}")
    return domains

blocked_domains = []
if BLOCK_THREAT_DOMAINS != "off":
    feed = _load_threat_domains(THREAT_FEED)
    print(f"threat-domain feed '{THREAT_FEED}': {len(feed):,} distinct FQDNs")
    if BLOCK_THREAT_DOMAINS == "matched_only":
        blocked_domains = sorted(f for f in all_internet_fqdns if f in feed)
        print(f"observed FQDNs matching the feed: {len(blocked_domains)}")
    else:  # all
        blocked_domains = sorted(feed)
    if len(blocked_domains) > MAX_INTERNET_DESTINATIONS:
        print(f"⚠️  {len(blocked_domains)} blocked domains > {MAX_INTERNET_DESTINATIONS} limit — "
              f"keeping the first {MAX_INTERNET_DESTINATIONS}. Use matched_only to narrow.")
        blocked_domains = blocked_domains[:MAX_INTERNET_DESTINATIONS]
    print(f"will block {len(blocked_domains)} domain(s).")
else:
    print("Domain blocking off.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build & preview the egress policy
# MAGIC
# MAGIC Assembles the `egress.network_access` block: `RESTRICTED_ACCESS` with the allowed internet +
# MAGIC storage destinations (and any blocked domains), plus the enforcement mode from `policy_mode`
# MAGIC (dry_run = log-only). Caps to the per-policy limits. Prints the exact JSON; sends nothing.

# COMMAND ----------

# DBTITLE 1,Build egress block(s) + preview
def _build_egress_block(t):
    """Build the egress block for one policy target dict t = {s3, gcs, azure, internet}. Blocked
    domains (threat intel) are applied to every target. Caps to the per-policy limits."""
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EA,
        EgressNetworkPolicyNetworkAccessPolicyInternetDestination as InetDest,
        EgressNetworkPolicyNetworkAccessPolicyInternetDestinationInternetDestinationType as InetType,
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcement as Enforcement,
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcementEnforcementMode as EnforcementMode,
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as RestrictionMode,
        EgressNetworkPolicyNetworkAccessPolicyStorageDestination as StorDest,
        EgressNetworkPolicyNetworkAccessPolicyStorageDestinationStorageDestinationType as StorType,
        NetworkPolicyEgress,
    )

    allowed_internet = [
        InetDest(destination=f, internet_destination_type=InetType.DNS_NAME)
        for f in list(t["internet"])[:MAX_INTERNET_DESTINATIONS]
    ]
    blocked_internet = [
        InetDest(destination=d, internet_destination_type=InetType.DNS_NAME) for d in blocked_domains
    ] or None

    storage = []
    for (bucket, region) in t["s3"]:
        storage.append(StorDest(bucket_name=bucket, region=region, storage_destination_type=StorType.AWS_S3))
    for bucket in t["gcs"]:
        storage.append(StorDest(bucket_name=bucket, storage_destination_type=StorType.GOOGLE_CLOUD_STORAGE))
    for (acct, svc) in t["azure"]:
        storage.append(StorDest(azure_storage_account=acct, azure_storage_service=svc,
                                storage_destination_type=StorType.AZURE_STORAGE))
    storage = storage[:MAX_STORAGE_DESTINATIONS]

    enforcement_mode = EnforcementMode.DRY_RUN if POLICY_MODE == "dry_run" else EnforcementMode.ENFORCED
    return NetworkPolicyEgress(network_access=EA(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allowed_internet_destinations=allowed_internet or None,
        allowed_storage_destinations=storage or None,
        blocked_internet_destinations=blocked_internet,
        policy_enforcement=Enforcement(enforcement_mode=enforcement_mode),
    ))


def _target_has_content(t):
    return bool(t["s3"] or t["gcs"] or t["azure"] or t["internet"] or blocked_domains)


# Build one egress block per target that has content.
egress_blocks = {tgt: _build_egress_block(t) for tgt, t in targets.items() if _target_has_content(t)}

if not egress_blocks:
    print("Nothing to propose — no classified destinations. Check the observed-egress table above.")
else:
    for tgt in sorted(egress_blocks, key=str):
        t = targets[tgt]
        label = "single (all workspaces)" if tgt == ALL_WORKSPACES else f"workspace {tgt}"
        n_store = min(len(t["s3"]) + len(t["gcs"]) + len(t["azure"]), MAX_STORAGE_DESTINATIONS)
        print(f"\n=== {label}: egress ({POLICY_MODE} mode) — "
              f"{min(len(t['internet']), MAX_INTERNET_DESTINATIONS)} internet allow, "
              f"{n_store} storage allow, {len(blocked_domains)} blocked ===")
        print(json.dumps({"egress": egress_blocks[tgt].as_dict()}, indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Create the egress policy (gated)
# MAGIC
# MAGIC Creates/updates each proposed policy's **egress** block (ingress left untouched), gated by
# MAGIC `create_policy`. `auto_assign` binds the workspace(s). Requires an **account-admin**
# MAGIC AccountClient (widgets 4a–4e). Idempotent (deterministic names).
# MAGIC - `policy_scope=single` — one policy `<name_prefix>`; auto_assign binds **this** workspace.
# MAGIC - `policy_scope=per_workspace` — policy `<name_prefix>-ws-<id>` per workspace; auto_assign binds each.

# COMMAND ----------

# DBTITLE 1,Create + assign
from databricks.sdk import WorkspaceClient

THIS_WORKSPACE_ID = WorkspaceClient().get_workspace_id()


def _policy_name(target):
    """Deterministic policy id. single -> <prefix>; per_workspace -> <prefix>-ws-<id> (keep the full
    workspace id, truncate the prefix if needed to fit the length limit)."""
    if target == ALL_WORKSPACES:
        return NAME_PREFIX[:MAX_POLICY_ID_LEN]
    suffix = f"-ws-{target}"
    return f"{NAME_PREFIX[:max(MAX_POLICY_ID_LEN - len(suffix), 1)].rstrip('-')}{suffix}"


def _account_client():
    from databricks.sdk import AccountClient
    if not ACCOUNT_ID:
        raise ValueError("account_id (widget 4a) is required to create/assign a network policy.")
    if ACCOUNT_SP_CLIENT_ID and ACCOUNT_SECRET_SCOPE and ACCOUNT_SECRET_KEY:
        secret = dbutils.secrets.get(scope=ACCOUNT_SECRET_SCOPE, key=ACCOUNT_SECRET_KEY)
        return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID,
                             client_id=ACCOUNT_SP_CLIENT_ID, client_secret=secret)
    return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID)


if globals().get("_COMBINED_RUN", False):
    # Running under the combiner (full_policy_helper) — it does the merged create. Skip this cell so
    # the built `egress_blocks` dict is left intact for merging.
    print("Combined run — skipping egress create; the combiner will create the merged policy.")
elif not CREATE_POLICY:
    print(f"Not creating (mode={POLICY_MODE}, scope={POLICY_SCOPE}). Set create_policy=true to create "
          f"the egress policy(ies)" + (" and assign the workspace(s)." if AUTO_ASSIGN else "."))
elif not egress_blocks:
    print("Nothing to create — no proposed egress destinations.")
else:
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy, WorkspaceNetworkOption

    a = _account_client()
    for tgt in sorted(egress_blocks, key=str):
        pid = _policy_name(tgt)
        # In single scope with auto_assign, bind THIS workspace; in per_workspace, bind that target.
        bind_ws = THIS_WORKSPACE_ID if tgt == ALL_WORKSPACES else int(tgt)
        try:
            try:
                existing = a.network_policies.get_network_policy_rpc(network_policy_id=pid)
                action = "updated"
            except NotFound:
                existing = AccountNetworkPolicy(account_id=ACCOUNT_ID, network_policy_id=pid)
                action = "created"
            existing.egress = egress_blocks[tgt]  # replace egress; leave ingress blocks untouched
            if action == "created":
                result = a.network_policies.create_network_policy_rpc(network_policy=existing)
                effective_id = result.network_policy_id or pid
            else:
                a.network_policies.update_network_policy_rpc(network_policy_id=pid, network_policy=existing)
                effective_id = pid
            msg = f"  ✅ {action} '{effective_id}' (egress, {POLICY_MODE})"
            if AUTO_ASSIGN:
                a.workspace_network_configuration.update_workspace_network_option_rpc(
                    workspace_id=bind_ws,
                    workspace_network_option=WorkspaceNetworkOption(
                        workspace_id=bind_ws, network_policy_id=effective_id),
                )
                msg += f" and bound workspace {bind_ws}"
            print(msg)
        except Exception as e:  # noqa: BLE001 - surface per-target failures, keep going
            print(f"  ❌ target {tgt}: {e}")
    if POLICY_MODE == "enforce" and AUTO_ASSIGN:
        print("⛔ ENFORCED — egress not on the allow-list is now blocked. Verify workloads still reach what they need.")
