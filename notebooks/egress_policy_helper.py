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
# MAGIC 3. Enriches internet FQDNs with RDAP owner (optional).
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
dbutils.widgets.dropdown("enable_rdap", "true", ["true", "false"], "2a. RDAP owner lookup (FQDNs)?")

# --- Policy shape ---
dbutils.widgets.text("name_prefix", "cbi-helper", "3a. Name prefix for policy/rules")
dbutils.widgets.dropdown("policy_mode", "dry_run", ["dry_run", "enforce"], "3b. Egress policy mode")
# Threat-intel domain blocking: off | matched_only (block observed FQDNs that hit a feed) |
# all (block the whole suspicious-domain feed). Independent of the allow-list.
dbutils.widgets.dropdown(
    "block_threat_domains", "off", ["off", "matched_only", "all"], "3c. Block threat-intel domains"
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
BLOCK_THREAT_DOMAINS = dbutils.widgets.get("block_threat_domains")  # off | matched_only | all
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
      f"| policy_mode={POLICY_MODE} block_threat_domains={BLOCK_THREAT_DOMAINS}")

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


rows = observed_egress.toPandas().to_dict(orient="records")
s3_dests, gcs_dests, azure_dests, internet_fqdns = {}, {}, {}, {}
skipped_bare_s3 = 0
for r in rows:
    kind, info = _classify(r["destination"])
    if kind == "s3" and info.get("region"):
        s3_dests[(info["bucket"], info["region"])] = r["events"]
    elif kind == "gcs":
        gcs_dests[info["bucket"]] = r["events"]
    elif kind == "azure":
        azure_dests[(info["account"], info["service"])] = r["events"]
    elif kind == "internet":
        internet_fqdns[info["fqdn"]] = internet_fqdns.get(info["fqdn"], 0) + r["events"]
    else:
        skipped_bare_s3 += 1

print(f"classified: {len(s3_dests)} S3, {len(gcs_dests)} GCS, {len(azure_dests)} Azure storage; "
      f"{len(internet_fqdns)} internet FQDNs; skipped {skipped_bare_s3} bare/path-style S3 endpoint(s).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## RDAP owner lookup for internet FQDNs (optional)
# MAGIC
# MAGIC For context on the review table — who owns each domain. One lookup per distinct FQDN via
# MAGIC `rdap.org` (widget `2a`).

# COMMAND ----------

# DBTITLE 1,RDAP domain lookup
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_RDAP_TIMEOUT, _RDAP_RETRIES, _UA = 8, 2, "Databricks-CBI-Helper"


def _rdap_domain_owner(fqdn):
    """Best-effort registrant/owner for a domain via rdap.org. Returns None on any failure."""
    # RDAP domain queries use the registrable domain; try the FQDN then its last two labels.
    candidates = [fqdn]
    parts = fqdn.split(".")
    if len(parts) > 2:
        candidates.append(".".join(parts[-2:]))
    for name in candidates:
        url = f"https://rdap.org/domain/{name}"
        for attempt in range(1, _RDAP_RETRIES + 1):
            try:
                req = Request(url, headers={"Accept": "application/rdap+json", "User-Agent": _UA})
                with urlopen(req, timeout=_RDAP_TIMEOUT) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                for entity in payload.get("entities", []) or []:
                    vcard = entity.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for fld in vcard[1]:
                            if len(fld) >= 4 and fld[0] == "fn" and fld[3]:
                                return fld[3]
                return payload.get("handle")
            except (HTTPError, URLError, TimeoutError, ValueError):
                break  # try next candidate
    return None


rdap_owner = {}
if ENABLE_RDAP and internet_fqdns:
    for fqdn in internet_fqdns:
        rdap_owner[fqdn] = _rdap_domain_owner(fqdn)
        time.sleep(0.1)
    print(f"RDAP: resolved owner for {sum(1 for v in rdap_owner.values() if v)} of {len(internet_fqdns)} FQDN(s).")
else:
    print("RDAP lookup off or no FQDNs.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Review — proposed egress allow-list
# MAGIC
# MAGIC What the helper would allow. Review before creating. Storage tables carry the fields the CBI
# MAGIC egress policy needs (S3 bucket+region, GCS bucket, Azure account+service).

# COMMAND ----------

# DBTITLE 1,Review tables
internet_pdf = pd.DataFrame(
    [{"fqdn": f, "events": n, "rdap_owner": rdap_owner.get(f)} for f, n in sorted(
        internet_fqdns.items(), key=lambda kv: kv[1], reverse=True)]
)
s3_pdf = pd.DataFrame(
    [{"bucket": b, "region": reg, "events": n} for (b, reg), n in sorted(
        s3_dests.items(), key=lambda kv: kv[1], reverse=True)]
)
gcs_pdf = pd.DataFrame([{"bucket": b, "events": n} for b, n in sorted(
    gcs_dests.items(), key=lambda kv: kv[1], reverse=True)])
azure_pdf = pd.DataFrame(
    [{"account": acct, "service": svc, "events": n} for (acct, svc), n in sorted(
        azure_dests.items(), key=lambda kv: kv[1], reverse=True)]
)

print(f"Internet FQDNs: {len(internet_pdf)} | S3: {len(s3_pdf)} | GCS: {len(gcs_pdf)} | Azure: {len(azure_pdf)}")
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
# MAGIC domains. Feed: malware-filter urlhaus-filter (abuse.ch URLhaus, deduped to FQDNs) — free,
# MAGIC no key, ~29k malicious domains.

# COMMAND ----------

# DBTITLE 1,Build blocked domains
# malware-filter's "online malicious domains" list: URLhaus (abuse.ch) malicious URLs deduped to
# one host per line — free, no key, '#'-commented header, refreshed ~12h (AGPL-3.0; attribution:
# "URLhaus abuse.ch + malware-filter project"). This plain-domain variant is used (not the base
# urlhaus-filter.txt, which is Adblock-syntax, nor the raw URLhaus feed, which is mostly bare IPs).
# It still contains some bare-IP lines, which are dropped below (blocks are FQDN-only). To swap
# feeds, change this URL + the per-line parse.
THREAT_DOMAINS_URL = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt"


def _load_threat_domains():
    """Distinct malicious FQDNs from the malware-filter urlhaus-filter feed. Plaintext, one domain
    per line ('#'/'!' comments). IP literals are dropped (blocked destinations are FQDN-only).
    Best-effort — returns an empty set on any fetch failure."""
    import ipaddress as _ip
    domains = set()
    try:
        req = Request(THREAT_DOMAINS_URL, headers={"User-Agent": _UA})
        with urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        for line in text.splitlines():
            host = line.strip().lower()
            if not host or host.startswith(("#", "!")) or "." not in host:
                continue
            try:
                _ip.ip_address(host)  # an IP literal — not a valid FQDN block target
                continue
            except ValueError:
                pass
            domains.add(host)
    except Exception as e:  # noqa: BLE001
        print(f"  ! could not fetch threat-domain feed: {e}")
    return domains

blocked_domains = []
if BLOCK_THREAT_DOMAINS != "off":
    feed = _load_threat_domains()
    print(f"threat-domain feed: {len(feed):,} distinct hostnames")
    if BLOCK_THREAT_DOMAINS == "matched_only":
        blocked_domains = sorted(f for f in internet_fqdns if f in feed)
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

# DBTITLE 1,Build egress block + preview
def _build_egress_block():
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
        for f in list(internet_fqdns)[:MAX_INTERNET_DESTINATIONS]
    ]
    blocked_internet = [
        InetDest(destination=d, internet_destination_type=InetType.DNS_NAME) for d in blocked_domains
    ] or None

    storage = []
    for (bucket, region) in s3_dests:
        storage.append(StorDest(bucket_name=bucket, region=region, storage_destination_type=StorType.AWS_S3))
    for bucket in gcs_dests:
        storage.append(StorDest(bucket_name=bucket, storage_destination_type=StorType.GOOGLE_CLOUD_STORAGE))
    for (acct, svc) in azure_dests:
        storage.append(StorDest(azure_storage_account=acct, azure_storage_service=svc,
                                storage_destination_type=StorType.AZURE_STORAGE))
    if len(storage) > MAX_STORAGE_DESTINATIONS:
        print(f"⚠️  {len(storage)} storage destinations > {MAX_STORAGE_DESTINATIONS} limit — "
              f"keeping the first {MAX_STORAGE_DESTINATIONS}.")
        storage = storage[:MAX_STORAGE_DESTINATIONS]

    enforcement_mode = EnforcementMode.DRY_RUN if POLICY_MODE == "dry_run" else EnforcementMode.ENFORCED
    return NetworkPolicyEgress(network_access=EA(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allowed_internet_destinations=allowed_internet or None,
        allowed_storage_destinations=storage or None,
        blocked_internet_destinations=blocked_internet,
        policy_enforcement=Enforcement(enforcement_mode=enforcement_mode),
    ))


if not (internet_fqdns or s3_dests or gcs_dests or azure_dests or blocked_domains):
    print("Nothing to propose — no classified destinations. Check the observed-egress table above.")
    _egress_block = None
else:
    _egress_block = _build_egress_block()
    print(f"Proposed egress ({POLICY_MODE} mode): "
          f"{min(len(internet_fqdns), MAX_INTERNET_DESTINATIONS)} internet allow, "
          f"{min(len(s3_dests)+len(gcs_dests)+len(azure_dests), MAX_STORAGE_DESTINATIONS)} storage allow, "
          f"{len(blocked_domains)} blocked:\n")
    print(json.dumps({"egress": _egress_block.as_dict()}, indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Create the egress policy (gated)
# MAGIC
# MAGIC Creates/updates the account network policy's **egress** block (ingress left untouched), gated by
# MAGIC `create_policy`. `auto_assign` binds this workspace. Requires an **account-admin** AccountClient
# MAGIC (widgets 4a–4e). Idempotent: reuses the `<name_prefix>-<workspace_id>` policy name.

# COMMAND ----------

# DBTITLE 1,Create + assign
from databricks.sdk import WorkspaceClient

WORKSPACE_ID = WorkspaceClient().get_workspace_id()
RESOLVED_POLICY_ID = f"{NAME_PREFIX}-{WORKSPACE_ID}"
if len(RESOLVED_POLICY_ID) > MAX_POLICY_ID_LEN:
    print(f"⚠️  policy name '{RESOLVED_POLICY_ID}' is {len(RESOLVED_POLICY_ID)} chars (limit "
          f"~{MAX_POLICY_ID_LEN}). Shorten name_prefix if create fails with 'Invalid NetworkPolicyId'.")


def _account_client():
    from databricks.sdk import AccountClient
    if not ACCOUNT_ID:
        raise ValueError("account_id (widget 4a) is required to create/assign a network policy.")
    if ACCOUNT_SP_CLIENT_ID and ACCOUNT_SECRET_SCOPE and ACCOUNT_SECRET_KEY:
        secret = dbutils.secrets.get(scope=ACCOUNT_SECRET_SCOPE, key=ACCOUNT_SECRET_KEY)
        return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID,
                             client_id=ACCOUNT_SP_CLIENT_ID, client_secret=secret)
    return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID)


if not CREATE_POLICY:
    print(f"Not creating (mode={POLICY_MODE}). Set create_policy=true to create the egress policy"
          f"{' and assign this workspace' if AUTO_ASSIGN else ''}.")
elif _egress_block is None:
    print("Nothing to create — no proposed egress destinations.")
else:
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy, WorkspaceNetworkOption

    a = _account_client()
    try:
        existing = a.network_policies.get_network_policy_rpc(network_policy_id=RESOLVED_POLICY_ID)
        action = "updated"
    except NotFound:
        existing = AccountNetworkPolicy(account_id=ACCOUNT_ID, network_policy_id=RESOLVED_POLICY_ID)
        action = "created"

    existing.egress = _egress_block  # replace egress; leave ingress/ingress_dry_run untouched
    if action == "created":
        result = a.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or RESOLVED_POLICY_ID
    else:
        a.network_policies.update_network_policy_rpc(network_policy_id=RESOLVED_POLICY_ID, network_policy=existing)
        effective_id = RESOLVED_POLICY_ID
    print(f"Policy {action}: {effective_id} (egress, {POLICY_MODE} mode)")

    if AUTO_ASSIGN:
        a.workspace_network_configuration.update_workspace_network_option_rpc(
            workspace_id=WORKSPACE_ID,
            workspace_network_option=WorkspaceNetworkOption(
                workspace_id=WORKSPACE_ID, network_policy_id=effective_id),
        )
        print(f"Assigned workspace {WORKSPACE_ID} to {effective_id}.")
        if POLICY_MODE == "enforce":
            print("⛔ ENFORCED — egress not on the allow-list is now blocked. Verify workloads still reach what they need.")
    else:
        print(f"Not assigned (auto_assign=false). Bind workspace {WORKSPACE_ID} to '{effective_id}' when ready.")
