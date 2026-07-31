# Databricks notebook source
# MAGIC %md
# MAGIC # Context-Based Ingress (CBI) Helper
# MAGIC
# MAGIC This notebook analyses recent `system.access.audit` traffic and proposes a first-pass
# MAGIC **context-based ingress (CBI)** allow-list for a Databricks account network policy.
# MAGIC
# MAGIC It:
# MAGIC 1. Summarises request surfaces and per-principal network diversity in the audit log.
# MAGIC 2. Finds the public source IPs that account for real, successful traffic.
# MAGIC 3. Enriches those IPs with **threat intelligence** (known-bad ranges) and **cloud-provider
# MAGIC    range** membership, plus RDAP owner lookup.
# MAGIC 4. Proposes allow-rule CIDR framings per IP group (`minimal` / `optimal` / `maximum`),
# MAGIC    optionally scoped by **destination** (e.g. Apps-only) and **identity** (specific users /
# MAGIC    service principals). Flagged (threat/cloud-owned) groups are always excluded.
# MAGIC 5. Optionally adds **threat-intel deny rules** (one per feed) — either just the ranges that
# MAGIC    matched observed traffic, or entire feeds regardless of matches (`threat_deny_rules`).
# MAGIC 6. Builds either **one policy for all workspaces** (`policy_scope=single`) or a **tailored
# MAGIC    policy per workspace** with recommended assignments (`policy_scope=per_workspace`), and
# MAGIC    warns + auto-caps to the network-policy limits (50 rules / 2000 CIDRs / 100 identities).
# MAGIC 7. Optionally writes the result into the account network policy via the Databricks SDK, in
# MAGIC    **`dry_run`** (log-only) or **`enforce`** (blocking) mode — both gated behind an explicit,
# MAGIC    mode-specific confirmation.
# MAGIC
# MAGIC > ⚠️ **Safety:** every suggestion is advisory. The default `policy_mode` is `dry_run`, which
# MAGIC > cannot block traffic. **`enforce` CAN lock users out** if the allow-list is incomplete — it
# MAGIC > only writes when `apply_policy=true`. Validate in `dry_run` and review its logs before
# MAGIC > switching `policy_mode` to `enforce`.
# MAGIC
# MAGIC **All decisions are made via the widgets at the top (see "Parameters & decisions").**

# COMMAND ----------

# MAGIC %md
# MAGIC ## Install a current Databricks SDK
# MAGIC
# MAGIC The CBI policy dataclasses (`CustomerFacingIngressNetworkPolicy*`) require a newer
# MAGIC `databricks-sdk` than the one bundled with serverless / some DBRs. Pin and restart Python
# MAGIC **before** any SDK import so every environment runs the same version.

# COMMAND ----------

# DBTITLE 1,Install & pin databricks-sdk
# MAGIC %pip install --quiet "databricks-sdk>=0.113.0"

# COMMAND ----------

# DBTITLE 1,Restart Python to load the pinned SDK
dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parameters & decisions
# MAGIC
# MAGIC Every choice the notebook needs is made here, up front. The cell below **creates all widgets**;
# MAGIC the table that follows explains each one. Set them in the widget bar, then run the notebook
# MAGIC top to bottom. Nothing below this section creates new widgets.

# COMMAND ----------

# DBTITLE 1,Create all widgets
# Feed list is defined here (not in the loader) so the threat-intel multiselect can be built up
# front. It must match the keys registered in THREAT_FEED_LOADERS further down.
ALL_THREAT_FEEDS = ["spamhaus_drop", "tor_exit", "firehol_level1", "ipsum", "dshield", "cins_ci_army"]

# --- Analysis window & candidate selection ---
dbutils.widgets.text("lookback_days", "30", "1a. Lookback (days)")
dbutils.widgets.text("min_events", "1", "1b. Min successful events per IP")
dbutils.widgets.dropdown(
    "treat_null_status_as_success", "true", ["true", "false"], "1c. NULL status = success?"
)
dbutils.widgets.dropdown("include_ipv6", "false", ["true", "false"], "1d. Include IPv6?")
# workspace_id = 0 in the audit log means account-level access. We build workspace network policies,
# so exclude those rows by default; set true to include them.
dbutils.widgets.dropdown(
    "include_account_level", "false", ["true", "false"], "1e. Include account-level (ws_id=0)?"
)

# --- Enrichment ---
# multiselect requires the default to be a SINGLE value present in choices (it cannot pre-select
# multiple). Use an "ALL" sentinel as the default; it expands to every feed when read below.
# Remove any pre-existing threat_feeds widget first so a stale value (e.g. from an earlier build)
# can't fail recreation by not being in the current choices list.
try:
    dbutils.widgets.remove("threat_feeds")
except Exception:  # noqa: BLE001 - widget may not exist yet
    pass
dbutils.widgets.multiselect(
    "threat_feeds", "ALL", ["ALL"] + ALL_THREAT_FEEDS, "2a. Threat-intel feeds (ALL = every feed)"
)
dbutils.widgets.dropdown("refresh_enrichment", "true", ["true", "false"], "2b. Refresh feeds?")
dbutils.widgets.text("enrichment_catalog", "main", "2c. Enrichment catalog")
dbutils.widgets.text("enrichment_schema", "network_cbi", "2d. Enrichment schema (blank=temp views)")
dbutils.widgets.dropdown("enable_rdap", "true", ["true", "false"], "2e. RDAP owner lookup?")

# --- Policy shape ---
dbutils.widgets.dropdown(
    "policy_framing", "optimal", ["minimal", "optimal", "maximum"], "3a. CIDR framing"
)
dbutils.widgets.dropdown(
    "scoping_mode", "ip_only",
    ["ip_only", "ip_and_destination", "ip_and_identity", "ip_identity_and_destination"],
    "3b. Scoping mode",
)
# single = one policy across all workspaces (built from all candidate traffic); per_workspace =
# a tailored policy per workspace with a recommended workspace->policy assignment.
dbutils.widgets.dropdown(
    "policy_scope", "single", ["single", "per_workspace"], "3b2. Policy scope"
)
# Flagged (threat/cloud) groups are ALWAYS excluded from proposed rules — remove any stale
# exclude_flagged widget from earlier versions so it doesn't linger in the widget bar.
try:
    dbutils.widgets.remove("exclude_flagged")
except Exception:  # noqa: BLE001 - widget may not exist
    pass
dbutils.widgets.dropdown("policy_mode", "dry_run", ["dry_run", "enforce"], "3c. Policy mode")
# Optionally add deny rules from threat intel, independent of observed traffic. off = none;
# matched_only = deny just the threat CIDRs that matched an observed IP (small); all = deny the
# whole threat-intel table, one rule per feed (can be large — a size cap applies).
dbutils.widgets.dropdown(
    "threat_deny_rules", "off", ["off", "matched_only", "all"], "3d. Threat-intel deny rules"
)

# --- Account authentication (needed for identity resolution + apply; both are account-level) ---
dbutils.widgets.text("account_id", "", "4a. Databricks account_id (blank = set manually)")
dbutils.widgets.text(
    "account_host", "https://accounts.cloud.databricks.com", "4b. Account console host (edit for Azure/GCP)"
)
dbutils.widgets.text("account_sp_client_id", "", "4c. Account admin SP client_id")
dbutils.widgets.text("account_secret_scope", "", "4d. Secret scope holding SP secret")
dbutils.widgets.text("account_secret_key", "", "4e. Secret key for SP secret")

# --- Apply (gated) ---
dbutils.widgets.text("network_policy_id", "", "5a. Target network_policy_id")
dbutils.widgets.dropdown("apply_policy", "false", ["true", "false"], "5b. Apply the policy?")
# If the target policy doesn't exist yet, create it (default). Set false to require it to pre-exist.
dbutils.widgets.dropdown(
    "create_missing_policy", "true", ["true", "false"], "5c. Create policy if missing?"
)

# COMMAND ----------

# DBTITLE 1,Read widgets into constants + explain them
import pandas as pd

# Databricks account network-policy limits (used to warn + auto-cap so proposals stay valid).
MAX_INGRESS_RULES_PER_POLICY = 50
MAX_CIDRS_PER_POLICY = 2000
MAX_IDENTITIES_PER_POLICY = 100
MAX_POLICIES_PER_ACCOUNT = 1000

LOOKBACK_DAYS = int(dbutils.widgets.get("lookback_days"))
MIN_EVENTS = int(dbutils.widgets.get("min_events"))
TREAT_NULL_STATUS_AS_SUCCESS = dbutils.widgets.get("treat_null_status_as_success") == "true"
INCLUDE_IPV6 = dbutils.widgets.get("include_ipv6") == "true"
INCLUDE_ACCOUNT_LEVEL = dbutils.widgets.get("include_account_level") == "true"

_threat_feeds_raw = [f.strip() for f in dbutils.widgets.get("threat_feeds").split(",") if f.strip()]
# "ALL" (the default sentinel) or an empty selection expands to every feed.
if not _threat_feeds_raw or "ALL" in _threat_feeds_raw:
    SELECTED_THREAT_FEEDS = list(ALL_THREAT_FEEDS)
else:
    SELECTED_THREAT_FEEDS = [f for f in _threat_feeds_raw if f in ALL_THREAT_FEEDS]
REFRESH_ENRICHMENT = dbutils.widgets.get("refresh_enrichment") == "true"
ENRICHMENT_CATALOG = dbutils.widgets.get("enrichment_catalog").strip()
ENRICHMENT_SCHEMA = dbutils.widgets.get("enrichment_schema").strip()
ENABLE_RDAP = dbutils.widgets.get("enable_rdap") == "true"

POLICY_FRAMING = dbutils.widgets.get("policy_framing")
SCOPING_MODE = dbutils.widgets.get("scoping_mode")
POLICY_SCOPE = dbutils.widgets.get("policy_scope")  # single | per_workspace
POLICY_MODE = dbutils.widgets.get("policy_mode")
THREAT_DENY_RULES = dbutils.widgets.get("threat_deny_rules")  # off | matched_only | all

# Safety cap on total CIDRs placed into threat-intel deny rules, to avoid oversized policies.
MAX_DENY_CIDRS = 5000

# json is imported later in the feed-helpers cell; ensure it's available here too.
import json  # noqa: E402

DEFAULT_ACCOUNT_HOST = "https://accounts.cloud.databricks.com"

# account_id is an account-console concept and is not reliably exposed to a workspace runtime, so we
# do not try to auto-detect it — leave it blank unless set in widget 4a. The SCIM and apply steps
# fail early with a clear message if it's needed but unset (see _require_account_id).
ACCOUNT_ID = dbutils.widgets.get("account_id").strip()
# Host: widget value wins; otherwise the sensible default. (Azure/GCP users set widget 4b.)
ACCOUNT_HOST = dbutils.widgets.get("account_host").strip() or DEFAULT_ACCOUNT_HOST
ACCOUNT_SP_CLIENT_ID = dbutils.widgets.get("account_sp_client_id").strip()
ACCOUNT_SECRET_SCOPE = dbutils.widgets.get("account_secret_scope").strip()
ACCOUNT_SECRET_KEY = dbutils.widgets.get("account_secret_key").strip()

NETWORK_POLICY_ID = dbutils.widgets.get("network_policy_id").strip()
APPLY_POLICY = dbutils.widgets.get("apply_policy") == "true"
CREATE_MISSING_POLICY = dbutils.widgets.get("create_missing_policy") == "true"


def _require_account_id(operation):
    """Raise a clear, actionable error if account_id is unset. account_id can't be auto-detected
    from a workspace runtime, so the user must supply it for any account-level operation."""
    if not ACCOUNT_ID:
        raise ValueError(
            f"{operation} requires a Databricks account_id, which is not set.\n"
            "  Set widget '4a. Databricks account_id' to your numeric account id and re-run.\n"
            "  Find it in the Account console (accounts.cloud.databricks.com) → top-right user\n"
            "  menu, or in the account console URL after '/account/'."
        )


def _account_client():
    """Build an account-admin AccountClient. Both account-level operations this notebook can do —
    SCIM identity resolution and applying a network policy — require an account admin AND an
    account_id (widget 4a).

    Preferred: an account-level service principal that is an account admin, via OAuth M2M. Provide
    account_id + client_id + a secret scope/key holding its OAuth secret (widgets 4a–4e). If the SP
    fields are blank, falls back to the runtime's ambient account credentials, which only works if
    the environment is already configured for the account."""
    from databricks.sdk import AccountClient

    _require_account_id("Building an account client")
    if ACCOUNT_SP_CLIENT_ID and ACCOUNT_SECRET_SCOPE and ACCOUNT_SECRET_KEY:
        secret = dbutils.secrets.get(scope=ACCOUNT_SECRET_SCOPE, key=ACCOUNT_SECRET_KEY)
        return AccountClient(
            host=ACCOUNT_HOST, account_id=ACCOUNT_ID,
            client_id=ACCOUNT_SP_CLIENT_ID, client_secret=secret,
        )
    # Ambient fallback — relies on the runtime already holding account credentials.
    return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID)

# Derived
_null_status_ok = "TRUE" if TREAT_NULL_STATUS_AS_SUCCESS else "FALSE"
PERSIST_ENRICHMENT = bool(ENRICHMENT_SCHEMA)
ENRICHMENT_PREFIX = f"{ENRICHMENT_CATALOG}.{ENRICHMENT_SCHEMA}." if PERSIST_ENRICHMENT else ""
SCOPE_DESTINATION = SCOPING_MODE in ("ip_and_destination", "ip_identity_and_destination")
SCOPE_IDENTITY = SCOPING_MODE in ("ip_and_identity", "ip_identity_and_destination")
POLICY_MODE_TARGET = {"dry_run": "ingress_dry_run", "enforce": "ingress"}[POLICY_MODE]

_decisions = pd.DataFrame([
    ("1a. lookback_days", LOOKBACK_DAYS, "Days of system.access.audit history to analyse."),
    ("1b. min_events", MIN_EVENTS, "Min successful events for an IP to be a candidate."),
    ("1c. treat_null_status_as_success", TREAT_NULL_STATUS_AS_SUCCESS,
     "Whether NULL status_code counts as success. false = stricter (safer for an allow-list)."),
    ("1d. include_ipv6", INCLUDE_IPV6, "Include IPv6 sources in analysis (CBI policy itself is IPv4-only)."),
    ("1e. include_account_level", INCLUDE_ACCOUNT_LEVEL, "Include account-level (workspace_id=0) audit rows (default false)."),
    ("2a. threat_feeds", ",".join(SELECTED_THREAT_FEEDS), "Which open threat-intel feeds to load."),
    ("2b. refresh_enrichment", REFRESH_ENRICHMENT, "Re-download feeds this run vs reuse existing tables."),
    ("2c/2d. enrichment target", ENRICHMENT_PREFIX or "temp views", "Where enrichment Delta tables live."),
    ("2e. enable_rdap", ENABLE_RDAP, "Do RDAP owner lookups (external calls; needed for 'maximum' framing)."),
    ("3a. policy_framing", POLICY_FRAMING, "minimal=/32s, optimal=collapsed, maximum=full RDAP range."),
    ("3b. scoping_mode", SCOPING_MODE, "Whether rules are scoped by destination and/or identity."),
    ("3b2. policy_scope", POLICY_SCOPE, "single=one policy for all workspaces; per_workspace=a tailored policy + assignment per workspace."),
    ("3c. policy_mode", POLICY_MODE, "dry_run=log-only (ingress_dry_run); enforce=blocking (ingress)."),
    ("3d. threat_deny_rules", THREAT_DENY_RULES,
     "off=none; matched_only=deny threat CIDRs that matched observed IPs; all=deny whole feeds (one rule each)."),
    ("4a. account_id", ACCOUNT_ID or "(unset — set manually)",
     "Databricks account_id (needed for SCIM + apply). Not auto-detectable from a workspace runtime."),
    ("4b. account_host", ACCOUNT_HOST, "Account console host. Defaults to AWS; set for Azure/GCP."),
    ("4c. account_sp_client_id", ACCOUNT_SP_CLIENT_ID or "(ambient)",
     "Account-admin service principal client_id for OAuth M2M."),
    ("4d/4e. account secret", f"{ACCOUNT_SECRET_SCOPE}/{ACCOUNT_SECRET_KEY}" if ACCOUNT_SECRET_SCOPE else "(ambient)",
     "Secret scope+key holding the SP's OAuth secret (never hardcode it)."),
    ("5a. network_policy_id", NETWORK_POLICY_ID or "(unset)", "Target account network policy to update."),
    ("5b. apply_policy", APPLY_POLICY, "Master switch for the apply step (dry_run is the safe default mode)."),
    ("5c. create_missing_policy", CREATE_MISSING_POLICY,
     "If the target policy doesn't exist, create it (default true) vs require it to pre-exist."),
], columns=["widget", "value", "meaning"])
# The value column mixes int/bool/str; cast to string so display()'s Arrow conversion doesn't fail
# on the resulting object-dtype column.
_decisions["value"] = _decisions["value"].astype(str)
print(f"scoping: destination={SCOPE_DESTINATION} identity={SCOPE_IDENTITY} | "
      f"policy_mode={POLICY_MODE} -> {POLICY_MODE_TARGET}")
print(f"account_host: {ACCOUNT_HOST}")
print(f"account_id: {ACCOUNT_ID or '(unset — set widget 4a if you need identity scoping or apply)'}")
display(_decisions)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Egress FQDNs this notebook calls
# MAGIC
# MAGIC If you run this in an environment with **egress controls** (corporate proxy allow-list, or
# MAGIC **Databricks Serverless Egress Control / SEG**), these are the external hosts the notebook
# MAGIC needs to reach. Feeds you deselect (widget `2a`) or RDAP if you disable it (`2e`) aren't
# MAGIC called. The Databricks control-plane / SDK endpoints are reached over your normal workspace
# MAGIC connectivity and are not listed here.

# COMMAND ----------

# DBTITLE 1,Egress FQDN allow-list
_egress = pd.DataFrame([
    ("www.spamhaus.org", "Spamhaus DROP v4/v6 threat feed", "threat feed: spamhaus_drop"),
    ("check.torproject.org", "Tor exit-node list", "threat feed: tor_exit"),
    ("raw.githubusercontent.com", "FireHOL level1 + IPsum feeds (GitHub raw)", "threat feeds: firehol_level1, ipsum"),
    ("feeds.dshield.org", "SANS ISC DShield attacker subnets", "threat feed: dshield"),
    ("cinsscore.com", "CINS CI Army malicious-IP list", "threat feed: cins_ci_army"),
    ("ip-ranges.amazonaws.com", "AWS published IP ranges", "cloud ranges: aws"),
    ("www.gstatic.com", "GCP published IP ranges", "cloud ranges: gcp"),
    ("docs.oracle.com", "Oracle Cloud published IP ranges", "cloud ranges: oracle"),
    ("www.microsoft.com", "Azure Service Tags download page (URL discovery)", "cloud ranges: azure"),
    ("download.microsoft.com", "Azure Service Tags JSON", "cloud ranges: azure"),
    ("www.databricks.com", "Databricks published IP ranges (control plane / serverless)", "databricks ranges"),
    ("rdap.org", "RDAP bootstrap / owner lookup (redirects to RIR RDAP servers)", "enrichment: RDAP"),
    ("*.rir RDAP servers", "e.g. rdap.arin.net, rdap.db.ripe.net — followed from rdap.org referrals", "enrichment: RDAP"),
    ("pypi.org / files.pythonhosted.org", "pip install databricks-sdk", "SDK install (top of notebook)"),
], columns=["fqdn", "purpose", "used_by"])
print("Hosts this notebook may call out to (subject to your widget choices):")
display(_egress)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Account admin requirements
# MAGIC
# MAGIC The analysis and enrichment cells run under your normal workspace identity and need only read
# MAGIC access to `system.access.audit`. **Two operations are account-level and require an account
# MAGIC admin** — a notebook's default identity is a *workspace* identity and cannot perform them:
# MAGIC
# MAGIC | Operation | When it runs | Privilege needed |
# MAGIC |---|---|---|
# MAGIC | **Apply a CBI policy** (`network_policies.*_rpc`) | Only in the gated apply cell (`apply_policy=true`) | **Account admin** |
# MAGIC | **Resolve identities** (SCIM `users`/`service_principals` list) | Only when `scoping_mode` includes identity | **Account admin** (reads account identities) |
# MAGIC
# MAGIC So the account-admin credential is required if you (a) apply any policy, **or** (b) build an
# MAGIC **identity-scoped** policy. Pure analysis, or IP-only / destination-only proposals that you
# MAGIC don't apply from here, need nothing extra.
# MAGIC
# MAGIC **Recommended setup — an account-admin service principal via OAuth M2M:**
# MAGIC 1. Create a **service principal** and grant it the **account admin** role (Account console →
# MAGIC    User management → Service principals → Role).
# MAGIC 2. Generate an **OAuth secret** for it (client_id + secret).
# MAGIC 3. Store the secret in a Databricks **secret scope** — never hardcode it:
# MAGIC    `databricks secrets create-scope <scope>` then
# MAGIC    `databricks secrets put-secret <scope> <key>`.
# MAGIC 4. Set widgets **4a–4e**: `account_id`, `account_host`, the SP `client_id`, and the secret
# MAGIC    scope/key. `_account_client()` then authenticates as that SP.
# MAGIC
# MAGIC If widgets 4c–4e are left blank the notebook falls back to the runtime's **ambient** account
# MAGIC credentials (`AccountClient()`), which only works where the environment is already configured
# MAGIC for the account (e.g. an account-admin OAuth profile). A workspace PAT is **not** sufficient
# MAGIC for account-level calls.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Recent audit baseline
# MAGIC
# MAGIC The last `lookback_days` of `system.access.audit`, with source IPs normalised via
# MAGIC `try_ip_host` and tagged with IP version. This named result (`audit_recent`) is the common
# MAGIC input for every summary below.

# COMMAND ----------

# DBTITLE 1,audit_recent
audit_recent = spark.sql(
    f"""
    SELECT
      event_date,
      event_time,
      workspace_id,
      audit_level,
      service_name,
      action_name,
      COALESCE(user_identity.email, user_identity.subject_name, 'UNKNOWN') AS principal,
      user_identity.email AS principal_email,
      user_identity.subject_name AS subject_name,
      source_ip_address,
      try_ip_host(source_ip_address) AS normalized_ip,
      ip_version(try_ip_host(source_ip_address)) AS ip_version,
      user_agent,
      response.status_code AS status_code,
      session_id,
      request_id
    FROM system.access.audit
    WHERE event_date >= current_date() - INTERVAL {LOOKBACK_DAYS} DAYS
    """
)
audit_recent.createOrReplaceTempView("audit_recent")
print(f"audit_recent rows: {audit_recent.count():,}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Surface summary
# MAGIC
# MAGIC Event, principal, distinct-IP and session counts per `service_name` + `action_name`.

# COMMAND ----------

# DBTITLE 1,audit_surface_summary
# MAGIC %sql
# MAGIC SELECT
# MAGIC   service_name,
# MAGIC   action_name,
# MAGIC   COUNT(*) AS events,
# MAGIC   COUNT(DISTINCT principal) AS principals,
# MAGIC   COUNT(DISTINCT normalized_ip) AS distinct_ips,
# MAGIC   COUNT(DISTINCT session_id) AS sessions,
# MAGIC   MIN(event_time) AS first_seen,
# MAGIC   MAX(event_time) AS last_seen
# MAGIC FROM audit_recent
# MAGIC GROUP BY ALL
# MAGIC ORDER BY events DESC, principals DESC
# MAGIC LIMIT 100

# COMMAND ----------

# MAGIC %md
# MAGIC ## Network diversity by principal
# MAGIC
# MAGIC How spread-out each identity's source network is. `distinct_networks` counts distinct /24s
# MAGIC for IPv4 and /48s for IPv6, so both families contribute. High diversity flags roaming /
# MAGIC shared-egress identities that a per-IP allow-list will struggle to pin down.

# COMMAND ----------

# DBTITLE 1,principal_network_diversity
# MAGIC %sql
# MAGIC WITH principal_networks AS (
# MAGIC   SELECT
# MAGIC     principal,
# MAGIC     COUNT(*) AS events,
# MAGIC     COUNT(DISTINCT normalized_ip) AS distinct_ips,
# MAGIC     COUNT(DISTINCT CASE
# MAGIC       WHEN ip_version = 4 THEN try_ip_cidr(CONCAT(normalized_ip, '/24'))
# MAGIC       WHEN ip_version = 6 THEN try_ip_cidr(CONCAT(normalized_ip, '/48'))
# MAGIC     END) AS distinct_networks,
# MAGIC     COUNT(DISTINCT user_agent) AS distinct_user_agents,
# MAGIC     COUNT(DISTINCT service_name) AS distinct_services,
# MAGIC     MIN(event_time) AS first_seen,
# MAGIC     MAX(event_time) AS last_seen
# MAGIC   FROM audit_recent
# MAGIC   WHERE normalized_ip IS NOT NULL
# MAGIC   GROUP BY principal
# MAGIC )
# MAGIC SELECT *
# MAGIC FROM principal_networks
# MAGIC ORDER BY distinct_networks DESC, distinct_ips DESC, events DESC
# MAGIC LIMIT 100

# COMMAND ----------

# MAGIC %md
# MAGIC ## Frequent public source IPs
# MAGIC
# MAGIC The candidate set: **public** source IPs (private, loopback, link-local, CGNAT and
# MAGIC documentation ranges excluded) carrying **successful** traffic, aggregated per IP and
# MAGIC thresholded at `min_events`. Also collects, per IP, the principals and services observed —
# MAGIC the raw material for identity and destination scoping later.

# COMMAND ----------

# DBTITLE 1,frequent_public_ips
_ipv6_predicate = "OR ip_version = 6" if INCLUDE_IPV6 else ""
# workspace_id = 0 is account-level access; exclude unless the user opts in (we build workspace
# network policies). Kept as an explicit, visible predicate.
_account_level_predicate = "" if INCLUDE_ACCOUNT_LEVEL else "AND workspace_id <> 0"

frequent_public_ips = spark.sql(
    f"""
    WITH successful AS (
      SELECT
        workspace_id,
        principal, principal_email, subject_name,
        service_name, action_name,
        normalized_ip AS public_ip, ip_version,
        event_date, session_id
      FROM audit_recent
      WHERE normalized_ip IS NOT NULL
        AND (ip_version = 4 {_ipv6_predicate})
        AND (status_code < 400 OR (status_code IS NULL AND {_null_status_ok}))
        {_account_level_predicate}
        AND NOT (
          ip_version = 4 AND (
            ip_cidr_contains('10.0.0.0/8', normalized_ip)
            OR ip_cidr_contains('172.16.0.0/12', normalized_ip)
            OR ip_cidr_contains('192.168.0.0/16', normalized_ip)
            OR ip_cidr_contains('127.0.0.0/8', normalized_ip)
            OR ip_cidr_contains('169.254.0.0/16', normalized_ip)
            OR ip_cidr_contains('100.64.0.0/10', normalized_ip)
            OR ip_cidr_contains('192.0.2.0/24', normalized_ip)
            OR ip_cidr_contains('198.18.0.0/15', normalized_ip)
            OR ip_cidr_contains('198.51.100.0/24', normalized_ip)
            OR ip_cidr_contains('203.0.113.0/24', normalized_ip)
            OR normalized_ip = '0.0.0.0'
          )
        )
    )
    SELECT
      public_ip,
      ANY_VALUE(ip_version) AS ip_version,
      COUNT(*) AS events,
      COUNT(DISTINCT principal) AS principals,
      COUNT(DISTINCT service_name) AS services,
      COUNT(DISTINCT action_name) AS actions,
      COUNT(DISTINCT event_date) AS active_days,
      COUNT(DISTINCT session_id) AS sessions,
      MIN(event_date) AS first_active_date,
      MAX(event_date) AS last_active_date,
      sort_array(collect_set(principal)) AS principal_list,
      sort_array(collect_set(principal_email)) AS principal_emails,
      sort_array(collect_set(subject_name)) AS subject_names,
      sort_array(collect_set(service_name)) AS service_list,
      sort_array(collect_set(workspace_id)) AS workspace_ids
    FROM successful
    GROUP BY public_ip
    HAVING COUNT(*) >= {MIN_EVENTS}
    ORDER BY events DESC, principals DESC
    """
)
frequent_public_ips.createOrReplaceTempView("frequent_public_ips")
print(f"candidate public IPs (>= {MIN_EVENTS} events): {frequent_public_ips.count():,}")
display(frequent_public_ips)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Enrichment feeds — shared helpers
# MAGIC
# MAGIC Dependency-free helpers to download open threat-intel and cloud-provider IP range feeds and
# MAGIC materialise them as Delta tables (or temp views when no schema is set). All feeds are free,
# MAGIC need no API key, and permit internal use.

# COMMAND ----------

# DBTITLE 1,Feed download helpers
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FEED_TIMEOUT_SECONDS = 30
FEED_USER_AGENT = "Databricks-CBI-Helper"


def _http_get(url, as_json=False):
    """GET a URL with a short retry, returning text or parsed JSON. Returns None on failure."""
    delay, last_error = 1.0, None
    for attempt in range(1, 4):
        try:
            request = Request(url, headers={"User-Agent": FEED_USER_AGENT, "Accept": "*/*"})
            with urlopen(request, timeout=FEED_TIMEOUT_SECONDS) as response:
                raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw) if as_json else raw
        except (HTTPError, URLError, TimeoutError) as error:
            last_error = error
            if attempt < 3:
                time.sleep(delay)
                delay *= 2
    print(f"  ! feed fetch failed for {url}: {last_error}")
    return None


def _valid_cidr(value, want_version=None):
    """Return a normalised CIDR string if `value` parses as a network, else None."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, AttributeError):
        return None
    if want_version and net.version != want_version:
        return None
    return str(net)


def _materialize(rows, columns, name):
    """Persist rows as a Delta table under the enrichment schema, or a temp view otherwise.
    Returns the fully-qualified name/view used for querying."""
    df = spark.createDataFrame(rows, schema=columns) if rows else spark.createDataFrame([], schema=columns)
    if PERSIST_ENRICHMENT:
        try:
            spark.sql(f"CREATE CATALOG IF NOT EXISTS {ENRICHMENT_CATALOG}")
        except Exception:
            pass  # Catalog already exists or workspace requires managed location
        spark.sql(f"CREATE SCHEMA IF NOT EXISTS {ENRICHMENT_CATALOG}.{ENRICHMENT_SCHEMA}")
        target = f"{ENRICHMENT_PREFIX}{name}"
        df.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(target)
        print(f"  wrote {df.count():,} rows -> {target}")
        return target
    df.createOrReplaceTempView(name)
    print(f"  registered temp view {name} ({df.count():,} rows)")
    return name


def _table_exists(name):
    return spark.catalog.tableExists(f"{ENRICHMENT_PREFIX}{name}") if PERSIST_ENRICHMENT else False

# COMMAND ----------

# MAGIC %md
# MAGIC ### Threat-intelligence ranges (`threat_intel_ips`)
# MAGIC
# MAGIC Unions the feeds selected in widget `2a` into `(cidr, source_feed, threat_type, confidence,
# MAGIC source_url, loaded_at)`. `confidence` 1 = high, 2 = medium. `source_url` traces each row.
# MAGIC
# MAGIC | Feed | Represents | Grain | License |
# MAGIC |---|---|---|---|
# MAGIC | **Spamhaus DROP** (v4/v6) | hijacked / botnet C2 ranges | CIDR | free, attribution |
# MAGIC | **Tor exit list** | anonymiser infrastructure | IP | public |
# MAGIC | **FireHOL level1** | conservative blocklist aggregation | CIDR | public-domain philosophy |
# MAGIC | **IPsum** | 30+ feed aggregation; kept where seen on ≥3 lists, conf 1 at ≥5 | IP | Unlicense |
# MAGIC | **DShield** (SANS ISC) | top attacking /24 subnets | /24 CIDR | free/public |
# MAGIC | **CINS CI Army** | poorly-rated IPs, gap-filler | IP | free public use |
# MAGIC
# MAGIC To add a feed: write a `_feed_*` loader, register it in `THREAT_FEED_LOADERS`, and add its
# MAGIC key to `ALL_THREAT_FEEDS` at the top.

# COMMAND ----------

# DBTITLE 1,Refresh threat_intel_ips
THREAT_INTEL_COLUMNS = (
    "cidr STRING, source_feed STRING, threat_type STRING, confidence INT, "
    "source_url STRING, loaded_at TIMESTAMP"
)
_threat_table_name = "threat_intel_ips"

SPAMHAUS_DROP_V4_URL = "https://www.spamhaus.org/drop/drop_v4.json"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.json"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
FIREHOL_LEVEL1_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"
CINS_CI_ARMY_URL = "https://cinsscore.com/list/ci-badguys.txt"

IPSUM_MIN_LISTS = 3
IPSUM_HIGH_CONFIDENCE_LISTS = 5


def _feed_spamhaus_drop(now):
    rows = []
    for url, ver in [(SPAMHAUS_DROP_V4_URL, 4), (SPAMHAUS_DROP_V6_URL, 6)]:
        text = _http_get(url)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            cidr = _valid_cidr(obj.get("cidr", ""), want_version=ver)
            if cidr:
                rows.append((cidr, "spamhaus_drop", "botnet_c2", 1, url, now))
    return rows


def _feed_tor_exit(now):
    rows = []
    text = _http_get(TOR_EXIT_URL)
    if text:
        for line in text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            cidr = _valid_cidr(f"{ip}/32" if ":" not in ip else f"{ip}/128")
            if cidr:
                rows.append((cidr, "tor_exit", "anonymizer", 2, TOR_EXIT_URL, now))
    return rows


def _feed_firehol_level1(now):
    rows = []
    text = _http_get(FIREHOL_LEVEL1_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cidr = _valid_cidr(line)
            if cidr:
                rows.append((cidr, "firehol_level1", "aggregated_blocklist", 1, FIREHOL_LEVEL1_URL, now))
    return rows


def _feed_ipsum(now):
    rows = []
    text = _http_get(IPSUM_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            count = int(parts[1])
            if count < IPSUM_MIN_LISTS:
                continue
            cidr = _valid_cidr(f"{parts[0]}/32", want_version=4)
            if cidr:
                confidence = 1 if count >= IPSUM_HIGH_CONFIDENCE_LISTS else 2
                rows.append((cidr, "ipsum", "aggregated_blocklist", confidence, IPSUM_URL, now))
    return rows


def _feed_dshield(now):
    rows = []
    text = _http_get(DSHIELD_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2].isdigit():
                continue
            cidr = _valid_cidr(f"{parts[0]}/{parts[2]}", want_version=4)
            if cidr:
                rows.append((cidr, "dshield", "attacker_subnet", 1, DSHIELD_URL, now))
    return rows


def _feed_cins_ci_army(now):
    rows = []
    text = _http_get(CINS_CI_ARMY_URL)
    if text:
        for line in text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            cidr = _valid_cidr(f"{ip}/32", want_version=4)
            if cidr:
                rows.append((cidr, "cins_ci_army", "malicious_host", 2, CINS_CI_ARMY_URL, now))
    return rows


THREAT_FEED_LOADERS = {
    "spamhaus_drop": _feed_spamhaus_drop,
    "tor_exit": _feed_tor_exit,
    "firehol_level1": _feed_firehol_level1,
    "ipsum": _feed_ipsum,
    "dshield": _feed_dshield,
    "cins_ci_army": _feed_cins_ci_army,
}


def _load_threat_intel(selected_feeds):
    now = datetime.now(timezone.utc)
    rows = []
    for feed in selected_feeds:
        loader = THREAT_FEED_LOADERS.get(feed)
        if not loader:
            continue
        feed_rows = loader(now)
        print(f"  {feed}: {len(feed_rows):,} rows")
        rows.extend(feed_rows)
    seen, deduped = set(), []
    for row in rows:
        key = (row[0], row[1])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    return deduped


if REFRESH_ENRICHMENT or not _table_exists(_threat_table_name):
    print(f"Refreshing threat_intel_ips from feeds: {', '.join(SELECTED_THREAT_FEEDS) or '(none)'}")
    threat_ref = _materialize(_load_threat_intel(SELECTED_THREAT_FEEDS), THREAT_INTEL_COLUMNS, _threat_table_name)
else:
    threat_ref = f"{ENRICHMENT_PREFIX}{_threat_table_name}"
    print(f"Using existing {threat_ref}")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Cloud-provider ranges (`cloud_provider_ranges`)
# MAGIC
# MAGIC Authoritative published IP ranges for the major clouds. An observed IP inside one of these is
# MAGIC cloud-hosted egress — useful context, and a signal not to allow-list a whole provider block.
# MAGIC All sources are the providers' **official** feeds (Azure Service Tags is resolved by scraping
# MAGIC Microsoft's official download page for the current dated JSON).

# COMMAND ----------

# DBTITLE 1,Refresh cloud_provider_ranges
CLOUD_COLUMNS = "cidr STRING, provider STRING, service STRING, region STRING, loaded_at TIMESTAMP"
_cloud_table_name = "cloud_provider_ranges"


def _load_cloud_ranges():
    now = datetime.now(timezone.utc)
    rows = []

    aws = _http_get("https://ip-ranges.amazonaws.com/ip-ranges.json", as_json=True)
    if aws:
        for p in aws.get("prefixes", []):
            cidr = _valid_cidr(p.get("ip_prefix", ""), want_version=4)
            if cidr:
                rows.append((cidr, "aws", p.get("service"), p.get("region"), now))
        for p in aws.get("ipv6_prefixes", []):
            cidr = _valid_cidr(p.get("ipv6_prefix", ""), want_version=6)
            if cidr:
                rows.append((cidr, "aws", p.get("service"), p.get("region"), now))

    gcp = _http_get("https://www.gstatic.com/ipranges/cloud.json", as_json=True)
    if gcp:
        for p in gcp.get("prefixes", []):
            cidr = _valid_cidr(p.get("ipv4Prefix") or p.get("ipv6Prefix") or "")
            if cidr:
                rows.append((cidr, "gcp", p.get("service"), p.get("scope"), now))

    oci = _http_get("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", as_json=True)
    if oci:
        for region in oci.get("regions", []):
            rname = region.get("region")
            for cidr_obj in region.get("cidrs", []):
                cidr = _valid_cidr(cidr_obj.get("cidr", ""))
                if cidr:
                    rows.append((cidr, "oracle", ",".join(cidr_obj.get("tags", []) or []), rname, now))

    # Azure Service Tags — scrape Microsoft's official download page for the current dated JSON.
    azure_json = None
    conf_page = _http_get("https://www.microsoft.com/en-us/download/details.aspx?id=56519")
    if conf_page:
        matches = re.findall(
            r"https://download\.microsoft\.com/download/[^\"']*ServiceTags_Public_\d+\.json", conf_page
        )
        if matches:
            azure_json = _http_get(sorted(set(matches))[-1], as_json=True)
    if azure_json:
        for v in azure_json.get("values", []):
            props = v.get("properties", {})
            for cidr_raw in props.get("addressPrefixes", []):
                cidr = _valid_cidr(cidr_raw)
                if cidr:
                    rows.append((cidr, "azure", props.get("systemService"), props.get("region"), now))
    else:
        print("  ! Azure Service Tags unavailable this run — continuing without them")

    seen, deduped = set(), []
    for row in rows:
        key = (row[0], row[1])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    return deduped


if REFRESH_ENRICHMENT or not _table_exists(_cloud_table_name):
    print("Refreshing cloud_provider_ranges ...")
    cloud_ref = _materialize(_load_cloud_ranges(), CLOUD_COLUMNS, _cloud_table_name)
else:
    cloud_ref = f"{ENRICHMENT_PREFIX}{_cloud_table_name}"
    print(f"Using existing {cloud_ref}")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Databricks-owned ranges (`databricks_ranges`)
# MAGIC
# MAGIC Databricks' **own** control-plane / serverless / storage IPs also appear as source IPs in the
# MAGIC audit log (the platform reaching into the workspace). Those are not a customer network to
# MAGIC allow-list, so we flag them and exclude such groups from the proposal.
# MAGIC
# MAGIC Source: the official machine-readable feed `databricks.com/networking/v1/ip-ranges.json`
# MAGIC (covers AWS, Azure and GCP; includes control-plane inbound + storage/ingestion ranges — the
# MAGIC same CIDRs published per-region at `docs.databricks.com/.../resources/ip-domain-region`). We
# MAGIC keep `region` and `direction` (inbound/outbound) for context. SCC-relay *FQDNs* are not in the
# MAGIC feed, but those matter for customer egress allow-listing, not our ingress source-IP analysis.

# COMMAND ----------

# DBTITLE 1,Refresh databricks_ranges
DATABRICKS_COLUMNS = "cidr STRING, platform STRING, region STRING, direction STRING, loaded_at TIMESTAMP"
_databricks_table_name = "databricks_ranges"
DATABRICKS_IP_RANGES_URL = "https://www.databricks.com/networking/v1/ip-ranges.json"


def _load_databricks_ranges():
    now = datetime.now(timezone.utc)
    rows = []
    data = _http_get(DATABRICKS_IP_RANGES_URL, as_json=True)
    if not data:
        print("  ! Databricks IP ranges unavailable this run — continuing without them")
        return rows
    for entry in data.get("prefixes", []):
        platform = entry.get("platform")
        region = entry.get("region")
        direction = entry.get("type")  # inbound | outbound
        for cidr_raw in (entry.get("ipv4Prefixes", []) + entry.get("ipv6Prefixes", [])):
            cidr = _valid_cidr(cidr_raw)
            if cidr:
                rows.append((cidr, platform, region, direction, now))
    seen, deduped = set(), []
    for row in rows:
        # de-dupe on (cidr, direction) — the same CIDR can appear across regions
        key = (row[0], row[3])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    return deduped


if REFRESH_ENRICHMENT or not _table_exists(_databricks_table_name):
    print("Refreshing databricks_ranges ...")
    databricks_ref = _materialize(_load_databricks_ranges(), DATABRICKS_COLUMNS, _databricks_table_name)
else:
    databricks_ref = f"{ENRICHMENT_PREFIX}{_databricks_table_name}"
    print(f"Using existing {databricks_ref}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## RDAP owner lookup (deduplicated, optional)
# MAGIC
# MAGIC For each **distinct** candidate IP we query RDAP once to recover the registered owner and the
# MAGIC full assigned range (the `maximum` framing). Deduplicating to one lookup per IP keeps this
# MAGIC fast. Controlled by widget `2e` (`enable_rdap`); when off, grouping falls back to the /24 (v4)
# MAGIC or /48 (v6) and the `maximum` framing is unavailable.

# COMMAND ----------

# DBTITLE 1,RDAP lookup helpers
from http.client import RemoteDisconnected

RDAP_TIMEOUT_SECONDS = 8
RDAP_MAX_RETRIES = 2
RDAP_MAX_REFERRAL_DEPTH = 3
RDAP_DELAY_SECONDS = 0.1


def _extract_entity_names(entities):
    names = []
    for entity in entities or []:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for field in vcard[1]:
                if len(field) >= 4 and field[0] == "fn" and field[3]:
                    names.append(field[3])
    return sorted(set(names))


def _rdap_should_retry(error):
    if isinstance(error, HTTPError):
        return error.code in {408, 425, 429, 500, 502, 503, 504}
    if isinstance(error, (TimeoutError, RemoteDisconnected)):
        return True
    if isinstance(error, URLError):
        reason = str(error.reason).lower()
        return any(p in reason for p in ["timed out", "timeout", "temporarily unavailable",
                                         "connection reset", "connection aborted",
                                         "connection refused", "remote end closed connection"])
    return any(p in str(error).lower() for p in ["timed out", "timeout",
                                                 "remote end closed connection", "temporarily unavailable"])


def _maximum_cidrs(start_ip, end_ip):
    if not start_ip or not end_ip:
        return None
    try:
        nets = list(ipaddress.summarize_address_range(
            ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)))
        return [str(n) for n in nets]
    except (ValueError, TypeError):
        return None


def _fetch_rdap(url):
    delay, last_error = 1.0, None
    for attempt in range(1, RDAP_MAX_RETRIES + 1):
        request = Request(url, headers={"Accept": "application/rdap+json, application/json",
                                        "User-Agent": FEED_USER_AGENT})
        try:
            with urlopen(request, timeout=RDAP_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8")), response.geturl(), None
        except Exception as error:  # noqa: BLE001 - urllib raises a wide range
            last_error = error
            if attempt < RDAP_MAX_RETRIES and _rdap_should_retry(error):
                time.sleep(delay)
                delay *= 2
                continue
            return None, url, error
    return None, url, last_error


def _rdap_referrals(payload, ip_address, current_url):
    urls = []
    for link in payload.get("links") or []:
        href = link.get("href")
        rel = (link.get("rel") or "").lower()
        media = (link.get("type") or "").lower()
        if not href or href == current_url:
            continue
        if media and "json" not in media and "rdap" not in media:
            continue
        if f"/ip/{ip_address}" in href or "type=ip" in href or rel in {"related", "alternate", "up"}:
            if href not in urls:
                urls.append(href)
    return urls


def rdap_lookup(ip_address):
    """Return {rdap_owner_name, rdap_type, maximum_cidrs} for an IP, following referrals."""
    empty = {"rdap_owner_name": None, "rdap_type": None, "maximum_cidrs": None}
    pending, visited, best = [f"https://rdap.org/ip/{ip_address}"], set(), empty
    while pending and len(visited) <= RDAP_MAX_REFERRAL_DEPTH:
        url = pending.pop(0)
        if url in visited:
            continue
        visited.add(url)
        payload, final_url, _ = _fetch_rdap(url)
        if payload is None:
            continue
        names = _extract_entity_names(payload.get("entities"))
        result = {
            "rdap_owner_name": names[0] if names else payload.get("name") or payload.get("handle"),
            "rdap_type": payload.get("type"),
            "maximum_cidrs": _maximum_cidrs(payload.get("startAddress"), payload.get("endAddress")),
        }
        if any(result.values()):
            return result
        best = result
        for ref in _rdap_referrals(payload, ip_address, final_url):
            if ref not in visited and ref not in pending:
                pending.append(ref)
    return best if any(best.values()) else empty

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build annotated CIDR suggestions
# MAGIC
# MAGIC Pulls the (already thresholded) candidate IPs to the driver, optionally runs one RDAP lookup
# MAGIC per IP, tests each IP for threat-intel and cloud-range membership, maps observed services to
# MAGIC CBI **destinations** (conservatively), and groups IPs by RDAP owner. Each group carries its
# MAGIC CIDR framings plus the principals and destinations seen — the inputs to scoped rules.

# COMMAND ----------

# DBTITLE 1,Compute suggestions
from collections import defaultdict


def _load_ranges(ref, extra_cols):
    pdf = spark.table(ref).toPandas()
    parsed = []
    for _, r in pdf.iterrows():
        try:
            net = ipaddress.ip_network(r["cidr"], strict=False)
        except ValueError:
            continue
        parsed.append((net, {c: r.get(c) for c in extra_cols}))
    return parsed


threat_ranges = _load_ranges(threat_ref, ["source_feed", "threat_type", "confidence", "source_url"])
cloud_ranges = _load_ranges(cloud_ref, ["provider", "service", "region"])
databricks_ranges = _load_ranges(databricks_ref, ["platform", "region", "direction"])
print(f"loaded {len(threat_ranges):,} threat ranges, {len(cloud_ranges):,} cloud ranges, "
      f"{len(databricks_ranges):,} Databricks ranges")


def _match_ranges(ip_obj, ranges):
    metas, cidrs = [], []
    for net, meta in ranges:
        if ip_obj.version == net.version and ip_obj in net:
            metas.append(meta)
            cidrs.append(str(net))
    return metas, cidrs


# Conservative audit service_name -> CBI destination category. Only clearly-identifiable
# destinations are mapped; anything else contributes "other", which forces all_destinations.
def _service_to_destination(service_name):
    s = (service_name or "").lower()
    if "apps" in s:
        return "apps_runtime"
    if "lakebase" in s or "database" in s:
        return "lakebase_runtime"
    return "other"


candidates_pdf = frequent_public_ips.toPandas()


def _as_list(value):
    """Coerce a record field to a plain Python list. Spark array<> columns come back from toPandas()
    as numpy arrays, whose truthiness is ambiguous — so `arr or []` raises. Handle None/NaN, numpy
    arrays and lists uniformly, dropping null/empty entries."""
    if value is None:
        return []
    if hasattr(value, "tolist"):  # numpy array
        value = value.tolist()
    elif not isinstance(value, (list, tuple)):
        # scalar NaN (float) or a lone string
        try:
            if pd.isna(value):
                return []
        except (TypeError, ValueError):
            pass
        value = [value]
    return [v for v in value if v is not None and v != ""]


rdap_cache = {}
enriched = []
threat_match_rows = []
for record in candidates_pdf.to_dict(orient="records"):
    ip_str = record["public_ip"]
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        continue

    if ENABLE_RDAP:
        if ip_str not in rdap_cache:
            rdap_cache[ip_str] = rdap_lookup(ip_str)
            time.sleep(RDAP_DELAY_SECONDS)
        rdap = rdap_cache[ip_str]
    else:
        rdap = {"rdap_owner_name": None, "rdap_type": None, "maximum_cidrs": None}

    # Normalise Spark array<> columns (numpy arrays after toPandas) to plain lists up front.
    record["principal_list"] = _as_list(record.get("principal_list"))
    record["principal_emails"] = _as_list(record.get("principal_emails"))
    record["subject_names"] = _as_list(record.get("subject_names"))
    record["workspace_ids"] = [int(w) for w in _as_list(record.get("workspace_ids"))]

    threat_hits, threat_cidrs = _match_ranges(ip_obj, threat_ranges)
    cloud_hits, _ = _match_ranges(ip_obj, cloud_ranges)
    databricks_hits, _ = _match_ranges(ip_obj, databricks_ranges)
    for meta, matched_cidr in zip(threat_hits, threat_cidrs):
        threat_match_rows.append({
            "observed_ip": ip_str, "matched_cidr": matched_cidr,
            "source_feed": meta["source_feed"], "threat_type": meta["threat_type"],
            "confidence": meta["confidence"], "source_url": meta.get("source_url"),
            "events": record["events"], "principals": record["principals"],
            "principal_list": record["principal_list"],
            "first_active_date": record.get("first_active_date"),
            "last_active_date": record.get("last_active_date"),
        })

    destinations = sorted({_service_to_destination(s) for s in _as_list(record.get("service_list"))})
    record.update({
        "ip_obj": ip_obj,
        "rdap_owner_name": rdap["rdap_owner_name"],
        "rdap_type": rdap["rdap_type"],
        "maximum_cidrs": rdap["maximum_cidrs"],
        "destinations": destinations,
        "threat_feeds": sorted({h["source_feed"] for h in threat_hits}),
        "threat_types": sorted({h["threat_type"] for h in threat_hits}),
        "threat_confidence": min([h["confidence"] for h in threat_hits], default=None),
        "cloud_provider": sorted({h["provider"] for h in cloud_hits}),
        "databricks_owned": sorted({h["platform"] for h in databricks_hits}),
    })
    enriched.append(record)


ALL_WORKSPACES = "__ALL__"  # policy_target sentinel for a single account-wide policy


def _fallback_group_key(rec):
    if rec["ip_obj"].version == 4:
        return str(ipaddress.ip_network(f"{rec['public_ip']}/24", strict=False))
    return str(ipaddress.ip_network(f"{rec['public_ip']}/48", strict=False))


# Group by (policy_target, rdap_owner). policy_target is ALL_WORKSPACES for single scope, else the
# workspace_id (each IP fans out to every workspace it was seen in). This lets per_workspace produce
# a tailored policy per workspace while single collapses everything to one.
groups = defaultdict(list)
for rec in enriched:
    owner = rec["rdap_owner_name"] or _fallback_group_key(rec)
    if POLICY_SCOPE == "per_workspace":
        targets = rec["workspace_ids"] or [ALL_WORKSPACES]
    else:
        targets = [ALL_WORKSPACES]
    for tgt in targets:
        groups[(tgt, owner)].append(rec)


def _collapse_destinations(dest_sets):
    """A group can be scoped to a single clean destination only if every IP in it maps to the
    same clearly-identifiable destination. Any 'other', or a mix, means all_destinations."""
    flat = {d for ds in dest_sets for d in ds}
    if flat and flat <= {"apps_runtime"}:
        return "apps_runtime"
    if flat and flat <= {"lakebase_runtime"}:
        return "lakebase_runtime"
    return "all_destinations"


suggestion_rows = []
for (policy_target, owner), recs in groups.items():
    ip_objs = [r["ip_obj"] for r in recs]
    minimal = [f"{ip}/{ip.max_prefixlen}" for ip in sorted(set(ip_objs), key=int)]
    optimal = [str(n) for n in ipaddress.collapse_addresses(sorted(set(ip_objs), key=int))]
    maximum = sorted({c for r in recs if r["maximum_cidrs"] for c in r["maximum_cidrs"]})
    threat_feeds = sorted({f for r in recs for f in r["threat_feeds"]})
    cloud_providers = sorted({p for r in recs for p in r["cloud_provider"]})
    databricks_owned = sorted({p for r in recs for p in r.get("databricks_owned", [])})
    principals = sorted({p for r in recs for p in r["principal_list"]})
    principal_emails = sorted({e for r in recs for e in (r.get("principal_emails") or []) if e})
    subject_names = sorted({sn for r in recs for sn in (r.get("subject_names") or []) if sn})
    scoped_destination = _collapse_destinations([set(r["destinations"]) for r in recs])
    suggestion_rows.append({
        "policy_target": policy_target,
        "rdap_owner": owner,
        "distinct_ips": len(set(ip_objs)),
        "total_events": sum(r["events"] for r in recs),
        "principals": principals,
        "principal_emails": principal_emails,
        "subject_names": subject_names,
        "scoped_destination": scoped_destination,
        "minimal_cidrs": minimal,
        "optimal_cidrs": optimal,
        "maximum_cidrs": maximum or None,
        "threat_feeds": threat_feeds or None,
        "cloud_provider": cloud_providers or None,
        "databricks_owned": databricks_owned or None,
        # Databricks-owned takes precedence: those IPs are the platform and must be ALLOWED (else an
        # enforced policy locks the control plane out), overriding any cloud-provider flag.
        "recommendation": (
            "ALLOW — Databricks-owned" if databricks_owned else
            "REVIEW — known-bad range" if threat_feeds else
            "REVIEW — cloud-owned range" if cloud_providers else
            "candidate"
        ),
    })

suggestions_pdf = pd.DataFrame(suggestion_rows).sort_values(
    ["policy_target", "recommendation", "total_events"], ascending=[True, True, False]
) if suggestion_rows else pd.DataFrame()
if suggestions_pdf.empty:
    print("No candidate IP groups produced suggestions — check the candidate set / thresholds above.")
else:
    display(suggestions_pdf)

# COMMAND ----------

# MAGIC %md
# MAGIC ## ⚠️ Threat-intelligence matches
# MAGIC
# MAGIC The most security-relevant output: **observed source IPs that fell inside a known-bad or
# MAGIC anonymiser range.** Each row names the matched CIDR, feed and `source_url`. These warrant
# MAGIC investigation regardless of the allow-list (traffic from a flagged IP already reaching the
# MAGIC workspace may mean a compromised identity). Flagged groups (threat-intel or cloud-owned) are
# MAGIC **always** excluded from the proposed rules.

# COMMAND ----------

# DBTITLE 1,Threat-intelligence matches among observed IPs
threat_matches_pdf = (
    pd.DataFrame(threat_match_rows).sort_values(["confidence", "events"], ascending=[True, False])
    if threat_match_rows else pd.DataFrame()
)
if threat_matches_pdf.empty:
    # A column-less empty DataFrame can't be display()'d (CANNOT_INFER_EMPTY_SCHEMA), so just note it.
    print("✅ No observed source IPs matched any threat-intelligence feed.")
else:
    n_ips = threat_matches_pdf["observed_ip"].nunique()
    feeds = ", ".join(sorted(threat_matches_pdf["source_feed"].unique()))
    print(f"⚠️  {n_ips} observed IP(s) matched threat intel across feed(s): {feeds}.\n"
          f"    Review these regardless of the allow-list — traffic from a flagged IP that already\n"
          f"    reached the workspace may indicate a compromised identity.")
    display(threat_matches_pdf)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Resolve identities (SCIM) — only when identity scoping is on
# MAGIC
# MAGIC The CBI `authentication` block needs a **numeric `principal_id`**, but the audit log only has
# MAGIC emails / usernames. When `scoping_mode` includes identity, we resolve each group's principals
# MAGIC to account principal IDs via the account SCIM API (`AccountClient.users` /
# MAGIC `service_principals`). Unresolved principals (deleted, renamed, group members) are dropped
# MAGIC with a warning — a rule is only as tight as the identities that resolve.
# MAGIC
# MAGIC > Groups are **not** supported by the CBI schema — only individual users and service
# MAGIC > principals (`PRINCIPAL_TYPE_USER` / `PRINCIPAL_TYPE_SERVICE_PRINCIPAL`).

# COMMAND ----------

# DBTITLE 1,Resolve principals to numeric IDs
identity_resolution = {}  # principal string -> {"principal_id": int, "principal_type": "USER"|"SERVICE_PRINCIPAL"}
unresolved_principals = set()

if SCOPE_IDENTITY:
    _acct = _account_client()  # account admin required — see "Account admin requirements" above

    def _resolve_user(email):
        if not email:
            return None
        try:
            for u in _acct.users.list(filter=f'userName eq "{email}"', count=1):
                if u.id:
                    return int(u.id)
        except Exception as e:  # noqa: BLE001
            print(f"  ! user lookup failed for {email}: {e}")
        return None

    def _resolve_sp(app_or_name):
        if not app_or_name:
            return None
        try:
            for sp in _acct.service_principals.list(filter=f'applicationId eq "{app_or_name}"', count=1):
                if sp.id:
                    return int(sp.id)
        except Exception as e:  # noqa: BLE001
            print(f"  ! SP lookup failed for {app_or_name}: {e}")
        return None

    # Collect the distinct principals across all groups and resolve each once.
    _all_emails = {e for row in suggestion_rows for e in row["principal_emails"]}
    _all_subjects = {s for row in suggestion_rows for s in row["subject_names"]}
    for email in _all_emails:
        pid = _resolve_user(email)
        if pid is not None:
            identity_resolution[email] = {"principal_id": pid, "principal_type": "USER"}
        else:
            unresolved_principals.add(email)
    for subj in _all_subjects:
        # subject_name is typically the SP application id for service principals
        pid = _resolve_sp(subj)
        if pid is not None:
            identity_resolution[subj] = {"principal_id": pid, "principal_type": "SERVICE_PRINCIPAL"}
        else:
            unresolved_principals.add(subj)

    print(f"Resolved {len(identity_resolution)} principal(s); {len(unresolved_principals)} unresolved.")
    if unresolved_principals:
        print("  Unresolved (will be omitted from identity scoping):")
        for p in sorted(unresolved_principals):
            print(f"    - {p}")
else:
    print("Identity scoping off — skipping SCIM resolution.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build proposed rules
# MAGIC
# MAGIC Turns each surviving group into a `PublicIngressRule` (its own `origin` CIDRs, plus
# MAGIC `destination` and/or `authentication` per `scoping_mode`). `ip_only` reproduces the original
# MAGIC behaviour: one rule, all destinations, all identities. IPv6 CIDRs are dropped (CBI is IPv4-only).

# COMMAND ----------

# DBTITLE 1,Assemble rule specs (per policy target, with limit enforcement)
_framing_col = {"minimal": "minimal_cidrs", "optimal": "optimal_cidrs", "maximum": "maximum_cidrs"}[POLICY_FRAMING]

# Build allow rule specs grouped by policy_target (ALL_WORKSPACES for single scope, else workspace_id).
target_specs = defaultdict(list)   # policy_target -> [allow spec, ...]
skipped_ipv6 = 0
excluded_flagged = 0
if not suggestions_pdf.empty:
    for _, row in suggestions_pdf.iterrows():
        # Databricks-owned groups are ALWAYS included (auto-allowed) and take precedence — they are
        # the platform reaching in; excluding them would lock the control plane out under an enforced
        # policy. Otherwise, threat-intel / cloud-provider-owned groups are always excluded.
        if not row["databricks_owned"] and (row["threat_feeds"] or row["cloud_provider"]):
            excluded_flagged += 1
            continue
        ipv4_cidrs = []
        for cidr in (row[_framing_col] or []):
            try:
                if ipaddress.ip_network(cidr, strict=False).version != 4:
                    skipped_ipv6 += 1
                    continue
            except ValueError:
                continue
            ipv4_cidrs.append(cidr)
        if not ipv4_cidrs:
            continue

        _label_base = "cbi-helper-databricks" if row["databricks_owned"] else f"cbi-helper-{row['rdap_owner']}"
        spec = {
            "label": _label_base[:250],
            "cidrs": ipv4_cidrs,
            # Databricks-owned control-plane must reach everything, so never destination/identity-scope it.
            "destination": row["scoped_destination"] if (SCOPE_DESTINATION and not row["databricks_owned"]) else "all_destinations",
            "identity_type": "ALL_USERS",
            "identities": [],
        }
        if SCOPE_IDENTITY and not row["databricks_owned"]:
            resolved = []
            for p in (row["principal_emails"] + row["subject_names"]):
                if p in identity_resolution:
                    resolved.append(identity_resolution[p])
            seen, deduped = set(), []
            for r in resolved:
                key = (r["principal_id"], r["principal_type"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(r)
            if deduped:
                spec["identity_type"] = "SELECTED_IDENTITIES"
                spec["identities"] = deduped
            else:
                spec["label"] += " [identity-unresolved]"
        target_specs[row["policy_target"]].append(spec)

# ip_only: collapse each target's groups into a single blanket rule (all CIDRs, all dest/identities).
if SCOPING_MODE == "ip_only":
    for tgt, specs in list(target_specs.items()):
        all_cidrs = []
        for spec in specs:
            for c in spec["cidrs"]:
                if c not in all_cidrs:
                    all_cidrs.append(c)
        target_specs[tgt] = [{
            "label": "cbi-helper-ip-only",
            "cidrs": all_cidrs,
            "destination": "all_destinations",
            "identity_type": "ALL_USERS",
            "identities": [],
        }]


def _enforce_limits(specs, deny, target):
    """Warn about and auto-cap a target policy's rules to the Databricks network-policy limits:
    50 ingress rules, 2000 CIDRs, 100 identities per policy. Mutates/returns capped (specs, deny)."""
    label = "single policy" if target == ALL_WORKSPACES else f"workspace {target}"

    # Identities per rule (100). Cap each rule's identity list.
    for spec in specs:
        n = len(spec.get("identities") or [])
        if n > MAX_IDENTITIES_PER_POLICY:
            print(f"  ⚠️  [{label}] rule '{spec['label']}' has {n} identities > "
                  f"{MAX_IDENTITIES_PER_POLICY} — using the first {MAX_IDENTITIES_PER_POLICY}.")
            spec["identities"] = spec["identities"][:MAX_IDENTITIES_PER_POLICY]

    # Ingress rules per policy (50): allow + deny combined.
    all_rules = specs + list(deny)
    if len(all_rules) > MAX_INGRESS_RULES_PER_POLICY:
        print(f"  ⚠️  [{label}] {len(all_rules)} rules (allow+deny) > {MAX_INGRESS_RULES_PER_POLICY} "
              f"— keeping the first {MAX_INGRESS_RULES_PER_POLICY} (allow rules prioritised).")
        specs = specs[:MAX_INGRESS_RULES_PER_POLICY]
        remaining = MAX_INGRESS_RULES_PER_POLICY - len(specs)
        deny = deny[:max(remaining, 0)]

    # CIDRs per policy (2000): sum across all rules; trim from the tail if over.
    def _total_cidrs(rs):
        return sum(len(r["cidrs"]) for r in rs)
    budget = MAX_CIDRS_PER_POLICY - _total_cidrs(specs)
    if budget < 0:
        print(f"  ⚠️  [{label}] allow CIDRs alone exceed {MAX_CIDRS_PER_POLICY} — trimming allow rules.")
        trimmed, used = [], 0
        for r in specs:
            room = MAX_CIDRS_PER_POLICY - used
            if room <= 0:
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed.append(r)
            used += len(r["cidrs"])
        specs, deny = trimmed, []
    else:
        # Fit deny CIDRs into the remaining budget.
        trimmed_deny, used = [], 0
        for r in deny:
            room = budget - used
            if room <= 0:
                print(f"  ⚠️  [{label}] deny CIDRs trimmed to fit the {MAX_CIDRS_PER_POLICY}-CIDR "
                      f"policy limit.")
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed_deny.append(r)
            used += len(r["cidrs"])
        deny = trimmed_deny
    return specs, deny

# --- Optional threat-intel DENY rules (one per source_feed), independent of allow rules ---
# off: none. matched_only: only threat CIDRs that matched an observed IP. all: every IPv4 CIDR in
# the threat-intel table. CBI is IPv4-only, so IPv6 threat ranges are skipped.
#
# When the deny list exceeds MAX_DENY_CIDRS we don't skip — we PRIORITISE and trim to the highest-
# value entries: keep confidence 1 (drop confidence 2), put threat_type='attacker_subnet' first,
# then take the top MAX_DENY_CIDRS. Selection order is preserved so the later per-policy 2000-CIDR
# cap (in _enforce_limits) also drops the lowest-priority entries first. A summary reports what's in
# vs out.
DENY_TYPE_PRIORITY = {"attacker_subnet": 0}  # everything else sorts after (priority 1)


def _deny_sort_key(rec):
    return (DENY_TYPE_PRIORITY.get(rec["threat_type"], 1), rec["confidence"], rec["source_feed"], rec["cidr"])


deny_specs = []
if THREAT_DENY_RULES != "off":
    # Collect per-CIDR records carrying feed/type/confidence, de-duped on cidr (keep most severe).
    by_cidr = {}
    if THREAT_DENY_RULES == "matched_only":
        src = [{"cidr": m["matched_cidr"], "source_feed": m["source_feed"],
                "threat_type": m["threat_type"], "confidence": m["confidence"]}
               for m in threat_match_rows]
    else:  # "all"
        src = [{"cidr": str(net), "source_feed": meta["source_feed"],
                "threat_type": meta["threat_type"], "confidence": meta["confidence"]}
               for net, meta in threat_ranges if net.version == 4]
    for rec in src:
        try:
            if ipaddress.ip_network(rec["cidr"], strict=False).version != 4:
                continue
        except ValueError:
            continue
        cur = by_cidr.get(rec["cidr"])
        # Keep the more severe entry per CIDR: lower confidence number wins, attacker_subnet wins.
        if cur is None or _deny_sort_key(rec) < _deny_sort_key(cur):
            by_cidr[rec["cidr"]] = rec

    all_records = list(by_cidr.values())
    total = len(all_records)

    if total > MAX_DENY_CIDRS:
        conf1 = [r for r in all_records if r["confidence"] == 1]
        pool = conf1 if conf1 else all_records
        pool.sort(key=_deny_sort_key)
        selected = pool[:MAX_DENY_CIDRS]
        dropped_conf2 = total - len(conf1) if conf1 else 0
        print(f"\n⚠️  Threat-intel deny list has {total:,} CIDRs (> cap {MAX_DENY_CIDRS:,}). "
              f"Prioritising instead of skipping:")
        print(f"    - kept confidence-1 only (dropped {dropped_conf2:,} confidence-2 CIDR(s))")
        print(f"    - attacker_subnet ranges first, then took the top {MAX_DENY_CIDRS:,}")
        print(f"    → INCLUDING {len(selected):,} of {total:,} threat CIDR(s); "
              f"{total - len(selected):,} NOT included.")
        print("    Raise MAX_DENY_CIDRS, use 'matched_only', or deselect feeds (2a) to change this.")
    else:
        selected = sorted(all_records, key=_deny_sort_key)

    # Group the selected records into one deny rule per feed, preserving priority order.
    by_feed = defaultdict(list)
    for rec in selected:
        if rec["cidr"] not in by_feed[rec["source_feed"]]:
            by_feed[rec["source_feed"]].append(rec["cidr"])
    for feed in sorted(by_feed):
        deny_specs.append({"label": f"cbi-helper-deny-{feed}"[:250], "cidrs": by_feed[feed]})

    if deny_specs:
        print(f"\nBuilt {len(deny_specs)} threat-intel deny rule(s) [{THREAT_DENY_RULES}], "
              f"{sum(len(s['cidrs']) for s in deny_specs):,} CIDR(s) total:")
        for spec in deny_specs:
            print(f"  DENY {spec['label']}: {len(spec['cidrs'])} CIDR(s)")

# Finalise per-target policies: attach the (shared) deny rules to each target and enforce limits.
# `policies` maps policy_target -> {"allow": [...], "deny": [...]}. Deny rules apply to every target.
print(f"\nFinalising policies (policy_scope={POLICY_SCOPE}) with limit enforcement "
      f"({MAX_INGRESS_RULES_PER_POLICY} rules / {MAX_CIDRS_PER_POLICY} CIDRs / "
      f"{MAX_IDENTITIES_PER_POLICY} identities per policy):")
policies = {}
for tgt in sorted(target_specs, key=str):
    allow, deny = _enforce_limits(list(target_specs[tgt]), list(deny_specs), tgt)
    policies[tgt] = {"allow": allow, "deny": deny}
    label = "single (all workspaces)" if tgt == ALL_WORKSPACES else f"workspace {tgt}"
    print(f"  {label}: {len(allow)} allow + {len(deny)} deny rule(s), "
          f"{sum(len(r['cidrs']) for r in allow + deny)} CIDR(s)")

if POLICY_SCOPE == "per_workspace" and len(policies) > MAX_POLICIES_PER_ACCOUNT:
    print(f"⚠️  {len(policies)} per-workspace policies > {MAX_POLICIES_PER_ACCOUNT} account limit — "
          f"consider policy_scope=single or consolidating workspaces.")
if skipped_ipv6:
    print(f"({skipped_ipv6} IPv6 CIDR(s) omitted overall — CBI policy supports IPv4 only)")
print(f"Excluded {excluded_flagged} flagged group(s) (threat-intel / cloud-owned).")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Proposed policy — JSON preview & explanation
# MAGIC
# MAGIC Builds the exact block the apply-cell would send and prints it as JSON. Nothing here calls the
# MAGIC API. The table explains each part of an account network policy and marks which block this run
# MAGIC targets (per `policy_mode`).

# COMMAND ----------

# DBTITLE 1,Preview proposed policy JSON + explanation
POLICY_MODE_RULE_LABEL = {"dry_run": "dry-run", "enforce": "enforced"}[POLICY_MODE]


def _build_rule(spec):
    from databricks.sdk.service.settings import (
        CustomerFacingIngressNetworkPolicyAppsRuntimeDestination as AppsDest,
        CustomerFacingIngressNetworkPolicyAuthentication as Auth,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentity as Identity,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentityPrincipalType as PrincipalType,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentityType as IdentityType,
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyLakebaseRuntimeDestination as LakebaseDest,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    origin = Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"])))

    destination = None
    if spec["destination"] == "apps_runtime":
        destination = Destination(apps_runtime=AppsDest(all_destinations=True))
    elif spec["destination"] == "lakebase_runtime":
        destination = Destination(lakebase_runtime=LakebaseDest(all_destinations=True))
    elif spec["destination"] == "all_destinations":
        destination = Destination(all_destinations=True)

    authentication = None
    if spec["identity_type"] == "SELECTED_IDENTITIES" and spec["identities"]:
        identities = [
            Identity(
                principal_id=i["principal_id"],
                principal_type=(PrincipalType.PRINCIPAL_TYPE_USER if i["principal_type"] == "USER"
                                else PrincipalType.PRINCIPAL_TYPE_SERVICE_PRINCIPAL),
            )
            for i in spec["identities"]
        ]
        authentication = Auth(
            identity_type=IdentityType.IDENTITY_TYPE_SELECTED_IDENTITIES, identities=identities
        )

    return Rule(label=f"{spec['label']} ({POLICY_MODE_RULE_LABEL})",
                origin=origin, destination=destination, authentication=authentication)


def _build_deny_rule(spec):
    """A deny rule is just an origin (CIDRs) with a label — no destination/identity scoping."""
    from databricks.sdk.service.settings import (
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
    )
    return Rule(label=f"{spec['label']} ({POLICY_MODE_RULE_LABEL})",
                origin=Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"]))))


def _build_ingress_block(specs, deny=None):
    """Assemble a CustomerFacingIngressNetworkPolicy from allow specs (+ optional deny specs).
    Shared by preview + apply so the JSON you review is exactly what gets sent."""
    from databricks.sdk.service.settings import (
        CustomerFacingIngressNetworkPolicy as IngressPolicy,
        CustomerFacingIngressNetworkPolicyPublicAccess as PublicAccess,
        CustomerFacingIngressNetworkPolicyPublicAccessRestrictionMode as RestrictionMode,
    )
    public = PublicAccess(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allow_rules=[_build_rule(s) for s in specs],
        deny_rules=[_build_deny_rule(s) for s in (deny or [])] or None,
    )
    return IngressPolicy(public_access=public)


if POLICY_MODE == "enforce":
    print("⛔ MODE = ENFORCE — proposal targets the *enforced* `ingress` block. Once applied,\n"
          "   source IPs NOT in the allow-list will be BLOCKED. Validate in dry_run first.\n")
else:
    print("🔎 MODE = DRY_RUN — proposal targets the log-only `ingress_dry_run` block; nothing is blocked.\n")

if not policies:
    print("No rule specs — nothing to preview. Revisit the framing / scoping / threat_deny_rules "
          "widgets, or check whether every candidate group was flagged and excluded.")
else:
    for tgt in sorted(policies, key=str):
        allow, deny = policies[tgt]["allow"], policies[tgt]["deny"]
        if not (allow or deny):
            continue
        label = "single policy (all workspaces)" if tgt == ALL_WORKSPACES else f"workspace {tgt}"
        block = _build_ingress_block(allow, deny)
        print(f"\n=== {label}: `{POLICY_MODE_TARGET}` block "
              f"({len(allow)} allow + {len(deny)} deny rule(s)) ===")
        print(json.dumps({POLICY_MODE_TARGET: block.as_dict()}, indent=2))

# Recommended workspace assignments (per_workspace scope only).
if POLICY_SCOPE == "per_workspace" and policies:
    _assign = pd.DataFrame(
        [{"workspace_id": t, "allow_rules": len(p["allow"]), "deny_rules": len(p["deny"]),
          "total_cidrs": sum(len(r["cidrs"]) for r in p["allow"] + p["deny"])}
         for t, p in policies.items() if t != ALL_WORKSPACES]
    )
    if not _assign.empty:
        print("\nRecommended per-workspace policy assignments "
              "(bind a policy to each workspace via the apply cell):")
        display(_assign.sort_values("workspace_id"))


def _touched(block):
    if block == POLICY_MODE_TARGET:
        return f"YES — proposal written here ({POLICY_MODE} mode)"
    return "NO — read and re-sent unchanged" if block == "egress" else "NO — left unchanged"

_policy_explainer = pd.DataFrame([
    {"policy_block": "ingress", "direction": "inbound", "enforced?": "YES — blocks traffic",
     "this run touches?": _touched("ingress"),
     "meaning": "Enforced allow-list. Non-matching source IPs are rejected."},
    {"policy_block": "ingress_dry_run", "direction": "inbound", "enforced?": "no — log only",
     "this run touches?": _touched("ingress_dry_run"),
     "meaning": "Same shape as ingress but log-only: recorded, never blocked. For trialling a policy."},
    {"policy_block": "egress", "direction": "outbound", "enforced?": "varies (SEG)",
     "this run touches?": _touched("egress"),
     "meaning": "Serverless egress controls. Preserved verbatim (update is a full replace)."},
])
print("\nAccount network policy anatomy:")
display(_policy_explainer)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Apply the proposed policy (gated)
# MAGIC
# MAGIC Writes the proposed rules into the account network policy via the SDK, targeting the block
# MAGIC chosen by `policy_mode`:
# MAGIC - **`dry_run`** → `ingress_dry_run.public_access` — **log-only, blocks nothing.**
# MAGIC - **`enforce`** → `ingress.public_access` — **enforced: non-matching source IPs are blocked.**
# MAGIC
# MAGIC Other blocks (and `egress`) are read and re-sent unchanged (update is a full replace). Runs
# MAGIC when `apply_policy = true`; the default `policy_mode=dry_run` is the safeguard (it only writes
# MAGIC the log-only block). Requires an **account-admin** `AccountClient` (see "Account admin
# MAGIC requirements" near the top; configure via widgets 4a–4e).
# MAGIC
# MAGIC By default it **creates the policy if it doesn't exist** (`create_missing_policy=true`,
# MAGIC widget 5c); set that to false to require the policy to pre-exist.
# MAGIC
# MAGIC **Scope behaviour:**
# MAGIC - `policy_scope=single` — creates/updates the single policy named in `network_policy_id`.
# MAGIC - `policy_scope=per_workspace` — treats `network_policy_id` as a **prefix**: for each
# MAGIC   workspace it creates/updates policy `<prefix>-ws-<workspace_id>` and binds the workspace to
# MAGIC   it via `update_workspace_network_option_rpc`. Per-workspace failures are reported
# MAGIC   individually and don't stop the others.

# COMMAND ----------

# DBTITLE 1,Apply proposed rules (dry_run or enforce)
def _apply_to_policy(a, policy_id, allow, deny):
    """Get-or-create an account network policy `policy_id` and set its target block
    (ingress|ingress_dry_run) to the proposed allow+deny rules, leaving the other blocks and egress
    unchanged (update is a full replace). Creates the policy when it doesn't exist and
    create_missing_policy is on. Returns (action, sent_block_dict) where action is created|updated."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy

    try:
        existing = a.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        if not CREATE_MISSING_POLICY:
            raise ValueError(
                f"Network policy '{policy_id}' does not exist and create_missing_policy=false. "
                f"Create it first or set widget 5d to true.")
        existing = AccountNetworkPolicy(account_id=ACCOUNT_ID, network_policy_id=policy_id)
        action = "created"

    setattr(existing, POLICY_MODE_TARGET, _build_ingress_block(allow, deny))
    if action == "created":
        result = a.network_policies.create_network_policy_rpc(network_policy=existing)
        # The server may assign the id; report whatever it returns.
        globals()["_last_created_policy_id"] = result.network_policy_id or policy_id
    else:
        a.network_policies.update_network_policy_rpc(network_policy_id=policy_id, network_policy=existing)
    return action, getattr(existing, POLICY_MODE_TARGET).as_dict()


if not APPLY_POLICY:
    print(f"Not applying (mode={POLICY_MODE}, scope={POLICY_SCOPE}). Set apply_policy=true to apply. "
          f"policy_mode=dry_run is the safe default (log-only); enforce blocks non-matching IPs.")
elif not NETWORK_POLICY_ID:
    print("Set network_policy_id (widget 5a) first.\n"
          f"  - single scope: the policy to create/update (created if missing when "
          f"create_missing_policy=true).\n"
          "  - per_workspace scope: used as a PREFIX; each workspace binds to policy "
          "'<network_policy_id>-ws-<workspace_id>' (created if missing).")
elif not policies:
    print("No allow or deny rule specs to apply — check the suggestions above.")
else:
    a = _account_client()  # account admin required — see "Account admin requirements" above

    if POLICY_SCOPE == "single":
        p = policies.get(ALL_WORKSPACES) or next(iter(policies.values()))
        print(f"Applying policy '{NETWORK_POLICY_ID}' ({POLICY_MODE_TARGET}, {POLICY_MODE} mode, "
              f"create_missing={CREATE_MISSING_POLICY})...")
        action, sent = _apply_to_policy(a, NETWORK_POLICY_ID, p["allow"], p["deny"])
        print(f"Policy {action}.")
        print(json.dumps({POLICY_MODE_TARGET: sent}, indent=2))
        print("Done." if POLICY_MODE == "dry_run"
              else "⛔ Done — ENFORCED. Verify you can still reach the workspace.")
    else:
        # per_workspace: get-or-create one policy per workspace, then bind the workspace to it.
        from databricks.sdk.service.settings import WorkspaceNetworkOption

        ws_targets = sorted(t for t in policies if t != ALL_WORKSPACES)
        print(f"per_workspace apply ({POLICY_MODE} mode, create_missing={CREATE_MISSING_POLICY}): "
              f"applying + binding {len(ws_targets)} workspace policy(ies).\n")
        for tgt in ws_targets:
            pid = f"{NETWORK_POLICY_ID}-ws-{tgt}"
            p = policies[tgt]
            try:
                action, _ = _apply_to_policy(a, pid, p["allow"], p["deny"])
                a.workspace_network_configuration.update_workspace_network_option_rpc(
                    workspace_id=int(tgt),
                    workspace_network_option=WorkspaceNetworkOption(
                        workspace_id=int(tgt), network_policy_id=pid),
                )
                print(f"  ✅ workspace {tgt}: {action} '{pid}' and bound.")
            except Exception as e:  # noqa: BLE001 - surface per-workspace failures, keep going
                print(f"  ❌ workspace {tgt}: {e}")
        print("\nDone." if POLICY_MODE == "dry_run"
              else "\n⛔ Done — ENFORCED per workspace. Verify workspace reachability.")