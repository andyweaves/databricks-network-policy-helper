# Databricks notebook source
# MAGIC %md
# MAGIC # IP Access List → CBI migration (simple)
# MAGIC
# MAGIC A minimal companion to `ingress_policy_helper.py`. It reads **this workspace's existing IP access
# MAGIC list** and migrates it **as-is** into an account **context-based ingress (CBI)** network
# MAGIC policy — no audit-log analysis, no enrichment, nothing added. ALLOW lists become allow rules,
# MAGIC BLOCK lists become deny rules. It assumes the customer is happy with their current ACL and
# MAGIC just wants it recreated as a network policy.
# MAGIC
# MAGIC Use `ingress_policy_helper.py` instead if you want traffic-based suggestions, threat-intel / cloud
# MAGIC enrichment, Databricks-IP auto-allow, or identity/destination scoping.
# MAGIC
# MAGIC > ⚠️ Default `policy_mode` is `enforce`. Switch to `dry_run` to trial log-only first. Since
# MAGIC > this migrates the ACL verbatim, an enforced policy behaves like the ACL it came from.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Install a current Databricks SDK
# MAGIC
# MAGIC The CBI policy dataclasses require a newer `databricks-sdk` than some runtimes bundle. Install
# MAGIC from the repo's `requirements.txt` and restart before importing the SDK. (Run from the
# MAGIC git-folder checkout so `../requirements.txt` resolves; otherwise
# MAGIC `%pip install --quiet "databricks-sdk>=0.113.0"` directly.)

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
dbutils.widgets.dropdown("policy_mode", "enforce", ["enforce", "dry_run"], "1. Policy mode")
dbutils.widgets.text("name_prefix", "np-helper", "2. Name prefix")
dbutils.widgets.dropdown(
    "egress_policy", "allow_all", ["allow_all", "dry_run", "restricted"], "3. Egress (on create)"
)
dbutils.widgets.dropdown("auto_assign", "true", ["true", "false"], "4. Auto-assign to this workspace?")
# Account auth — required to create/assign the policy (account-level operations).
dbutils.widgets.text("account_id", "", "5a. Databricks account_id")
dbutils.widgets.text("account_host", "https://accounts.cloud.databricks.com", "5b. Account console host")
dbutils.widgets.text("account_sp_client_id", "", "5c. Account admin SP client_id")
dbutils.widgets.text("account_secret_scope", "", "5d. Secret scope holding SP secret")
dbutils.widgets.text("account_secret_key", "", "5e. Secret key for SP secret")
dbutils.widgets.dropdown("create_policy", "false", ["true", "false"], "6. Create the policy?")

POLICY_MODE = dbutils.widgets.get("policy_mode")
NAME_PREFIX = dbutils.widgets.get("name_prefix").strip() or "np-helper"
EGRESS_POLICY = dbutils.widgets.get("egress_policy")
AUTO_ASSIGN = dbutils.widgets.get("auto_assign") == "true"
ACCOUNT_ID = dbutils.widgets.get("account_id").strip()
ACCOUNT_HOST = dbutils.widgets.get("account_host").strip() or "https://accounts.cloud.databricks.com"
ACCOUNT_SP_CLIENT_ID = dbutils.widgets.get("account_sp_client_id").strip()
ACCOUNT_SECRET_SCOPE = dbutils.widgets.get("account_secret_scope").strip()
ACCOUNT_SECRET_KEY = dbutils.widgets.get("account_secret_key").strip()
CREATE_POLICY = dbutils.widgets.get("create_policy") == "true"

POLICY_MODE_TARGET = {"dry_run": "ingress_dry_run", "enforce": "ingress"}[POLICY_MODE]
MAX_POLICY_ID_LEN = 30

# COMMAND ----------

# MAGIC %md
# MAGIC ## Read this workspace's IP access list + Databricks-owned ranges
# MAGIC
# MAGIC The ACL read is workspace-level (no account admin needed). This is a **faithful migration** —
# MAGIC it recreates the existing ACL exactly and adds nothing (it assumes the customer is happy with
# MAGIC their current ACL). Use `ingress_policy_helper.py` if you want enrichment / Databricks-IP auto-allow.

# COMMAND ----------

# DBTITLE 1,Read IP ACL
import ipaddress
from datetime import datetime, timezone

import pandas as pd

from databricks.sdk import WorkspaceClient

_w = WorkspaceClient()
WORKSPACE_ID = _w.get_workspace_id()

ip_acls = []
for acl in _w.ip_access_lists.list():
    if not acl.enabled:
        continue
    ip_acls.append({
        "label": acl.label,
        "list_type": acl.list_type.value if acl.list_type else None,
        "ip_addresses": list(acl.ip_addresses or []),
    })

print(f"workspace_id: {WORKSPACE_ID}")
if ip_acls:
    print(f"Found {len(ip_acls)} enabled IP access list(s):")
    for a in ip_acls:
        print(f"  [{a['list_type']}] {a['label']}: {len(a['ip_addresses'])} entr(ies)")
    display(pd.DataFrame([{**a, "ip_addresses": ", ".join(a["ip_addresses"])} for a in ip_acls]))
else:
    print("No enabled IP access lists on this workspace — nothing to migrate.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build the proposed policy
# MAGIC
# MAGIC ALLOW lists → allow rules, BLOCK lists → deny rules — a faithful recreation of the ACL,
# MAGIC nothing added. IPv4 only (CBI is IPv4-only). Builds and prints the exact block; nothing is
# MAGIC sent here.

# COMMAND ----------

# DBTITLE 1,Assemble + preview
import json


def _ipv4(cidrs):
    out = []
    for c in cidrs:
        v = c if "/" in c else f"{c}/32"
        try:
            if ipaddress.ip_network(v, strict=False).version == 4 and v not in out:
                out.append(v)
        except ValueError:
            pass
    return out


allow_specs, deny_specs = [], []
for a in ip_acls:
    cidrs = _ipv4(a["ip_addresses"])
    if not cidrs:
        continue
    label = f"{NAME_PREFIX}-ip-acl-{a['label']}"[:250]
    if a["list_type"] == "ALLOW":
        allow_specs.append({"label": label, "cidrs": cidrs})
    elif a["list_type"] == "BLOCK":
        deny_specs.append({"label": label, "cidrs": cidrs})


def _build_ingress_block(allow, deny):
    from databricks.sdk.service.settings import (
        CustomerFacingIngressNetworkPolicy as IngressPolicy,
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyPublicAccess as PublicAccess,
        CustomerFacingIngressNetworkPolicyPublicAccessRestrictionMode as RestrictionMode,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    def rule(spec):
        # A catch-all spec ({"catch_all": True}) maps to an all-public-IPs origin, not a CIDR list.
        origin = (Origin(all_ip_ranges=True) if spec.get("catch_all")
                  else Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"]))))
        return Rule(label=f"{spec['label']} ({POLICY_MODE})", origin=origin,
                    destination=Destination(all_destinations=True))

    # CBI RESTRICTED_ACCESS is default-DENY (deny rules are exceptions to allow rules). A workspace
    # IP ACL with only BLOCK lists is default-ALLOW, so migrating deny rules alone would block
    # everything. Preserve the ACL's meaning by adding a catch-all allow (all public IPs) when there
    # are deny rules but no allow rules.
    allow = list(allow)
    if deny and not allow:
        allow = [{"label": f"{NAME_PREFIX}-allow-all", "catch_all": True}]
        print("  ℹ️  Only BLOCK/deny rules present — added a catch-all allow (all public IPs) so the "
              "policy matches the ACL's default-allow-except-blocked behaviour.")

    return IngressPolicy(public_access=PublicAccess(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allow_rules=[rule(s) for s in allow],
        deny_rules=[rule(s) for s in deny] or None,
    ))


if not (allow_specs or deny_specs):
    print("No rules to build — no enabled IP ACL entries found.")
else:
    _preview = _build_ingress_block(allow_specs, deny_specs)
    print(f"Proposed `{POLICY_MODE_TARGET}` block ({len(allow_specs)} allow + {len(deny_specs)} deny "
          f"rule(s), {POLICY_MODE} mode):\n")
    print(json.dumps({POLICY_MODE_TARGET: _preview.as_dict()}, indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Apply (gated)
# MAGIC
# MAGIC Creates/updates the account network policy (via `create_policy=true`) and, if `auto_assign` is
# MAGIC on, binds **this** workspace to it. Requires an **account-admin** `AccountClient` — set the
# MAGIC account widgets (5a–5e); an account_id is mandatory.
# MAGIC
# MAGIC `dry_run` writes the log-only `ingress_dry_run` block; `enforce` writes the enforced `ingress`
# MAGIC block (non-matching source IPs are blocked).

# COMMAND ----------

# DBTITLE 1,Create/update + assign
def _account_client():
    from databricks.sdk import AccountClient

    if not ACCOUNT_ID:
        raise ValueError("account_id (widget 5a) is required to create/assign a network policy.")
    if ACCOUNT_SP_CLIENT_ID and ACCOUNT_SECRET_SCOPE and ACCOUNT_SECRET_KEY:
        secret = dbutils.secrets.get(scope=ACCOUNT_SECRET_SCOPE, key=ACCOUNT_SECRET_KEY)
        return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID,
                             client_id=ACCOUNT_SP_CLIENT_ID, client_secret=secret)
    return AccountClient(host=ACCOUNT_HOST, account_id=ACCOUNT_ID)


def _build_egress(kind):
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EgressAccess,
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcement as Enforcement,
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcementEnforcementMode as EnforcementMode,
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as EgressRestriction,
        NetworkPolicyEgress,
    )
    if kind == "allow_all":
        access = EgressAccess(restriction_mode=EgressRestriction.FULL_ACCESS)
    elif kind == "dry_run":
        access = EgressAccess(restriction_mode=EgressRestriction.RESTRICTED_ACCESS,
                              policy_enforcement=Enforcement(enforcement_mode=EnforcementMode.DRY_RUN))
    else:  # restricted
        access = EgressAccess(restriction_mode=EgressRestriction.RESTRICTED_ACCESS,
                              policy_enforcement=Enforcement(enforcement_mode=EnforcementMode.ENFORCED))
    return NetworkPolicyEgress(network_access=access)


RESOLVED_POLICY_ID = f"{NAME_PREFIX}-{WORKSPACE_ID}"
if len(RESOLVED_POLICY_ID) > MAX_POLICY_ID_LEN:
    print(f"⚠️  policy name '{RESOLVED_POLICY_ID}' is {len(RESOLVED_POLICY_ID)} chars — network "
          f"policy ids have a length limit (~{MAX_POLICY_ID_LEN}). If create fails with 'Invalid "
          f"NetworkPolicyId', shorten name_prefix.")

if not CREATE_POLICY:
    print(f"Not creating (mode={POLICY_MODE}). Set create_policy=true to create the policy"
          f"{' and assign this workspace' if AUTO_ASSIGN else ''}.")
elif not (allow_specs or deny_specs):
    print("Nothing to apply — no IP ACL rules built.")
else:
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy, WorkspaceNetworkOption

    a = _account_client()
    try:
        existing = a.network_policies.get_network_policy_rpc(network_policy_id=RESOLVED_POLICY_ID)
        action = "updated"
    except NotFound:
        existing = AccountNetworkPolicy(account_id=ACCOUNT_ID, network_policy_id=RESOLVED_POLICY_ID,
                                        egress=_build_egress(EGRESS_POLICY))
        action = "created"

    setattr(existing, POLICY_MODE_TARGET, _build_ingress_block(allow_specs, deny_specs))
    if action == "created":
        result = a.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or RESOLVED_POLICY_ID
    else:
        a.network_policies.update_network_policy_rpc(network_policy_id=RESOLVED_POLICY_ID, network_policy=existing)
        effective_id = RESOLVED_POLICY_ID
    print(f"Policy {action}: {effective_id} ({POLICY_MODE_TARGET}, {POLICY_MODE} mode)")

    if AUTO_ASSIGN:
        a.workspace_network_configuration.update_workspace_network_option_rpc(
            workspace_id=WORKSPACE_ID,
            workspace_network_option=WorkspaceNetworkOption(
                workspace_id=WORKSPACE_ID, network_policy_id=effective_id),
        )
        print(f"Assigned workspace {WORKSPACE_ID} to policy {effective_id}.")
        if POLICY_MODE == "enforce":
            print("⛔ ENFORCED — verify you can still reach this workspace.")
    else:
        print(f"Not assigned (auto_assign=false). Bind workspace {WORKSPACE_ID} to '{effective_id}' "
              f"manually when ready.")
