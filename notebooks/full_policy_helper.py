# Databricks notebook source
# MAGIC %md
# MAGIC # Full Network Policy Helper (ingress + egress)
# MAGIC
# MAGIC Combines the **ingress** (CBI) and **egress** (SEG) helpers into a single account network
# MAGIC policy. It `%run`s `audit_log_cbi` and `egress_policy_helper` (both in **propose-only** mode —
# MAGIC they build their rules but don't create anything), then **merges** ingress + egress per policy
# MAGIC target and creates one policy each.
# MAGIC
# MAGIC Use the individual notebooks if you only need one direction. All the ingress/egress widgets of
# MAGIC the child notebooks apply here too (set them in the widget bar); this notebook only adds the
# MAGIC final create/assign gate.
# MAGIC
# MAGIC > ⚠️ Nothing is written unless `create_policy=true`. `policy_mode=dry_run` (default) is log-only.
# MAGIC > Keep `policy_scope` **the same** for both directions (set it once; both children read it).

# COMMAND ----------

# MAGIC %md
# MAGIC ## Install a current Databricks SDK (once, here)
# MAGIC
# MAGIC The combiner installs + restarts **once**. It then sets `_COMBINED_RUN = True` so the child
# MAGIC notebooks skip their own restart (which would wipe the shared namespace) and leave their built
# MAGIC rule structures available for merging.

# COMMAND ----------

# DBTITLE 1,Install & restart
# MAGIC %pip install --quiet -r ../requirements.txt

# COMMAND ----------

# DBTITLE 1,Restart Python
dbutils.library.restartPython()

# COMMAND ----------

# DBTITLE 1,Combiner flag + gate widgets
# Tell the child notebooks not to restart Python (we've already done it) and not to create anything
# (the combiner does the merged create).
_COMBINED_RUN = True

# The child notebooks create their own widgets on %run. We only add the final create/assign gate;
# force the children to propose-only by overriding their create_policy after they run.
dbutils.widgets.dropdown("create_policy", "false", ["true", "false"], "Z1. Create the merged policy?")
dbutils.widgets.dropdown("auto_assign", "false", ["true", "false"], "Z2. Auto-assign to workspace(s)?")
dbutils.widgets.dropdown("reviewed_rules", "false", ["true", "false"], "Z3. I've reviewed the rules")
CREATE_POLICY = dbutils.widgets.get("create_policy") == "true"
AUTO_ASSIGN = dbutils.widgets.get("auto_assign") == "true"
REVIEWED_RULES = dbutils.widgets.get("reviewed_rules") == "true"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Run the ingress helper (propose only)
# MAGIC
# MAGIC `%run` shares this notebook's namespace, so after this cell the ingress `policies` dict
# MAGIC (policy_target → {allow, deny}) and helpers (`_build_ingress_block`, `_policy_name`,
# MAGIC `_account_client`, `ALL_WORKSPACES`, `POLICY_MODE_TARGET`) are available here.
# MAGIC
# MAGIC The child's own create cell is a no-op because it sees `_COMBINED_RUN = True` and skips it.

# COMMAND ----------

# MAGIC %run ./audit_log_cbi

# COMMAND ----------

# DBTITLE 1,Capture ingress results
ingress_policies = dict(policies)  # policy_target -> {"allow": [...], "deny": [...]}
_build_ingress = _build_ingress_block
_ingress_target_name = _policy_name  # (workspace_id=...) -> policy id
_acct_client = _account_client
_ALL = ALL_WORKSPACES
_INGRESS_MODE_TARGET = POLICY_MODE_TARGET  # ingress | ingress_dry_run
print(f"ingress: {len(ingress_policies)} target(s) -> "
      f"{[ (str(t), len(p['allow']), len(p['deny'])) for t, p in ingress_policies.items() ]}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Run the egress helper (propose only)
# MAGIC
# MAGIC After this, `egress_blocks` (policy_target → NetworkPolicyEgress) is available.

# COMMAND ----------

# MAGIC %run ./egress_policy_helper

# COMMAND ----------

# DBTITLE 1,Capture egress results
egress_by_target = dict(egress_blocks)  # policy_target -> NetworkPolicyEgress
print(f"egress: {len(egress_by_target)} target(s) -> {[str(t) for t in egress_by_target]}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Merge & preview
# MAGIC
# MAGIC For each policy target seen in either direction, build one `AccountNetworkPolicy` with the
# MAGIC ingress block (from the ingress helper, into `ingress`/`ingress_dry_run` per its policy_mode)
# MAGIC **and** the egress block (from the egress helper). Prints the merged JSON; sends nothing.
# MAGIC
# MAGIC > Both children use the same `policy_scope`, so their `policy_target` keys line up
# MAGIC > (`__ALL__` for single, or the workspace id for per_workspace).

# COMMAND ----------

# DBTITLE 1,Build merged policies
import json

from databricks.sdk.service.settings import AccountNetworkPolicy

all_targets = sorted(set(ingress_policies) | set(egress_by_target), key=str)


def _merged_policy_name(target):
    # Reuse the ingress helper's naming so ingress-only and combined runs land on the SAME policy.
    return _ingress_target_name() if target == _ALL else _ingress_target_name(workspace_id=target)


merged = {}  # policy_target -> (policy_id, AccountNetworkPolicy)
for tgt in all_targets:
    pid = _merged_policy_name(tgt)
    pol = AccountNetworkPolicy(account_id=ACCOUNT_ID, network_policy_id=pid)
    ing = ingress_policies.get(tgt)
    if ing and (ing["allow"] or ing["deny"]):
        setattr(pol, _INGRESS_MODE_TARGET, _build_ingress(ing["allow"], ing["deny"]))
    if tgt in egress_by_target:
        pol.egress = egress_by_target[tgt]
    merged[tgt] = (pid, pol)
    label = "single (all workspaces)" if tgt == _ALL else f"workspace {tgt}"
    print(f"\n=== {label} → policy '{pid}' ===")
    print(json.dumps(pol.as_dict(), indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ## ⚠️ Review checkpoint
# MAGIC
# MAGIC **Review the merged ingress + egress policy(ies) above** before creating. Set `reviewed_rules`
# MAGIC (Z3) to `true` when satisfied — the create cell refuses to run until you do.

# COMMAND ----------

# DBTITLE 1,Review gate — must confirm before create
if CREATE_POLICY and not REVIEWED_RULES:
    raise Exception(
        "STOP — review the merged ingress + egress policy(ies) above before creating. When "
        "satisfied, set widget 'Z3. I've reviewed the rules' to true and re-run."
    )
print("Review gate passed." if (CREATE_POLICY and REVIEWED_RULES) else
      "Review gate not required (propose-only run).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Create the merged policy (gated)
# MAGIC
# MAGIC Creates/updates each merged policy (idempotent — deterministic names), gated by this notebook's
# MAGIC `create_policy` (widget Z1). `auto_assign` (Z2) binds the workspace(s): single → this
# MAGIC workspace; per_workspace → each target. Requires an **account-admin** AccountClient (the child
# MAGIC notebooks' account widgets 4a–4e supply it).

# COMMAND ----------

# DBTITLE 1,Create + assign merged policies
from databricks.sdk import WorkspaceClient

THIS_WORKSPACE_ID = WorkspaceClient().get_workspace_id()

if not CREATE_POLICY:
    print("Not creating. Set create_policy=true (Z1) to create the merged policy(ies)"
          + (" and assign the workspace(s)." if AUTO_ASSIGN else "."))
elif not merged:
    print("Nothing to create — neither ingress nor egress produced rules.")
else:
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import WorkspaceNetworkOption

    a = _acct_client()
    for tgt in all_targets:
        pid, proposed = merged[tgt]
        bind_ws = THIS_WORKSPACE_ID if tgt == _ALL else int(tgt)
        try:
            # Get-or-create, then set BOTH the ingress target block and egress on the live object so
            # we don't clobber any block the proposal didn't touch.
            try:
                existing = a.network_policies.get_network_policy_rpc(network_policy_id=pid)
                action = "updated"
            except NotFound:
                existing = AccountNetworkPolicy(account_id=ACCOUNT_ID, network_policy_id=pid)
                action = "created"
            ing = ingress_policies.get(tgt)
            if ing and (ing["allow"] or ing["deny"]):
                setattr(existing, _INGRESS_MODE_TARGET, getattr(proposed, _INGRESS_MODE_TARGET))
            if tgt in egress_by_target:
                existing.egress = proposed.egress
            if action == "created":
                result = a.network_policies.create_network_policy_rpc(network_policy=existing)
                effective_id = result.network_policy_id or pid
            else:
                a.network_policies.update_network_policy_rpc(network_policy_id=pid, network_policy=existing)
                effective_id = pid
            msg = f"  ✅ {action} '{effective_id}' (ingress+egress)"
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
    print("\nReview each policy in the account console. If enforced, verify inbound + outbound still work.")
