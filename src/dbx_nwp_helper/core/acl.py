"""IP ACL → CBI verbatim migration engine.

Ported from `notebooks/ip_acl_migration.py`. Reads this workspace's enabled IP access lists and
recreates them as a CBI policy as-is (ALLOW → allow rules, BLOCK → deny rules), adding nothing but the
catch-all allow required when only BLOCK lists exist (CBI is default-deny).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import AclConfig
from . import policy

Note = Callable[[str], None]


@dataclass
class AclAnalysis:
    workspace_id: int
    ip_acls: list[dict] = field(default_factory=list)
    allow_specs: list[dict] = field(default_factory=list)
    deny_specs: list[dict] = field(default_factory=list)


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


def analyze(cfg: AclConfig, workspace_client) -> AclAnalysis:
    workspace_id = workspace_client.get_workspace_id()
    ip_acls = []
    for acl in workspace_client.ip_access_lists.list():
        if not acl.enabled:
            continue
        ip_acls.append({
            "label": acl.label,
            "list_type": acl.list_type.value if acl.list_type else None,
            "ip_addresses": list(acl.ip_addresses or []),
        })

    allow_specs, deny_specs = [], []
    for a in ip_acls:
        cidrs = _ipv4(a["ip_addresses"])
        if not cidrs:
            continue
        label = f"migrated-ip-acl-{a['label']}"[:250]
        if a["list_type"] == "ALLOW":
            allow_specs.append({"label": label, "cidrs": cidrs})
        elif a["list_type"] == "BLOCK":
            deny_specs.append({"label": label, "cidrs": cidrs})

    return AclAnalysis(workspace_id=workspace_id, ip_acls=ip_acls,
                       allow_specs=allow_specs, deny_specs=deny_specs)


def build_block(analysis: AclAnalysis, cfg: AclConfig, note: Note = lambda _m: None):
    return policy.build_ingress_block(
        analysis.allow_specs, analysis.deny_specs, cfg.policy_mode, cfg.name_prefix, note)


def preview_block(analysis: AclAnalysis, cfg: AclConfig, note: Note = lambda _m: None) -> dict:
    block = build_block(analysis, cfg, note)
    return {cfg.policy_mode_target: block.as_dict()}


def build_egress(kind: str):
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EgressAccess,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcement as Enforcement,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcementEnforcementMode as EnforcementMode,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as EgressRestriction,
    )
    from databricks.sdk.service.settings import (
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


def apply(analysis: AclAnalysis, cfg: AclConfig, account, account_id: str,
          note: Note = lambda _m: None) -> dict:
    """Create/update `<prefix>-<workspace_id>` and optionally assign this workspace."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy, WorkspaceNetworkOption

    policy_id = f"{cfg.name_prefix}-{analysis.workspace_id}"
    try:
        existing = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        existing = AccountNetworkPolicy(account_id=account_id, network_policy_id=policy_id,
                                        egress=build_egress(cfg.egress_policy))
        action = "created"

    setattr(existing, cfg.policy_mode_target, build_block(analysis, cfg, note))
    if action == "created":
        result = account.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or policy_id
    else:
        account.network_policies.update_network_policy_rpc(
            network_policy_id=policy_id, network_policy=existing)
        effective_id = policy_id

    out = {"action": action, "policy_id": effective_id}
    if cfg.auto_assign:
        account.workspace_network_configuration.update_workspace_network_option_rpc(
            workspace_id=analysis.workspace_id,
            workspace_network_option=WorkspaceNetworkOption(
                workspace_id=analysis.workspace_id, network_policy_id=effective_id),
        )
        out["assigned"] = analysis.workspace_id
    return out
