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
    # Workspace-wide IP-ACL enforcement state (enableIpAccessLists): True/False, or None if it
    # couldn't be read. False means the listed rules exist but aren't currently being enforced.
    ip_acls_enforced: bool | None = None


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


def _ip_acls_enforced(workspace_client) -> bool | None:
    """Read the workspace-wide `enableIpAccessLists` toggle. True/False, or None if unreadable."""
    try:
        status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
        val = str(status.get("enableIpAccessLists", "")).lower()
        if val in ("true", "false"):
            return val == "true"
    except Exception:  # noqa: BLE001 - best-effort; absence just means "unknown"
        pass
    return None


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
        # Recreate the rule labels prefixed with `migrated-` (preserving the original ACL label).
        label = f"migrated-{a['label']}"[:250]
        if a["list_type"] == "ALLOW":
            allow_specs.append({"label": label, "cidrs": cidrs})
        elif a["list_type"] == "BLOCK":
            deny_specs.append({"label": label, "cidrs": cidrs})

    return AclAnalysis(workspace_id=workspace_id, ip_acls=ip_acls,
                       allow_specs=allow_specs, deny_specs=deny_specs,
                       ip_acls_enforced=_ip_acls_enforced(workspace_client))


def workspace_pas_attached(account, workspace_id) -> bool | None:
    """True if the workspace has a Private Access Settings (PAS) object attached — i.e. it uses
    (AWS/GCP) PrivateLink. None if it couldn't be determined (Azure workspaces have no PAS, so this
    returns False there). Best-effort so a read failure degrades to a warning rather than a crash."""
    try:
        ws = account.workspaces.get(workspace_id=int(workspace_id))
        return bool(getattr(ws, "private_access_settings_id", None))
    except Exception:  # noqa: BLE001 - couldn't determine; caller warns
        return None


def assigned_ingress_state(account, workspace_id) -> tuple[str | None, str | None]:
    """Inspect the network policy currently assigned to the workspace. Returns
    (assigned_policy_id, ingress_state) where ingress_state is 'enforced' (has an enforced ingress
    block), 'dry_run' (only a dry-run ingress block), or None (no policy assigned, or no ingress
    block on it). Best-effort."""
    try:
        opt = account.workspace_network_configuration.get_workspace_network_option_rpc(
            workspace_id=int(workspace_id))
        policy_id = getattr(opt, "network_policy_id", None)
    except Exception:  # noqa: BLE001
        return None, None
    if not policy_id:
        return None, None
    try:
        pol = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
    except Exception:  # noqa: BLE001
        return policy_id, None
    if getattr(pol, "ingress", None) is not None:
        return policy_id, "enforced"
    if getattr(pol, "ingress_dry_run", None) is not None:
        return policy_id, "dry_run"
    return policy_id, None


def promote_dry_run_to_enforced(account, policy_id: str, note: Note = lambda _m: None) -> None:
    """Move a policy's dry-run ingress block into the enforced ingress slot (clearing dry-run)."""
    pol = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
    pol.ingress = pol.ingress_dry_run
    pol.ingress_dry_run = None
    account.network_policies.update_network_policy_rpc(network_policy_id=policy_id, network_policy=pol)
    note(f"Promoted network policy '{policy_id}' from dry-run to enforced ingress.")


def disable_ip_access_lists(workspace_client, note: Note = lambda _m: None) -> bool:
    """Turn OFF workspace-wide IP access list enforcement via `enableIpAccessLists=false`.

    Disables enforcement of *all* the workspace's IP access lists at once; the lists themselves are
    preserved, so it's reversible by setting the flag back to true. Returns True if it changed state,
    False if enforcement was already off. The caller must ensure a replacement CBI policy has been
    created and assigned first (validate_disable_ip_acls enforces that invariant)."""
    status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
    # Enforcement is only ON when the flag is explicitly "true"; anything else (missing key = never
    # configured, empty, or "false") means there's nothing to disable, so skip the write.
    if str(status.get("enableIpAccessLists", "")).lower() != "true":
        note("Workspace IP access list enforcement is already off (never configured or already "
             "disabled) — no change needed.")
        return False
    workspace_client.workspace_conf.set_status({"enableIpAccessLists": "false"})
    note("Disabled workspace IP access list enforcement (enableIpAccessLists=false). The lists "
         "themselves are preserved — set it back to true to re-enable.")
    return True


def resolve_policy_id(cfg: AclConfig, workspace_id) -> str:
    """The new policy's id: the explicit/entered name (--policy-name, resolved by the CLI to the
    profile name when left blank), falling back to the workspace id if nothing was set. Slugified
    and length-capped like every other command."""
    return policy.policy_name("", explicit=(cfg.policy_name or str(workspace_id)))


def build_block(analysis: AclAnalysis, cfg: AclConfig, note: Note = lambda _m: None):
    return policy.build_ingress_block(
        analysis.allow_specs, analysis.deny_specs, cfg.policy_mode, "", note)


def build_account_policy(analysis: AclAnalysis, cfg: AclConfig, account_id: str, policy_id: str,
                         note: Note = lambda _m: None):
    """The full AccountNetworkPolicy this migration would create (egress + the ingress mode block).
    Used both to create the policy and to export a curl-ready JSON payload."""
    from databricks.sdk.service.settings import AccountNetworkPolicy
    np = AccountNetworkPolicy(account_id=account_id, network_policy_id=policy_id,
                              egress=build_egress(cfg.egress_policy))
    setattr(np, cfg.policy_mode_target, build_block(analysis, cfg, note))
    return np


def policy_payload(analysis: AclAnalysis, cfg: AclConfig, account_id: str) -> dict:
    """The proposed network policy as a plain dict (for --export / a curl body)."""
    policy_id = resolve_policy_id(cfg, analysis.workspace_id)
    return build_account_policy(analysis, cfg, account_id, policy_id).as_dict()


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
    """Create/update the named policy and optionally assign this workspace."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import WorkspaceNetworkOption

    policy_id = resolve_policy_id(cfg, analysis.workspace_id)
    try:
        existing = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        existing = None
        action = "created"

    if action == "created":
        new_policy = build_account_policy(analysis, cfg, account_id, policy_id, note)
        result = account.network_policies.create_network_policy_rpc(network_policy=new_policy)
        effective_id = result.network_policy_id or policy_id
    else:
        setattr(existing, cfg.policy_mode_target, build_block(analysis, cfg, note))
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
