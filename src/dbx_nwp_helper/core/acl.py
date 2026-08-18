"""Network-policy state queries used by the ingress / egress apply pre-checks.

These helpers inspect the workspace's PrivateLink configuration and the network policy currently
assigned to it — so the `ingress` / `egress` commands can refuse to overwrite an enforced restrictive
policy (or warn about a dry-run one) before they create + assign a new one. Also carries
`disable_ip_access_lists`, which `ingress --disable-existing-ip-acls` uses to turn off the workspace's
old IP access lists once a replacement CBI policy is created and assigned.

The verbatim IP-ACL → CBI *migration* engine now lives in its own tool,
`databricks-migrate-ip-acls` (the `dbx-migrate-ip-acls` command).
"""

from __future__ import annotations

from collections.abc import Callable

Note = Callable[[str], None]


def workspace_pas_attached(account, workspace_id) -> bool | None:
    """True if the workspace has a Private Access Settings (PAS) object attached — i.e. it uses
    (AWS/GCP) PrivateLink. None if it couldn't be determined (Azure workspaces have no PAS, so this
    returns False there). Best-effort so a read failure degrades to a warning rather than a crash."""
    try:
        ws = account.workspaces.get(workspace_id=int(workspace_id))
        return bool(getattr(ws, "private_access_settings_id", None))
    except Exception:  # noqa: BLE001 - couldn't determine; caller warns
        return None


def _block_restrictive(blk) -> bool:
    """True if a single access sub-block restricts traffic — RESTRICTED_ACCESS mode, or any
    allow/deny rules. Permissive defaults (FULL_ACCESS / ALLOW_ALL_REGISTERED_ENDPOINTS / LEGACY_MODE
    with no rules) return False."""
    if blk is None:
        return False
    rm = getattr(blk, "restriction_mode", None)
    if str(getattr(rm, "value", rm) or "") == "RESTRICTED_ACCESS":
        return True
    return bool(getattr(blk, "allow_rules", None) or getattr(blk, "deny_rules", None))


def public_restrictive(ingress) -> bool:
    """True if the ingress block's public_access (source-IP) sub-block is restrictive."""
    return ingress is not None and _block_restrictive(getattr(ingress, "public_access", None))


def private_or_xws_restrictive(ingress) -> bool:
    """True if the ingress block's private_access (PrivateLink) or cross_workspace_access sub-block
    is restrictive — the parts the public-IP helpers don't build and can't yet preserve."""
    if ingress is None:
        return False
    return (_block_restrictive(getattr(ingress, "private_access", None))
            or _block_restrictive(getattr(ingress, "cross_workspace_access", None)))


def egress_restrictive(egress) -> bool:
    """True if a policy's egress block restricts outbound traffic — RESTRICTED_ACCESS mode, or any
    allow/block destination lists. A FULL_ACCESS egress (the permissive default an ingress-only
    policy carries) — or None — returns False."""
    if egress is None:
        return False
    na = getattr(egress, "network_access", None)
    if na is None:
        return False
    rm = getattr(na, "restriction_mode", None)
    if str(getattr(rm, "value", rm) or "") == "RESTRICTED_ACCESS":
        return True
    return bool(getattr(na, "allowed_internet_destinations", None)
                or getattr(na, "allowed_storage_destinations", None)
                or getattr(na, "blocked_internet_destinations", None))


def egress_enforced(egress) -> bool:
    """True if a restrictive egress block is ENFORCED (blocking). A DRY_RUN (or unset) enforcement
    mode is log-only. Only meaningful alongside egress_restrictive()."""
    na = getattr(egress, "network_access", None)
    pe = getattr(na, "policy_enforcement", None) if na is not None else None
    mode = getattr(pe, "enforcement_mode", None)
    return str(getattr(mode, "value", mode) or "") == "ENFORCED"


def assigned_policy(account, workspace_id) -> tuple[str | None, object | None]:
    """(assigned_policy_id, full policy object) for the workspace — (id, None) if the policy read
    failed, (None, None) if nothing is assigned. Best-effort."""
    try:
        opt = account.workspace_network_configuration.get_workspace_network_option_rpc(
            workspace_id=int(workspace_id))
        policy_id = getattr(opt, "network_policy_id", None)
    except Exception:  # noqa: BLE001
        return None, None
    if not policy_id:
        return None, None
    try:
        return policy_id, account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
    except Exception:  # noqa: BLE001
        return policy_id, None


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
