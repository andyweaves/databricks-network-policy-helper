"""SDK dataclass builders + create/update/assign for account network policies.

Shared by the ingress and ACL engines. The build_* functions turn plain rule-spec dicts into the
`CustomerFacingIngressNetworkPolicy*` / `NetworkPolicyEgress` dataclasses so the JSON you preview is
exactly what gets sent. apply_ingress()/apply_egress() do the gated create-or-update; assign() binds a
workspace. Ported from the notebooks' apply cells.
"""

from __future__ import annotations

from collections.abc import Callable

from ..config import MAX_POLICY_ID_LEN

Note = Callable[[str], None]


# --------------------------------------------------------------------------- ingress block builders
def build_ingress_rule(spec: dict, mode_label: str):
    from databricks.sdk.service.settings import (  # noqa: I001
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

    origin = (Origin(all_ip_ranges=True) if spec.get("catch_all")
              else Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"]))))

    if spec.get("destination") == "apps_runtime":
        destination = Destination(apps_runtime=AppsDest(all_destinations=True))
    elif spec.get("destination") == "lakebase_runtime":
        destination = Destination(lakebase_runtime=LakebaseDest(all_destinations=True))
    else:
        destination = Destination(all_destinations=True)

    authentication = None
    if spec.get("identity_type") == "SELECTED_IDENTITIES" and spec.get("identities"):
        identities = [
            Identity(
                principal_id=i["principal_id"],
                principal_type=(PrincipalType.PRINCIPAL_TYPE_USER if i["principal_type"] == "USER"
                                else PrincipalType.PRINCIPAL_TYPE_SERVICE_PRINCIPAL),
            )
            for i in spec["identities"]
        ]
        authentication = Auth(
            identity_type=IdentityType.IDENTITY_TYPE_SELECTED_IDENTITIES, identities=identities)

    return Rule(label=f"{spec['label']} ({mode_label})",
                origin=origin, destination=destination, authentication=authentication)


def build_deny_rule(spec: dict, mode_label: str):
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )
    return Rule(label=f"{spec['label']} ({mode_label})",
                origin=Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"]))),
                destination=Destination(all_destinations=True))


def build_ingress_block(allow: list[dict], deny: list[dict], mode_label: str, name_prefix: str,
                        note: Note = lambda _m: None):
    """Assemble a CustomerFacingIngressNetworkPolicy from allow specs (+ optional deny specs).

    RESTRICTED_ACCESS is default-DENY; if a policy ends up with deny rules but no allow rules,
    everything would be blocked — add a catch-all allow (all public IPs) to preserve
    "block these, allow the rest"."""
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicy as IngressPolicy,
        CustomerFacingIngressNetworkPolicyPublicAccess as PublicAccess,
        CustomerFacingIngressNetworkPolicyPublicAccessRestrictionMode as RestrictionMode,
    )
    allow = list(allow)
    if (deny or []) and not allow:
        allow = [{"label": f"{name_prefix}-allow-all", "catch_all": True,
                  "destination": "all_destinations", "identity_type": "ALL_USERS", "identities": []}]
        note("Policy has deny rules but no allow rules — added a catch-all allow (all public IPs) "
             "so non-denied traffic is still permitted (default-allow-except-blocked).")

    public = PublicAccess(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allow_rules=[build_ingress_rule(s, mode_label) for s in allow],
        deny_rules=[build_deny_rule(s, mode_label) for s in (deny or [])] or None,
    )
    return IngressPolicy(public_access=public)


def build_full_access_egress():
    """A permissive (FULL_ACCESS) egress block — used when an ingress-only helper creates a new
    policy (the API requires an egress block on create)."""
    from databricks.sdk.service.settings import (  # noqa: I001
        EgressNetworkPolicyNetworkAccessPolicy as EgressAccess,
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as EgressRestriction,
        NetworkPolicyEgress,
    )
    return NetworkPolicyEgress(network_access=EgressAccess(restriction_mode=EgressRestriction.FULL_ACCESS))


# --------------------------------------------------------------------------------- policy id naming
def policy_name(name_prefix: str, workspace_id: int | None = None) -> str:
    """Deterministic policy id. single -> <prefix>; per_workspace -> <prefix>-ws-<id> (keep the full
    workspace id, truncate the prefix to fit the length limit)."""
    if workspace_id is not None:
        suffix = f"-ws-{workspace_id}"
        room = MAX_POLICY_ID_LEN - len(suffix)
        return f"{name_prefix[:max(room, 1)].rstrip('-')}{suffix}"
    return name_prefix[:MAX_POLICY_ID_LEN]


# ----------------------------------------------------------------------------------- apply (writes)
def apply_ingress(account, account_id: str, policy_id: str, block, target_attr: str,
                  must_exist: bool = False) -> tuple[str, str, dict]:
    """Create-or-update policy `policy_id`, setting its target ingress block (ingress|ingress_dry_run)
    and leaving other blocks + egress unchanged (update is a full replace). Returns
    (action, effective_id, sent_block_dict)."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy

    try:
        existing = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        if must_exist:
            raise ValueError(
                f"policy_action=add_to_existing but no network policy '{policy_id}' was found. "
                "Check --existing-policy-id (create it first, or use create_new)."
            ) from None
        existing = AccountNetworkPolicy(
            account_id=account_id, network_policy_id=policy_id, egress=build_full_access_egress())
        action = "created"

    setattr(existing, target_attr, block)
    if action == "created":
        result = account.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or policy_id
        sent = getattr(result, target_attr, None) or getattr(existing, target_attr)
    else:
        account.network_policies.update_network_policy_rpc(
            network_policy_id=policy_id, network_policy=existing)
        effective_id = policy_id
        sent = getattr(existing, target_attr)
    return action, effective_id, sent.as_dict()


def apply_egress(account, account_id: str, policy_id: str, egress_block,
                 must_exist: bool = False) -> tuple[str, str]:
    """Create-or-update policy `policy_id`, replacing only its egress block (ingress untouched).
    Returns (action, effective_id)."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy

    try:
        existing = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        if must_exist:
            raise ValueError(
                f"policy_action=add_to_existing but no network policy '{policy_id}' was found. "
                "Check --existing-policy-id (create it first, or use create_new)."
            ) from None
        existing = AccountNetworkPolicy(account_id=account_id, network_policy_id=policy_id)
        action = "created"

    existing.egress = egress_block
    if action == "created":
        result = account.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or policy_id
    else:
        account.network_policies.update_network_policy_rpc(
            network_policy_id=policy_id, network_policy=existing)
        effective_id = policy_id
    return action, effective_id


def assign(account, workspace_id: int, policy_id: str) -> None:
    from databricks.sdk.service.settings import WorkspaceNetworkOption
    account.workspace_network_configuration.update_workspace_network_option_rpc(
        workspace_id=int(workspace_id),
        workspace_network_option=WorkspaceNetworkOption(
            workspace_id=int(workspace_id), network_policy_id=policy_id),
    )
