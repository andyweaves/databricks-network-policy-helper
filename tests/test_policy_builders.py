"""Unit tests for the SDK policy-block builders + policy_name."""

from __future__ import annotations

from dbx_nwp_helper.core import policy


def _allow(**kw):
    base = {
        "label": "r",
        "cidrs": ["1.2.3.4/32"],
        "destination": "all_destinations",
        "identity_type": "ALL_USERS",
        "identities": [],
    }
    base.update(kw)
    return base


class _CreateAcct:
    """Fake account: the policy doesn't exist yet (create path). Captures the created object."""

    def __init__(self):
        from databricks.sdk.errors import NotFound

        parent = self
        self.created = None

        class _NP:
            def get_network_policy_rpc(self, network_policy_id):
                raise NotFound("no such policy")

            def create_network_policy_rpc(self, network_policy):
                parent.created = network_policy
                return network_policy

        self.network_policies = _NP()


class _UpdateAcct:
    """Fake account: the policy already exists (update path). Captures the updated object."""

    def __init__(self, existing):
        parent = self
        self.updated = None

        class _NP:
            def get_network_policy_rpc(self, network_policy_id):
                return existing

            def update_network_policy_rpc(self, network_policy_id, network_policy):
                parent.updated = network_policy

        self.network_policies = _NP()


def _restricted_egress():
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EA,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as ER,
    )
    from databricks.sdk.service.settings import NetworkPolicyEgress

    return NetworkPolicyEgress(network_access=EA(restriction_mode=ER.RESTRICTED_ACCESS))


def test_build_full_access_ingress_is_public_full_access():
    assert policy.build_full_access_ingress().as_dict()["public_access"]["restriction_mode"] == "FULL_ACCESS"


def test_apply_egress_create_adds_full_access_ingress_default():
    acct = _CreateAcct()
    policy.apply_egress(acct, "acc", "p", policy.build_full_access_egress())
    d = acct.created.as_dict()
    assert "egress" in d
    # a new egress-only policy gets a defined, permissive ingress rather than none
    assert d["ingress"]["public_access"]["restriction_mode"] == "FULL_ACCESS"


def test_apply_egress_update_leaves_existing_ingress_untouched():
    from databricks.sdk.service.settings import AccountNetworkPolicy

    existing = AccountNetworkPolicy(
        account_id="acc",
        network_policy_id="p",
        egress=policy.build_full_access_egress(),
        ingress=policy.build_ingress_block([_allow()], [], "enforced", ""),
    )
    acct = _UpdateAcct(existing)
    policy.apply_egress(acct, "acc", "p", _restricted_egress())
    # existing ingress rules preserved; egress replaced with the new (restricted) block
    assert acct.updated.ingress.public_access.allow_rules  # still there
    assert acct.updated.egress.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_apply_ingress_create_adds_full_access_egress_default():
    acct = _CreateAcct()
    block = policy.build_ingress_block([_allow()], [], "dry-run", "")
    policy.apply_ingress(acct, "acc", "p", block, "ingress")
    assert acct.created.as_dict()["egress"]["network_access"]["restriction_mode"] == "FULL_ACCESS"


def test_apply_ingress_update_leaves_existing_egress_untouched():
    from databricks.sdk.service.settings import AccountNetworkPolicy

    existing = AccountNetworkPolicy(account_id="acc", network_policy_id="p", egress=_restricted_egress())
    acct = _UpdateAcct(existing)
    block = policy.build_ingress_block([_allow()], [], "enforced", "")
    policy.apply_ingress(acct, "acc", "p", block, "ingress")
    # the pre-existing restricted egress is preserved, not overwritten with a full-access default
    assert acct.updated.egress.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_ingress_rule_ip_ranges_wrapped():
    rule = policy.build_ingress_rule(_allow(), "dry-run").as_dict()
    assert rule["origin"]["included_ip_ranges"]["ip_ranges"] == ["1.2.3.4/32"]
    assert rule["destination"]["all_destinations"] is True
    assert rule["label"].endswith("(dry-run)")


def test_ingress_rule_apps_and_lakebase_destinations():
    apps = policy.build_ingress_rule(_allow(destination="apps_runtime"), "dry-run").as_dict()
    assert apps["destination"]["apps_runtime"]["all_destinations"] is True
    lb = policy.build_ingress_rule(_allow(destination="lakebase_runtime"), "dry-run").as_dict()
    assert lb["destination"]["lakebase_runtime"]["all_destinations"] is True


def test_ingress_rule_selected_identities_auth_omitted_on_broad_destinations():
    # The CBI API rejects an authentication block on Apps / Lakebase / all_destinations rules, so
    # even with SELECTED_IDENTITIES the builder must omit it (otherwise apply 400s).
    ids = [
        {"principal_id": 42, "principal_type": "USER"},
        {"principal_id": 7, "principal_type": "SERVICE_PRINCIPAL"},
    ]
    for dest in ("all_destinations", "apps_runtime", "lakebase_runtime"):
        spec = _allow(destination=dest, identity_type="SELECTED_IDENTITIES", identities=ids)
        rule = policy.build_ingress_rule(spec, "enforced").as_dict()
        assert "authentication" not in rule, dest


def test_catch_all_origin():
    rule = policy.build_ingress_rule(_allow(catch_all=True), "dry-run").as_dict()
    assert rule["origin"]["all_ip_ranges"] is True
    assert "included_ip_ranges" not in rule["origin"]


def test_deny_rule_shape():
    rule = policy.build_deny_rule({"label": "d", "cidrs": ["9.9.9.0/24"]}, "enforced").as_dict()
    assert rule["origin"]["included_ip_ranges"]["ip_ranges"] == ["9.9.9.0/24"]
    assert rule["destination"]["all_destinations"] is True


def test_deny_without_allow_injects_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[],
        deny=[{"label": "np-deny", "cidrs": ["9.9.9.0/24"]}],
        mode_label="dry-run",
        note=notes.append,
    ).as_dict()
    pub = block["public_access"]
    assert pub["allow_rules"][0]["origin"]["all_ip_ranges"] is True
    assert pub["deny_rules"]
    assert any("catch-all" in n for n in notes)


def test_allow_with_deny_no_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[_allow()],
        deny=[{"label": "d", "cidrs": ["9.9.9.0/24"]}],
        mode_label="dry-run",
        note=notes.append,
    ).as_dict()
    pub = block["public_access"]
    assert len(pub["allow_rules"]) == 1
    assert pub["allow_rules"][0]["origin"].get("all_ip_ranges") is None
    assert not notes  # no catch-all note


def test_restriction_mode_always_restricted():
    block = policy.build_ingress_block([_allow()], [], "dry-run", "np").as_dict()
    assert block["public_access"]["restriction_mode"] == "RESTRICTED_ACCESS"


def test_full_access_egress():
    egr = policy.build_full_access_egress().as_dict()
    assert egr["network_access"]["restriction_mode"] == "FULL_ACCESS"


def test_policy_name_single_truncates_prefix():
    assert policy.policy_name("np-helper") == "np-helper"
    long = policy.policy_name("x" * 50)
    assert len(long) == 30


def test_policy_name_per_workspace_keeps_full_id():
    name = policy.policy_name("np-helper", workspace_id=1657683783405196)
    # the full workspace id is always preserved, even if the prefix must be trimmed
    assert name.endswith("-ws-1657683783405196")


def test_policy_name_per_workspace_trims_long_prefix():
    # a long prefix + a long ws id exceeds the 30-char budget -> prefix trimmed, id kept whole
    name = policy.policy_name("really-long-prefix-name", workspace_id=1657683783405196)
    assert name.endswith("-ws-1657683783405196")
    assert not name.startswith("really-long-prefix-name")


def test_policy_name_long_prefix_per_workspace_within_budget():
    name = policy.policy_name("really-long-prefix-name", workspace_id=42)
    assert name.endswith("-ws-42")


def test_policy_name_current_workspace_uses_profile_suffix():
    assert policy.policy_name("np-helper", suffix="sfe-plain") == "np-helper-sfe-plain"


def test_policy_name_suffix_is_slugified():
    # a profile with spaces / odd chars is normalised to a policy-id-safe slug
    name = policy.policy_name("np", suffix="My Prod Workspace!")
    assert name == "np-my-prod-workspace"


def test_policy_name_suffix_trims_prefix_to_fit():
    name = policy.policy_name("really-long-prefix-name", suffix="my-workspace-profile")
    assert name.endswith("-my-workspace-profile")
    assert len(name) <= 30


def test_policy_name_explicit_overrides_and_slugifies():
    # an explicit --policy-name wins over the derived id and is normalised to an id-safe slug
    assert policy.policy_name("np", explicit="My Prod Policy!") == "my-prod-policy"
    assert policy.policy_name("np", workspace_id=42, explicit="chosen-name") == "chosen-name"


def test_policy_name_explicit_capped_to_limit():
    assert len(policy.policy_name("np", explicit="x" * 60)) == 30


def test_policy_name_explicit_empty_slug_falls_back_to_prefix():
    # a name that slugs away to nothing falls back to the (slugified) prefix, never an empty id
    assert policy.policy_name("np-helper", explicit="!!!") == "np-helper"
