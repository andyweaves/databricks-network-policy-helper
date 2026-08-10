"""Unit tests for the SDK policy-block builders + policy_name."""

from __future__ import annotations

from dbx_netpolicy.core import policy


def _allow(**kw):
    base = {"label": "r", "cidrs": ["1.2.3.4/32"], "destination": "all_destinations",
            "identity_type": "ALL_USERS", "identities": []}
    base.update(kw)
    return base


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


def test_ingress_rule_selected_identities():
    spec = _allow(identity_type="SELECTED_IDENTITIES",
                  identities=[{"principal_id": 42, "principal_type": "USER"},
                              {"principal_id": 7, "principal_type": "SERVICE_PRINCIPAL"}])
    rule = policy.build_ingress_rule(spec, "enforced").as_dict()
    auth = rule["authentication"]
    assert auth["identity_type"] == "IDENTITY_TYPE_SELECTED_IDENTITIES"
    ids = auth["identities"]
    assert {i["principal_id"] for i in ids} == {42, 7}
    assert any(i["principal_type"] == "PRINCIPAL_TYPE_USER" for i in ids)
    assert any(i["principal_type"] == "PRINCIPAL_TYPE_SERVICE_PRINCIPAL" for i in ids)


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
        allow=[], deny=[{"label": "np-deny", "cidrs": ["9.9.9.0/24"]}],
        mode_label="dry-run", name_prefix="np", note=notes.append).as_dict()
    pub = block["public_access"]
    assert pub["allow_rules"][0]["origin"]["all_ip_ranges"] is True
    assert pub["deny_rules"]
    assert any("catch-all" in n for n in notes)


def test_allow_with_deny_no_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[_allow()], deny=[{"label": "d", "cidrs": ["9.9.9.0/24"]}],
        mode_label="dry-run", name_prefix="np", note=notes.append).as_dict()
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
