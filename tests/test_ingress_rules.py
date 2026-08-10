"""Unit tests for the ingress rule-assembly logic (core/ingress_rules.py).

Builds IngressAnalysis objects directly (no SQL / no network) to exercise build_rules across
scoping modes, ACL handling, denied-IP deny rules, and threat-deny prioritisation, plus
resolve_identities and apply against fake account clients.
"""

from __future__ import annotations

import ipaddress

import pandas as pd

from dbx_netpolicy.config import IngressConfig
from dbx_netpolicy.core import ingress_rules as rules
from dbx_netpolicy.core.ingress import ALL_WORKSPACES, IngressAnalysis


def _suggestion(**kw):
    base = {
        "policy_target": ALL_WORKSPACES, "rdap_owner": "Acme", "distinct_ips": 1, "total_events": 10,
        "principals": [], "principal_emails": [], "subject_names": [],
        "scoped_destination": "all_destinations",
        "minimal_cidrs": ["203.0.55.10/32"], "optimal_cidrs": ["203.0.55.10/32"], "maximum_cidrs": None,
        "threat_feeds": None, "cloud_provider": None, "databricks_owned": None,
        "recommendation": "candidate",
    }
    base.update(kw)
    return base


def _analysis(suggestion_rows=None, ip_acls=None, denied=None, threat_match_rows=None,
              threat_ranges=None):
    rows = suggestion_rows or []
    sugg = pd.DataFrame(rows) if rows else pd.DataFrame()
    return IngressAnalysis(
        candidates=pd.DataFrame(), suggestions=sugg, threat_matches=pd.DataFrame(),
        denied_requests=denied if denied is not None else pd.DataFrame(columns=["source_ip"]),
        ip_acls=ip_acls or [], suggestion_rows=rows, threat_match_rows=threat_match_rows or [],
        threat_ranges=threat_ranges or [])


# ------------------------------------------------------------------- scoping / framing
def test_ip_only_collapses_to_single_blanket_rule():
    a = _analysis([_suggestion(rdap_owner="A", minimal_cidrs=["1.1.1.1/32"]),
                   _suggestion(rdap_owner="B", minimal_cidrs=["2.2.2.2/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", policy_framing="minimal"))
    allow = pols[ALL_WORKSPACES]["allow"]
    assert len(allow) == 1
    assert allow[0]["label"].endswith("-ip-only")
    assert set(allow[0]["cidrs"]) == {"1.1.1.1/32", "2.2.2.2/32"}


def test_flagged_groups_excluded_and_counted():
    a = _analysis([
        _suggestion(rdap_owner="clean", minimal_cidrs=["1.1.1.1/32"]),
        _suggestion(rdap_owner="bad", threat_feeds=["ipsum"], minimal_cidrs=["9.9.9.9/32"]),
        _suggestion(rdap_owner="cloud", cloud_provider=["aws"], minimal_cidrs=["8.8.8.8/32"]),
    ])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
    cidrs = pols[ALL_WORKSPACES]["allow"][0]["cidrs"]
    assert cidrs == ["1.1.1.1/32"]
    assert a.excluded_flagged == 2


def test_databricks_owned_included_despite_cloud_flag():
    a = _analysis([_suggestion(rdap_owner="dbx", cloud_provider=["aws"],
                               databricks_owned=["aws"], minimal_cidrs=["4.4.4.4/32"])])
    # non-ip_only so the databricks rule keeps its own label
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_destination"))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert any("databricks" in lbl for lbl in labels)
    assert a.excluded_flagged == 0


def test_destination_scoping_applied_for_non_databricks():
    a = _analysis([_suggestion(rdap_owner="apps", scoped_destination="apps_runtime",
                               minimal_cidrs=["5.5.5.5/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_destination"))
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["destination"] == "apps_runtime"


def test_optimal_framing_uses_optimal_column():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"], optimal_cidrs=["1.1.1.0/24"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", policy_framing="optimal"))
    assert pols[ALL_WORKSPACES]["allow"][0]["cidrs"] == ["1.1.1.0/24"]


def test_ipv6_cidrs_skipped_and_counted():
    a = _analysis([_suggestion(minimal_cidrs=["2001:db8::1/128", "1.2.3.4/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_destination", policy_framing="minimal"))
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["cidrs"] == ["1.2.3.4/32"]
    assert a.skipped_ipv6 == 1


# --------------------------------------------------------------------------- identity scoping
def test_identity_scoping_selected_identities():
    a = _analysis([_suggestion(principal_emails=["a@x.com"], subject_names=[],
                               minimal_cidrs=["1.1.1.1/32"])])
    ident = {"a@x.com": {"principal_id": 42, "principal_type": "USER"}}
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_identity"), identity_resolution=ident)
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["identity_type"] == "SELECTED_IDENTITIES"
    assert spec["identities"] == [{"principal_id": 42, "principal_type": "USER"}]


def test_identity_scoping_unresolved_labels_rule():
    a = _analysis([_suggestion(principal_emails=["ghost@x.com"], minimal_cidrs=["1.1.1.1/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_identity"), identity_resolution={})
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["identity_type"] == "ALL_USERS"
    assert "identity-unresolved" in spec["label"]


# ------------------------------------------------------------------------------- ACL handling
def _acl(label, list_type, ips, enabled=True):
    return {"label": label, "list_type": list_type, "enabled": enabled, "ip_addresses": ips}


def test_acl_migrate_and_enrich_adds_acl_allow_to_traffic():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])],
                  ip_acls=[_acl("office", "ALLOW", ["8.8.8.8/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only",
                                              ip_acl_handling="migrate_and_enrich"))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert any(lbl.endswith("-ip-only") for lbl in labels)
    assert any("acl-office" in lbl for lbl in labels)


def test_acl_migrate_only_drops_traffic_rules():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])],
                  ip_acls=[_acl("office", "ALLOW", ["8.8.8.8/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", ip_acl_handling="migrate"))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert all("ip-only" not in lbl for lbl in labels)
    assert any("acl-office" in lbl for lbl in labels)


def test_acl_ignore_excludes_acl():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])],
                  ip_acls=[_acl("office", "ALLOW", ["8.8.8.8/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", ip_acl_handling="ignore"))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert not any("acl" in lbl for lbl in labels)


def test_acl_block_becomes_deny_rule():
    a = _analysis(ip_acls=[_acl("blocklist", "BLOCK", ["6.6.6.0/24"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
    deny = pols[ALL_WORKSPACES]["deny"]
    assert any("acl-blocklist" in s["label"] for s in deny)


def test_disabled_acl_skipped():
    a = _analysis(ip_acls=[_acl("off", "ALLOW", ["8.8.8.8/32"], enabled=False)])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
    assert pols == {} or not pols.get(ALL_WORKSPACES, {}).get("allow")


# --------------------------------------------------------------------------- denied-IP deny rules
def test_deny_denied_ips_builds_deny_rule():
    denied = pd.DataFrame([{"source_ip": "70.1.2.3"}, {"source_ip": "70.1.2.3"},
                           {"source_ip": "2001:db8::1"}])
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])], denied=denied)
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", deny_denied_ips=True))
    deny = pols[ALL_WORKSPACES]["deny"]
    denied_rule = [s for s in deny if "currently-denied" in s["label"]][0]
    assert denied_rule["cidrs"] == ["70.1.2.3/32"]  # deduped, IPv6 dropped


# ---------------------------------------------------------------------- threat-intel deny rules
def _tr(cidr, feed, ttype, conf):
    return (ipaddress.ip_network(cidr), {"source_feed": feed, "threat_type": ttype, "confidence": conf})


def test_threat_deny_all_one_rule_per_feed():
    a = _analysis(threat_ranges=[
        _tr("9.9.9.0/24", "ipsum", "aggregated_blocklist", 1),
        _tr("8.8.8.0/24", "dshield", "attacker_subnet", 1),
        _tr("2001:db8::/32", "ipsum", "x", 1),  # ipv6 skipped
    ])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="all"))
    deny = pols.get(ALL_WORKSPACES, {}).get("deny", [])
    feeds = {s["label"].split("-deny-")[-1] for s in deny}
    assert feeds == {"ipsum", "dshield"}
    for s in deny:
        assert all(ipaddress.ip_network(c).version == 4 for c in s["cidrs"])


def test_threat_deny_matched_only_uses_match_rows():
    a = _analysis(threat_match_rows=[
        {"matched_cidr": "9.9.9.0/24", "source_feed": "ipsum",
         "threat_type": "aggregated_blocklist", "confidence": 2}])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="matched_only"))
    deny = pols.get(ALL_WORKSPACES, {}).get("deny", [])
    assert any(s["cidrs"] == ["9.9.9.0/24"] for s in deny)


def test_threat_deny_dedupes_keeping_most_severe():
    # same cidr, one conf2 non-attacker + one conf1 attacker -> attacker/conf1 wins.
    a = _analysis(threat_ranges=[
        _tr("9.9.9.0/24", "ipsum", "aggregated_blocklist", 2),
        _tr("9.9.9.0/24", "dshield", "attacker_subnet", 1)])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="all"))
    deny = pols[ALL_WORKSPACES]["deny"]
    # only the dshield/attacker entry survives dedupe
    assert len(deny) == 1
    assert "dshield" in deny[0]["label"]


# ----------------------------------------------------------------------------- apply + resolve
class _FakeUser:
    def __init__(self, _id):
        self.id = _id


class _FakeScim:
    def __init__(self, mapping):
        self._m = mapping

    def list(self, filter, count=1):  # noqa: A002 - matches SDK kwarg name
        for key, val in self._m.items():
            if f'"{key}"' in filter:
                return [_FakeUser(val)]
        return []


class _FakeNetworkPolicies:
    def __init__(self):
        self.created, self.updated = [], []

    def get_network_policy_rpc(self, network_policy_id):
        from databricks.sdk.errors import NotFound
        raise NotFound("nope")

    def create_network_policy_rpc(self, network_policy):
        self.created.append(network_policy)
        return network_policy


class _FakeWsNetConfig:
    def __init__(self):
        self.bound = []

    def update_workspace_network_option_rpc(self, workspace_id, workspace_network_option):
        self.bound.append(workspace_id)


class _FakeAccount:
    def __init__(self, user_map=None):
        self.network_policies = _FakeNetworkPolicies()
        self.workspace_network_configuration = _FakeWsNetConfig()
        self.users = _FakeScim(user_map or {})
        self.service_principals = _FakeScim({})


def test_resolve_identities_maps_users():
    a = _analysis([_suggestion(principal_emails=["a@x.com"], subject_names=[])])
    acct = _FakeAccount(user_map={"a@x.com": 99})
    res = rules.resolve_identities(a, acct)
    assert res == {"a@x.com": {"principal_id": 99, "principal_type": "USER"}}


def test_apply_single_create_new_no_assign():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])
    cfg = IngressConfig(scoping_mode="ip_only", name_prefix="np-smoke")
    cfg.apply.create_policy = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=123)
    assert results[0]["action"] == "created"
    assert results[0]["policy_id"] == "np-smoke"
    assert "assigned" not in results[0]
    assert acct.workspace_network_configuration.bound == []


def test_apply_single_auto_assign_binds_workspace():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])
    cfg = IngressConfig(scoping_mode="ip_only", name_prefix="np")
    cfg.apply.create_policy = True
    cfg.apply.auto_assign = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=555)
    assert results[0]["assigned"] == 555
    assert acct.workspace_network_configuration.bound == [555]
