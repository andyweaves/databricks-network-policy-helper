"""Unit tests for egress analyze/build, ACL analyze/apply, and the SQL query builders."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper import queries
from dbx_nwp_helper.config import AclConfig, EgressConfig
from dbx_nwp_helper.core import acl as acl_core
from dbx_nwp_helper.core import egress as eg


# ------------------------------------------------------------------------ egress recommendation
def test_egress_recommend_maps_owner():
    assert eg.recommend("Databricks") == "ALLOW — Databricks-owned"
    assert eg.recommend("AWS") == "REVIEW — Cloud-owned"
    assert eg.recommend("GCP") == "REVIEW — Cloud-owned"
    assert eg.recommend("Azure") == "REVIEW — Cloud-owned"
    assert eg.recommend("non-cloud / unknown") == "REVIEW — Other infra provider"
    assert eg.recommend("non-cloud: Cloudflare") == "REVIEW — Other infra provider"


def test_egress_recommend_unknown_when_no_lookup():
    # owner lookup disabled (None) or DNS failed -> don't claim a provider
    assert eg.recommend(None) == "REVIEW — owner unknown"
    assert eg.recommend("DNS resolution failed - check egress control") == "REVIEW — owner unknown"


# --------------------------------------------------------------------------------- egress
def test_egress_owner_lookup_rdap_fallback(monkeypatch):
    # FQDN resolves to an IP that's NOT in any cloud range -> RDAP fallback names the owner.
    observed = pd.DataFrame([
        {"destination": "api.example.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1], "resolved_ips": ["104.16.1.1"]}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])  # nothing matches offline
    from dbx_nwp_helper.feeds import rdap
    monkeypatch.setattr(rdap, "lookup", lambda ip: {"rdap_owner_name": "Cloudflare"})
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "non-cloud: Cloudflare"
    assert eg.recommend(a.fqdn_owner["api.example.com"]) == "REVIEW — Other infra provider"


def test_egress_owner_lookup_cloud_match_no_rdap(monkeypatch):
    # An IP in a cloud range is named directly; RDAP must NOT be called.
    observed = pd.DataFrame([
        {"destination": "api.example.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1], "resolved_ips": ["52.10.0.5"]}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    import ipaddress
    monkeypatch.setattr(eg, "_load_cloud_networks",
                        lambda: [(ipaddress.ip_network("52.10.0.0/16"), "AWS")])
    from dbx_nwp_helper.feeds import rdap
    monkeypatch.setattr(rdap, "lookup", lambda ip: (_ for _ in ()).throw(
        AssertionError("RDAP must not be called when the offline cloud match succeeds")))
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "AWS"


def test_egress_analyze_targets_and_union(monkeypatch):
    observed = pd.DataFrame([
        {"destination": "b.s3.us-west-2.amazonaws.com", "destination_type": "DNS", "events": 10,
         "workspace_ids": [1], "resolved_ips": []},
        {"destination": "mb.storage.googleapis.com", "destination_type": "DNS", "events": 3,
         "workspace_ids": [1], "resolved_ips": []},
        {"destination": "acct.blob.core.windows.net", "destination_type": "DNS", "events": 2,
         "workspace_ids": [1], "resolved_ips": []},
        {"destination": "api.openai.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1], "resolved_ips": ["1.2.3.4"]},
        {"destination": "s3.us-east-1.amazonaws.com", "destination_type": "DNS", "events": 1,
         "workspace_ids": [1], "resolved_ips": []},  # bare S3 -> skipped
    ])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {("b", "us-west-2"): 10}
    assert eg.union(a.targets, "gcs") == {"mb": 3}
    assert eg.union(a.targets, "azure") == {("acct", "blob"): 2}
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5}
    assert a.skipped_bare_s3 == 1


def test_egress_global_s3_region_inferred(monkeypatch):
    # <bucket>.s3.amazonaws.com has no region in the host -> infer it, keep the bucket.
    observed = pd.DataFrame([
        {"destination": "mybucket.s3.amazonaws.com", "destination_type": "DNS", "events": 4,
         "workspace_ids": [1], "resolved_ips": []}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: "us-east-1")
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {("mybucket", "us-east-1"): 4}
    assert a.dropped_s3_no_region == []


def test_egress_global_s3_region_uninferable_dropped(monkeypatch):
    # region can't be inferred -> drop the bucket, flag it, and never emit an invalid rule.
    observed = pd.DataFrame([
        {"destination": "mybucket.s3.amazonaws.com", "destination_type": "DNS", "events": 4,
         "workspace_ids": [1], "resolved_ips": []}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: None)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {}
    assert a.dropped_s3_no_region == ["mybucket"]
    # the built block must contain no S3 storage destination (no invalid region-less entry)
    assert eg.build_blocks(a, cfg) == {}


def test_egress_build_skips_regionless_s3_defensively():
    # Even if a region-less entry somehow reaches the target dict, the builder must skip it.
    a = eg.EgressAnalysis(observed=pd.DataFrame(),
                          targets={eg.ALL_WORKSPACES: {"s3": {("b", ""): 3}, "gcs": {}, "azure": {},
                                                       "internet": {}}})
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    # target has "content" (the s3 dict is non-empty) but the region-less entry is skipped ->
    # no allowed_storage_destinations
    block = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert not block.get("allowed_storage_destinations")


def test_egress_per_workspace_fans_out(monkeypatch):
    observed = pd.DataFrame([
        {"destination": "api.openai.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1, 2], "resolved_ips": []}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, policy_scope="per_workspace", block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert set(a.targets) == {1, 2}


def test_egress_build_blocks_restricted_with_enforcement(monkeypatch):
    observed = pd.DataFrame([
        {"destination": "api.openai.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1], "resolved_ips": []}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, policy_mode="enforce", block_threat_domains="off",
                       policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    prev = eg.preview_blocks(a, cfg)
    na = prev[eg.ALL_WORKSPACES]["egress"]["network_access"]
    assert na["restriction_mode"] == "RESTRICTED_ACCESS"
    assert na["policy_enforcement"]["enforcement_mode"] == "ENFORCED"


def test_egress_blocked_domains_matched_only(monkeypatch):
    observed = pd.DataFrame([
        {"destination": "evil.example.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1], "resolved_ips": []},
        {"destination": "good.example.com", "destination_type": "DNS", "events": 5,
         "workspace_ids": [1], "resolved_ips": []}])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_threat_domains", lambda feed: {"evil.example.com", "other.bad"})
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="matched_only")
    a = eg.analyze(cfg, sql_conn=None)
    # only the observed FQDN that is on the feed is blocked
    assert a.blocked_domains == ["evil.example.com"]


def test_egress_empty_produces_no_blocks(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: pd.DataFrame(
        columns=["destination", "destination_type", "events", "workspace_ids", "resolved_ips"]))
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.preview_blocks(a, cfg) == {}


# ------------------------------------------------------------------------------------- acl
class _FakeAcl:
    def __init__(self, label, list_type, enabled, ips):
        self.label, self.enabled, self.ip_addresses = label, enabled, ips
        self.list_type = type("LT", (), {"value": list_type})()


class _FakeWs:
    def __init__(self, acls, ws_id=42):
        self.ip_access_lists = type("A", (), {"list": lambda self=None: acls})()
        self._id = ws_id

    def get_workspace_id(self):
        return self._id


def test_acl_analyze_splits_allow_deny_ipv4_only():
    ws = _FakeWs([
        _FakeAcl("office", "ALLOW", True, ["8.8.8.8/32", "2001:db8::/32"]),
        _FakeAcl("bad", "BLOCK", True, ["9.9.9.0/24"]),
        _FakeAcl("off", "ALLOW", False, ["1.1.1.1"]),
    ])
    a = acl_core.analyze(AclConfig(name_prefix="np"), ws)
    assert a.workspace_id == 42
    assert len(a.allow_specs) == 1 and a.allow_specs[0]["cidrs"] == ["8.8.8.8/32"]  # ipv6 dropped
    assert len(a.deny_specs) == 1 and a.deny_specs[0]["cidrs"] == ["9.9.9.0/24"]


def test_acl_build_egress_kinds():
    for kind, mode in [("allow_all", "FULL_ACCESS"), ("dry_run", "RESTRICTED_ACCESS"),
                       ("restricted", "RESTRICTED_ACCESS")]:
        d = acl_core.build_egress(kind).as_dict()["network_access"]
        assert d["restriction_mode"] == mode


def test_acl_preview_block_target():
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])])
    cfg = AclConfig(policy_mode="dry_run", name_prefix="np")
    a = acl_core.analyze(cfg, ws)
    prev = acl_core.preview_block(a, cfg)
    assert "ingress_dry_run" in prev


# --------------------------------------------------------------------------------- queries
def test_frequent_public_ips_predicate_toggles():
    q_default = queries.frequent_public_ips(30, 1, include_ipv6=False,
                                            treat_null_status_as_success=False,
                                            include_account_level=False)
    assert "ip_version = 6" not in q_default
    # workspace_id is a STRING column -> compare against '0', not the integer 0.
    assert "CAST(workspace_id AS STRING) <> '0'" in q_default
    assert "workspace_id <> 0" not in q_default
    assert "status_code IS NULL AND FALSE" in q_default

    q_all = queries.frequent_public_ips(7, 5, include_ipv6=True,
                                        treat_null_status_as_success=True,
                                        include_account_level=True)
    assert "OR ip_version = 6" in q_all
    # the account-level filter predicate is omitted when including account-level rows
    assert "CAST(workspace_id AS STRING) <> '0'" not in q_all
    assert "status_code IS NULL AND TRUE" in q_all
    assert "INTERVAL 7 DAYS" in q_all
    assert "COUNT(*) >= 5" in q_all


def test_observed_egress_source_filter():
    assert "network_source_type = 'DBSQL'" in queries.observed_egress(30, 1, "DBSQL")
    assert "network_source_type =" not in queries.observed_egress(30, 1, "")


def test_denied_requests_query_filters_403():
    q = queries.denied_requests(14)
    assert "IpAccessDenied" in q and "status_code = 403" in q
    assert "INTERVAL 14 DAYS" in q
