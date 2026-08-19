"""Unit tests for egress analyze/build, ACL analyze/apply, and the SQL query builders."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper import queries
from dbx_nwp_helper.config import EgressConfig
from dbx_nwp_helper.core import acl as acl_core
from dbx_nwp_helper.core import egress as eg


# ------------------------------------------------------------------------ egress recommendation
def test_egress_recommend_maps_owner():
    assert eg.recommend("Databricks") == "ALLOW — Databricks-owned"
    assert eg.recommend("AWS") == "REVIEW — Cloud-owned"
    assert eg.recommend("GCP") == "REVIEW — Cloud-owned"
    assert eg.recommend("Azure") == "REVIEW — Cloud-owned"
    # a named non-cloud owner (from RDAP)
    assert eg.recommend("Cloudflare, Inc.") == "REVIEW — Other infra provider"


def test_egress_recommend_unknown_when_no_lookup():
    # owner lookup disabled (None), an explicit Unknown, or DNS failed -> don't claim a provider
    assert eg.recommend(None) == "REVIEW — owner unknown"
    assert eg.recommend("Unknown") == "REVIEW — owner unknown"
    assert eg.recommend("DNS resolution failed - check egress control") == "REVIEW — owner unknown"


# --------------------------------------------------------------------------------- egress
def test_egress_owner_lookup_rdap_fallback(monkeypatch):
    # FQDN resolves to an IP that's NOT in any cloud range -> RDAP fallback names the owner.
    observed = pd.DataFrame(
        [
            {
                "destination": "api.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["104.16.1.1"],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])  # nothing matches offline
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(rdap, "lookup", lambda ip: {"rdap_owner_name": "Cloudflare"})
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "Cloudflare"  # just the owner, no "non-cloud:" prefix
    assert eg.recommend(a.fqdn_owner["api.example.com"]) == "REVIEW — Other infra provider"


def test_egress_owner_unknown_when_rdap_also_misses(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "api.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["104.16.1.1"],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(rdap, "lookup", lambda ip: {"rdap_owner_name": None})
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "Unknown"


def test_egress_owner_lookup_cloud_match_no_rdap(monkeypatch):
    # An IP in a cloud range is named directly; RDAP must NOT be called.
    observed = pd.DataFrame(
        [
            {
                "destination": "api.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["52.10.0.5"],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    import ipaddress

    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [(ipaddress.ip_network("52.10.0.0/16"), "AWS")])
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(
        rdap,
        "lookup",
        lambda ip: (_ for _ in ()).throw(
            AssertionError("RDAP must not be called when the offline cloud match succeeds")
        ),
    )
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "AWS"


def test_egress_analyze_targets_and_union(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "b.s3.us-west-2.amazonaws.com",
                "destination_type": "DNS",
                "events": 10,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "mb.storage.googleapis.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "acct.blob.core.windows.net",
                "destination_type": "DNS",
                "events": 2,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["1.2.3.4"],
            },
            {
                "destination": "s3.us-east-1.amazonaws.com",
                "destination_type": "DNS",
                "events": 1,
                "workspace_ids": [1],
                "resolved_ips": [],
            },  # bare S3 -> skipped
        ]
    )
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
    observed = pd.DataFrame(
        [
            {
                "destination": "mybucket.s3.amazonaws.com",
                "destination_type": "DNS",
                "events": 4,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: "us-east-1")
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {("mybucket", "us-east-1"): 4}
    assert a.dropped_s3_no_region == []


def test_egress_global_s3_region_uninferable_dropped(monkeypatch):
    # region can't be inferred -> drop the bucket, flag it, and never emit an invalid rule.
    observed = pd.DataFrame(
        [
            {
                "destination": "mybucket.s3.amazonaws.com",
                "destination_type": "DNS",
                "events": 4,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
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
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {("b", ""): 3}, "gcs": {}, "azure": {}, "internet": {}}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    # target has "content" (the s3 dict is non-empty) but the region-less entry is skipped ->
    # no allowed_storage_destinations
    block = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert not block.get("allowed_storage_destinations")


def test_egress_per_workspace_fans_out(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1, 2],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, policy_scope="per_workspace", block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert set(a.targets) == {1, 2}


def test_egress_build_blocks_restricted_with_enforcement(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(
        enable_rdap=False, policy_mode="enforce", block_threat_domains="off", policy_scope="all_workspaces"
    )
    a = eg.analyze(cfg, sql_conn=None)
    prev = eg.preview_blocks(a, cfg)
    na = prev[eg.ALL_WORKSPACES]["egress"]["network_access"]
    assert na["restriction_mode"] == "RESTRICTED_ACCESS"
    assert na["policy_enforcement"]["enforcement_mode"] == "ENFORCED"


def test_egress_blocked_domains_matched_only(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "evil.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "good.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_threat_domains", lambda feed: {"evil.example.com", "other.bad"})
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="matched_only")
    a = eg.analyze(cfg, sql_conn=None)
    # only the observed FQDN that is on the feed is blocked
    assert a.blocked_domains == ["evil.example.com"]


def test_egress_warns_and_caps_over_internet_limit():
    # >100 internet FQDNs must be capped to the limit AND the operator warned (silent truncation
    # would block the dropped destinations in enforce mode).
    internet = {f"h{i}.example.com": 1 for i in range(eg.MAX_INTERNET_DESTINATIONS + 25)}
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": internet}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    notes = []
    blocks = eg.build_blocks(a, cfg, note=notes.append)
    dests = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]["allowed_internet_destinations"]
    assert len(dests) == eg.MAX_INTERNET_DESTINATIONS
    assert any("internet" in n and "egress limit" in n for n in notes)


def test_egress_cap_keeps_highest_traffic_internet():
    # over the cap, the lowest-traffic FQDNs are dropped and the busiest are kept (deterministic).
    n = eg.MAX_INTERNET_DESTINATIONS
    internet = {f"h{i}.example.com": (n + 2 - i) for i in range(n + 2)}  # h0 busiest, h{n+1} quietest
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": internet}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    kept = {
        d["destination"]
        for d in blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]["allowed_internet_destinations"]
    }
    assert len(kept) == n
    assert "h0.example.com" in kept  # busiest kept
    assert f"h{n}.example.com" not in kept and f"h{n + 1}.example.com" not in kept  # quietest dropped


def test_egress_cap_keeps_highest_traffic_storage_across_providers():
    # storage is ranked across s3/gcs/azure together, so a busy S3 bucket survives the cap even
    # though it's built after a full page of low-traffic GCS buckets.
    n = eg.MAX_STORAGE_DESTINATIONS
    gcs = {f"bucket{i}": 1 for i in range(n)}  # n low-traffic GCS buckets
    s3 = {("busy-bucket", "us-east-1"): 999}  # one high-traffic S3 bucket
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": s3, "gcs": gcs, "azure": {}, "internet": {}}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    dests = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]["allowed_storage_destinations"]
    assert len(dests) == n
    assert any(d.get("bucket_name") == "busy-bucket" for d in dests)


def test_egress_under_internet_limit_does_not_warn():
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": {"api.openai.com": 3}}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    notes = []
    eg.build_blocks(a, cfg, note=notes.append)
    assert notes == []


def test_egress_export_payload_builds_full_policy():
    # --export: egress block + a permissive FULL_ACCESS ingress default, single-policy id.
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": {"api.openai.com": 5}}},
    )
    cfg = EgressConfig(
        enable_rdap=False,
        block_threat_domains="off",
        policy_scope="all_workspaces",
        policy_mode="enforce",
        policy_name="my-egress",
    )
    payload = eg.export_payload(a, cfg, "acc-1", this_workspace_id=42)
    assert payload["network_policy_id"] == "my-egress"
    assert payload["account_id"] == "acc-1"
    assert "egress" in payload
    assert payload["ingress"]["public_access"]["restriction_mode"] == "FULL_ACCESS"


def test_egress_empty_produces_no_blocks(monkeypatch):
    monkeypatch.setattr(
        "dbx_nwp_helper.sql.query",
        lambda _c, _t: pd.DataFrame(
            columns=["destination", "destination_type", "events", "workspace_ids", "resolved_ips"]
        ),
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.preview_blocks(a, cfg) == {}


# ------------------------------------------------------------------------------------- acl
class _FakeWorkspaceConf:
    def __init__(self, initial="true"):
        self._val = initial
        self.set_calls = []

    def get_status(self, keys):
        assert keys == "enableIpAccessLists"
        return {"enableIpAccessLists": self._val}

    def set_status(self, contents):
        self.set_calls.append(contents)
        self._val = contents.get("enableIpAccessLists", self._val)


class _WsWithConf:
    def __init__(self, initial="true"):
        self.workspace_conf = _FakeWorkspaceConf(initial)


def test_disable_ip_access_lists_flips_toggle_off():
    ws = _WsWithConf(initial="true")
    assert acl_core.disable_ip_access_lists(ws) is True
    assert ws.workspace_conf.set_calls == [{"enableIpAccessLists": "false"}]


def test_disable_ip_access_lists_idempotent_when_already_off():
    ws = _WsWithConf(initial="false")
    # already disabled -> no write, reports no change
    assert acl_core.disable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def test_disable_ip_access_lists_noop_when_never_configured():
    # workspace-conf has no enableIpAccessLists key at all (IP ACLs never set up) -> nothing to
    # disable, no write, graceful.
    class _Conf:
        def __init__(self):
            self.set_calls = []

        def get_status(self, keys):
            return {}

        def set_status(self, contents):
            self.set_calls.append(contents)

    class _WS:
        def __init__(self):
            self.workspace_conf = _Conf()

    ws = _WS()
    assert acl_core.disable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def _pas_account(pas_id):
    class _WS:
        def get(self, workspace_id):
            return type("W", (), {"private_access_settings_id": pas_id})()

    return type("Acct", (), {"workspaces": _WS()})()


def test_workspace_pas_attached_true_false():
    assert acl_core.workspace_pas_attached(_pas_account("pas-abc"), 42) is True
    assert acl_core.workspace_pas_attached(_pas_account(None), 42) is False


def test_workspace_pas_attached_none_on_error():
    class _WS:
        def get(self, workspace_id):
            raise RuntimeError("no perms")

    acct = type("Acct", (), {"workspaces": _WS()})()
    assert acl_core.workspace_pas_attached(acct, 42) is None


def _policy_account(assigned_policy_id, policy_obj):
    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": assigned_policy_id})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            return policy_obj

    return type("Acct", (), {"workspace_network_configuration": _WNC(), "network_policies": _NP()})()


def _ingress(
    public_mode="FULL_ACCESS", private_mode="ALLOW_ALL_REGISTERED_ENDPOINTS", xws_mode="LEGACY_MODE"
):
    def _blk(mode):
        return type("B", (), {"restriction_mode": mode, "allow_rules": None, "deny_rules": None})()

    return type(
        "Ing",
        (),
        {
            "public_access": _blk(public_mode),
            "private_access": _blk(private_mode),
            "cross_workspace_access": _blk(xws_mode),
        },
    )()


def test_public_vs_private_restrictive_helpers():
    assert acl_core.public_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.public_restrictive(_ingress()) is False
    # private / cross-workspace restrictiveness is independent of public
    assert acl_core.private_or_xws_restrictive(_ingress(private_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.private_or_xws_restrictive(_ingress(xws_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.private_or_xws_restrictive(_ingress()) is False
    assert acl_core.private_or_xws_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is False


def _egress(restricted=True, enforced=True, internet=None, storage=None):
    import types

    na = types.SimpleNamespace(
        restriction_mode="RESTRICTED_ACCESS" if restricted else "FULL_ACCESS",
        allowed_internet_destinations=internet,
        allowed_storage_destinations=storage,
        blocked_internet_destinations=None,
        policy_enforcement=types.SimpleNamespace(enforcement_mode="ENFORCED" if enforced else "DRY_RUN"),
    )
    return types.SimpleNamespace(network_access=na)


def test_egress_restrictive_matches_restricted_mode_and_dest_lists():
    assert acl_core.egress_restrictive(None) is False
    assert acl_core.egress_restrictive(_egress(restricted=False)) is False  # FULL_ACCESS
    assert acl_core.egress_restrictive(_egress(restricted=True)) is True  # RESTRICTED_ACCESS
    # FULL_ACCESS but with an allow list present -> still restrictive
    assert acl_core.egress_restrictive(_egress(restricted=False, internet=["x"])) is True


def test_egress_enforced_reads_enforcement_mode():
    assert acl_core.egress_enforced(_egress(enforced=True)) is True
    assert acl_core.egress_enforced(_egress(enforced=False)) is False  # DRY_RUN
    assert acl_core.egress_enforced(None) is False


def test_assigned_policy_returns_id_and_object():
    pol = object()
    assert acl_core.assigned_policy(_policy_account("p1", pol), 42) == ("p1", pol)
    assert acl_core.assigned_policy(_policy_account(None, None), 42) == (None, None)


# --------------------------------------------------------------------------------- queries
def test_frequent_public_ips_predicate_toggles():
    q_default = queries.frequent_public_ips(
        30, 1, include_ipv6=False, treat_null_status_as_success=False, include_account_level=False
    )
    assert "ip_version = 6" not in q_default
    # workspace_id is a STRING column -> compare against '0', not the integer 0.
    assert "CAST(workspace_id AS STRING) <> '0'" in q_default
    assert "workspace_id <> 0" not in q_default
    assert "status_code IS NULL AND FALSE" in q_default

    q_all = queries.frequent_public_ips(
        7, 5, include_ipv6=True, treat_null_status_as_success=True, include_account_level=True
    )
    assert "OR ip_version = 6" in q_all
    # the account-level filter predicate is omitted when including account-level rows
    assert "CAST(workspace_id AS STRING) <> '0'" not in q_all
    assert "status_code IS NULL AND TRUE" in q_all
    assert "INTERVAL 7 DAYS" in q_all
    assert "COUNT(*) >= 5" in q_all


def test_observed_egress_source_filter():
    assert "network_source_type = 'DBSQL'" in queries.observed_egress(30, 1, "DBSQL")
    assert "network_source_type =" not in queries.observed_egress(30, 1, "")
    # a single quote in the filter is escaped (doubled), not left to break/inject into the query
    assert "network_source_type = 'we''ird'" in queries.observed_egress(30, 1, "we'ird")


def test_denied_requests_query_filters_403():
    q = queries.denied_requests(14)
    assert "IpAccessDenied" in q and "status_code = 403" in q
    assert "INTERVAL 14 DAYS" in q


# ---------------------------------------------------------------- egress owner resolution cascade
def _internet_analysis(fqdn):
    t = eg._new_target()
    t["internet"][fqdn] = 1
    return eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: t})


def test_owner_lookup_private_ip(monkeypatch):
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])
    a = _internet_analysis("host.internal")
    eg._owner_lookup(a, {"host.internal": ["10.0.0.5"]}, EgressConfig())
    assert a.fqdn_owner["host.internal"] == "private/internal IP"


def test_owner_lookup_cloud_range_wins_over_rdap(monkeypatch):
    import ipaddress

    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [(ipaddress.ip_network("52.0.0.0/8"), "AWS")])
    from dbx_nwp_helper.feeds import rdap

    # a cloud-range hit must short-circuit before RDAP is ever consulted
    monkeypatch.setattr(
        rdap, "lookup", lambda ip: (_ for _ in ()).throw(AssertionError("RDAP must not be called"))
    )
    a = _internet_analysis("aws.example.com")
    eg._owner_lookup(a, {"aws.example.com": ["52.1.2.3"]}, EgressConfig())
    assert a.fqdn_owner["aws.example.com"] == "AWS"


def test_owner_lookup_dns_failure_is_flagged(monkeypatch):
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])
    monkeypatch.setattr(eg.socket, "gethostbyname", lambda h: (_ for _ in ()).throw(OSError("NXDOMAIN")))
    a = _internet_analysis("nxdomain.test")
    eg._owner_lookup(a, {}, EgressConfig())  # no pre-resolved IP -> gethostbyname -> fails
    assert a.fqdn_owner["nxdomain.test"] == "DNS resolution failed - check egress control"


def test_load_cloud_networks_builds_tuples_and_skips_bad_cidrs(monkeypatch):
    from dbx_nwp_helper.feeds import cloud as cloud_feed
    from dbx_nwp_helper.feeds import databricks as dbx_feed

    monkeypatch.setattr(
        cloud_feed,
        "load_cloud_ranges",
        lambda: pd.DataFrame(
            [{"cidr": "52.0.0.0/8", "provider": "aws"}, {"cidr": "junk", "provider": "gcp"}]
        ),
    )
    monkeypatch.setattr(dbx_feed, "load_databricks_ranges", lambda: pd.DataFrame([{"cidr": "3.3.3.0/24"}]))
    nets = eg._load_cloud_networks()
    owners = {o for _n, o in nets}
    assert "AWS" in owners  # provider upper-cased
    assert "Databricks" in owners  # databricks feed tagged
    assert all("junk" not in str(n) for n, _o in nets)  # invalid CIDR silently skipped


# ------------------------------------------------------------------------ S3 region inference
def test_infer_s3_region_from_success_header(monkeypatch):
    class _Resp:
        headers = {"x-amz-bucket-region": "eu-west-1"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: _Resp())
    assert eg._infer_s3_region("bkt") == "eu-west-1"


def test_infer_s3_region_from_error_response_header(monkeypatch):
    # a 301/403 to the wrong-region endpoint still carries x-amz-bucket-region on the error object
    class _Hdrs:
        def get(self, _k):
            return "us-west-2"

    err = Exception("301 Moved")
    err.headers = _Hdrs()

    def boom(req, timeout=10):
        raise err

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert eg._infer_s3_region("bkt") == "us-west-2"


def test_infer_s3_region_none_when_no_header(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=10: (_ for _ in ()).throw(Exception("no header"))
    )
    assert eg._infer_s3_region("bkt") is None


def test_analyze_drops_s3_bucket_when_region_unknown(monkeypatch):
    # A global-endpoint S3 host has no region; if it can't be inferred the bucket is dropped (region
    # is required by the API) and surfaced in dropped_s3_no_region.
    observed = pd.DataFrame(
        [
            {
                "destination": "globalbucket.s3.amazonaws.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: None)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.dropped_s3_no_region == ["globalbucket"]
    assert not eg.union(a.targets, "s3")


# ----------------------------------------------------------------- threat-domain block list
def test_blocked_domains_all_mode_uses_whole_feed(monkeypatch):
    monkeypatch.setattr(eg, "_load_threat_domains", lambda feed: {"evil.com", "bad.net"})
    a = eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: eg._new_target()})
    eg._blocked_domains(a, EgressConfig(block_threat_domains="all", threat_feed="threatfox"), lambda _m: None)
    assert set(a.blocked_domains) == {"bad.net", "evil.com"}  # sorted, whole feed


def test_blocked_domains_capped_at_limit(monkeypatch):
    from dbx_nwp_helper.config import MAX_INTERNET_DESTINATIONS

    feed = {f"d{i}.example" for i in range(MAX_INTERNET_DESTINATIONS + 5)}
    monkeypatch.setattr(eg, "_load_threat_domains", lambda feed_key: feed)
    a = eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: eg._new_target()})
    notes = []
    eg._blocked_domains(a, EgressConfig(block_threat_domains="all"), lambda m: notes.append(m))
    assert len(a.blocked_domains) == MAX_INTERNET_DESTINATIONS
    assert any("limit" in n for n in notes)  # operator warned about the truncation


def test_load_threat_domains_parses_hostfile(monkeypatch):
    text = "\n".join(
        [
            "# comment",
            "! banner",
            "127.0.0.1 evil.example.com",
            "0.0.0.0 bad.test",
            "1.2.3.4",
            "0.0.0.0 5.5.5.5",
        ]
    )

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return text.encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=45: _Resp())
    domains = eg._load_threat_domains("threatfox")
    assert "evil.example.com" in domains and "bad.test" in domains
    assert "5.5.5.5" not in domains  # IP literal is not a valid FQDN block target
