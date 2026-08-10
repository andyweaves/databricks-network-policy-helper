"""Offline engine tests using fixture DataFrames + fake enrichment ranges.

No network / no Databricks — patches the feed loaders and SQL to exercise the ingress/egress/acl
engines end-to-end through rule building and SDK-block construction.
"""

from __future__ import annotations

import pandas as pd
import pytest

from dbx_nwp_helper.config import AclConfig, EgressConfig, IngressConfig
from dbx_nwp_helper.core import acl as acl_core
from dbx_nwp_helper.core import egress as eg
from dbx_nwp_helper.core import ingress as ing
from dbx_nwp_helper.core import ingress_rules as rules


class _FakeAcl:
    def __init__(self, label, list_type, enabled, ips):
        self.label, self.enabled, self.ip_addresses = label, enabled, ips
        self.list_type = type("LT", (), {"value": list_type})()


class _FakeIpAclApi:
    def __init__(self, acls):
        self._acls = acls

    def list(self):
        return self._acls


class _FakeWorkspaceClient:
    def __init__(self, acls=None, ws_id=123):
        self.ip_access_lists = _FakeIpAclApi(acls or [])
        self._ws_id = ws_id

    def get_workspace_id(self):
        return self._ws_id


@pytest.fixture
def candidates_df():
    return pd.DataFrame([
        {"public_ip": "203.0.55.10", "ip_version": 4, "events": 100, "principals": 2, "services": 1,
         "actions": 3, "active_days": 5, "sessions": 4, "first_active_date": "2026-01-01",
         "last_active_date": "2026-01-05", "principal_list": ["a@x.com"],
         "principal_emails": ["a@x.com"], "subject_names": [], "service_list": ["apps"],
         "workspace_ids": [123]},
        {"public_ip": "8.8.8.8", "ip_version": 4, "events": 5, "principals": 1, "services": 1,
         "actions": 1, "active_days": 1, "sessions": 1, "first_active_date": "2026-01-02",
         "last_active_date": "2026-01-02", "principal_list": ["b@x.com"],
         "principal_emails": ["b@x.com"], "subject_names": [], "service_list": ["jobs"],
         "workspace_ids": [123]},
    ])


def _patch_feeds(monkeypatch, threat_rows=None, cloud_rows=None, dbx_rows=None):
    from dbx_nwp_helper.feeds import loaders
    monkeypatch.setattr(loaders, "threat_intel", lambda feeds, refresh=False: pd.DataFrame(
        threat_rows or [], columns=["cidr", "source_feed", "threat_type", "confidence",
                                    "source_url", "loaded_at"]))
    monkeypatch.setattr(loaders, "cloud_ranges", lambda refresh=False: pd.DataFrame(
        cloud_rows or [], columns=["cidr", "provider", "service", "region", "loaded_at"]))
    monkeypatch.setattr(loaders, "databricks_ranges", lambda refresh=False: pd.DataFrame(
        dbx_rows or [], columns=["cidr", "platform", "region", "direction", "loaded_at"]))


def test_ingress_ip_only_dry_run(monkeypatch, candidates_df):
    # 8.8.8.8 is on a threat feed -> excluded from allow rules; 203.0.55.10 stays.
    _patch_feeds(monkeypatch, threat_rows=[
        ("8.8.8.0/24", "ipsum", "aggregated_blocklist", 1, "http://x", "2026-01-01")])

    # Stub sql.query to return our candidates / empty denied.
    import dbx_nwp_helper.sql as sqlmod

    def fake_query(_conn, text):
        if "outbound_network" in text:
            return pd.DataFrame()
        if "IpAccessDenied" in text:
            return pd.DataFrame(columns=["source_ip"])
        return candidates_df
    monkeypatch.setattr(sqlmod, "query", fake_query)

    cfg = IngressConfig(min_events=1, enable_rdap=False, policy_framing="minimal",
                        scoping_mode="ip_only", policy_scope="all_workspaces")
    analysis = ing.analyze(cfg, sql_conn=None, workspace_client=_FakeWorkspaceClient())
    assert not analysis.suggestions.empty
    # threat match table should include 8.8.8.8
    assert "8.8.8.8" in set(analysis.threat_matches["observed_ip"])

    # A plain (non-flagged) candidate is recommended for review as an unknown hosting provider.
    recs = set(analysis.suggestions["recommendation"])
    assert "REVIEW — Other hosting provider" in recs
    assert "candidate" not in recs

    policies = rules.build_rules(analysis, cfg)
    previews = rules.preview_blocks(policies, cfg)
    # single scope -> one target
    assert "__ALL__" in policies
    block = previews["__ALL__"]["ingress_dry_run"]
    cidrs = block["public_access"]["allow_rules"][0]["origin"]["included_ip_ranges"]["ip_ranges"]
    assert "203.0.55.10/32" in cidrs
    assert all(not c.startswith("8.8.8") for c in cidrs)  # threat IP excluded
    assert analysis.excluded_flagged == 1


def test_ingress_databricks_owned_takes_precedence(monkeypatch, candidates_df):
    # Mark 8.8.8.0/24 as BOTH cloud and databricks-owned -> should be ALLOWED (databricks wins).
    _patch_feeds(
        monkeypatch,
        cloud_rows=[("8.8.8.0/24", "gcp", "svc", "us", "2026-01-01")],
        dbx_rows=[("8.8.8.0/24", "aws", "us", "inbound", "2026-01-01")],
    )
    import dbx_nwp_helper.sql as sqlmod
    monkeypatch.setattr(sqlmod, "query", lambda _c, t: (
        pd.DataFrame(columns=["source_ip"]) if "IpAccessDenied" in t else candidates_df))
    cfg = IngressConfig(enable_rdap=False, scoping_mode="ip_only", policy_scope="all_workspaces")
    analysis = ing.analyze(cfg, None, _FakeWorkspaceClient())
    recs = {r["rdap_owner"]: r for _, r in analysis.suggestions.iterrows()}
    dbx_group = [r for r in recs.values() if r["databricks_owned"]]
    assert dbx_group and dbx_group[0]["recommendation"] == "ALLOW — Databricks-owned"


def test_acl_migration_block_only_adds_catch_all():
    cfg = AclConfig(policy_mode="dry_run", name_prefix="np")
    wc = _FakeWorkspaceClient(acls=[_FakeAcl("blocklist", "BLOCK", True, ["1.2.3.4"])])
    analysis = acl_core.analyze(cfg, wc)
    assert analysis.deny_specs and not analysis.allow_specs
    preview = acl_core.preview_block(analysis, cfg)
    pub = preview["ingress_dry_run"]["public_access"]
    # catch-all allow injected because only BLOCK lists exist
    assert pub["allow_rules"][0]["origin"].get("all_ip_ranges") is True
    assert pub["deny_rules"]


def test_egress_classification_and_block(monkeypatch):
    observed = pd.DataFrame([
        {"destination": "mybucket.s3.us-west-2.amazonaws.com", "destination_type": "DNS",
         "events": 10, "workspace_ids": [123], "resolved_ips": []},
        {"destination": "api.openai.com", "destination_type": "DNS", "events": 4,
         "workspace_ids": [123], "resolved_ips": ["1.2.3.4"]},
    ])
    import dbx_nwp_helper.sql as sqlmod
    monkeypatch.setattr(sqlmod, "query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    analysis = eg.analyze(cfg, None)
    assert eg.union(analysis.targets, "s3")
    assert "api.openai.com" in eg.union(analysis.targets, "internet")
    previews = eg.preview_blocks(analysis, cfg)
    egr = previews["__ALL__"]["egress"]["network_access"]
    assert egr["restriction_mode"] == "RESTRICTED_ACCESS"
    assert any(d["destination"] == "api.openai.com" for d in egr["allowed_internet_destinations"])
