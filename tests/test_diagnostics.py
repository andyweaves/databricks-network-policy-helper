"""Tests for the empty-candidate diagnostic funnel (query builder, engine wiring, render hints)."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper import queries, render
from dbx_nwp_helper.config import IngressConfig
from dbx_nwp_helper.core import ingress as ing


def test_candidate_funnel_query_shape():
    q = queries.candidate_funnel(30, treat_null_status_as_success=False)
    for col in ["total_rows", "with_source_ip", "ipv4", "ipv6", "successful", "workspace_level",
                "account_level", "public_ipv4", "distinct_public_ok", "distinct_public_ok_ws"]:
        assert col in q
    assert "status_code IS NULL AND FALSE" in q
    assert "INTERVAL 30 DAYS" in q


def test_analyze_runs_funnel_only_when_empty(monkeypatch):
    # frequent_public_ips -> empty; funnel query -> a fixture row; feeds stubbed empty.
    from dbx_nwp_helper.feeds import loaders
    monkeypatch.setattr(loaders, "threat_intel", lambda f, refresh=False: pd.DataFrame(
        columns=["cidr", "source_feed", "threat_type", "confidence", "source_url", "loaded_at"]))
    monkeypatch.setattr(loaders, "cloud_ranges", lambda refresh=False: pd.DataFrame(
        columns=["cidr", "provider", "service", "region", "loaded_at"]))
    monkeypatch.setattr(loaders, "databricks_ranges", lambda refresh=False: pd.DataFrame(
        columns=["cidr", "platform", "region", "direction", "loaded_at"]))

    funnel_row = pd.DataFrame([{"total_rows": 100, "with_source_ip": 80, "ipv4": 80, "ipv6": 0,
                                "successful": 80, "workspace_level": 0, "account_level": 80,
                                "public_ipv4": 80, "distinct_public_ok": 5, "distinct_public_ok_ws": 0}])

    def fake_query(_c, text):
        if "candidate_funnel" in text or "distinct_public_ok_ws" in text:
            return funnel_row
        if "IpAccessDenied" in text:
            return pd.DataFrame(columns=["source_ip"])
        return pd.DataFrame()  # frequent_public_ips empty

    monkeypatch.setattr("dbx_nwp_helper.sql.query", fake_query)

    class _WS:
        ip_access_lists = type("A", (), {"list": lambda self=None: []})()

        def get_workspace_id(self):
            return 123

    a = ing.analyze(IngressConfig(enable_rdap=False, policy_scope="all_workspaces"),
                    sql_conn=None, workspace_client=_WS())
    assert a.candidates.empty
    assert a.funnel is not None
    assert a.funnel["distinct_public_ok"] == 5
    assert a.funnel["distinct_public_ok_ws"] == 0


def test_render_hint_account_level(capsys):
    # public IPs exist but only account-level -> hint to use --include-account-level.
    funnel = {"total_rows": 100, "with_source_ip": 80, "ipv4": 80, "ipv6": 0, "successful": 80,
              "workspace_level": 0, "account_level": 80, "public_ipv4": 80,
              "distinct_public_ok": 5, "distinct_public_ok_ws": 0}
    render._explain_empty_candidates(funnel, IngressConfig(include_account_level=False))
    out = capsys.readouterr().out
    assert "--include-account-level" in out


def test_render_hint_privatelink(capsys):
    # source IPs all private -> PrivateLink/NAT hint.
    funnel = {"total_rows": 100, "with_source_ip": 80, "ipv4": 80, "ipv6": 0, "successful": 80,
              "workspace_level": 80, "account_level": 0, "public_ipv4": 0,
              "distinct_public_ok": 0, "distinct_public_ok_ws": 0}
    render._explain_empty_candidates(funnel, IngressConfig())
    out = capsys.readouterr().out
    assert "PrivateLink" in out or "NAT" in out


def test_render_hint_no_rows(capsys):
    funnel = {"total_rows": 0, "with_source_ip": 0, "ipv4": 0, "ipv6": 0, "successful": 0,
              "workspace_level": 0, "account_level": 0, "public_ipv4": 0,
              "distinct_public_ok": 0, "distinct_public_ok_ws": 0}
    render._explain_empty_candidates(funnel, IngressConfig())
    out = capsys.readouterr().out
    assert "lookback" in out.lower()
