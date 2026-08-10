"""Tests for the apply-time empty guards — a run that produces no rules must fail with a clear
message and a non-zero exit, not crash with a KeyError."""

from __future__ import annotations

import pandas as pd
from typer.testing import CliRunner

from dbx_netpolicy import cli
from dbx_netpolicy.core.ingress import IngressAnalysis

runner = CliRunner()


def test_has_rules_helper():
    assert cli._has_rules({}) is False
    assert cli._has_rules({"__ALL__": {"allow": [], "deny": []}}) is False
    assert cli._has_rules({"__ALL__": {"allow": [{"cidrs": ["1.1.1.1/32"]}], "deny": []}}) is True
    assert cli._has_rules({"__ALL__": {"allow": [], "deny": [{"cidrs": ["9.9.9.0/24"]}]}}) is True


def _empty_analysis():
    return IngressAnalysis(
        candidates=pd.DataFrame(), suggestions=pd.DataFrame(),
        threat_matches=pd.DataFrame(), denied_requests=pd.DataFrame(columns=["source_ip"]),
        ip_acls=[], funnel={"total_rows": 0, "with_source_ip": 0, "ipv4": 0, "ipv6": 0,
                            "successful": 0, "workspace_level": 0, "account_level": 0,
                            "public_ipv4": 0, "distinct_public_ok": 0, "distinct_public_ok_ws": 0})


def test_ingress_create_with_no_rules_exits_nonzero(monkeypatch):
    # Stub the whole data path so no network is touched and analysis is empty.
    monkeypatch.setattr(cli, "_step", lambda _m: None)

    import dbx_netpolicy.auth as auth
    import dbx_netpolicy.sql as sqlmod
    from dbx_netpolicy.core import ingress as ing

    monkeypatch.setattr(auth, "workspace_client", lambda conn: object())
    monkeypatch.setattr(sqlmod, "resolve_warehouse", lambda conn: "/sql/1.0/warehouses/x")

    class _Conn:
        def __enter__(self):
            return object()

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(sqlmod, "connection", lambda conn, hp: _Conn())
    monkeypatch.setattr(ing, "analyze", lambda *a, **k: _empty_analysis())
    # account client should never be reached; make it explode if it is.
    monkeypatch.setattr(auth, "account_client", lambda conn: (_ for _ in ()).throw(
        AssertionError("account_client must not be called when there are no rules")))

    result = runner.invoke(cli.app, [
        "ingress", "--warehouse-http-path", "/sql/1.0/warehouses/x",
        "--account-id", "acc", "--create-policy", "--yes"])
    assert result.exit_code == 1
    assert "Nothing to apply" in result.stdout
