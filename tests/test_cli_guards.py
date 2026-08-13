"""Tests for the apply-time empty guards — a run that produces no rules must fail with a clear
message and a non-zero exit, not crash with a KeyError."""

from __future__ import annotations

import pandas as pd
import pytest
from typer.testing import CliRunner

from dbx_nwp_helper import cli
from dbx_nwp_helper.core.ingress import IngressAnalysis

runner = CliRunner()


def test_resolve_profile_passthrough():
    assert cli._resolve_profile("myprofile") == "myprofile"


def test_resolve_profile_respects_env_auth(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://x.cloud.databricks.com")
    assert cli._resolve_profile(None) is None


def test_resolve_profile_none_and_no_profiles_errors(monkeypatch):
    import typer
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setattr(cli, "_available_profiles", lambda: [])
    with pytest.raises(typer.BadParameter):
        cli._resolve_profile(None)


def test_resolve_profile_none_noninteractive_errors(monkeypatch):
    import typer
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["a", "b"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter):
        cli._resolve_profile(None)


def test_confirm_params_yes_skips(monkeypatch):
    # --yes must not prompt and must not raise.
    called = {"n": 0}
    monkeypatch.setattr("typer.confirm", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    cli._confirm_params(yes=True)
    assert called["n"] == 0


def test_confirm_params_noninteractive_skips(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("must not prompt non-interactively")))
    cli._confirm_params(yes=False)


def test_confirm_params_decline_aborts(monkeypatch):
    import typer
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_params(yes=False)
    assert exc.value.exit_code == 0  # user chose to abort — a clean exit, not an error


def test_confirm_params_accept_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._confirm_params(yes=False)  # must not raise


def test_confirm_write_yes_proceeds():
    assert cli._confirm_write("dry_run", yes=True) is True


def test_confirm_write_interactive_decline(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    assert cli._confirm_write("enforce", yes=False) is False


def test_responsibility_warning_shown(capsys):
    from dbx_nwp_helper import console
    console.responsibility_warning("source IP addresses / CIDRs")
    out = capsys.readouterr().out
    assert "responsib" in out.lower()
    assert "security-enforcing" in out.lower()
    # mentions the reuse-the-JSON case, not just create-here
    assert "copy this JSON" in out or "copy" in out.lower()


def test_ensure_account_id_passthrough_when_set():
    from dbx_nwp_helper.config import Connection
    conn = Connection(account_id="already-set")
    cli._ensure_account_id(conn, "Creating a policy")  # no prompt, no raise
    assert conn.account_id == "already-set"


def test_ensure_account_id_noninteractive_errors(monkeypatch):
    import typer

    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter):
        cli._ensure_account_id(Connection(account_id=""), "Creating a policy")


def test_ensure_account_id_prompts_interactive(monkeypatch):
    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    class _Q:
        def ask(self):
            return "  1234567890  "
    monkeypatch.setattr("questionary.text", lambda *a, **k: _Q())
    conn = Connection(account_id="")
    cli._ensure_account_id(conn, "Creating a policy")
    assert conn.account_id == "1234567890"


def test_maybe_disable_ip_acls_noop_when_flag_false():
    class _WS:
        @property
        def workspace_conf(self):
            raise AssertionError("must not touch the workspace when the flag is off")

    cli._maybe_disable_ip_acls(False, [{"assigned": 42}], _WS())  # must not raise


def test_maybe_disable_ip_acls_skips_when_nothing_assigned():
    # apply errored / assigned nothing -> we must NOT strip the workspace's IP-ACL protection.
    class _WS:
        @property
        def workspace_conf(self):
            raise AssertionError("must not disable ACLs when no policy was assigned")

    cli._maybe_disable_ip_acls(True, [{"target": "x", "error": "boom"}], _WS())  # must not raise


def test_maybe_disable_ip_acls_runs_when_assigned():
    seen = {}

    class _Conf:
        def get_status(self, keys):
            return {"enableIpAccessLists": "true"}

        def set_status(self, contents):
            seen["set"] = contents

    class _WS:
        workspace_conf = _Conf()

    cli._maybe_disable_ip_acls(True, [{"assigned": 42, "policy_id": "p"}], _WS())
    assert seen["set"] == {"enableIpAccessLists": "false"}


def test_maybe_disable_ip_acls_warns_on_sdk_failure(capsys):
    # if disabling raises (e.g. no workspace-admin rights), the run must NOT crash — the policy is
    # already applied and assigned, so we warn and continue.
    class _Conf:
        def get_status(self, keys):
            raise RuntimeError("permission denied")

    class _WS:
        workspace_conf = _Conf()

    cli._maybe_disable_ip_acls(True, [{"assigned": 42, "policy_id": "p"}], _WS())  # must not raise
    out = capsys.readouterr().out
    assert "manually" in out.lower()


def test_migrate_acl_disable_without_create_is_rejected():
    # --disable-existing-ip-acls without --create-policy must fail up front (before any SDK call),
    # so the workspace can't be left unprotected.
    result = runner.invoke(cli.app, [
        "migrate-acl", "--profile", "test", "--disable-existing-ip-acls"])
    assert result.exit_code == 2
    assert "disable-existing-ip-acls" in result.output


class _FakeWsClient:
    class _Cfg:
        host = "https://ws.cloud.databricks.com"

    config = _Cfg()

    def get_workspace_id(self):
        return 12345


def test_confirm_workspace_yes_displays_and_does_not_prompt(monkeypatch, capsys):
    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr(auth, "workspace_client", lambda conn: _FakeWsClient())
    monkeypatch.setattr("typer.confirm", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("must not prompt with --yes")))
    wc = cli._confirm_workspace(Connection(profile="myprof"), yes=True)
    assert isinstance(wc, _FakeWsClient)
    out = capsys.readouterr().out
    # the panel must surface all three so the target is unmistakable
    assert "12345" in out and "ws.cloud.databricks.com" in out and "myprof" in out


def test_confirm_workspace_decline_aborts(monkeypatch):
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr(auth, "workspace_client", lambda conn: _FakeWsClient())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="p"), yes=False)
    assert exc.value.exit_code == 0  # declining the wrong workspace is a clean abort


def test_note_policy_name_shows_normalized_id(capsys):
    cli._note_policy_name("dbx-nwp", "My Policy")
    assert "my-policy" in capsys.readouterr().out


def test_note_policy_name_silent_when_clean_or_blank(capsys):
    cli._note_policy_name("dbx-nwp", "clean-name")   # already normalised -> no notice
    cli._note_policy_name("dbx-nwp", "")             # not set -> no notice
    assert capsys.readouterr().out == ""


def test_resolve_acl_policy_name_keeps_explicit():
    from dbx_nwp_helper.config import AclConfig, Connection
    cfg = AclConfig(policy_name="chosen")
    cli._resolve_acl_policy_name(cfg, Connection(profile="p"), object(), yes=True)
    assert cfg.policy_name == "chosen"


def test_resolve_acl_policy_name_uses_profile_when_blank_and_noninteractive():
    from dbx_nwp_helper.config import AclConfig, Connection

    class _WC:
        def get_workspace_id(self):
            return 42

    cfg = AclConfig()
    cli._resolve_acl_policy_name(cfg, Connection(profile="myprof"), _WC(), yes=True)
    assert cfg.policy_name == "myprof"  # blank -> profile name (no prompt under --yes)


class _AclWorkspace:
    class _Cfg:
        host = "https://ws.cloud.databricks.com"

    config = _Cfg()

    def get_workspace_id(self):
        return 42

    class _Acls:
        def list(self):
            lt = type("LT", (), {"value": "ALLOW"})()
            return [type("A", (), {"label": "office", "enabled": True, "list_type": lt,
                                   "ip_addresses": ["8.8.8.8/32"]})()]

    ip_access_lists = _Acls()

    class _Conf:
        def get_status(self, keys):
            return {"enableIpAccessLists": "true"}

    workspace_conf = _Conf()


class _CleanAclAccount:
    """Account client that passes migrate-acl preflight: no PAS, no assigned network policy."""
    class _WS:
        def get(self, workspace_id):
            return type("W", (), {"private_access_settings_id": None})()

    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": None})()

    workspaces = _WS()
    workspace_network_configuration = _WNC()


def test_migrate_acl_export_writes_json(monkeypatch, tmp_path):
    import json

    import dbx_nwp_helper.auth as auth
    monkeypatch.setattr(auth, "workspace_client", lambda conn: _AclWorkspace())
    monkeypatch.setattr(auth, "account_client", lambda conn: _CleanAclAccount())
    out = tmp_path / "policy.json"
    # propose-only (no --create-policy) + --yes; migrate-acl now needs --account-id for its
    # PAS / existing-policy pre-checks, but --export must still write the curl-ready JSON.
    result = runner.invoke(cli.app, [
        "migrate-acl", "--profile", "test", "--account-id", "acc-1", "--export", str(out), "--yes"])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["network_policy_id"] == "test"       # blank name -> profile name ("test")
    assert data["account_id"] == "acc-1"
    assert "egress" in data and "ingress" in data     # enforce default -> ingress block present


def test_acl_preflight_aborts_on_pas(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, yes=True)
    assert e.value.exit_code == 1


def test_acl_preflight_aborts_on_existing_enforced_policy(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "enforced"))
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, yes=True)
    assert e.value.exit_code == 1


def test_acl_preflight_dry_run_cancels_without_promote_noninteractive(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "dry_run"))
    promoted = {"n": 0}
    monkeypatch.setattr("dbx_nwp_helper.core.acl.promote_dry_run_to_enforced",
                        lambda *a, **k: promoted.__setitem__("n", promoted["n"] + 1))
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, yes=True)  # --yes -> no prompt, no promotion
    assert e.value.exit_code == 0 and promoted["n"] == 0


def test_acl_preflight_dry_run_promotes_when_confirmed(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "dry_run"))
    promoted = {"n": 0}
    monkeypatch.setattr("dbx_nwp_helper.core.acl.promote_dry_run_to_enforced",
                        lambda *a, **k: promoted.__setitem__("n", promoted["n"] + 1))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, yes=False)
    assert e.value.exit_code == 0 and promoted["n"] == 1  # promoted, then migration cancelled


def test_acl_preflight_passes_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, yes=True)  # must not raise


def test_acl_preflight_warns_but_proceeds_when_pas_unknown(monkeypatch, capsys):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: None)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, yes=True)  # must not raise
    assert "couldn't verify" in capsys.readouterr().out.lower()


def test_ingress_policy_name_with_per_workspace_is_rejected():
    result = runner.invoke(cli.app, [
        "ingress", "--profile", "test", "--policy-name", "x", "--policy-scope", "per_workspace"])
    assert result.exit_code == 2
    assert "policy-name" in result.output


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

    import dbx_nwp_helper.auth as auth
    import dbx_nwp_helper.sql as sqlmod
    from dbx_nwp_helper.core import ingress as ing

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
        "ingress", "--profile", "test", "--warehouse-http-path", "/sql/1.0/warehouses/x",
        "--account-id", "acc", "--create-policy", "--yes"])
    assert result.exit_code == 1
    assert "Nothing to apply" in result.stdout
