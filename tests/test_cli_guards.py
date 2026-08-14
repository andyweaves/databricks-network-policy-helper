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


def test_checkpoint_yes_skips_prompt(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("must not prompt with --yes")))
    cli._checkpoint(yes=True)  # must not raise


def test_checkpoint_noninteractive_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("must not prompt non-interactively")))
    cli._checkpoint(yes=False)  # must not raise


def test_checkpoint_continue_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._checkpoint(yes=False)  # must not raise


def test_checkpoint_decline_aborts_cleanly(monkeypatch):
    import typer
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._checkpoint(yes=False)
    assert exc.value.exit_code == 0  # 'n' -> clean abort


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
    # --disable-existing-ip-acls without a create+assign must fail up front (before any SDK call),
    # so the workspace can't be left unprotected. (create-policy defaults on, so force it off here.)
    result = runner.invoke(cli.app, [
        "migrate-acl", "--profile", "test", "--no-create-policy", "--no-auto-assign",
        "--disable-existing-ip-acls"])
    assert result.exit_code == 2
    assert "disable-existing-ip-acls" in result.output


def test_migrate_acl_assign_without_create_is_rejected():
    # 8d: auto-assign with --no-create-policy is nonsensical (nothing to bind) -> rejected up front.
    result = runner.invoke(cli.app, ["migrate-acl", "--profile", "test", "--no-create-policy"])
    assert result.exit_code == 2
    assert "auto-assign" in result.output


def test_migrate_acl_dry_run_disable_is_rejected():
    # 8c: disabling the old ACLs while the new policy only logs (dry_run) would leave no enforced
    # ingress control -> rejected up front.
    result = runner.invoke(cli.app, [
        "migrate-acl", "--profile", "test", "--policy-mode", "dry_run",
        "--disable-existing-ip-acls"])
    assert result.exit_code == 2
    assert "dry_run" in result.output or "dry-run" in result.output


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


def test_confirm_workspace_bad_profile_exits_cleanly(monkeypatch, capsys):
    # A mistyped --profile must produce a clean, actionable message (not a raw SDK traceback).
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr(auth, "workspace_client", lambda conn: (_ for _ in ()).throw(
        ValueError("resolve: /Users/x/.databrickscfg has no sfe-cloud profile configured")))
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["sfe-foghorn", "e2-dogfood"])
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="sfe-cloud"), yes=True)
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "sfe-cloud" in out and "sfe-foghorn" in out  # names the bad profile + lists available


def test_account_client_bad_profile_exits_cleanly(monkeypatch, capsys):
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr(auth, "account_client", lambda conn: (_ for _ in ()).throw(
        ValueError("resolve: /Users/x/.databrickscfg has no acct profile configured")))
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["acct-admin"])
    with pytest.raises(typer.Exit) as exc:
        cli._account_client_or_exit(Connection(account_profile="acct"))
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "--account-profile" in out and "acct" in out


def test_workspace_client_other_valueerror_still_clean(monkeypatch, capsys):
    # A non-profile config error should also exit cleanly rather than traceback.
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection
    monkeypatch.setattr(auth, "workspace_client", lambda conn: (_ for _ in ()).throw(
        ValueError("default auth: cannot configure default credentials")))
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile=None), yes=True)
    assert exc.value.exit_code == 1
    assert "Databricks client" in capsys.readouterr().out


def _acl_analysis(enabled=1, disabled=0):
    import types
    ip_acls = [{"label": f"a{i}", "list_type": "ALLOW", "ip_addresses": ["8.8.8.8/32"]}
               for i in range(enabled)]
    dis = [{"label": f"d{i}", "list_type": "ALLOW", "ip_addresses": ["1.1.1.1/32"]}
           for i in range(disabled)]
    return types.SimpleNamespace(workspace_id=42, ip_acls=ip_acls, disabled_acls=dis)


def test_acl_ip_gate_proceeds_when_enabled_with_rules(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.ip_acl_enforcement_state", lambda wc: True)
    cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=True)  # must not raise


def test_acl_ip_gate_enabled_no_rules_exits(monkeypatch, capsys):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.ip_acl_enforcement_state", lambda wc: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=0), object(), yes=True)
    assert e.value.exit_code == 0
    assert "no rules" in capsys.readouterr().out.lower()


def test_acl_ip_gate_disabled_no_rules_exits(monkeypatch, capsys):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.ip_acl_enforcement_state", lambda wc: False)
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=0), object(), yes=True)
    assert e.value.exit_code == 0
    out = capsys.readouterr().out.lower()
    assert "disabled" in out and "no rules" in out


def test_acl_ip_gate_disabled_with_rules_noninteractive_aborts(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.ip_acl_enforcement_state", lambda wc: False)
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=True)  # --yes: no auto re-enable
    assert e.value.exit_code == 0


def test_acl_ip_gate_disabled_with_rules_decline_reenable(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.ip_acl_enforcement_state", lambda wc: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    called = {"n": 0}
    monkeypatch.setattr("dbx_nwp_helper.core.acl.enable_ip_access_lists",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=False)
    assert e.value.exit_code == 0
    assert called["n"] == 0  # declined -> must NOT re-enable


def test_acl_ip_gate_disabled_with_rules_accept_reenable_and_continues(monkeypatch, capsys):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.ip_acl_enforcement_state", lambda wc: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    called = {"n": 0}
    monkeypatch.setattr("dbx_nwp_helper.core.acl.enable_ip_access_lists",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    # accept -> re-enable, then CONTINUE the run (must not raise).
    cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=False)
    assert called["n"] == 1
    assert "continuing" in capsys.readouterr().out.lower()


def test_ensure_acl_policy_name_unique_reprompts_then_accepts(monkeypatch):
    from dbx_nwp_helper.config import AclConfig
    seen = iter([True, False])  # first name exists, second is free
    monkeypatch.setattr("dbx_nwp_helper.core.acl.policy_exists", lambda a, pid: next(seen))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    class _Q:
        def ask(self):
            return "fresh-name"
    monkeypatch.setattr("questionary.text", lambda *a, **k: _Q())
    cfg = AclConfig(policy_name="taken")
    cli._ensure_acl_policy_name_unique(cfg, object(), 42, yes=False)
    assert cfg.policy_name == "fresh-name"


def test_ensure_acl_policy_name_unique_noninteractive_aborts(monkeypatch):
    import typer

    from dbx_nwp_helper.config import AclConfig
    monkeypatch.setattr("dbx_nwp_helper.core.acl.policy_exists", lambda a, pid: True)
    cfg = AclConfig(policy_name="taken")
    with pytest.raises(typer.Exit) as e:
        cli._ensure_acl_policy_name_unique(cfg, object(), 42, yes=True)
    assert e.value.exit_code == 1


def test_note_policy_name_shows_normalized_id(capsys):
    cli._note_policy_name("My Policy")
    assert "my-policy" in capsys.readouterr().out


def test_note_policy_name_silent_when_clean_or_blank(capsys):
    cli._note_policy_name("clean-name")   # already normalised -> no notice
    cli._note_policy_name("")             # not set -> no notice
    assert capsys.readouterr().out == ""


def test_resolve_policy_name_keeps_explicit():
    from dbx_nwp_helper.config import AclConfig, Connection
    cfg = AclConfig(policy_name="chosen")
    cli._resolve_policy_name(cfg, Connection(profile="p"), object(), yes=True)
    assert cfg.policy_name == "chosen"


def test_resolve_policy_name_uses_profile_when_blank_and_noninteractive():
    from dbx_nwp_helper.config import AclConfig, Connection

    class _WC:
        def get_workspace_id(self):
            return 42

    cfg = AclConfig()
    cli._resolve_policy_name(cfg, Connection(profile="myprof"), _WC(), yes=True)
    assert cfg.policy_name == "myprof"  # blank -> profile name (no prompt under --yes)


def test_resolve_policy_name_skips_add_to_existing():
    # add_to_existing takes its id from --existing-policy-id, so no name is resolved.
    from dbx_nwp_helper.config import Connection, IngressConfig
    cfg = IngressConfig()
    cfg.apply.policy_action = "add_to_existing"
    cli._resolve_policy_name(cfg, Connection(profile="myprof"), object(), yes=True)
    assert cfg.policy_name == ""


def test_resolve_policy_name_ingress_defaults_to_profile():
    from dbx_nwp_helper.config import Connection, IngressConfig

    class _WC:
        def get_workspace_id(self):
            return 7

    cfg = IngressConfig(policy_scope="per_workspace")
    cli._resolve_policy_name(cfg, Connection(profile="egress-prof"), _WC(), yes=True)
    assert cfg.policy_name == "egress-prof"  # per_workspace uses it as the prefix


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
    """Account client that passes migrate-acl preflight: no PAS, no VPC endpoints, no assigned
    network policy, and the chosen policy name is free (create-only uniqueness check)."""
    class _WS:
        def get(self, workspace_id):
            return type("W", (), {"private_access_settings_id": None, "network_id": None})()

    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": None})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            from databricks.sdk.errors import NotFound
            raise NotFound("no such policy")

    workspaces = _WS()
    workspace_network_configuration = _WNC()
    network_policies = _NP()


def test_migrate_acl_export_writes_json(monkeypatch, tmp_path):
    import json

    import dbx_nwp_helper.auth as auth
    monkeypatch.setattr(auth, "workspace_client", lambda conn: _AclWorkspace())
    monkeypatch.setattr(auth, "account_client", lambda conn: _CleanAclAccount())
    out = tmp_path / "policy.json"
    # propose-only (--no-create-policy --no-auto-assign) + --yes; migrate-acl needs --account-id for
    # its PAS / VPC-endpoint / existing-policy pre-checks, but --export must still write the JSON.
    result = runner.invoke(cli.app, [
        "migrate-acl", "--profile", "test", "--account-id", "acc-1", "--export", str(out),
        "--no-create-policy", "--no-auto-assign", "--yes"])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["network_policy_id"] == "test"       # blank name -> profile name ("test")
    assert data["account_id"] == "acc-1"
    assert "egress" in data and "ingress" in data     # enforce default -> ingress block present
    # --export also writes a sibling Terraform config.
    tf = out.with_suffix(".tf")
    assert tf.exists()
    assert 'resource "databricks_account_network_policy"' in tf.read_text()


def test_write_tf_export_into_directory(tmp_path):
    payload = {"network_policy_id": "pol-x", "ingress": {"public_access": {"restriction_mode": "X"}}}
    dest = cli._write_tf_export(str(tmp_path), payload)
    assert dest.endswith("pol-x.tf")
    assert 'resource "databricks_account_network_policy" "pol_x"' in (
        (tmp_path / "pol-x.tf").read_text(encoding="utf-8"))


def test_export_writes_utf8_non_ascii_labels(tmp_path):
    # A non-ASCII rule label must write cleanly on any platform — Windows' default cp1252 would
    # otherwise raise UnicodeEncodeError, so both writers pin UTF-8.
    import json
    from pathlib import Path
    payload = {"network_policy_id": "pol", "ingress": {"public_access": {
        "restriction_mode": "RESTRICTED_ACCESS",
        "allow_rules": [{"label": "café-café", "destination": {"all_destinations": True}}]}}}
    tf = cli._write_tf_export(str(tmp_path), payload)
    js = cli._write_json_export(str(tmp_path), payload)
    assert "café-café" in Path(tf).read_text(encoding="utf-8")
    loaded = json.loads(Path(js).read_text(encoding="utf-8"))
    assert loaded["ingress"]["public_access"]["allow_rules"][0]["label"] == "café-café"


def test_acl_preflight_aborts_on_pas(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)
    assert e.value.exit_code == 1


def test_acl_preflight_aborts_on_existing_enforced_policy_when_assigning(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "enforced"))
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)
    assert e.value.exit_code == 1


def test_acl_preflight_enforced_warns_and_proceeds_when_not_assigning(monkeypatch, capsys):
    # not assigning -> existing enforced policy stays put; warn and continue (no abort).
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "enforced"))
    cli._acl_preflight(object(), 42, will_assign=False, yes=True)  # must not raise
    assert "isn't assigning" in capsys.readouterr().out


def test_acl_preflight_dry_run_warns_and_proceeds_when_not_assigning(monkeypatch):
    # not assigning -> no promote prompt, no cancel; just warn and continue.
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "dry_run"))
    monkeypatch.setattr("dbx_nwp_helper.core.acl.promote_dry_run_to_enforced",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not promote")))
    cli._acl_preflight(object(), 42, will_assign=False, yes=True)  # must not raise


def test_acl_preflight_dry_run_cancels_without_promote_noninteractive(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state",
                        lambda a, w: ("p1", "dry_run"))
    promoted = {"n": 0}
    monkeypatch.setattr("dbx_nwp_helper.core.acl.promote_dry_run_to_enforced",
                        lambda *a, **k: promoted.__setitem__("n", promoted["n"] + 1))
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)  # --yes -> no prompt/promotion
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
        cli._acl_preflight(object(), 42, will_assign=True, yes=False)
    assert e.value.exit_code == 0 and promoted["n"] == 1  # promoted, then migration cancelled


def test_acl_preflight_passes_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, will_assign=True, yes=True)  # must not raise


def test_acl_preflight_warns_but_proceeds_when_pas_unknown(monkeypatch, capsys):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: None)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, will_assign=True, yes=True)  # must not raise
    assert "couldn't verify" in capsys.readouterr().out.lower()


def test_write_json_export_to_directory_uses_policy_id_filename(tmp_path):
    import json
    from pathlib import Path
    dest = cli._write_json_export(str(tmp_path), {"network_policy_id": "my-acl", "egress": {}})
    assert dest == str(tmp_path / "my-acl.json")
    assert json.loads(Path(dest).read_text())["network_policy_id"] == "my-acl"


def test_write_json_export_creates_missing_parent_dirs(tmp_path):
    from pathlib import Path
    target = tmp_path / "nested" / "sub" / "policy.json"
    dest = cli._write_json_export(str(target), {"network_policy_id": "p"})
    assert dest == str(target) and Path(target).exists()


def test_write_json_export_bad_path_errors_cleanly(tmp_path):
    import typer
    # a path whose parent is a *file* can't be created -> clean Exit, not a traceback
    afile = tmp_path / "afile"
    afile.write_text("x")
    with pytest.raises(typer.Exit) as e:
        cli._write_json_export(str(afile / "policy.json"), {"network_policy_id": "p"})
    assert e.value.exit_code == 1


def _fake_pol(ingress=None, dry=None, egress=None):
    return type("P", (), {"ingress": ingress, "ingress_dry_run": dry, "egress": egress})()


def test_ingress_preflight_aborts_on_pas(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: True)
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_aborts_on_private_config(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(ingress="X")))
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: ing == "X")
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_aborts_on_enforced_public(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(ingress="ENF")))
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_warns_on_dry_run_public_then_proceeds(monkeypatch, capsys):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(ingress=None, dry="DRY")))
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "DRY")
    cli._ingress_preflight(object(), 42, "new-id", yes=True)  # must not raise
    assert "DRY-RUN" in capsys.readouterr().out


def test_ingress_preflight_proceeds_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: (None, None))
    cli._ingress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def _egr(restricted=True, enforced=True):
    """A fake egress block matching NetworkPolicyEgress.network_access shape."""
    import types
    na = types.SimpleNamespace(
        restriction_mode="RESTRICTED_ACCESS" if restricted else "FULL_ACCESS",
        allowed_internet_destinations=None, allowed_storage_destinations=None,
        blocked_internet_destinations=None,
        policy_enforcement=types.SimpleNamespace(
            enforcement_mode="ENFORCED" if enforced else "DRY_RUN"))
    return types.SimpleNamespace(network_access=na)


def test_ingress_preflight_aborts_when_new_id_drops_enforced_egress(monkeypatch):
    # A new ingress policy id rebinds the workspace to a FULL_ACCESS-egress policy, dropping the
    # assigned policy's ENFORCED egress -> abort.
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(egress=_egr(True, True))))
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "different-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_same_id_keeps_egress(monkeypatch):
    # Updating the SAME policy id preserves its egress, so an enforced egress must NOT abort.
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(egress=_egr(True, True))))
    cli._ingress_preflight(object(), 42, "p1", yes=True)  # same id -> must not raise


def test_egress_preflight_aborts_on_enforced_egress(monkeypatch):
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(egress=_egr(True, True))))
    with pytest.raises(typer.Exit) as e:
        cli._egress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_egress_preflight_warns_on_dry_run_egress_then_proceeds(monkeypatch, capsys):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(egress=_egr(True, enforced=False))))
    cli._egress_preflight(object(), 42, "p1", yes=True)  # same id -> no opposite-direction check
    assert "DRY-RUN egress" in capsys.readouterr().out


def test_egress_preflight_proceeds_on_full_access(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(egress=_egr(restricted=False))))
    cli._egress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def test_egress_preflight_aborts_when_new_id_drops_enforced_ingress(monkeypatch):
    # New egress policy id rebinds to a FULL_ACCESS-ingress policy, dropping the assigned policy's
    # enforced ingress -> abort.
    import typer
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(ingress="ENF", egress=_egr(restricted=False))))
    with pytest.raises(typer.Exit) as e:
        cli._egress_preflight(object(), 42, "different-id", yes=True)
    assert e.value.exit_code == 1


def test_egress_preflight_same_id_keeps_ingress(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy",
                        lambda a, w: ("p1", _fake_pol(ingress="ENF", egress=_egr(restricted=False))))
    cli._egress_preflight(object(), 42, "p1", yes=True)  # same id -> must not raise


def test_egress_preflight_proceeds_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: (None, None))
    cli._egress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def test_ingress_policy_name_with_add_to_existing_is_rejected():
    # per_workspace + --policy-name is now allowed (name = prefix); add_to_existing still isn't (the
    # id comes from --existing-policy-id).
    result = runner.invoke(cli.app, [
        "ingress", "--profile", "test", "--policy-name", "x", "--create-policy",
        "--policy-action", "add_to_existing", "--existing-policy-id", "some-id"])
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
