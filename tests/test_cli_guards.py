"""Tests for the apply-time empty guards — a run that produces no rules must fail with a clear
message and a non-zero exit, not crash with a KeyError."""

from __future__ import annotations

import pandas as pd
import pytest
from typer.testing import CliRunner

from dbx_nwp_helper import cli
from dbx_nwp_helper.core.ingress import IngressAnalysis

runner = CliRunner()


def _plain(text: str) -> str:
    """Strip ANSI escape codes so substring assertions hold regardless of whether the runtime emitted
    colour. GitHub Actions forces colour on, and Rich styles option tokens as separate coloured spans
    (`--policy-name` -> `-` `-policy` `-name`), which otherwise splits substrings with escape
    sequences; a local non-TTY run emits no colour, so the same assertion passes there but not in CI."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


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
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
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
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    cli._checkpoint(yes=True)  # must not raise


def test_checkpoint_noninteractive_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
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


def test_run_analysis_returns_value_on_success():
    assert cli._run_analysis(lambda: "ok") == "ok"


def test_run_analysis_handles_inet_unsupported(capsys):
    import typer

    def boom():
        raise RuntimeError("[INET_FUNCTIONS_NOT_ENABLED] ip_cidr_contains is disabled or unsupported.")

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    assert "preview" in _plain(capsys.readouterr().out).lower()


def test_run_analysis_handles_warehouse_timeout(capsys):
    import typer

    # the reported failure: the databricks-sql connector exhausts its retry budget and raises
    def boom():
        raise RuntimeError(
            "Error during request to server. Retry request would exceed Retry policy max retry "
            "duration of 900.0 seconds"
        )

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    out = _plain(capsys.readouterr().out)
    assert "didn't complete" in out and "warehouse" in out


def test_run_analysis_reraises_unknown_errors():
    # an error we don't recognise must NOT be swallowed — it propagates unchanged
    def boom():
        raise ValueError("something unexpected")

    with pytest.raises(ValueError, match="something unexpected"):
        cli._run_analysis(boom)


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
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
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

    monkeypatch.setattr(
        auth,
        "workspace_client",
        lambda conn: (_ for _ in ()).throw(
            ValueError("resolve: /Users/x/.databrickscfg has no sfe-cloud profile configured")
        ),
    )
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

    monkeypatch.setattr(
        auth,
        "account_client",
        lambda conn: (_ for _ in ()).throw(
            ValueError("resolve: /Users/x/.databrickscfg has no acct profile configured")
        ),
    )
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

    monkeypatch.setattr(
        auth,
        "workspace_client",
        lambda conn: (_ for _ in ()).throw(ValueError("default auth: cannot configure default credentials")),
    )
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile=None), yes=True)
    assert exc.value.exit_code == 1
    assert "Databricks client" in capsys.readouterr().out


def test_note_policy_name_shows_normalized_id(capsys):
    cli._note_policy_name("My Policy")
    assert "my-policy" in capsys.readouterr().out


def test_note_policy_name_silent_when_clean_or_blank(capsys):
    cli._note_policy_name("clean-name")  # already normalised -> no notice
    cli._note_policy_name("")  # not set -> no notice
    assert capsys.readouterr().out == ""


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


def test_write_tf_export_into_directory(tmp_path):
    payload = {"network_policy_id": "pol-x", "ingress": {"public_access": {"restriction_mode": "X"}}}
    dest = cli._write_tf_export(str(tmp_path), payload)
    assert dest.endswith("pol-x.tf")
    assert 'resource "databricks_account_network_policy" "pol_x"' in (
        (tmp_path / "pol-x.tf").read_text(encoding="utf-8")
    )


def test_export_writes_utf8_non_ascii_labels(tmp_path):
    # A non-ASCII rule label must write cleanly on any platform — Windows' default cp1252 would
    # otherwise raise UnicodeEncodeError, so both writers pin UTF-8.
    import json
    from pathlib import Path

    payload = {
        "network_policy_id": "pol",
        "ingress": {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [{"label": "café-café", "destination": {"all_destinations": True}}],
            }
        },
    }
    tf = cli._write_tf_export(str(tmp_path), payload)
    js = cli._write_json_export(str(tmp_path), payload)
    assert "café-café" in Path(tf).read_text(encoding="utf-8")
    loaded = json.loads(Path(js).read_text(encoding="utf-8"))
    assert loaded["ingress"]["public_access"]["allow_rules"][0]["label"] == "café-café"


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


def test_confirm_overwrite_new_file_always_writes(tmp_path):
    # a path that doesn't exist yet never prompts
    assert cli._confirm_overwrite(tmp_path / "new.json", yes=False) is True


def test_confirm_overwrite_existing_kept_when_declined(monkeypatch, tmp_path):
    import typer

    existing = tmp_path / "policy.json"
    existing.write_text("old")
    # simulate an interactive terminal where the user declines the overwrite
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(typer, "confirm", lambda *a, **k: False)
    assert cli._confirm_overwrite(existing, yes=False) is False
    # ...and --yes overwrites without prompting even when the file exists
    assert cli._confirm_overwrite(existing, yes=True) is True


def test_write_json_export_keeps_existing_when_declined(monkeypatch, tmp_path):
    import json

    dest = tmp_path / "my-acl.json"
    dest.write_text('{"network_policy_id": "OLD"}')
    monkeypatch.setattr(cli, "_confirm_overwrite", lambda d, yes: False)
    # a declined overwrite returns None and leaves the original file untouched
    assert cli._write_json_export(str(tmp_path), {"network_policy_id": "my-acl", "egress": {}}) is None
    assert json.loads(dest.read_text())["network_policy_id"] == "OLD"


def test_export_policy_overwrites_with_yes(tmp_path):
    import json

    # first write, then a second --yes write must overwrite both files silently
    payload_v1 = {"network_policy_id": "pol", "egress": {}}
    payload_v2 = {"network_policy_id": "pol", "egress": {"changed": True}}
    cli._export_policy(str(tmp_path), payload_v1, yes=True)
    cli._export_policy(str(tmp_path), payload_v2, yes=True)
    assert json.loads((tmp_path / "pol.json").read_text())["egress"] == {"changed": True}


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
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(ingress="X"))
    )
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: ing == "X")
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_aborts_on_enforced_public(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(ingress="ENF"))
    )
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_warns_on_dry_run_public_then_proceeds(monkeypatch, capsys):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(ingress=None, dry="DRY"))
    )
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
        allowed_internet_destinations=None,
        allowed_storage_destinations=None,
        blocked_internet_destinations=None,
        policy_enforcement=types.SimpleNamespace(enforcement_mode="ENFORCED" if enforced else "DRY_RUN"),
    )
    return types.SimpleNamespace(network_access=na)


def test_ingress_preflight_aborts_when_new_id_drops_enforced_egress(monkeypatch):
    # A new ingress policy id rebinds the workspace to a FULL_ACCESS-egress policy, dropping the
    # assigned policy's ENFORCED egress -> abort.
    import typer

    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(egress=_egr(True, True)))
    )
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "different-id", yes=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_same_id_keeps_egress(monkeypatch):
    # Updating the SAME policy id preserves its egress, so an enforced egress must NOT abort.
    monkeypatch.setattr("dbx_nwp_helper.core.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(egress=_egr(True, True)))
    )
    cli._ingress_preflight(object(), 42, "p1", yes=True)  # same id -> must not raise


def test_egress_preflight_aborts_on_enforced_egress(monkeypatch):
    import typer

    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(egress=_egr(True, True)))
    )
    with pytest.raises(typer.Exit) as e:
        cli._egress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_egress_preflight_warns_on_dry_run_egress_then_proceeds(monkeypatch, capsys):
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(egress=_egr(True, enforced=False))),
    )
    cli._egress_preflight(object(), 42, "p1", yes=True)  # same id -> no opposite-direction check
    assert "DRY-RUN egress" in capsys.readouterr().out


def test_egress_preflight_proceeds_on_full_access(monkeypatch):
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(egress=_egr(restricted=False))),
    )
    cli._egress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def test_egress_preflight_aborts_when_new_id_drops_enforced_ingress(monkeypatch):
    # New egress policy id rebinds to a FULL_ACCESS-ingress policy, dropping the assigned policy's
    # enforced ingress -> abort.
    import typer

    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(ingress="ENF", egress=_egr(restricted=False))),
    )
    with pytest.raises(typer.Exit) as e:
        cli._egress_preflight(object(), 42, "different-id", yes=True)
    assert e.value.exit_code == 1


def test_egress_preflight_same_id_keeps_ingress(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(ingress="ENF", egress=_egr(restricted=False))),
    )
    cli._egress_preflight(object(), 42, "p1", yes=True)  # same id -> must not raise


def test_egress_preflight_proceeds_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: (None, None))
    cli._egress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def test_ingress_policy_name_with_add_to_existing_is_rejected():
    # per_workspace + --policy-name is now allowed (name = prefix); add_to_existing still isn't (the
    # id comes from --existing-policy-id).
    result = runner.invoke(
        cli.app,
        [
            "ingress",
            "--profile",
            "test",
            "--policy-name",
            "x",
            "--create-policy",
            "--policy-action",
            "add_to_existing",
            "--existing-policy-id",
            "some-id",
        ],
    )
    assert result.exit_code == 2
    assert "policy-name" in _plain(result.output)


def test_has_rules_helper():
    assert cli._has_rules({}) is False
    assert cli._has_rules({"__ALL__": {"allow": [], "deny": []}}) is False
    assert cli._has_rules({"__ALL__": {"allow": [{"cidrs": ["1.1.1.1/32"]}], "deny": []}}) is True
    assert cli._has_rules({"__ALL__": {"allow": [], "deny": [{"cidrs": ["9.9.9.0/24"]}]}}) is True


def _empty_analysis():
    return IngressAnalysis(
        candidates=pd.DataFrame(),
        suggestions=pd.DataFrame(),
        threat_matches=pd.DataFrame(),
        denied_requests=pd.DataFrame(columns=["source_ip"]),
        ip_acls=[],
        funnel={
            "total_rows": 0,
            "with_source_ip": 0,
            "ipv4": 0,
            "ipv6": 0,
            "successful": 0,
            "workspace_level": 0,
            "account_level": 0,
            "public_ipv4": 0,
            "distinct_public_ok": 0,
            "distinct_public_ok_ws": 0,
        },
    )


def test_ingress_create_with_no_rules_exits_nonzero(monkeypatch):
    # Stub the whole data path so no network is touched and analysis is empty.
    monkeypatch.setattr(cli, "_step", lambda _m: None)

    import dbx_nwp_helper.auth as auth
    import dbx_nwp_helper.sql as sqlmod
    from dbx_nwp_helper.core import ingress as ing
    from dbx_nwp_helper.core import ingress_rules as rules

    monkeypatch.setattr(auth, "workspace_client", lambda conn: object())
    monkeypatch.setattr(sqlmod, "resolve_warehouse", lambda conn: "/sql/1.0/warehouses/x")
    # Account auth is now resolved + verified UP FRONT (fail-fast), so stub it to succeed; the point
    # of this test is that no *apply* (write) happens when the empty analysis yields no rules.
    monkeypatch.setattr(cli, "_resolve_account_profile", lambda conn: None)
    monkeypatch.setattr(auth, "this_workspace_id", lambda conn: 42)
    monkeypatch.setattr(cli, "_account_client_or_exit", lambda conn, workspace_id=None: object())

    class _Conn:
        def __enter__(self):
            return object()

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(sqlmod, "connection", lambda conn, hp: _Conn())
    monkeypatch.setattr(ing, "analyze", lambda *a, **k: _empty_analysis())
    # the apply (the actual write) must never run when there are no rules.
    monkeypatch.setattr(
        rules,
        "apply",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("apply must not run when there are no rules")),
    )

    result = runner.invoke(
        cli.app,
        [
            "ingress",
            "--profile",
            "test",
            "--warehouse-http-path",
            "/sql/1.0/warehouses/x",
            "--account-id",
            "acc",
            "--create-policy",
            "--yes",
        ],
    )
    assert result.exit_code == 1
    assert "Nothing to apply" in result.stdout


# --- ported auth / account-resolution improvements ---------------------------------------------
def _sq(text: str) -> str:
    """Strip ANSI + all whitespace, so substring asserts survive Rich panel wrapping."""
    return "".join(_plain(text).split())


def test_account_host_from_workspace_host():
    f = cli.account_host_from_workspace_host
    # AWS prod / staging / vanity: replace the single workspace label with 'accounts'
    assert f("https://dbc-11112222-3333.cloud.databricks.com") == "https://accounts.cloud.databricks.com"
    assert (
        f("https://dbc-11112222-3333.staging.cloud.databricks.com/")
        == "https://accounts.staging.cloud.databricks.com"
    )
    assert f("https://acme.cloud.databricks.com") == "https://accounts.cloud.databricks.com"
    # GCP: two workspace-specific labels (<id>.<shard>) dropped; anchor on the base domain
    assert (
        f("https://1111111111111111.4.staging.gcp.databricks.com")
        == "https://accounts.staging.gcp.databricks.com"
    )
    assert f("https://2222222222222222.8.gcp.databricks.com") == "https://accounts.gcp.databricks.com"
    assert f("https://acme.gcp.databricks.com") == "https://accounts.gcp.databricks.com"
    # Azure fixed host (region label must NOT leak in)
    assert f("https://adb-0000000000000000.0.azuredatabricks.net") == "https://accounts.azuredatabricks.net"
    # undecidable / empty -> None (caller keeps its default; user can pin --account-host)
    assert f("https://databricks.acme.example") is None
    assert f("") is None and f(None) is None


def test_norm_host_strips_scheme_and_slash():
    assert cli._norm_host("https://accounts.azuredatabricks.net/") == "accounts.azuredatabricks.net"
    assert cli._norm_host("accounts.azuredatabricks.net") == "accounts.azuredatabricks.net"
    assert cli._norm_host("") == "" and cli._norm_host(None) == ""


_CFG = {
    "az-ws": {"host": "https://adb-1.7.azuredatabricks.net", "account_id": "aaaaaaaa"},
    "az-acct": {"host": "https://accounts.azuredatabricks.net", "account_id": "aaaaaaaa"},
    "aws-acct": {"host": "https://accounts.staging.cloud.databricks.com", "account_id": "bbbbbbbb"},
    "az-acct-dupe": {"host": "accounts.azuredatabricks.net", "account_id": "aaaaaaaa"},
}


def test_matching_account_profiles_matches_on_host_and_id(monkeypatch):
    monkeypatch.setattr(cli, "_read_config_profiles", lambda: _CFG)
    assert set(cli._matching_account_profiles("https://accounts.azuredatabricks.net", "aaaaaaaa")) == {
        "az-acct",
        "az-acct-dupe",
    }
    # right id but wrong host -> no match; right host but wrong id -> no match
    assert cli._matching_account_profiles("https://accounts.azuredatabricks.net", "bbbbbbbb") == []
    assert cli._matching_account_profiles("https://accounts.staging.cloud.databricks.com", "aaaaaaaa") == []
    assert cli._matching_account_profiles("", "aaaaaaaa") == []


def test_resolve_account_profile_single_match(monkeypatch, capsys):
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(cli, "_read_config_profiles", lambda: {"az-acct": _CFG["az-acct"]})
    conn = Connection(account_host="https://accounts.azuredatabricks.net", account_id="aaaaaaaa")
    cli._resolve_account_profile(conn)
    assert conn.account_profile == "az-acct"
    assert "az-acct" in _sq(capsys.readouterr().out)


def test_resolve_account_profile_noop_when_explicit_or_no_match(monkeypatch):
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(cli, "_read_config_profiles", lambda: _CFG)
    explicit = Connection(
        account_host="https://accounts.azuredatabricks.net", account_id="aaaaaaaa", account_profile="chosen"
    )
    cli._resolve_account_profile(explicit)
    assert explicit.account_profile == "chosen"
    nomatch = Connection(account_host="https://accounts.gcp.databricks.com", account_id="nope")
    cli._resolve_account_profile(nomatch)
    assert nomatch.account_profile is None


def test_resolve_account_host_derives_and_respects_explicit(capsys):
    from dbx_nwp_helper.config import Connection

    wc = type("WC", (), {"config": type("C", (), {"host": "https://acme.gcp.databricks.com"})()})()
    derived = Connection()  # account_host_explicit defaults False
    cli._resolve_account_host(derived, wc)
    assert derived.account_host == "https://accounts.gcp.databricks.com"
    pinned = Connection(account_host="https://accounts.cloud.databricks.com", account_host_explicit=True)
    cli._resolve_account_host(pinned, wc)
    assert pinned.account_host == "https://accounts.cloud.databricks.com"  # explicit respected


def test_default_account_id_from_workspace(capsys):
    from dbx_nwp_helper.config import Connection

    wc = type("WC", (), {"config": type("C", (), {"account_id": "aaaaaaaa"})()})()
    conn = Connection(account_id="")
    cli._default_account_id_from_workspace(conn, wc)
    assert conn.account_id == "aaaaaaaa"
    # an explicit --account-id is not overwritten
    explicit = Connection(account_id="explicit")
    cli._default_account_id_from_workspace(explicit, wc)
    assert explicit.account_id == "explicit"


def test_looks_like_account_console():
    f = cli._looks_like_account_console
    assert f("https://accounts.azuredatabricks.net") is True
    assert f("https://accounts.staging.cloud.databricks.com") is True
    assert f("https://adb-1.7.azuredatabricks.net") is False
    assert f("https://dbc-x.cloud.databricks.com") is False
    assert f("") is False


def _fake_account(ok=True, err=None):
    class _WS:
        def get(self, workspace_id):
            if not ok:
                raise err or RuntimeError("boom")
            return object()

    return type("Acct", (), {"workspaces": _WS()})()


def test_verify_account_access_returns_account_on_success():
    from dbx_nwp_helper.config import Connection

    acct = _fake_account(ok=True)
    assert cli._verify_account_access_or_exit(Connection(account_id="a"), acct, 42) is acct


def test_verify_account_access_exits_cleanly_on_rejection(capsys):
    import typer

    from dbx_nwp_helper.config import Connection

    conn = Connection(account_id="acc-123", account_host="https://accounts.azuredatabricks.net")
    with pytest.raises(typer.Exit) as exc:
        cli._verify_account_access_or_exit(conn, _fake_account(ok=False), 42)
    assert exc.value.exit_code == 1
    out = _sq(capsys.readouterr().out)
    assert "acc-123" in out and "--account-profile" in out


def test_confirm_workspace_rejects_account_console_profile(monkeypatch, capsys):
    import typer

    from dbx_nwp_helper.config import Connection

    wc = type("WC", (), {"config": type("C", (), {"host": "https://accounts.azuredatabricks.net"})()})()
    monkeypatch.setattr(cli, "_workspace_client_or_exit", lambda conn: wc)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="az-acct"), yes=True)
    assert exc.value.exit_code == 1
    out = _sq(capsys.readouterr().out)
    assert "accountconsole" in out.lower() and "--account-profile" in out
