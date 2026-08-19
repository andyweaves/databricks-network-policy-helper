"""Tests for the expired-credential detection + re-auth retry flow in cli.py."""

from __future__ import annotations

import pytest
import typer

from dbx_nwp_helper import cli


def test_is_expired_auth_matches_reauth_messages():
    assert cli._is_expired_auth("... you must reauthenticate ...")
    assert cli._is_expired_auth("invalid refresh token")
    assert cli._is_expired_auth("cannot get access token")
    assert cli._is_expired_auth("please run: databricks auth login --profile foo")


def test_is_expired_auth_ignores_unrelated_errors():
    assert not cli._is_expired_auth("default auth: cannot configure default credentials")
    assert not cli._is_expired_auth("profile configured but host missing")


def test_reauth_profile_prefers_profile_named_in_error():
    # the account client often resolves to a *different* auto-discovered profile than the one asked
    # for; re-auth must target the profile the SDK error actually names.
    msg = "Run: databricks auth login --profile sfe-account."
    assert cli._reauth_profile(msg, fallback="sfe-workspace") == "sfe-account"


def test_reauth_profile_falls_back_when_unnamed():
    assert cli._reauth_profile("token expired", fallback="myprofile") == "myprofile"


def test_client_or_exit_retries_build_after_successful_reauth(monkeypatch):
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("please reauthenticate: databricks auth login --profile p")
        return "client"

    monkeypatch.setattr(cli, "_reauthenticate", lambda profile: True)
    assert cli._client_or_exit(build, "p", "--profile") == "client"
    assert calls["n"] == 2  # built once (failed), re-authed, built again (succeeded)


def test_client_or_exit_exits_when_reauth_declined(monkeypatch):
    def build():
        raise ValueError("please reauthenticate: databricks auth login --profile p")

    monkeypatch.setattr(cli, "_reauthenticate", lambda profile: False)
    with pytest.raises(typer.Exit):
        cli._client_or_exit(build, "p", "--profile")


def test_client_or_exit_does_not_reauth_on_plain_config_error(monkeypatch):
    reauth_called = {"n": 0}

    def build():
        raise ValueError("default auth: cannot configure default credentials")

    def _reauth(profile):
        reauth_called["n"] += 1
        return True

    monkeypatch.setattr(cli, "_reauthenticate", _reauth)
    with pytest.raises(typer.Exit):
        cli._client_or_exit(build, "p", "--profile")
    assert reauth_called["n"] == 0  # never offered re-auth for a non-expiry error
