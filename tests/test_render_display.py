"""Tests for the render-layer display helpers: suggestions table, enrichment flags, policy URL."""

from __future__ import annotations

import types

import pandas as pd

from dbx_nwp_helper import render


def _analysis_with_denied():
    empty = pd.DataFrame()
    denied = pd.DataFrame([{"source_ip": "1.2.3.4", "denied_events": 3, "principals": "a@x.com",
                            "first_denied": "d1", "last_denied": "d2"}])
    return types.SimpleNamespace(candidates=empty, funnel=None, suggestions=empty,
                                 threat_matches=empty, denied_requests=denied)


def test_denied_requests_note_says_not_applied_when_flag_off(capsys):
    from dbx_nwp_helper.config import IngressConfig
    render.ingress_analysis(_analysis_with_denied(), IngressConfig(deny_denied_ips=False))
    out = capsys.readouterr().out
    assert "Recently denied requests" in out
    assert "recently blocked by the IP ACL" in out
    assert "NOT added as deny rules" in out


def test_denied_requests_note_says_applied_when_flag_on(capsys):
    from dbx_nwp_helper.config import IngressConfig
    render.ingress_analysis(_analysis_with_denied(), IngressConfig(deny_denied_ips=True))
    assert "will be added as deny rules" in capsys.readouterr().out


def test_acl_egress_note_explains_each_option(capsys):
    from dbx_nwp_helper import render
    render.acl_egress_note("allow_all")
    assert "FULL_ACCESS" in capsys.readouterr().out
    render.acl_egress_note("dry_run")
    assert "log-only" in capsys.readouterr().out.lower()
    render.acl_egress_note("restricted")
    assert "BLOCKS ALL" in capsys.readouterr().out


def test_decisions_panel_renders_flag_dash_names(capsys):
    # settings must display in dash form so they match the CLI flags (copy-paste as `--<name>`).
    from dbx_nwp_helper import console
    console.decisions_panel("cfg", [("enable_rdap", True, "meaning")])
    out = capsys.readouterr().out
    assert "enable-rdap" in out and "enable_rdap" not in out


def test_apply_results_reports_id_and_url(capsys):
    render.apply_results(
        [{"target": "single", "action": "created", "policy_id": "np-helper"}],
        account_host="https://accounts.cloud.databricks.com", account_id="ACC")
    out = capsys.readouterr().out
    assert "network policy id: np-helper" in out
    assert "network-access-policies/np-helper?account_id=ACC" in out


def test_apply_results_reports_id_without_url_when_no_account(capsys):
    render.apply_results([{"target": "single", "action": "updated", "policy_id": "np-helper"}])
    out = capsys.readouterr().out
    assert "network policy id: np-helper" in out
    assert "network-access-policies" not in out  # no URL without host/account_id


def test_apply_results_reports_errors(capsys):
    render.apply_results([{"target": 123, "error": "boom"}])
    out = capsys.readouterr().out
    assert "boom" in out


def test_policy_url_format():
    url = render.policy_url("https://accounts.cloud.databricks.com", "ACC123", "np-helper")
    assert url == ("https://accounts.cloud.databricks.com/security/networking/"
                   "network-access-policies/np-helper?account_id=ACC123")


def test_policy_url_strips_trailing_slash():
    url = render.policy_url("https://accounts.cloud.databricks.com/", "ACC", "p")
    assert "databricks.com/security" in url
    assert "//security" not in url


def test_fmt_flag_none_is_no():
    assert render._fmt_flag(None) == "no"


def test_fmt_flag_empty_list_is_no():
    assert render._fmt_flag([]) == "no"


def test_fmt_flag_lists_matched_names():
    assert render._fmt_flag(["ipsum", "dshield"]) == "ipsum, dshield"


def test_fmt_flag_numpy_array():
    import numpy as np
    assert render._fmt_flag(np.array(["aws"])) == "aws"


def _sugg_row(**kw):
    base = {"policy_target": "__ALL__", "rdap_owner": "Acme", "recommendation": "candidate",
            "distinct_ips": 2, "total_events": 50,
            "minimal_cidrs": ["1.2.3.4/32", "5.6.7.8/32"], "optimal_cidrs": ["1.2.3.4/31"],
            "maximum_cidrs": None, "scoped_destination": "all_destinations",
            "threat_feeds": None, "cloud_provider": None, "databricks_owned": None}
    base.update(kw)
    return base


def test_suggestions_display_all_workspaces_label_and_cidrs():
    df = render._suggestions_display(pd.DataFrame([_sugg_row()]), "minimal")
    row = df.iloc[0]
    assert row["policy_target"] == "(all workspaces)"
    assert row["cidrs"] == "1.2.3.4/32, 5.6.7.8/32"
    assert row["threat_feeds"] == "no"
    assert row["cloud_provider"] == "no"
    assert row["databricks_owned"] == "no"


def test_suggestions_display_optimal_framing_uses_optimal_cidrs():
    df = render._suggestions_display(pd.DataFrame([_sugg_row()]), "optimal")
    assert df.iloc[0]["cidrs"] == "1.2.3.4/31"


def test_suggestions_display_maximum_framing_none_shows_none():
    df = render._suggestions_display(pd.DataFrame([_sugg_row()]), "maximum")
    assert df.iloc[0]["cidrs"] == "(none)"


def test_suggestions_display_per_workspace_target_kept():
    df = render._suggestions_display(pd.DataFrame([_sugg_row(policy_target=1234)]), "minimal")
    assert df.iloc[0]["policy_target"] == 1234


def test_suggestions_display_flags_show_matched_names():
    df = render._suggestions_display(
        pd.DataFrame([_sugg_row(cloud_provider=["aws"], databricks_owned=["aws"])]), "minimal")
    row = df.iloc[0]
    assert row["cloud_provider"] == "aws"
    assert row["databricks_owned"] == "aws"
