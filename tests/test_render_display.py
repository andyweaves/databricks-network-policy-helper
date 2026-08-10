"""Tests for the render-layer display helpers: suggestions table, enrichment flags, policy URL."""

from __future__ import annotations

import pandas as pd

from dbx_netpolicy import render


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
