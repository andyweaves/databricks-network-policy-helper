"""Tests for the render-layer display helpers: suggestions table, enrichment flags, policy URL."""

from __future__ import annotations

import types

import pandas as pd

from dbx_nwp_helper import render


def _analysis_with_denied():
    empty = pd.DataFrame()
    denied = pd.DataFrame(
        [
            {
                "source_ip": "1.2.3.4",
                "denied_events": 3,
                "principals": "a@x.com",
                "first_denied": "d1",
                "last_denied": "d2",
            }
        ]
    )
    return types.SimpleNamespace(
        candidates=empty, funnel=None, suggestions=empty, threat_matches=empty, denied_requests=denied
    )


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


def test_decisions_panel_renders_flag_dash_names(capsys):
    # settings must display in dash form so they match the CLI flags (copy-paste as `--<name>`).
    from dbx_nwp_helper import console

    console.decisions_panel("cfg", [("enable_rdap", True, "meaning")])
    out = capsys.readouterr().out
    assert "enable-rdap" in out and "enable_rdap" not in out


def test_apply_results_reports_id_and_url(capsys):
    render.apply_results(
        [{"target": "single", "action": "created", "policy_id": "np-helper"}],
        account_host="https://accounts.cloud.databricks.com",
        account_id="ACC",
    )
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
    assert url == (
        "https://accounts.cloud.databricks.com/security/networking/"
        "network-access-policies/np-helper?account_id=ACC123"
    )


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
    base = {
        "policy_target": "__ALL__",
        "rdap_owner": "Acme",
        "recommendation": "candidate",
        "distinct_ips": 2,
        "total_events": 50,
        "minimal_cidrs": ["1.2.3.4/32", "5.6.7.8/32"],
        "optimal_cidrs": ["1.2.3.4/31"],
        "maximum_cidrs": None,
        "scoped_destination": "all_destinations",
        "threat_feeds": None,
        "cloud_provider": None,
        "databricks_owned": None,
    }
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
        pd.DataFrame([_sugg_row(cloud_provider=["aws"], databricks_owned=["aws"])]), "minimal"
    )
    row = df.iloc[0]
    assert row["cloud_provider"] == "aws"
    assert row["databricks_owned"] == "aws"


def test_fmt_flag_scalar_string_passthrough():
    assert render._fmt_flag("aws") == "aws"


# --------------------------------------------------------------------------------- egress tables
def _egress_analysis(**kw):
    from dbx_nwp_helper.core.egress import EgressAnalysis

    base = dict(
        observed=pd.DataFrame([{"x": 1}]),
        targets={
            "__ALL__": {
                "s3": {("bkt", "us-east-1"): 10},
                "gcs": {"gbkt": 5},
                "azure": {("acct", "blob"): 3},
                "internet": {"api.openai.com": 8},
            }
        },
        fqdn_ip={"api.openai.com": "1.2.3.4"},
        fqdn_owner={"api.openai.com": "Unknown"},
        blocked_domains=["evil.com"],
        skipped_bare_s3=2,
        dropped_s3_no_region=["globalbucket"],
    )
    base.update(kw)
    return EgressAnalysis(**base)


def test_egress_analysis_renders_all_destination_tables(capsys, monkeypatch):
    from dbx_nwp_helper import console

    monkeypatch.setattr(console.console, "_width", 220)  # keep cells from folding for assertions
    render.egress_analysis(_egress_analysis())
    out = capsys.readouterr().out
    assert "Internet FQDNs" in out and "api.openai.com" in out
    assert "AWS S3 buckets" in out and "GCS buckets" in out and "Azure storage" in out
    assert "evil.com" in out  # threat-intel blocked-domain table
    assert "globalbucket" in out  # dropped-S3-no-region warning names the bucket
    assert "bare" in out.lower()  # skipped bare/path-style S3 note


def test_egress_analysis_warns_when_observed_empty(capsys):
    from dbx_nwp_helper.core.egress import EgressAnalysis

    render.egress_analysis(EgressAnalysis(observed=pd.DataFrame(), targets={"__ALL__": _new_target()}))
    assert "outbound_network is empty" in capsys.readouterr().out


def _new_target():
    return {"s3": {}, "gcs": {}, "azure": {}, "internet": {}}


def test_egress_preview_renders_block_with_scope_label(capsys):
    from dbx_nwp_helper.config import EgressConfig

    previews = {"__ALL__": {"egress": {"network_access": {"restriction_mode": "RESTRICTED_ACCESS"}}}}
    render.egress_preview(previews, EgressConfig(policy_scope="current_workspace"))
    out = capsys.readouterr().out
    assert "this workspace" in out and "RESTRICTED_ACCESS" in out


def test_egress_preview_empty_says_nothing_to_propose(capsys):
    from dbx_nwp_helper.config import EgressConfig

    render.egress_preview({}, EgressConfig())
    assert "Nothing to propose" in capsys.readouterr().out


# ------------------------------------------------------------------------- ingress preview / hints
def _ingress_analysis(**kw):
    from dbx_nwp_helper.core.ingress import IngressAnalysis

    empty = pd.DataFrame()
    base = dict(candidates=empty, suggestions=empty, threat_matches=empty, denied_requests=empty, ip_acls=[])
    base.update(kw)
    return IngressAnalysis(**base)


def test_ingress_preview_reports_all_exclusions(capsys):
    from dbx_nwp_helper.config import IngressConfig

    a = _ingress_analysis()
    a.excluded_flagged, a.excluded_unresolved, a.skipped_ipv6 = 2, 1, 3
    previews = {"__ALL__": {"public_access": {"restriction_mode": "RESTRICTED_ACCESS"}}}
    render.ingress_preview(previews, IngressConfig(policy_scope="all_workspaces"), a)
    out = capsys.readouterr().out
    assert "all workspaces" in out  # single-policy all_workspaces label
    assert "threat-intel-matched" in out  # excluded_flagged banner
    assert "identity" in out.lower()  # excluded_unresolved banner
    assert "IPv6" in out  # skipped_ipv6 banner


def test_ingress_preview_empty_says_no_specs(capsys):
    from dbx_nwp_helper.config import IngressConfig

    render.ingress_preview({}, IngressConfig(), _ingress_analysis())
    assert "No rule specs to preview" in capsys.readouterr().out


def test_ingress_analysis_shows_threat_matches(capsys):
    from dbx_nwp_helper.config import IngressConfig

    tm = pd.DataFrame(
        [
            {
                "observed_ip": "9.9.9.9",
                "matched_cidr": "9.9.9.0/24",
                "source_feed": "ipsum",
                "threat_type": "botnet",
                "confidence": 1,
                "events": 3,
                "principals": 1,
            }
        ]
    )
    render.ingress_analysis(_ingress_analysis(threat_matches=tm), IngressConfig())
    out = capsys.readouterr().out
    assert "9.9.9.9" in out and "threat intel" in out.lower()


def test_ingress_analysis_shows_suggestions(capsys):
    from dbx_nwp_helper.config import IngressConfig

    render.ingress_analysis(_ingress_analysis(suggestions=pd.DataFrame([_sugg_row()])), IngressConfig())
    assert "Ranked suggestions" in capsys.readouterr().out


def test_explain_empty_candidates_hints_account_level(capsys):
    from dbx_nwp_helper.config import IngressConfig

    # public IPs exist only on account-level rows -> hint to pass --include-account-level.
    funnel = {
        "total_rows": 100,
        "with_source_ip": 80,
        "ipv4": 80,
        "ipv6": 0,
        "successful": 80,
        "workspace_level": 0,
        "account_level": 80,
        "public_ipv4": 80,
        "distinct_public_ok": 5,
        "distinct_public_ok_ws": 0,
    }
    render.ingress_analysis(_ingress_analysis(funnel=funnel), IngressConfig(include_account_level=False))
    out = capsys.readouterr().out
    assert "ACCOUNT-LEVEL" in out and "--include-account-level" in out


def test_explain_empty_candidates_hints_private_ips(capsys):
    from dbx_nwp_helper.config import IngressConfig

    # source IPs are all private/reserved -> PrivateLink/NAT hint.
    funnel = {
        "total_rows": 100,
        "with_source_ip": 80,
        "ipv4": 80,
        "ipv6": 0,
        "successful": 80,
        "workspace_level": 80,
        "account_level": 0,
        "public_ipv4": 0,
        "distinct_public_ok": 0,
        "distinct_public_ok_ws": 0,
    }
    render.ingress_analysis(_ingress_analysis(funnel=funnel), IngressConfig())
    assert "PrivateLink" in capsys.readouterr().out


def test_target_label_variants():
    from dbx_nwp_helper.core.ingress import ALL_WORKSPACES

    assert render._target_label(123, "per_workspace", ALL_WORKSPACES) == "workspace 123"
    assert render._target_label(ALL_WORKSPACES, "current_workspace", ALL_WORKSPACES) == "this workspace"
    assert render._target_label(ALL_WORKSPACES, "all_workspaces", ALL_WORKSPACES) == "all workspaces"
