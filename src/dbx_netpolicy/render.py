"""Presentation layer: turn engine results into Rich output.

Kept separate from core/ (pure logic) and cli.py (arg parsing / flow) so the guided wizard and the
flag-driven commands render identically. Each function takes an analysis/result object and prints.
"""

from __future__ import annotations

import pandas as pd

from . import console
from .config import AclConfig, EgressConfig, IngressConfig
from .core import egress as egress_core
from .core.egress import EgressAnalysis
from .core.ingress import ALL_WORKSPACES, IngressAnalysis


# ------------------------------------------------------------------------------------- decisions
def ingress_decisions(cfg: IngressConfig) -> None:
    console.decisions_panel("Ingress (CBI) configuration", [
        ("lookback_days", cfg.lookback_days, "Days of system.access.audit history to analyse."),
        ("min_events", cfg.min_events, "Min successful events for an IP to be a candidate."),
        ("treat_null_status_as_success", cfg.treat_null_status_as_success,
         "Whether NULL status counts as success (false = stricter)."),
        ("include_ipv6", cfg.include_ipv6, "Analyse IPv6 (policy itself is IPv4-only)."),
        ("include_account_level", cfg.include_account_level, "Include workspace_id=0 rows."),
        ("threat_feeds", cfg.threat_feeds, "Threat-intel feeds to load."),
        ("enable_rdap", cfg.enable_rdap, "RDAP owner lookup (needed for 'maximum' framing)."),
        ("policy_framing", cfg.policy_framing, "minimal=/32s, optimal=collapsed, maximum=RDAP range."),
        ("scoping_mode", cfg.scoping_mode, "Whether rules are scoped by destination and/or identity."),
        ("policy_scope", cfg.policy_scope, "single=one policy; per_workspace=one per workspace."),
        ("policy_mode", cfg.policy_mode, "dry_run=log-only; enforce=blocking."),
        ("threat_deny_rules", cfg.threat_deny_rules, "Add deny rules from threat intel."),
        ("name_prefix", cfg.name_prefix, "Prefix for policy names + rule labels."),
        ("ip_acl_handling", cfg.ip_acl_handling, "Existing IP ACL treatment."),
        ("deny_denied_ips", cfg.deny_denied_ips, "Deny source IPs currently seen blocked (403)."),
        ("create_policy", cfg.apply.create_policy, "Master switch: nothing is written unless true."),
        ("policy_action", cfg.apply.policy_action, "create_new or add_to_existing."),
        ("existing_policy_id", cfg.apply.existing_policy_id, "Target id for add_to_existing."),
        ("auto_assign", cfg.apply.auto_assign, "Bind the workspace(s) to the policy."),
    ])


def egress_decisions(cfg: EgressConfig) -> None:
    console.decisions_panel("Egress (SEG) configuration", [
        ("lookback_days", cfg.lookback_days, "Days of outbound_network history."),
        ("min_events", cfg.min_events, "Min events per destination."),
        ("source_type_filter", cfg.source_type_filter, "network_source_type filter (blank=all)."),
        ("enable_rdap", cfg.enable_rdap, "Cloud-owner lookup for internet FQDNs."),
        ("policy_scope", cfg.policy_scope, "single=one policy; per_workspace=one per workspace."),
        ("policy_mode", cfg.policy_mode, "dry_run=log-only; enforce=blocking."),
        ("block_threat_domains", cfg.block_threat_domains, "off / matched_only / all."),
        ("threat_feed", cfg.threat_feed, "Threat-domain feed (abuse.ch ThreatFox)."),
        ("name_prefix", cfg.name_prefix, "Prefix for policy names."),
        ("create_policy", cfg.apply.create_policy, "Master switch: nothing is written unless true."),
        ("policy_action", cfg.apply.policy_action, "create_new or add_to_existing."),
        ("existing_policy_id", cfg.apply.existing_policy_id, "Target id for add_to_existing."),
        ("auto_assign", cfg.apply.auto_assign, "Bind the workspace(s) to the policy."),
    ])


def acl_decisions(cfg: AclConfig) -> None:
    console.decisions_panel("IP ACL → CBI migration configuration", [
        ("policy_mode", cfg.policy_mode, "enforce (default) or dry_run."),
        ("name_prefix", cfg.name_prefix, "Prefix for the policy name/rule labels."),
        ("egress_policy", cfg.egress_policy, "Egress set on create: allow_all/dry_run/restricted."),
        ("auto_assign", cfg.auto_assign, "Bind this workspace to the new policy."),
        ("create_policy", cfg.create_policy, "Master switch: nothing is written unless true."),
    ])


# ------------------------------------------------------------------------------- ingress tables
def ingress_analysis(analysis: IngressAnalysis) -> None:
    console.rule("Candidate public source IPs")
    console.dataframe(_trim(analysis.candidates,
                            ["public_ip", "events", "principals", "services", "active_days",
                             "first_active_date", "last_active_date"]),
                      f"Frequent public source IPs ({len(analysis.candidates):,})")

    console.rule("Proposed CIDR groups")
    if analysis.suggestions.empty:
        console.banner("warn", "No candidate IP groups produced suggestions — check thresholds.")
    else:
        console.dataframe(_trim(analysis.suggestions,
                                ["policy_target", "rdap_owner", "recommendation", "distinct_ips",
                                 "total_events", "scoped_destination", "threat_feeds",
                                 "cloud_provider", "databricks_owned"]),
                          "Ranked suggestions (flagged groups excluded from allow rules)")

    console.rule("⚠️  Threat-intelligence matches")
    if analysis.threat_matches.empty:
        console.banner("success", "No observed source IPs matched any threat-intelligence feed.")
    else:
        n = analysis.threat_matches["observed_ip"].nunique()
        console.banner("warn", f"{n} observed IP(s) matched threat intel — investigate regardless "
                               "of the allow-list (may indicate a compromised identity).")
        console.dataframe(_trim(analysis.threat_matches,
                                ["observed_ip", "matched_cidr", "source_feed", "threat_type",
                                 "confidence", "events", "principals"]),
                          "Observed IPs on a threat feed")

    if not analysis.denied_requests.empty:
        console.rule("Currently-denied requests (403 / IpAccessDenied)")
        console.dataframe(_trim(analysis.denied_requests,
                                ["source_ip", "denied_events", "principals", "first_denied",
                                 "last_denied"]),
                          "Source IPs currently blocked by the IP ACL")


def ingress_preview(previews: dict, cfg: IngressConfig, analysis: IngressAnalysis) -> None:
    console.rule("Proposed policy — JSON preview")
    console.mode_banner(cfg.policy_mode)
    if not previews:
        console.banner("warn", "No rule specs to preview — revisit framing/scoping/threat options.")
        return
    for tgt in sorted(previews, key=str):
        label = "single policy (all workspaces)" if tgt == ALL_WORKSPACES else f"workspace {tgt}"
        console.json_panel(f"{label} — `{cfg.policy_mode_target}` block", previews[tgt])
    if analysis.excluded_flagged:
        console.banner("info",
                       f"Excluded {analysis.excluded_flagged} flagged group(s) (threat/cloud-owned).")
    if analysis.skipped_ipv6:
        console.banner("info", f"{analysis.skipped_ipv6} IPv6 CIDR(s) omitted (CBI is IPv4-only).")


# -------------------------------------------------------------------------------- egress tables
def egress_analysis(analysis: EgressAnalysis) -> None:
    console.rule("Observed egress destinations")
    if analysis.observed.empty:
        console.banner("warn", "outbound_network is empty for this window. Stand up an egress policy "
                               "in dry_run (restricted, log-only) first, let it observe, then re-run.")
    targets = analysis.targets
    internet = egress_core.union(targets, "internet")
    s3 = egress_core.union(targets, "s3")
    gcs = egress_core.union(targets, "gcs")
    azure = egress_core.union(targets, "azure")

    console.dataframe(
        pd.DataFrame([{"fqdn": f, "events": n, "resolved_ip": analysis.fqdn_ip.get(f),
                       "hosting_owner": analysis.fqdn_owner.get(f)}
                      for f, n in sorted(internet.items(), key=lambda kv: kv[1], reverse=True)]),
        f"Internet FQDNs to allow ({len(internet)})")
    console.dataframe(
        pd.DataFrame([{"bucket": b, "region": reg, "events": n}
                      for (b, reg), n in sorted(s3.items(), key=lambda kv: kv[1], reverse=True)]),
        f"AWS S3 buckets ({len(s3)})")
    console.dataframe(
        pd.DataFrame([{"bucket": b, "events": n}
                      for b, n in sorted(gcs.items(), key=lambda kv: kv[1], reverse=True)]),
        f"GCS buckets ({len(gcs)})")
    console.dataframe(
        pd.DataFrame([{"account": a, "service": s, "events": n}
                      for (a, s), n in sorted(azure.items(), key=lambda kv: kv[1], reverse=True)]),
        f"Azure storage ({len(azure)})")
    if analysis.blocked_domains:
        console.dataframe(
            pd.DataFrame([{"blocked_domain": d, "observed_in_egress": d in internet}
                          for d in analysis.blocked_domains]),
            f"Threat-intel blocked domains ({len(analysis.blocked_domains)})")
    if analysis.skipped_bare_s3:
        console.banner("info", f"Skipped {analysis.skipped_bare_s3} bare/path-style S3 endpoint(s).")


def egress_preview(previews: dict, cfg: EgressConfig) -> None:
    console.rule("Proposed egress policy — JSON preview")
    console.mode_banner(cfg.policy_mode)
    if not previews:
        console.banner("warn", "Nothing to propose — no classified destinations.")
        return
    for tgt in sorted(previews, key=str):
        label = "single (all workspaces)" if tgt == egress_core.ALL_WORKSPACES else f"workspace {tgt}"
        console.json_panel(f"{label} — egress block", previews[tgt])


# ---------------------------------------------------------------------------------- acl tables
def acl_analysis(analysis, cfg: AclConfig) -> None:
    console.rule("Existing IP access list")
    if not analysis.ip_acls:
        console.banner("warn", "No enabled IP access lists on this workspace — nothing to migrate.")
        return
    console.dataframe(
        pd.DataFrame([{**a, "ip_addresses": ", ".join(a["ip_addresses"])} for a in analysis.ip_acls]),
        f"Enabled IP access lists on workspace {analysis.workspace_id}")


def acl_preview(preview: dict, cfg: AclConfig) -> None:
    console.rule("Proposed policy — JSON preview")
    console.mode_banner(cfg.policy_mode)
    console.json_panel(f"`{cfg.policy_mode_target}` block", preview)


# ------------------------------------------------------------------------------- apply results
def apply_results(results: list[dict]) -> None:
    console.rule("Apply results")
    for r in results:
        if "error" in r:
            console.banner("danger", f"target {r['target']}: {r['error']}")
            continue
        msg = f"{r['action']} '{r['policy_id']}'"
        if r.get("assigned") is not None:
            msg += f" and bound workspace {r['assigned']}"
        console.banner("success", msg)


def _trim(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """Keep only the columns that exist, in the given order (for compact tables)."""
    if df is None or df.empty:
        return df
    keep = [c for c in cols if c in df.columns]
    return df[keep] if keep else df
