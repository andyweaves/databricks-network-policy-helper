"""Ingress (CBI) engine: candidate IPs → enrich → group → CIDR framings → rule specs → apply.

Ported from `notebooks/ingress_helper.py`. The engine is stepwise so the CLI can render a review
table after each stage: analyze() runs the SQL + enrichment and returns the review DataFrames;
build_rules() turns suggestions into per-target allow/deny specs; preview()/apply() build and send
the SDK blocks. All account-level work (SCIM, apply) takes an AccountClient the caller supplies.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

import pandas as pd

from ..config import IngressConfig
from ..feeds import loaders, rdap
from . import enrich

ALL_WORKSPACES = "__ALL__"


@dataclass
class IngressAnalysis:
    """Everything analyze() produced — the review tables + intermediate state build_rules() needs."""
    candidates: pd.DataFrame
    suggestions: pd.DataFrame
    threat_matches: pd.DataFrame
    denied_requests: pd.DataFrame
    ip_acls: list[dict]
    suggestion_rows: list[dict] = field(default_factory=list)
    threat_match_rows: list[dict] = field(default_factory=list)
    threat_ranges: list = field(default_factory=list)
    excluded_flagged: int = 0
    skipped_ipv6: int = 0
    # Populated only when the candidate set is empty: a one-row filter-funnel dict explaining where
    # the audit rows were dropped (see queries.candidate_funnel).
    funnel: dict | None = None


def analyze(cfg: IngressConfig, sql_conn, workspace_client, on_step=lambda _m: None) -> IngressAnalysis:
    """Run SQL + enrichment and produce the candidate/suggestion/threat-match review tables."""
    from .. import queries, sql

    # current_workspace scope restricts the analysis to this workspace's own traffic.
    only_ws = workspace_client.get_workspace_id() if cfg.policy_scope == "current_workspace" else None
    if only_ws is not None:
        on_step(f"Scope=current_workspace — restricting analysis to workspace {only_ws}.")

    on_step("Querying frequent public source IPs…")
    candidates = sql.query(sql_conn, queries.frequent_public_ips(
        cfg.lookback_days, cfg.min_events, cfg.include_ipv6,
        cfg.treat_null_status_as_success, cfg.include_account_level, only_workspace_id=only_ws))

    # When there are no candidates, run a cheap diagnostic funnel so we can explain *why* rather than
    # just reporting an empty table (the most common confusion: public IPs live on account-level rows,
    # or PrivateLink/NAT masks the real source IP).
    funnel = None
    if candidates.empty:
        on_step("No candidates — running a diagnostic funnel to explain why…")
        fdf = sql.query(sql_conn, queries.candidate_funnel(
            cfg.lookback_days, cfg.treat_null_status_as_success))
        funnel = fdf.to_dict(orient="records")[0] if not fdf.empty else None

    on_step("Reading the workspace IP access list + denied requests…")
    ip_acls = _read_ip_acls(workspace_client)
    denied = sql.query(sql_conn, queries.denied_requests(cfg.lookback_days))

    on_step("Loading enrichment feeds (threat-intel / cloud / Databricks ranges)…")
    threat_df = loaders.threat_intel(cfg.threat_feeds, refresh=cfg.refresh_feeds)
    cloud_df = loaders.cloud_ranges(refresh=cfg.refresh_feeds)
    dbx_df = loaders.databricks_ranges(refresh=cfg.refresh_feeds)
    on_step(f"Loaded enrichment ranges: {len(threat_df):,} threat-intel, {len(cloud_df):,} cloud, "
            f"{len(dbx_df):,} Databricks.")
    # A feed that comes back empty (download failed) would make its membership checks silently false;
    # flag it so the operator knows the enrichment is degraded rather than trusting a clean result.
    for label, df in (("cloud-provider", cloud_df), ("Databricks", dbx_df)):
        if df.empty:
            on_step(f"⚠️  {label} ranges are EMPTY — those checks can't run (likely a feed download "
                    f"failure). Re-run with --refresh-feeds, or check network/proxy egress.")
    threat_ranges = enrich.load_ranges(threat_df, ["source_feed", "threat_type", "confidence", "source_url"])
    cloud_ranges = enrich.load_ranges(cloud_df, ["provider", "service", "region"])
    databricks_ranges = enrich.load_ranges(dbx_df, ["platform", "region", "direction"])

    on_step("Enriching candidate IPs (RDAP owner lookup, range membership)…")
    enriched, threat_match_rows = _enrich_candidates(
        candidates, cfg, threat_ranges, cloud_ranges, databricks_ranges)

    suggestion_rows = _build_suggestions(enriched, cfg)

    suggestions_pdf = (
        pd.DataFrame(suggestion_rows).sort_values(
            ["policy_target", "recommendation", "total_events"], ascending=[True, True, False])
        if suggestion_rows else pd.DataFrame()
    )
    threat_matches_pdf = (
        pd.DataFrame(threat_match_rows).sort_values(["confidence", "events"], ascending=[True, False])
        if threat_match_rows else pd.DataFrame()
    )
    return IngressAnalysis(
        candidates=candidates, suggestions=suggestions_pdf, threat_matches=threat_matches_pdf,
        denied_requests=denied, ip_acls=ip_acls, suggestion_rows=suggestion_rows,
        threat_match_rows=threat_match_rows, threat_ranges=threat_ranges, funnel=funnel,
    )


def _read_ip_acls(workspace_client) -> list[dict]:
    acls = []
    try:
        for acl in workspace_client.ip_access_lists.list():
            acls.append({
                "label": acl.label,
                "list_type": acl.list_type.value if acl.list_type else None,
                "enabled": acl.enabled,
                "ip_addresses": list(acl.ip_addresses or []),
            })
    except Exception:  # noqa: BLE001 - API may be unavailable / not configured
        pass
    return acls


def _enrich_candidates(candidates, cfg, threat_ranges, cloud_ranges, databricks_ranges):
    import time

    rdap_cache, enriched, threat_match_rows = {}, [], []
    for record in candidates.to_dict(orient="records"):
        ip_str = record["public_ip"]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if cfg.enable_rdap:
            if ip_str not in rdap_cache:
                rdap_cache[ip_str] = rdap.lookup(ip_str)
                time.sleep(rdap.RDAP_DELAY_SECONDS)
            rdap_result = rdap_cache[ip_str]
        else:
            rdap_result = {"rdap_owner_name": None, "rdap_type": None, "maximum_cidrs": None}

        record["principal_list"] = enrich.as_list(record.get("principal_list"))
        record["principal_emails"] = enrich.as_list(record.get("principal_emails"))
        record["subject_names"] = enrich.as_list(record.get("subject_names"))
        record["workspace_ids"] = [int(w) for w in enrich.as_list(record.get("workspace_ids"))]

        threat_hits, threat_cidrs = enrich.match_ranges(ip_obj, threat_ranges)
        cloud_hits, _ = enrich.match_ranges(ip_obj, cloud_ranges)
        databricks_hits, _ = enrich.match_ranges(ip_obj, databricks_ranges)
        for meta, matched_cidr in zip(threat_hits, threat_cidrs, strict=False):
            threat_match_rows.append({
                "observed_ip": ip_str, "matched_cidr": matched_cidr,
                "source_feed": meta["source_feed"], "threat_type": meta["threat_type"],
                "confidence": meta["confidence"], "source_url": meta.get("source_url"),
                "events": record["events"], "principals": record["principals"],
                "first_active_date": record.get("first_active_date"),
                "last_active_date": record.get("last_active_date"),
            })

        destinations = sorted({enrich.service_to_destination(s)
                               for s in enrich.as_list(record.get("service_list"))})
        record.update({
            "ip_obj": ip_obj,
            "rdap_owner_name": rdap_result["rdap_owner_name"],
            "maximum_cidrs": rdap_result["maximum_cidrs"],
            "destinations": destinations,
            "threat_feeds": sorted({h["source_feed"] for h in threat_hits}),
            "cloud_provider": sorted({h["provider"] for h in cloud_hits}),
            "databricks_owned": sorted({h["platform"] for h in databricks_hits}),
        })
        enriched.append(record)
    return enriched, threat_match_rows


def _fallback_group_key(rec):
    if rec["ip_obj"].version == 4:
        return str(ipaddress.ip_network(f"{rec['public_ip']}/24", strict=False))
    return str(ipaddress.ip_network(f"{rec['public_ip']}/48", strict=False))


def _collapse_destinations(dest_sets):
    flat = {d for ds in dest_sets for d in ds}
    if flat and flat <= {"apps_runtime"}:
        return "apps_runtime"
    if flat and flat <= {"lakebase_runtime"}:
        return "lakebase_runtime"
    return "all_destinations"


def _build_suggestions(enriched, cfg) -> list[dict]:
    groups = defaultdict(list)
    for rec in enriched:
        owner = rec["rdap_owner_name"] or _fallback_group_key(rec)
        targets = (rec["workspace_ids"] or [ALL_WORKSPACES]) if cfg.policy_scope == "per_workspace" \
            else [ALL_WORKSPACES]
        for tgt in targets:
            groups[(tgt, owner)].append(rec)

    suggestion_rows = []
    for (policy_target, owner), recs in groups.items():
        ip_objs = [r["ip_obj"] for r in recs]
        minimal = [f"{ip}/{ip.max_prefixlen}" for ip in sorted(set(ip_objs), key=int)]
        optimal = [str(n) for n in ipaddress.collapse_addresses(sorted(set(ip_objs), key=int))]
        maximum = sorted({c for r in recs if r["maximum_cidrs"] for c in r["maximum_cidrs"]})
        threat_feeds = sorted({f for r in recs for f in r["threat_feeds"]})
        cloud_providers = sorted({p for r in recs for p in r["cloud_provider"]})
        databricks_owned = sorted({p for r in recs for p in r.get("databricks_owned", [])})
        principals = sorted({p for r in recs for p in r["principal_list"]})
        principal_emails = sorted({e for r in recs for e in (r.get("principal_emails") or []) if e})
        subject_names = sorted({sn for r in recs for sn in (r.get("subject_names") or []) if sn})
        scoped_destination = _collapse_destinations([set(r["destinations"]) for r in recs])
        suggestion_rows.append({
            "policy_target": policy_target,
            "rdap_owner": owner,
            "distinct_ips": len(set(ip_objs)),
            "total_events": sum(r["events"] for r in recs),
            "principals": principals,
            "principal_emails": principal_emails,
            "subject_names": subject_names,
            "scoped_destination": scoped_destination,
            "minimal_cidrs": minimal,
            "optimal_cidrs": optimal,
            "maximum_cidrs": maximum or None,
            "threat_feeds": threat_feeds or None,
            "cloud_provider": cloud_providers or None,
            "databricks_owned": databricks_owned or None,
            "recommendation": (
                "ALLOW — Databricks-owned" if databricks_owned else
                "REVIEW — known-bad range" if threat_feeds else
                "REVIEW — cloud-owned range" if cloud_providers else
                "candidate"
            ),
        })
    return suggestion_rows
