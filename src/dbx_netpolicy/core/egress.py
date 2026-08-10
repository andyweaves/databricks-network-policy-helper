"""Egress (SEG) engine: classify observed destinations → owner lookup → rule specs → apply.

Ported from `notebooks/egress_helper.py`. analyze() reads outbound_network, classifies destinations
(S3/GCS/Azure storage vs internet FQDN), and optionally matches FQDNs to a cloud owner offline.
build_blocks()/apply() assemble and send the egress block(s).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

import pandas as pd

from ..config import (
    MAX_INTERNET_DESTINATIONS,
    MAX_STORAGE_DESTINATIONS,
    EgressConfig,
)
from ..feeds import cloud as cloud_feed
from ..feeds.http import FEED_USER_AGENT
from .enrich import as_list

Note = Callable[[str], None]
ALL_WORKSPACES = "__ALL__"

_S3_VH = re.compile(r'^(?P<bucket>[a-z0-9.\-]+)\.s3[.\-](?:(?P<region>[a-z0-9\-]+)\.)?amazonaws\.com$', re.I)
_S3_BARE = re.compile(r'^s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com$', re.I)
_GCS = re.compile(r'^(?:(?P<bucket>[a-z0-9._\-]+)\.)?storage\.googleapis\.com$', re.I)
_AZ = re.compile(r'^(?P<acct>[a-z0-9]+)\.(?P<svc>blob|dfs|file)\.core\.windows\.net$', re.I)

# ThreatFox — abuse.ch botnet-C2 IOC hostfile (free, no key). Best FQDN fit for the exfil use case.
THREAT_FEEDS = {"threatfox": "https://threatfox.abuse.ch/downloads/hostfile/"}


@dataclass
class EgressAnalysis:
    observed: pd.DataFrame
    targets: dict = field(default_factory=dict)         # policy_target -> {s3,gcs,azure,internet}
    fqdn_ip: dict = field(default_factory=dict)
    fqdn_owner: dict = field(default_factory=dict)
    blocked_domains: list = field(default_factory=list)
    skipped_bare_s3: int = 0


def _classify(host: str) -> tuple[str, dict]:
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return "skip_bare_s3", {}
    m = _S3_VH.match(h)
    if m and m.group("bucket") != "s3":
        return "s3", {"bucket": m.group("bucket"), "region": m.group("region")}
    if _S3_BARE.match(h):
        return "skip_bare_s3", {"host": h}
    g = _GCS.match(h)
    if g and g.group("bucket"):
        return "gcs", {"bucket": g.group("bucket")}
    a = _AZ.match(h)
    if a:
        return "azure", {"account": a.group("acct"), "service": a.group("svc")}
    return "internet", {"fqdn": h}


def _new_target():
    return {"s3": {}, "gcs": {}, "azure": {}, "internet": {}}


def analyze(cfg: EgressConfig, sql_conn, on_step=lambda _m: None) -> EgressAnalysis:
    from .. import queries, sql

    on_step("Querying observed egress destinations…")
    observed = sql.query(sql_conn, queries.observed_egress(
        cfg.lookback_days, cfg.min_events, cfg.source_type_filter))

    targets = defaultdict(_new_target)
    fqdn_resolved_ips = {}
    skipped_bare_s3 = 0
    for r in observed.to_dict(orient="records"):
        kind, info = _classify(r["destination"])
        events = int(r["events"])
        if kind == "s3":
            key, bucketname = ("s3", (info["bucket"], info.get("region") or ""))
        elif kind == "gcs":
            key, bucketname = ("gcs", info["bucket"])
        elif kind == "azure":
            key, bucketname = ("azure", (info["account"], info["service"]))
        elif kind == "internet":
            key, bucketname = ("internet", info["fqdn"])
            ips = fqdn_resolved_ips.setdefault(info["fqdn"], [])
            for ip in as_list(r.get("resolved_ips")):
                if ip not in ips:
                    ips.append(ip)
        else:
            skipped_bare_s3 += 1
            continue
        tgts = ([int(w) for w in as_list(r.get("workspace_ids"))] or [ALL_WORKSPACES]) \
            if cfg.policy_scope == "per_workspace" else [ALL_WORKSPACES]
        for t in tgts:
            d = targets[t][key]
            d[bucketname] = d.get(bucketname, 0) + events

    if not targets:
        targets[ALL_WORKSPACES] = _new_target()

    analysis = EgressAnalysis(observed=observed, targets=dict(targets), skipped_bare_s3=skipped_bare_s3)

    if cfg.enable_rdap:
        on_step("Matching internet FQDNs to a cloud owner (offline range match)…")
        _owner_lookup(analysis, fqdn_resolved_ips, cfg)

    if cfg.block_threat_domains != "off":
        on_step(f"Loading threat-domain feed '{cfg.threat_feed}'…")
        _blocked_domains(analysis, cfg, on_step)

    return analysis


def union(targets: dict, key: str) -> dict:
    merged = {}
    for t in targets:
        for k, n in targets[t][key].items():
            merged[k] = merged.get(k, 0) + n
    return merged


def _load_cloud_networks():
    """[(network, owner)] for offline IP membership tests — reuses the cloud feed loader plus
    the Databricks feed."""
    nets = []
    df = cloud_feed.load_cloud_ranges()
    for _, r in df.iterrows():
        try:
            nets.append((ipaddress.ip_network(r["cidr"], strict=False), r["provider"].upper()))
        except (ValueError, KeyError, AttributeError):
            pass
    from ..feeds import databricks as dbx_feed
    ddf = dbx_feed.load_databricks_ranges()
    for _, r in ddf.iterrows():
        try:
            nets.append((ipaddress.ip_network(r["cidr"], strict=False), "Databricks"))
        except (ValueError, KeyError):
            pass
    return nets


def _owner_lookup(analysis: EgressAnalysis, fqdn_resolved_ips: dict, cfg: EgressConfig):
    all_fqdns = union(analysis.targets, "internet")
    if not all_fqdns:
        return
    cloud_nets = _load_cloud_networks()

    def owner_for_ip(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.is_private:
            return "private/internal IP"
        for net, owner in cloud_nets:
            if addr.version == net.version and addr in net:
                return owner
        return "non-cloud / unknown"

    for fqdn in all_fqdns:
        ip = next(iter(fqdn_resolved_ips.get(fqdn, [])), None)
        if ip is None:
            try:
                ip = socket.gethostbyname(fqdn)
            except OSError:
                ip = None
        analysis.fqdn_ip[fqdn] = ip
        analysis.fqdn_owner[fqdn] = (owner_for_ip(ip) if ip is not None
                                     else "DNS resolution failed - check egress control")


def _host_hostfile(line: str) -> str:
    parts = line.split()
    return parts[1].lower() if len(parts) == 2 else ""


def _load_threat_domains(feed_key: str) -> set[str]:
    from urllib.request import Request, urlopen
    url = THREAT_FEEDS[feed_key]
    domains = set()
    try:
        req = Request(url, headers={"User-Agent": FEED_USER_AGENT})
        with urlopen(req, timeout=45) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith(("#", "!", "[")):
                continue
            host = _host_hostfile(s)
            if not host or "." not in host:
                continue
            try:
                ipaddress.ip_address(host)  # IP literal — not a valid FQDN block target
                continue
            except ValueError:
                pass
            domains.add(host)
    except Exception:  # noqa: BLE001
        pass
    return domains


def _blocked_domains(analysis: EgressAnalysis, cfg: EgressConfig, note: Note):
    feed = _load_threat_domains(cfg.threat_feed)
    all_fqdns = union(analysis.targets, "internet")
    if cfg.block_threat_domains == "matched_only":
        blocked = sorted(f for f in all_fqdns if f in feed)
    else:
        blocked = sorted(feed)
    if len(blocked) > MAX_INTERNET_DESTINATIONS:
        note(f"{len(blocked)} blocked domains > {MAX_INTERNET_DESTINATIONS} limit — keeping the "
             f"first {MAX_INTERNET_DESTINATIONS}. Use matched_only to narrow.")
        blocked = blocked[:MAX_INTERNET_DESTINATIONS]
    analysis.blocked_domains = blocked


# ------------------------------------------------------------------------------- build + apply
def _build_egress_block(t: dict, blocked_domains: list, policy_mode: str):
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EA,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyInternetDestination as InetDest,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyInternetDestinationInternetDestinationType as InetType,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcement as Enforcement,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcementEnforcementMode as EnforcementMode,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as RestrictionMode,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyStorageDestination as StorDest,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyStorageDestinationStorageDestinationType as StorType,
    )
    from databricks.sdk.service.settings import (
        NetworkPolicyEgress,
    )

    allowed_internet = [
        InetDest(destination=f, internet_destination_type=InetType.DNS_NAME)
        for f in list(t["internet"])[:MAX_INTERNET_DESTINATIONS]
    ]
    blocked_internet = [
        InetDest(destination=d, internet_destination_type=InetType.DNS_NAME) for d in blocked_domains
    ] or None

    storage = []
    for (bucket, region) in t["s3"]:
        storage.append(StorDest(bucket_name=bucket, region=region or None,
                                storage_destination_type=StorType.AWS_S3))
    for bucket in t["gcs"]:
        storage.append(StorDest(bucket_name=bucket, storage_destination_type=StorType.GOOGLE_CLOUD_STORAGE))
    for (acct, svc) in t["azure"]:
        storage.append(StorDest(azure_storage_account=acct, azure_storage_service=svc,
                                storage_destination_type=StorType.AZURE_STORAGE))
    storage = storage[:MAX_STORAGE_DESTINATIONS]

    enforcement_mode = EnforcementMode.DRY_RUN if policy_mode == "dry_run" else EnforcementMode.ENFORCED
    return NetworkPolicyEgress(network_access=EA(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allowed_internet_destinations=allowed_internet or None,
        allowed_storage_destinations=storage or None,
        blocked_internet_destinations=blocked_internet,
        policy_enforcement=Enforcement(enforcement_mode=enforcement_mode),
    ))


def _target_has_content(t: dict, blocked_domains: list) -> bool:
    return bool(t["s3"] or t["gcs"] or t["azure"] or t["internet"] or blocked_domains)


def build_blocks(analysis: EgressAnalysis, cfg: EgressConfig) -> dict:
    """{policy_target -> NetworkPolicyEgress} for each target with content."""
    return {tgt: _build_egress_block(t, analysis.blocked_domains, cfg.policy_mode)
            for tgt, t in analysis.targets.items()
            if _target_has_content(t, analysis.blocked_domains)}


def preview_blocks(analysis: EgressAnalysis, cfg: EgressConfig) -> dict:
    return {tgt: {"egress": block.as_dict()} for tgt, block in build_blocks(analysis, cfg).items()}


def apply(analysis: EgressAnalysis, cfg: EgressConfig, account, account_id: str,
          this_workspace_id, note: Note = lambda _m: None) -> list[dict]:
    from . import policy

    blocks = build_blocks(analysis, cfg)
    add_to_existing = cfg.apply.policy_action == "add_to_existing"
    results = []
    for tgt in sorted(blocks, key=str):
        pid = cfg.apply.existing_policy_id if add_to_existing else policy.policy_name(
            cfg.name_prefix, workspace_id=(None if tgt == ALL_WORKSPACES else int(tgt)))
        bind_ws = this_workspace_id if tgt == ALL_WORKSPACES else int(tgt)
        try:
            action, effective_id = policy.apply_egress(
                account, account_id, pid, blocks[tgt], must_exist=add_to_existing)
            result = {"target": tgt, "action": action, "policy_id": effective_id}
            if cfg.apply.auto_assign:
                policy.assign(account, bind_ws, effective_id)
                result["assigned"] = bind_ws
            results.append(result)
        except Exception as e:  # noqa: BLE001
            results.append({"target": tgt, "error": str(e)})
    return results
