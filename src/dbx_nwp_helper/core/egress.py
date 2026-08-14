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
    DEFAULT_NAME_PREFIX,
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
    # S3 buckets dropped because a region couldn't be determined (region is required by the API for
    # AWS storage destinations). List of bucket names.
    dropped_s3_no_region: list = field(default_factory=list)


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


def _infer_s3_region(bucket: str) -> str | None:
    """Best-effort S3 bucket region lookup. A HEAD to the global endpoint returns the bucket's home
    region in the `x-amz-bucket-region` header, no credentials required. Returns the region or None.
    Cached per bucket by the caller."""
    from urllib.request import Request, urlopen
    for url in (f"https://{bucket}.s3.amazonaws.com", f"https://s3.amazonaws.com/{bucket}"):
        try:
            req = Request(url, method="HEAD")
            with urlopen(req, timeout=10) as resp:
                region = resp.headers.get("x-amz-bucket-region")
                if region:
                    return region
        except Exception as e:  # noqa: BLE001 - 301/403/404 all still carry the region header
            hdrs = getattr(getattr(e, "headers", None), "get", lambda _k: None)
            region = hdrs("x-amz-bucket-region") if hdrs else None
            if region:
                return region
    return None


def analyze(cfg: EgressConfig, sql_conn, on_step=lambda _m: None,
            this_workspace_id=None) -> EgressAnalysis:
    from .. import queries, sql

    only_ws = this_workspace_id if cfg.policy_scope == "current_workspace" else None
    if only_ws is not None:
        on_step(f"Scope=current_workspace — restricting analysis to workspace {only_ws}.")

    on_step("Querying observed egress destinations…")
    observed = sql.query(sql_conn, queries.observed_egress(
        cfg.lookback_days, cfg.min_events, cfg.source_type_filter, only_workspace_id=only_ws))

    targets = defaultdict(_new_target)
    fqdn_resolved_ips = {}
    skipped_bare_s3 = 0
    s3_region_cache: dict[str, str | None] = {}  # bucket -> region (inferred once), None if unknown
    dropped_s3: dict[str, bool] = {}             # bucket -> True once dropped (dedupe warnings)
    for r in observed.to_dict(orient="records"):
        kind, info = _classify(r["destination"])
        events = int(r["events"])
        if kind == "s3":
            bucket = info["bucket"]
            region = info.get("region")
            if not region:
                # Global endpoint (<bucket>.s3.amazonaws.com) has no region in the host. Region is
                # required by the API, so infer it via a HEAD; drop the bucket if we can't.
                if bucket not in s3_region_cache:
                    on_step(f"Inferring S3 region for bucket '{bucket}'…")
                    s3_region_cache[bucket] = _infer_s3_region(bucket)
                region = s3_region_cache[bucket]
            if not region:
                dropped_s3[bucket] = True
                continue
            key, bucketname = ("s3", (bucket, region))
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

    analysis = EgressAnalysis(observed=observed, targets=dict(targets), skipped_bare_s3=skipped_bare_s3,
                              dropped_s3_no_region=sorted(dropped_s3))

    if cfg.enable_rdap:
        on_step("Matching internet FQDNs to a cloud owner (offline range match)…")
        _owner_lookup(analysis, fqdn_resolved_ips, cfg)

    if cfg.block_threat_domains != "off":
        on_step(f"Loading threat-domain feed '{cfg.threat_feed}'…")
        _blocked_domains(analysis, cfg, on_step)

    return analysis


_CLOUD_OWNERS = {"AWS", "GCP", "AZURE", "Azure", "ORACLE", "Oracle"}
# Owner values that mean "we couldn't identify it" rather than a real provider name.
_UNKNOWN_OWNERS = {None, "Unknown", "DNS resolution failed - check egress control"}


def recommend(hosting_owner: str | None) -> str:
    """Map an internet-FQDN hosting owner to a recommendation:
      Databricks                     -> ALLOW — Databricks-owned
      AWS / GCP / Azure / Oracle     -> REVIEW — Cloud-owned
      a named RDAP owner             -> REVIEW — Other infra provider
      Unknown / DNS failed / off     -> REVIEW — owner unknown  (don't claim a provider we can't see)
    (Storage destinations — S3/GCS/Azure — are always cloud-owned, so they get REVIEW — Cloud-owned.)"""
    if hosting_owner == "Databricks":
        return "ALLOW — Databricks-owned"
    if hosting_owner in _CLOUD_OWNERS:
        return "REVIEW — Cloud-owned"
    if hosting_owner in _UNKNOWN_OWNERS:
        return "REVIEW — owner unknown"
    # A real, named non-cloud owner from RDAP (Cloudflare, GitHub, Palo Alto, …).
    return "REVIEW — Other infra provider"


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
        """Cloud provider name if the IP is in a published range, else None (caller tries RDAP)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.is_private:
            return "private/internal IP"
        for net, owner in cloud_nets:
            if addr.version == net.version and addr in net:
                return owner
        return None

    from ..feeds import rdap

    rdap_cache: dict[str, str | None] = {}

    def rdap_owner(ip):
        """RDAP fallback for IPs not in a published cloud range — names the real owner (Cloudflare,
        Akamai, DigitalOcean, …). Cached per IP; best-effort (None on failure)."""
        if ip not in rdap_cache:
            rdap_cache[ip] = (rdap.lookup(ip) or {}).get("rdap_owner_name")
        return rdap_cache[ip]

    for fqdn in all_fqdns:
        ip = next(iter(fqdn_resolved_ips.get(fqdn, [])), None)
        if ip is None:
            try:
                ip = socket.gethostbyname(fqdn)
            except OSError:
                ip = None
        analysis.fqdn_ip[fqdn] = ip
        if ip is None:
            analysis.fqdn_owner[fqdn] = "DNS resolution failed - check egress control"
            continue
        # Cloud-range match (AWS/GCP/Azure/Oracle/Databricks) wins; else RDAP owner; else Unknown.
        owner = owner_for_ip(ip) or rdap_owner(ip) or "Unknown"
        analysis.fqdn_owner[fqdn] = owner


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

    # Both destination lists are capped at 100; when there are more, keep the highest-traffic ones
    # (deterministic: events desc, then name asc as a stable tie-break) rather than an arbitrary
    # dict order — the excess is dropped from the allow-list, so it should be the least-used.
    internet_ranked = sorted(t["internet"].items(), key=lambda kv: (-kv[1], kv[0]))
    allowed_internet = [
        InetDest(destination=f, internet_destination_type=InetType.DNS_NAME)
        for f, _events in internet_ranked[:MAX_INTERNET_DESTINATIONS]
    ]
    blocked_internet = [
        InetDest(destination=d, internet_destination_type=InetType.DNS_NAME) for d in blocked_domains
    ] or None

    # (events, tie-break key, StorDest) across all three storage kinds, ranked together so the cap
    # keeps the busiest buckets/accounts regardless of provider.
    storage_ranked = []
    for (bucket, region), events in t["s3"].items():
        if not region:
            continue  # region is required for AWS S3; a region-less entry would be rejected
        storage_ranked.append((events, f"s3:{bucket}:{region}",
                               StorDest(bucket_name=bucket, region=region,
                                        storage_destination_type=StorType.AWS_S3)))
    for bucket, events in t["gcs"].items():
        storage_ranked.append((events, f"gcs:{bucket}",
                               StorDest(bucket_name=bucket,
                                        storage_destination_type=StorType.GOOGLE_CLOUD_STORAGE)))
    for (acct, svc), events in t["azure"].items():
        storage_ranked.append((events, f"azure:{acct}:{svc}",
                               StorDest(azure_storage_account=acct, azure_storage_service=svc,
                                        storage_destination_type=StorType.AZURE_STORAGE)))
    storage_ranked.sort(key=lambda e: (-e[0], e[1]))
    storage = [sd for _events, _key, sd in storage_ranked[:MAX_STORAGE_DESTINATIONS]]

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


def _warn_egress_limits(t: dict, tgt, note: Note) -> None:
    """Warn when a target's destinations exceed the per-policy egress caps (100 internet FQDNs / 100
    storage destinations). The excess is dropped from the allow-list — and would be *blocked* in
    enforce mode — so the operator must be told rather than have it happen silently."""
    where = "" if tgt == ALL_WORKSPACES else f" [workspace {tgt}]"
    n_internet = len(t["internet"])
    if n_internet > MAX_INTERNET_DESTINATIONS:
        note(f"{n_internet} internet FQDN destinations{where} exceed the "
             f"{MAX_INTERNET_DESTINATIONS}-destination egress limit — keeping the "
             f"{MAX_INTERNET_DESTINATIONS} highest-traffic; the rest won't be allow-listed (and "
             f"would be blocked in enforce mode). Raise --min-events or narrow --lookback-days to "
             f"fit under the cap.")
    n_storage = len(t["s3"]) + len(t["gcs"]) + len(t["azure"])
    if n_storage > MAX_STORAGE_DESTINATIONS:
        note(f"{n_storage} storage destinations{where} exceed the "
             f"{MAX_STORAGE_DESTINATIONS}-destination egress limit — keeping the "
             f"{MAX_STORAGE_DESTINATIONS} highest-traffic; the rest won't be allow-listed (and "
             f"would be blocked in enforce mode).")


def build_blocks(analysis: EgressAnalysis, cfg: EgressConfig, note: Note = lambda _m: None) -> dict:
    """{policy_target -> NetworkPolicyEgress} for each target with content."""
    blocks = {}
    for tgt, t in analysis.targets.items():
        if not _target_has_content(t, analysis.blocked_domains):
            continue
        _warn_egress_limits(t, tgt, note)
        blocks[tgt] = _build_egress_block(t, analysis.blocked_domains, cfg.policy_mode)
    return blocks


def preview_blocks(analysis: EgressAnalysis, cfg: EgressConfig, note: Note = lambda _m: None) -> dict:
    return {tgt: {"egress": block.as_dict()}
            for tgt, block in build_blocks(analysis, cfg, note).items()}


def _single_policy_id(cfg: EgressConfig, profile, this_workspace_id) -> str:
    """The policy id for a single-policy scope (current_workspace / all_workspaces): the
    add_to_existing target, else the resolved policy name (profile/workspace-id default)."""
    from . import policy
    if cfg.apply.policy_action == "add_to_existing":
        return cfg.apply.existing_policy_id
    name = cfg.policy_name or profile or str(this_workspace_id)
    return policy.policy_name("", explicit=name)


def export_payload(analysis: EgressAnalysis, cfg: EgressConfig, account_id: str, this_workspace_id,
                   profile: str | None = None) -> dict:
    """The proposed network policy as a plain dict (for --export / a curl body): the egress block +
    a permissive FULL_ACCESS ingress default. Single-policy scopes only."""
    from databricks.sdk.service.settings import AccountNetworkPolicy

    from . import policy
    blocks = build_blocks(analysis, cfg)
    egress_block = blocks.get(ALL_WORKSPACES) or (next(iter(blocks.values())) if blocks else None)
    np = AccountNetworkPolicy(
        account_id=account_id, network_policy_id=_single_policy_id(cfg, profile, this_workspace_id),
        ingress=policy.build_full_access_ingress(), egress=egress_block)
    return np.as_dict()


def apply(analysis: EgressAnalysis, cfg: EgressConfig, account, account_id: str,
          this_workspace_id, profile: str | None = None, note: Note = lambda _m: None) -> list[dict]:
    from . import policy

    blocks = build_blocks(analysis, cfg)
    add_to_existing = cfg.apply.policy_action == "add_to_existing"
    results = []
    for tgt in sorted(blocks, key=str):
        # per_workspace fans out to <prefix>-ws-<id>; every single-policy case (incl. add_to_existing
        # and --policy-name) resolves via _single_policy_id.
        if tgt == ALL_WORKSPACES:
            pid = _single_policy_id(cfg, profile, this_workspace_id)
        else:
            prefix = cfg.policy_name or profile or DEFAULT_NAME_PREFIX
            pid = policy.policy_name(prefix, workspace_id=int(tgt))
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
