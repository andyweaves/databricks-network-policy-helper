"""Threat-intelligence IP feeds → a `threat_intel_ips` DataFrame.

Columns: cidr, source_feed, threat_type, confidence, source_url, loaded_at.
confidence 1 = high, 2 = medium. Ported verbatim from the ingress notebook's feed loaders.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd

from .http import http_get
from .util import dedupe, valid_cidr

THREAT_INTEL_COLUMNS = ["cidr", "source_feed", "threat_type", "confidence", "source_url", "loaded_at"]

SPAMHAUS_DROP_V4_URL = "https://www.spamhaus.org/drop/drop_v4.json"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.json"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
FIREHOL_LEVEL1_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"
CINS_CI_ARMY_URL = "https://cinsscore.com/list/ci-badguys.txt"

IPSUM_MIN_LISTS = 3
IPSUM_HIGH_CONFIDENCE_LISTS = 5


def _feed_spamhaus_drop(now):
    rows = []
    for url, ver in [(SPAMHAUS_DROP_V4_URL, 4), (SPAMHAUS_DROP_V6_URL, 6)]:
        text = http_get(url)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            cidr = valid_cidr(obj.get("cidr", ""), want_version=ver)
            if cidr:
                rows.append((cidr, "spamhaus_drop", "botnet_c2", 1, url, now))
    return rows


def _feed_tor_exit(now):
    rows = []
    text = http_get(TOR_EXIT_URL)
    if text:
        for line in text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            cidr = valid_cidr(f"{ip}/32" if ":" not in ip else f"{ip}/128")
            if cidr:
                rows.append((cidr, "tor_exit", "anonymizer", 2, TOR_EXIT_URL, now))
    return rows


def _feed_firehol_level1(now):
    rows = []
    text = http_get(FIREHOL_LEVEL1_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cidr = valid_cidr(line)
            if cidr:
                rows.append((cidr, "firehol_level1", "aggregated_blocklist", 1, FIREHOL_LEVEL1_URL, now))
    return rows


def _feed_ipsum(now):
    rows = []
    text = http_get(IPSUM_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            count = int(parts[1])
            if count < IPSUM_MIN_LISTS:
                continue
            cidr = valid_cidr(f"{parts[0]}/32", want_version=4)
            if cidr:
                confidence = 1 if count >= IPSUM_HIGH_CONFIDENCE_LISTS else 2
                rows.append((cidr, "ipsum", "aggregated_blocklist", confidence, IPSUM_URL, now))
    return rows


def _feed_dshield(now):
    rows = []
    text = http_get(DSHIELD_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2].isdigit():
                continue
            cidr = valid_cidr(f"{parts[0]}/{parts[2]}", want_version=4)
            if cidr:
                rows.append((cidr, "dshield", "attacker_subnet", 1, DSHIELD_URL, now))
    return rows


def _feed_cins_ci_army(now):
    rows = []
    text = http_get(CINS_CI_ARMY_URL)
    if text:
        for line in text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            cidr = valid_cidr(f"{ip}/32", want_version=4)
            if cidr:
                rows.append((cidr, "cins_ci_army", "malicious_host", 2, CINS_CI_ARMY_URL, now))
    return rows


THREAT_FEED_LOADERS = {
    "spamhaus_drop": _feed_spamhaus_drop,
    "tor_exit": _feed_tor_exit,
    "firehol_level1": _feed_firehol_level1,
    "ipsum": _feed_ipsum,
    "dshield": _feed_dshield,
    "cins_ci_army": _feed_cins_ci_army,
}


def load_threat_intel(selected_feeds: list[str]) -> pd.DataFrame:
    """Union the selected feeds into a de-duplicated (cidr, feed) DataFrame."""
    now = datetime.now(timezone.utc)
    rows = []
    for feed in selected_feeds:
        loader = THREAT_FEED_LOADERS.get(feed)
        if not loader:
            continue
        feed_rows = loader(now)
        from ..console import console

        console.print(f"  [muted]{feed}: {len(feed_rows):,} rows[/muted]")
        rows.extend(feed_rows)
    rows = dedupe(rows, (0, 1))
    return pd.DataFrame(rows, columns=THREAT_INTEL_COLUMNS)
