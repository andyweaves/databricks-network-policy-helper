"""Databricks-owned IP ranges → a `databricks_ranges` DataFrame.

Columns: cidr, platform, region, direction, loaded_at. Databricks' own control-plane / serverless /
storage IPs appear as source IPs in the audit log (the platform reaching in); they're auto-allowed so
an enforced policy won't lock the control plane out. Source: the official machine-readable feed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from .http import http_get
from .util import dedupe, valid_cidr

DATABRICKS_COLUMNS = ["cidr", "platform", "region", "direction", "loaded_at"]
DATABRICKS_IP_RANGES_URL = "https://www.databricks.com/networking/v1/ip-ranges.json"


def load_databricks_ranges() -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    rows = []
    data = http_get(DATABRICKS_IP_RANGES_URL, as_json=True)
    if not data:
        from ..console import banner

        banner("warn", "Databricks IP ranges unavailable this run — continuing without them")
        return pd.DataFrame(rows, columns=DATABRICKS_COLUMNS)
    for entry in data.get("prefixes", []):
        platform = entry.get("platform")
        region = entry.get("region")
        direction = entry.get("type")  # inbound | outbound
        for cidr_raw in entry.get("ipv4Prefixes", []) + entry.get("ipv6Prefixes", []):
            cidr = valid_cidr(cidr_raw)
            if cidr:
                rows.append((cidr, platform, region, direction, now))
    rows = dedupe(rows, (0, 3))  # (cidr, direction) — same CIDR can appear across regions
    return pd.DataFrame(rows, columns=DATABRICKS_COLUMNS)
