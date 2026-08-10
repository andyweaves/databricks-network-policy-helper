"""IP enrichment + range-membership helpers shared by the ingress engine."""

from __future__ import annotations

import ipaddress

import pandas as pd


def as_list(value):
    """Coerce a record field to a plain Python list. Handles None/NaN, numpy arrays and lists
    uniformly, dropping null/empty entries."""
    if value is None:
        return []
    if hasattr(value, "tolist"):  # numpy array
        value = value.tolist()
    elif not isinstance(value, (list, tuple)):
        try:
            if pd.isna(value):
                return []
        except (TypeError, ValueError):
            pass
        value = [value]
    return [v for v in value if v is not None and v != ""]


def load_ranges(df: pd.DataFrame, extra_cols: list[str]) -> list[tuple]:
    """Parse a feed DataFrame into [(ip_network, {meta})] for membership tests."""
    parsed = []
    for _, r in df.iterrows():
        try:
            net = ipaddress.ip_network(r["cidr"], strict=False)
        except (ValueError, KeyError):
            continue
        parsed.append((net, {c: r.get(c) for c in extra_cols}))
    return parsed


def match_ranges(ip_obj, ranges: list[tuple]) -> tuple[list[dict], list[str]]:
    metas, cidrs = [], []
    for net, meta in ranges:
        if ip_obj.version == net.version and ip_obj in net:
            metas.append(meta)
            cidrs.append(str(net))
    return metas, cidrs


def service_to_destination(service_name: str | None) -> str:
    """Conservative audit service_name -> CBI destination category."""
    s = (service_name or "").lower()
    if "apps" in s:
        return "apps_runtime"
    if "lakebase" in s or "database" in s:
        return "lakebase_runtime"
    return "other"
