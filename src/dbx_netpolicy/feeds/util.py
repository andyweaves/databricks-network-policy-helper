"""Small shared helpers for feed parsing."""

from __future__ import annotations

import ipaddress


def valid_cidr(value: str, want_version: int | None = None) -> str | None:
    """Return a normalised CIDR string if `value` parses as a network, else None."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, AttributeError):
        return None
    if want_version and net.version != want_version:
        return None
    return str(net)


def dedupe(rows: list[tuple], key_indices: tuple[int, ...]) -> list[tuple]:
    """De-duplicate row tuples on the given column indices, preserving order."""
    seen, out = set(), []
    for row in rows:
        key = tuple(row[i] for i in key_indices)
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out
