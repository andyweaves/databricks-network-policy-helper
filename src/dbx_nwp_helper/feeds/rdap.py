"""RDAP owner lookup (deduplicated, optional) — recovers the registered owner and full assigned
range (the `maximum` framing) for a candidate IP, following referrals. Ported from the notebook.
"""

from __future__ import annotations

import ipaddress
import json
import time
from http.client import RemoteDisconnected
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .http import FEED_USER_AGENT

RDAP_TIMEOUT_SECONDS = 8
RDAP_MAX_RETRIES = 2
RDAP_MAX_REFERRAL_DEPTH = 3
RDAP_DELAY_SECONDS = 0.1

_EMPTY = {"rdap_owner_name": None, "rdap_type": None, "maximum_cidrs": None}


def _extract_entity_names(entities):
    names = []
    for entity in entities or []:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for field in vcard[1]:
                if len(field) >= 4 and field[0] == "fn" and field[3]:
                    names.append(field[3])
    return sorted(set(names))


def _should_retry(error):
    if isinstance(error, HTTPError):
        return error.code in {408, 425, 429, 500, 502, 503, 504}
    if isinstance(error, (TimeoutError, RemoteDisconnected)):
        return True
    if isinstance(error, URLError):
        reason = str(error.reason).lower()
        return any(p in reason for p in ["timed out", "timeout", "temporarily unavailable",
                                         "connection reset", "connection aborted",
                                         "connection refused", "remote end closed connection"])
    return any(p in str(error).lower() for p in ["timed out", "timeout",
                                                 "remote end closed connection", "temporarily unavailable"])


def _maximum_cidrs(start_ip, end_ip):
    if not start_ip or not end_ip:
        return None
    try:
        nets = list(ipaddress.summarize_address_range(
            ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)))
        return [str(n) for n in nets]
    except (ValueError, TypeError):
        return None


def _fetch(url):
    delay, last_error = 1.0, None
    for attempt in range(1, RDAP_MAX_RETRIES + 1):
        request = Request(url, headers={"Accept": "application/rdap+json, application/json",
                                        "User-Agent": FEED_USER_AGENT})
        try:
            with urlopen(request, timeout=RDAP_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8")), response.geturl(), None
        except Exception as error:  # noqa: BLE001
            last_error = error
            if attempt < RDAP_MAX_RETRIES and _should_retry(error):
                time.sleep(delay)
                delay *= 2
                continue
            return None, url, error
    return None, url, last_error


def _referrals(payload, ip_address, current_url):
    urls = []
    for link in payload.get("links") or []:
        href = link.get("href")
        rel = (link.get("rel") or "").lower()
        media = (link.get("type") or "").lower()
        if not href or href == current_url:
            continue
        if media and "json" not in media and "rdap" not in media:
            continue
        if f"/ip/{ip_address}" in href or "type=ip" in href or rel in {"related", "alternate", "up"}:
            if href not in urls:
                urls.append(href)
    return urls


def lookup(ip_address: str) -> dict:
    """Return {rdap_owner_name, rdap_type, maximum_cidrs} for an IP, following referrals."""
    pending, visited, best = [f"https://rdap.org/ip/{ip_address}"], set(), dict(_EMPTY)
    while pending and len(visited) <= RDAP_MAX_REFERRAL_DEPTH:
        url = pending.pop(0)
        if url in visited:
            continue
        visited.add(url)
        payload, final_url, _ = _fetch(url)
        if payload is None:
            continue
        names = _extract_entity_names(payload.get("entities"))
        result = {
            "rdap_owner_name": names[0] if names else payload.get("name") or payload.get("handle"),
            "rdap_type": payload.get("type"),
            "maximum_cidrs": _maximum_cidrs(payload.get("startAddress"), payload.get("endAddress")),
        }
        if any(result.values()):
            return result
        best = result
        for ref in _referrals(payload, ip_address, final_url):
            if ref not in visited and ref not in pending:
                pending.append(ref)
    return best if any(best.values()) else dict(_EMPTY)
