"""Dependency-free HTTP GET with a short exponential-backoff retry (ported from the notebooks)."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FEED_TIMEOUT_SECONDS = 30
FEED_USER_AGENT = "Databricks-Network-Policy-Helper"


def http_get(url: str, as_json: bool = False) -> Any | None:
    """GET a URL with a short retry, returning text or parsed JSON. Returns None on failure."""
    delay, last_error = 1.0, None
    for attempt in range(1, 4):
        try:
            request = Request(url, headers={"User-Agent": FEED_USER_AGENT, "Accept": "*/*"})
            with urlopen(request, timeout=FEED_TIMEOUT_SECONDS) as response:
                raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw) if as_json else raw
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < 3:
                time.sleep(delay)
                delay *= 2
    from ..console import banner

    banner("warn", f"feed fetch failed for {url}: {last_error}")
    return None
