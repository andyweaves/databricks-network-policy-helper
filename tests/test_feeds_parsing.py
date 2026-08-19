"""Unit tests for feed line-parsing + shared helpers (no network — feed loaders are monkeypatched
at the HTTP layer)."""

from __future__ import annotations

from datetime import datetime, timezone

from dbx_nwp_helper.feeds import http, threat, util

NOW = datetime.now(timezone.utc)


def test_http_get_returns_none_on_malformed_json(monkeypatch):
    """A non-JSON body (e.g. a proxy error page) must degrade to None, not raise."""

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"<html>not json</html>"

    monkeypatch.setattr(http, "urlopen", lambda *a, **k: _Resp())
    monkeypatch.setattr(http.time, "sleep", lambda _s: None)  # don't wait through the backoff
    assert http.http_get("https://x.test/feed.json", as_json=True) is None
    # text mode still returns the body unchanged
    assert http.http_get("https://x.test/feed.txt") == "<html>not json</html>"


def test_valid_cidr_normalises_and_filters_version():
    assert util.valid_cidr("10.0.0.5/8") == "10.0.0.0/8"
    assert util.valid_cidr("1.2.3.4") == "1.2.3.4/32"
    assert util.valid_cidr("not-an-ip") is None
    assert util.valid_cidr("2001:db8::/32", want_version=4) is None
    assert util.valid_cidr("2001:db8::/32", want_version=6) == "2001:db8::/32"


def test_dedupe_preserves_order_on_keys():
    rows = [("a", 1), ("a", 2), ("b", 1)]
    assert util.dedupe(rows, (0,)) == [("a", 1), ("b", 1)]
    assert util.dedupe(rows, (0, 1)) == rows


def _patch_http(monkeypatch, text):
    monkeypatch.setattr(threat, "http_get", lambda url, as_json=False: text)


def test_spamhaus_parses_jsonl(monkeypatch):
    text = "\n".join(['{"cidr":"1.2.3.0/24"}', "garbage", '{"cidr":"bad"}'])
    _patch_http(monkeypatch, text)
    rows = threat._feed_spamhaus_drop(NOW)
    cidrs = {r[0] for r in rows}
    assert "1.2.3.0/24" in cidrs
    assert all(r[1] == "spamhaus_drop" and r[3] == 1 for r in rows)


def test_ipsum_min_lists_and_confidence(monkeypatch):
    # count 2 (<3) dropped; 3 -> conf 2; 6 -> conf 1.
    text = "1.1.1.1\t2\n2.2.2.2\t3\n3.3.3.3\t6\n# comment\n"
    _patch_http(monkeypatch, text)
    rows = {r[0]: r for r in threat._feed_ipsum(NOW)}
    assert "1.1.1.1/32" not in rows
    assert rows["2.2.2.2/32"][3] == 2
    assert rows["3.3.3.3/32"][3] == 1


def test_dshield_tab_format(monkeypatch):
    text = "1.2.3.0\t1.2.3.255\t24\tsomething\n# header\nbad line\n"
    _patch_http(monkeypatch, text)
    rows = threat._feed_dshield(NOW)
    assert rows and rows[0][0] == "1.2.3.0/24"
    assert rows[0][2] == "attacker_subnet"


def test_tor_exit_v4_and_comments(monkeypatch):
    text = "9.9.9.9\n# note\n\n8.8.8.8\n"
    _patch_http(monkeypatch, text)
    cidrs = {r[0] for r in threat._feed_tor_exit(NOW)}
    assert cidrs == {"9.9.9.9/32", "8.8.8.8/32"}


def test_firehol_and_cins_skip_comments(monkeypatch):
    _patch_http(monkeypatch, "# h\n5.5.5.0/24\nbad\n")
    assert {r[0] for r in threat._feed_firehol_level1(NOW)} == {"5.5.5.0/24"}
    _patch_http(monkeypatch, "# h\n6.6.6.6\n")
    assert {r[0] for r in threat._feed_cins_ci_army(NOW)} == {"6.6.6.6/32"}


def test_load_threat_intel_dedupes_across_feeds(monkeypatch):
    # firehol + cins both yield the same cidr under different feeds -> both kept (dedupe on cidr+feed).
    monkeypatch.setattr(
        threat, "http_get", lambda url, as_json=False: ("1.2.3.0/24" if "firehol" in url else "1.2.3.0")
    )
    df = threat.load_threat_intel(["firehol_level1", "cins_ci_army"])
    # firehol -> 1.2.3.0/24 ; cins -> 1.2.3.0/32 : different cidr strings, both present
    assert set(df["source_feed"]) == {"firehol_level1", "cins_ci_army"}


def test_all_loaders_registered():
    from dbx_nwp_helper.config import THREAT_FEEDS

    assert set(THREAT_FEEDS) == set(threat.THREAT_FEED_LOADERS)
