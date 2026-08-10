"""Unit tests for limit enforcement, the feed cache, egress classification, and TLS setup."""

from __future__ import annotations

import pandas as pd

from dbx_netpolicy.config import (
    MAX_CIDRS_PER_POLICY,
    MAX_IDENTITIES_PER_POLICY,
    MAX_INGRESS_RULES_PER_POLICY,
)
from dbx_netpolicy.core import limits
from dbx_netpolicy.core.egress import _classify, _host_hostfile
from dbx_netpolicy.feeds import cache


def _noop(_m):
    pass


def test_limits_caps_identities_per_rule():
    spec = {"label": "r", "cidrs": ["1.1.1.1/32"],
            "identities": [{"principal_id": i, "principal_type": "USER"}
                           for i in range(MAX_IDENTITIES_PER_POLICY + 10)]}
    allow, _ = limits.enforce_limits([spec], [], "x", _noop)
    assert len(allow[0]["identities"]) == MAX_IDENTITIES_PER_POLICY


def test_limits_caps_rule_count_prioritising_allow():
    specs = [{"label": f"a{i}", "cidrs": ["1.1.1.1/32"]} for i in range(MAX_INGRESS_RULES_PER_POLICY)]
    deny = [{"label": "d", "cidrs": ["2.2.2.2/32"]}]
    allow, deny_out = limits.enforce_limits(specs, deny, "x", _noop)
    assert len(allow) == MAX_INGRESS_RULES_PER_POLICY
    assert deny_out == []  # no room left for deny


def test_limits_caps_total_cidrs():
    # One allow rule with more than the CIDR budget -> trimmed.
    big = {"label": "a", "cidrs": [f"10.0.{i // 256}.{i % 256}/32"
                                   for i in range(MAX_CIDRS_PER_POLICY + 50)]}
    allow, _ = limits.enforce_limits([big], [], "x", _noop)
    assert sum(len(r["cidrs"]) for r in allow) <= MAX_CIDRS_PER_POLICY


def test_limits_deny_fits_remaining_budget():
    allow = [{"label": "a", "cidrs": [f"10.0.0.{i}/32" for i in range(10)]}]
    deny = [{"label": "d", "cidrs": [f"11.0.0.{i}/32" for i in range(5)]}]
    a_out, d_out = limits.enforce_limits(allow, deny, "x", _noop)
    assert sum(len(r["cidrs"]) for r in a_out + d_out) <= MAX_CIDRS_PER_POLICY
    assert d_out  # fits comfortably


def test_egress_classify_variants():
    assert _classify("b.s3.us-west-2.amazonaws.com") == ("s3", {"bucket": "b", "region": "us-west-2"})
    # global endpoint: no region in host
    kind, info = _classify("b.s3.amazonaws.com")
    assert kind == "s3" and info["bucket"] == "b" and info["region"] is None
    assert _classify("s3.us-east-1.amazonaws.com")[0] == "skip_bare_s3"
    assert _classify("mb.storage.googleapis.com") == ("gcs", {"bucket": "mb"})
    assert _classify("acct.blob.core.windows.net") == ("azure", {"account": "acct", "service": "blob"})
    assert _classify("api.openai.com") == ("internet", {"fqdn": "api.openai.com"})
    assert _classify("")[0] == "skip_bare_s3"


def test_egress_classify_strips_trailing_dot_and_case():
    assert _classify("API.OpenAI.Com.") == ("internet", {"fqdn": "api.openai.com"})


def test_host_hostfile_parser():
    assert _host_hostfile("0.0.0.0 evil.example.com") == "evil.example.com"
    assert _host_hostfile("127.0.0.1 bad.test") == "bad.test"
    assert _host_hostfile("just-one-token") == ""


def test_cache_store_load_roundtrip_and_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    df = pd.DataFrame({"cidr": ["1.2.3.0/24"], "x": [1]})
    cache.store("t", df)
    assert cache.is_fresh("t")
    loaded = cache.load("t")
    assert loaded.to_dict(orient="records") == df.to_dict(orient="records")
    # stale when TTL is 0
    assert cache.is_fresh("t", ttl=0) is False


def test_cache_get_or_build_uses_builder_when_stale(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        return pd.DataFrame({"a": [calls["n"]]})

    df1 = cache.get_or_build("k", build, refresh=False)
    df2 = cache.get_or_build("k", build, refresh=False)  # cached, builder not called again
    assert calls["n"] == 1
    assert df1.equals(df2)
    cache.get_or_build("k", build, refresh=True)  # forced rebuild
    assert calls["n"] == 2


def test_cache_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    cache.store("a", pd.DataFrame({"x": [1]}))
    cache.store("b", pd.DataFrame({"x": [1]}))
    removed = cache.clear()
    assert set(removed) == {"a", "b"}
    assert cache.load("a") is None


def test_tls_enable_idempotent():
    from dbx_netpolicy import tls
    # Should return a bool and never raise; second call is a no-op.
    first = tls.enable()
    second = tls.enable()
    assert isinstance(first, bool)
    assert second is True or first is False
