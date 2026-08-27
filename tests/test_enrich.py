"""Unit tests for the pure enrichment helpers (list coercion, range parsing/membership, and the
audit service_name -> CBI destination mapping)."""

from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd

from dbx_nwp_helper.core import enrich

# --- as_list ------------------------------------------------------------------


def test_as_list_none_is_empty():
    assert enrich.as_list(None) == []


def test_as_list_drops_none_and_empty_string_entries():
    assert enrich.as_list([1, None, "", 2]) == [1, 2]


def test_as_list_wraps_scalar():
    assert enrich.as_list("x") == ["x"]


def test_as_list_handles_tuple():
    assert enrich.as_list((1, 2)) == [1, 2]


def test_as_list_handles_numpy_array():
    assert enrich.as_list(np.array([1, 2, 3])) == [1, 2, 3]


def test_as_list_nan_scalar_is_empty():
    assert enrich.as_list(float("nan")) == []


# --- load_ranges --------------------------------------------------------------


def test_load_ranges_parses_valid_and_skips_invalid():
    df = pd.DataFrame({"cidr": ["10.0.0.0/8", "not-a-cidr"], "label": ["good", "bad"]})
    ranges = enrich.load_ranges(df, ["label"])
    assert len(ranges) == 1
    net, meta = ranges[0]
    assert net == ipaddress.ip_network("10.0.0.0/8")
    assert meta == {"label": "good"}


def test_load_ranges_skips_rows_missing_cidr_column_key():
    # A row whose cidr is NaN/None raises inside ip_network and is skipped, not fatal.
    df = pd.DataFrame({"cidr": [None, "192.0.2.0/24"]})
    ranges = enrich.load_ranges(df, [])
    assert [str(net) for net, _ in ranges] == ["192.0.2.0/24"]


# --- match_ranges -------------------------------------------------------------


def test_match_ranges_returns_matching_membership():
    ranges = [(ipaddress.ip_network("10.0.0.0/8"), {"m": 1})]
    metas, cidrs = enrich.match_ranges(ipaddress.ip_address("10.1.2.3"), ranges)
    assert metas == [{"m": 1}]
    assert cidrs == ["10.0.0.0/8"]


def test_match_ranges_no_match():
    ranges = [(ipaddress.ip_network("10.0.0.0/8"), {"m": 1})]
    assert enrich.match_ranges(ipaddress.ip_address("8.8.8.8"), ranges) == ([], [])


def test_match_ranges_ignores_version_mismatch():
    ranges = [(ipaddress.ip_network("2001:db8::/32"), {"m": 1})]
    # A v4 address must never match a v6 network.
    assert enrich.match_ranges(ipaddress.ip_address("10.1.2.3"), ranges) == ([], [])


# --- service_to_destination ---------------------------------------------------


def test_service_to_destination_apps():
    assert enrich.service_to_destination("databricks-apps") == "apps_runtime"


def test_service_to_destination_lakebase_and_database():
    assert enrich.service_to_destination("lakebase") == "lakebase_runtime"
    assert enrich.service_to_destination("some-database-svc") == "lakebase_runtime"


def test_service_to_destination_other_and_none():
    assert enrich.service_to_destination("clusters") == "other"
    assert enrich.service_to_destination(None) == "other"
