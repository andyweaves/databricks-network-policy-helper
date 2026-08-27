"""Unit tests for RDAP owner-name extraction (role ranking so the org name beats the abuse contact)."""

from __future__ import annotations

from urllib.error import HTTPError, URLError

from dbx_nwp_helper.feeds import rdap


def _entity(name, roles):
    return {"roles": roles, "vcardArray": ["vcard", [["fn", {}, "text", name]]]}


def test_registrant_beats_abuse_regardless_of_alphabetical_order():
    # "Abuse" sorts before "Cloudflare" alphabetically; role ranking must still pick the registrant.
    entities = [_entity("Abuse", ["abuse"]), _entity("Cloudflare, Inc.", ["registrant"])]
    names = rdap._extract_entity_names(entities)
    assert names[0] == "Cloudflare, Inc."


def test_role_priority_order():
    entities = [
        _entity("Tech Contact", ["technical"]),
        _entity("The Registrar", ["registrar"]),
        _entity("The Registrant", ["registrant"]),
    ]
    assert rdap._extract_entity_names(entities)[0] == "The Registrant"


def test_unknown_role_ranks_between_known_and_abuse():
    entities = [_entity("Abuse Desk", ["abuse"]), _entity("Some Org", [])]
    # unknown role (5) still beats abuse (9)
    assert rdap._extract_entity_names(entities)[0] == "Some Org"


def test_nested_entities_are_included():
    entities = [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Parent Registrar"]]],
            "entities": [_entity("Nested Org", ["registrant"])],
        }
    ]
    names = rdap._extract_entity_names(entities)
    assert "Parent Registrar" in names and "Nested Org" in names


def test_dedupes_preserving_rank():
    entities = [_entity("Same", ["abuse"]), _entity("Same", ["registrant"])]
    assert rdap._extract_entity_names(entities) == ["Same"]


def test_empty_entities():
    assert rdap._extract_entity_names([]) == []
    assert rdap._extract_entity_names(None) == []


def test_entity_without_vcard_skipped():
    assert rdap._extract_entity_names([{"roles": ["registrant"]}]) == []


# --- CIDR range summarisation -------------------------------------------------


def test_maximum_cidrs_summarises_range():
    assert rdap._maximum_cidrs("192.0.2.0", "192.0.2.255") == ["192.0.2.0/24"]


def test_maximum_cidrs_none_on_missing_endpoint():
    assert rdap._maximum_cidrs(None, "192.0.2.255") is None
    assert rdap._maximum_cidrs("192.0.2.0", None) is None


def test_maximum_cidrs_none_on_invalid_input():
    # Non-address strings must not raise — they yield None.
    assert rdap._maximum_cidrs("not-an-ip", "also-not") is None


# --- retry decisions ----------------------------------------------------------


def test_should_retry_on_throttle_and_server_errors():
    for code in (408, 425, 429, 500, 502, 503, 504):
        assert rdap._should_retry(HTTPError("http://x", code, "msg", None, None)) is True


def test_should_not_retry_on_client_error():
    assert rdap._should_retry(HTTPError("http://x", 404, "not found", None, None)) is False


def test_should_retry_on_timeout_and_urlerror_reasons():
    assert rdap._should_retry(TimeoutError()) is True
    assert rdap._should_retry(URLError("connection reset by peer")) is True
    assert rdap._should_retry(URLError("the read operation timed out")) is True


def test_should_not_retry_on_unrelated_urlerror():
    assert rdap._should_retry(URLError("name or service not known")) is False


# --- Retry-After parsing ------------------------------------------------------


class _WithHeaders:
    def __init__(self, headers):
        self.headers = headers


def test_retry_after_parses_delta_seconds():
    assert rdap._retry_after_seconds(_WithHeaders({"Retry-After": "5"})) == 5.0


def test_retry_after_none_when_absent_or_garbage():
    assert rdap._retry_after_seconds(_WithHeaders(None)) is None
    assert rdap._retry_after_seconds(_WithHeaders({})) is None
    assert rdap._retry_after_seconds(_WithHeaders({"Retry-After": "soon"})) is None
    assert rdap._retry_after_seconds(object()) is None  # no .headers attribute


# --- referral link selection --------------------------------------------------


def test_referrals_selects_ip_and_related_json_links_only():
    current = "https://rdap.org/ip/1.2.3.4"
    payload = {
        "links": [
            {"href": "https://rir.example/ip/1.2.3.4", "type": "application/rdap+json"},
            {"href": "https://rir.example/related", "rel": "related", "type": "application/json"},
            {"href": "https://rir.example/page.html", "rel": "related", "type": "text/html"},
            {"href": current, "rel": "up"},  # same as current URL -> skipped
            {"href": "https://rir.example/unrelated", "rel": "self"},  # not ip/related/alternate/up
        ]
    }
    assert rdap._referrals(payload, "1.2.3.4", current) == [
        "https://rir.example/ip/1.2.3.4",
        "https://rir.example/related",
    ]


def test_referrals_dedupes():
    payload = {
        "links": [
            {"href": "https://rir.example/ip/1.2.3.4", "type": "application/rdap+json"},
            {"href": "https://rir.example/ip/1.2.3.4", "rel": "related"},
        ]
    }
    assert rdap._referrals(payload, "1.2.3.4", "https://rdap.org/ip/1.2.3.4") == [
        "https://rir.example/ip/1.2.3.4"
    ]


# --- lookup loop (offline: _fetch monkeypatched) ------------------------------


def test_lookup_returns_first_useful_result(monkeypatch):
    payload = {
        "entities": [_entity("Example Org", ["registrant"])],
        "type": "NETWORK",
        "startAddress": "192.0.2.0",
        "endAddress": "192.0.2.255",
    }
    monkeypatch.setattr(rdap, "_fetch", lambda url: (payload, url, None))
    result = rdap.lookup("192.0.2.10")
    assert result == {
        "rdap_owner_name": "Example Org",
        "rdap_type": "NETWORK",
        "maximum_cidrs": ["192.0.2.0/24"],
    }


def test_lookup_follows_referral_chain(monkeypatch):
    bootstrap = {
        "entities": [],
        "links": [{"href": "https://rir.example/ip/1.2.3.4", "type": "application/rdap+json"}],
    }
    authoritative = {"entities": [_entity("Real Owner", ["registrant"])], "type": "NETWORK"}
    responses = {
        "https://rdap.org/ip/1.2.3.4": bootstrap,
        "https://rir.example/ip/1.2.3.4": authoritative,
    }
    monkeypatch.setattr(rdap, "_fetch", lambda url: (responses.get(url), url, None))
    assert rdap.lookup("1.2.3.4")["rdap_owner_name"] == "Real Owner"


def test_lookup_returns_empty_when_nothing_resolves(monkeypatch):
    monkeypatch.setattr(rdap, "_fetch", lambda url: (None, url, URLError("boom")))
    assert rdap.lookup("1.2.3.4") == {
        "rdap_owner_name": None,
        "rdap_type": None,
        "maximum_cidrs": None,
    }
