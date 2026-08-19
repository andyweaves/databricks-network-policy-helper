"""Unit tests for RDAP owner-name extraction (role ranking so the org name beats the abuse contact)."""

from __future__ import annotations

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
