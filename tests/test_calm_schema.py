from __future__ import annotations

import pytest

from scanner.calm_schema import validate_document


def codes(doc):
    return [(i.severity, i.code) for i in validate_document(doc)]


def errors(doc):
    return [i for i in validate_document(doc) if i.severity == "error"]


def test_valid_document_has_no_errors(doc):
    assert errors(doc) == []


def test_missing_required_node_field_is_a_schema_error(doc):
    del doc["nodes"][1]["description"]
    assert ("error", "schema") in codes(doc)


def test_protocol_outside_calm_enum_is_rejected(doc):
    rel = next(r for r in doc["relationships"] if "protocol" in r)
    rel["protocol"] = "gRPC"  # not in CALM 1.x
    issues = errors(doc)
    assert any(i.code == "schema" and "protocol" in i.path for i in issues)


def test_relationship_type_must_pick_exactly_one_kind(doc):
    rel = next(r for r in doc["relationships"] if "connects" in r["relationship-type"])
    rel["relationship-type"]["deployed-in"] = {"container": "x", "nodes": ["y"]}
    assert ("error", "schema") in codes(doc)


def test_unsupported_schema_url_is_reported(doc):
    doc["$schema"] = "https://calm.finos.org/release/0.9/meta/calm.json"
    assert ("error", "unsupported-schema") in codes(doc)


def test_dangling_references_are_caught(doc):
    rel = next(r for r in doc["relationships"] if "connects" in r["relationship-type"])
    rel["relationship-type"]["connects"]["destination"]["node"] = "ghost"
    rel2 = next(r for r in doc["relationships"] if "composed-of" in r["relationship-type"])
    rel2["relationship-type"]["composed-of"]["nodes"].append("phantom")
    messages = [i.message for i in errors(doc) if i.code == "dangling-reference"]
    assert "unknown node 'ghost'" in messages and "unknown node 'phantom'" in messages


def test_duplicate_unique_ids_are_caught(doc):
    doc["nodes"][2]["unique-id"] = doc["nodes"][1]["unique-id"]
    assert ("error", "duplicate-id") in codes(doc)


def test_invalid_control_id_is_caught(doc):
    node = doc["nodes"][-1]
    node["controls"]["bad id!"] = next(iter(node["controls"].values()))
    assert ("error", "control-id") in codes(doc)


def test_control_config_is_validated_against_its_requirement_schema(doc):
    node = next(n for n in doc["nodes"] if n["unique-id"] == "orders-db")
    cfg = node["controls"]["encryption-at-rest"]["requirements"][0]["config"]
    cfg["status"] = "bogus"
    issues = errors(doc)
    assert any(i.code == "control-config" and "bogus" in i.message for i in issues)


def test_verified_control_must_carry_evidence(doc):
    node = next(n for n in doc["nodes"] if n["unique-id"] == "orders-db")
    node["controls"]["encryption-at-rest"]["requirements"][0]["config"]["evidence"] = []
    assert any(i.code == "control-config" for i in errors(doc))


def test_unknown_requirement_url_is_a_warning_not_an_error(doc):
    node = doc["nodes"][-1]
    control = next(iter(node["controls"].values()))
    control["requirements"][0]["requirement-url"] = "https://example.org/custom.json"
    assert ("warning", "requirement-unresolved") in codes(doc)
    assert errors(doc) == []


@pytest.mark.parametrize("empty", [{}, {"nodes": []}])
def test_minimal_documents_are_structurally_valid(empty):
    assert errors(empty) == []
