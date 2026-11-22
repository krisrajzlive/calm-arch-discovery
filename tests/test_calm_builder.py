from __future__ import annotations

import json
import re

import pytest

from scanner.calm_builder import discover, slug
from scanner.calm_schema import CALM_SCHEMA_URL, validate_document
from tests.conftest import COMMITTED_DOC, FIXTURE_REPO

PROTOCOLS = {
    "HTTP",
    "HTTPS",
    "FTP",
    "SFTP",
    "JDBC",
    "WebSocket",
    "SocketIO",
    "LDAP",
    "AMQP",
    "TLS",
    "mTLS",
    "TCP",
}


def nodes_by_id(doc):
    return {n["unique-id"]: n for n in doc["nodes"]}


def control_status(node, control_id):
    return node["controls"][control_id]["requirements"][0]["config"]["status"]


def test_document_is_valid_calm(discovered):
    doc, issues = discovered
    assert doc["$schema"] == CALM_SCHEMA_URL
    assert [i for i in issues if i.severity == "error"] == []


def test_every_node_has_at_least_one_control_with_a_requirement(doc):
    for node in doc["nodes"]:
        assert node["controls"], node["unique-id"]
        for control in node["controls"].values():
            assert control["description"]
            assert control["requirements"][0]["requirement-url"].endswith(".requirement.json")


def test_nodes_carry_owner_and_environment_metadata(doc):
    for node in doc["nodes"]:
        assert node["metadata"]["owner"]
        assert node["metadata"]["environment"]
    api = nodes_by_id(doc)["orders-api"]
    assert api["node-type"] == "service"
    assert api["metadata"]["owner"] == "@payments-platform/orders-squad"
    assert api["metadata"]["environments"] == ["production", "local"]


def test_node_types_and_unique_ids(doc):
    nodes = nodes_by_id(doc)
    assert len(nodes) == len(doc["nodes"])
    assert nodes["orders-db"]["node-type"] == "database"
    assert nodes["storefront-web"]["node-type"] == "webclient"
    assert nodes["ns-payments"]["node-type"] == "network"
    assert nodes["public-gateway"]["node-type"] == "service"  # ingress modelled as a service
    assert nodes["public-gateway"]["metadata"]["role"] == "ingress"
    assert nodes["payments-platform"]["node-type"] == "system"
    ids = list(nodes) + [r["unique-id"] for r in doc["relationships"]]
    assert len(ids) == len(set(ids))


def test_connects_relationships_use_calm_protocol_enum(doc):
    connects = [r for r in doc["relationships"] if "connects" in r["relationship-type"]]
    assert len(connects) == 9
    assert {r["protocol"] for r in connects} <= PROTOCOLS
    by_id = {r["unique-id"]: r for r in connects}
    db = by_id["orders-api-to-orders-db"]
    assert db["protocol"] == "JDBC" and db["metadata"]["tls"] is True
    mesh = by_id["orders-api-to-payments-service"]
    assert mesh["protocol"] == "mTLS" and mesh["metadata"]["application-protocol"] == "http"


def test_deployed_in_and_composed_of(doc):
    rels = {r["unique-id"]: r["relationship-type"] for r in doc["relationships"]}
    ns = rels["deployed-in-ns-payments"]["deployed-in"]
    assert ns["container"] == "ns-payments" and "orders-db" in ns["nodes"]
    assert "mail-relay" in rels["deployed-in-net-backend"]["deployed-in"]["nodes"]
    composed = rels["payments-platform-composed-of"]["composed-of"]
    assert composed["container"] == "payments-platform"
    assert "orders-api" in composed["nodes"] and "ns-payments" not in composed["nodes"]


def test_control_statuses_reflect_repository_evidence(doc):
    n = nodes_by_id(doc)
    for cid in n["orders-db"]["controls"]:
        assert control_status(n["orders-db"], cid) == "verified", cid
    assert control_status(n["cache"], "encryption-at-rest") == "unverified"
    assert control_status(n["payments-service"], "network-segmentation") == "verified"
    assert control_status(n["notification-worker"], "container-hardening") == "unverified"
    assert control_status(n["payments-platform"], "ownership-governance") == "verified"
    assert (
        control_status(n["ns-payments"], "network-segmentation") == "unverified"
    )  # no default-deny


def test_encryption_in_transit_lists_plaintext_inbound_links_as_gaps(doc):
    cfg = nodes_by_id(doc)["orders-api"]["controls"]["encryption-in-transit"]["requirements"][0][
        "config"
    ]
    assert cfg["status"] == "unverified"
    assert set(cfg["gaps"]) == {"public-gateway-to-orders-api", "storefront-web-to-orders-api"}
    assert cfg["evidence"] == ["notification-worker-to-orders-api: HTTPS"]


def test_generation_is_deterministic():
    first, _ = discover(FIXTURE_REPO)
    second, _ = discover(FIXTURE_REPO)
    assert json.dumps(first, sort_keys=False) == json.dumps(second, sort_keys=False)


def test_committed_architecture_is_not_stale(discovered):
    """The CI drift gate, as a unit test: regenerate and compare with the committed document."""
    assert json.loads(COMMITTED_DOC.read_text(encoding="utf-8")) == discovered[0]


def test_system_name_override_and_revision_opt_in():
    doc, issues = discover(FIXTURE_REPO, name="Payments Platform v2", include_revision=True)
    assert doc["metadata"]["name"] == "Payments Platform v2"
    assert doc["nodes"][0]["unique-id"] == "payments-platform-v2"
    assert not [i for i in issues if i.severity == "error"]
    assert "source-revision" not in discover(FIXTURE_REPO)[0]["metadata"]


def test_unique_ids_are_disambiguated(write_repo):
    root = write_repo({"docker-compose.yml": "services:\n  shop: {image: 'example/shop'}\n"})
    doc, issues = discover(root, name="shop")  # system and service share the slug
    assert [n["unique-id"] for n in doc["nodes"]] == ["shop", "shop-2"]
    assert not [i for i in issues if i.severity == "error"]


@pytest.mark.parametrize("value", ["Orders API", "a__b", "--x--", "ÄÖ"])
def test_slug_is_a_valid_control_and_id_fragment(value):
    assert re.fullmatch(r"[a-z0-9-]+", slug(value))


def test_validate_document_on_committed_file_has_no_errors():
    doc = json.loads(COMMITTED_DOC.read_text(encoding="utf-8"))
    assert [i for i in validate_document(doc) if i.severity == "error"] == []
