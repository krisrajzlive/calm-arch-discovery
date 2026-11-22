"""Loader + Cypher queries against a real Neo4j (docker compose up -d neo4j)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from neo4j import GraphDatabase

from graph.neo4j_loader import load_into_neo4j, split_queries
from tests.conftest import ROOT

pytestmark = pytest.mark.integration

QUERIES = split_queries((ROOT / "graph" / "sample_queries.cypher").read_text(encoding="utf-8"))
DELETE_ARCH = "MATCH (n {architecture: $a}) DETACH DELETE n"


def run(cfg: dict[str, str], cypher: str, **params: Any) -> list[dict[str, Any]]:
    with GraphDatabase.driver(cfg["uri"], auth=(cfg["user"], cfg["password"])) as driver:
        records, _, _ = driver.execute_query(cypher, parameters_=params)
        return [r.data() for r in records]


def query(cfg: dict[str, str], prefix: str, arch: str, service: str = "orders-api"):
    _, cypher = next(q for q in QUERIES if q[0].split()[0] == prefix)
    return run(cfg, cypher, architecture=arch, service=service)


def load(cfg: dict[str, str], doc: dict[str, Any], **kwargs: Any) -> None:
    load_into_neo4j(doc, cfg["uri"], cfg["user"], cfg["password"], **kwargs)


def counts(cfg: dict[str, str], arch: str) -> tuple[int, int]:
    nodes = run(cfg, "MATCH (n {architecture: $a}) RETURN count(n) AS c", a=arch)[0]["c"]
    rels = run(cfg, "MATCH ({architecture: $a})-[r]->() RETURN count(r) AS c", a=arch)[0]["c"]
    return nodes, rels


def fresh_name() -> str:
    return f"it-{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def arch(neo4j_conn, doc) -> Iterator[str]:
    name = fresh_name()
    doc["metadata"]["name"] = name
    load(neo4j_conn, doc)
    yield name
    run(neo4j_conn, DELETE_ARCH, a=name)


def test_load_creates_every_vertex_and_edge(neo4j_conn, arch):
    assert counts(neo4j_conn, arch) == (42, 62)


def test_constraints_are_created(neo4j_conn, arch):
    names = {r["name"] for r in run(neo4j_conn, "SHOW CONSTRAINTS YIELD name RETURN name")}
    assert {"calm_node_uid", "calm_control_uid"} <= names


def test_loading_twice_is_idempotent(neo4j_conn, doc):
    name = fresh_name()
    doc["metadata"]["name"] = name
    try:
        load(neo4j_conn, doc)
        load(neo4j_conn, doc)
        assert counts(neo4j_conn, name) == (42, 62)
    finally:
        run(neo4j_conn, DELETE_ARCH, a=name)


def test_reload_prunes_what_the_document_no_longer_contains(neo4j_conn, doc):
    name = fresh_name()
    doc["metadata"]["name"] = name
    try:
        load(neo4j_conn, doc)
        doc["nodes"] = [n for n in doc["nodes"] if n["unique-id"] != "mail-relay"]
        kept = []
        for rel in doc["relationships"]:
            kind = rel["relationship-type"]
            if "mail-relay" in json.dumps(kind) and "connects" in kind:
                continue
            for key in ("composed-of", "deployed-in"):
                if key in kind:
                    kind[key]["nodes"] = [n for n in kind[key]["nodes"] if n != "mail-relay"]
            kept.append(rel)
        doc["relationships"] = kept

        stale_query = (
            "MATCH (n {architecture: $a}) WHERE n.unique_id = 'mail-relay' "
            "OR n.node_id = 'mail-relay' RETURN count(n) AS c"
        )
        load(neo4j_conn, doc, prune=False)
        assert run(neo4j_conn, stale_query, a=name)[0]["c"] == 5  # node + its 4 controls remain
        load(neo4j_conn, doc, prune=True)
        assert run(neo4j_conn, stale_query, a=name)[0]["c"] == 0
        assert counts(neo4j_conn, name)[0] == 42 - 5
    finally:
        run(neo4j_conn, DELETE_ARCH, a=name)


def test_architectures_are_isolated(neo4j_conn, arch, doc):
    other = fresh_name()
    doc["metadata"]["name"] = other
    try:
        load(neo4j_conn, doc)
        assert counts(neo4j_conn, arch) == (42, 62) == counts(neo4j_conn, other)
    finally:
        run(neo4j_conn, DELETE_ARCH, a=other)


def test_q1_services_without_controls_is_empty_for_discovered_document(neo4j_conn, arch):
    assert query(neo4j_conn, "1", arch) == []


def test_q1_finds_a_node_whose_controls_were_removed(neo4j_conn):
    name = fresh_name()
    bad = json.loads(
        (ROOT / "tests" / "data" / "node-without-controls.calm.json").read_text(encoding="utf-8")
    )
    bad["metadata"]["name"] = name
    try:
        load(neo4j_conn, bad)
        assert [r["node"] for r in query(neo4j_conn, "1", name)] == ["orders-api"]
    finally:
        run(neo4j_conn, DELETE_ARCH, a=name)


def test_q1b_unverified_controls(neo4j_conn, arch):
    by_node = {r["node"]: set(r["unverified_controls"]) for r in query(neo4j_conn, "1b", arch)}
    assert by_node["cache"] == {
        "auth-required",
        "encryption-in-transit",
        "encryption-at-rest",
        "network-segmentation",
    }
    assert "orders-db" not in by_node


def test_q2_transitive_dependencies(neo4j_conn, arch):
    hops = {r["dependency"]: r["hops"] for r in query(neo4j_conn, "2", arch, "orders-api")}
    assert hops == {
        "cache": 1,
        "orders-db": 1,
        "payments-service": 1,
        "notification-worker": 2,
        "mail-relay": 3,
    }  # orders-api is not its own dependency despite the cycle through it


def test_q3_reports_the_dependency_cycle_once(neo4j_conn, arch):
    (row,) = query(neo4j_conn, "3", arch)
    assert row["length"] == 3
    assert row["cycle"][0] == row["cycle"][-1] == "notification-worker"
    assert set(row["cycle"]) == {"notification-worker", "orders-api", "payments-service"}


def test_q4_unencrypted_relationships(neo4j_conn, arch):
    rows = {(r["source"], r["target"]) for r in query(neo4j_conn, "4", arch)}
    assert rows == {
        ("notification-worker", "mail-relay"),
        ("orders-api", "cache"),
        ("payments-service", "notification-worker"),
        ("public-gateway", "orders-api"),
        ("public-gateway", "storefront-web"),
        ("storefront-web", "orders-api"),
    }  # JDBC with sslmode=require and mesh mTLS are not listed


def test_q5_internet_to_datastore_paths_are_simple_paths(neo4j_conn, arch):
    rows = query(neo4j_conn, "5", arch)
    assert len(rows) == 4
    assert all(len(set(r["route"])) == len(r["route"]) for r in rows)
    assert all(r["route"][0] == "public-gateway" for r in rows)
    assert not any(r["fully_encrypted"] for r in rows)
