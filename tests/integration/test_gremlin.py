"""Generated Neptune script + Gremlin queries on a real TinkerPop Gremlin Server.

docker compose --profile gremlin up -d gremlin
"""

from __future__ import annotations

import pytest

from graph.gremlin_exporter import build_statements, query, submit
from graph.model import from_calm
from tests.conftest import ROOT

pytestmark = pytest.mark.integration

QUERY_LINES = [
    ln
    for ln in (ROOT / "graph" / "sample_queries.groovy").read_text(encoding="utf-8").splitlines()
    if ln.startswith("g.")
]


@pytest.fixture()
def loaded(gremlin_url, doc):
    submit(gremlin_url, build_statements(from_calm(doc)))
    return gremlin_url


def q(url: str, index: int):
    return query(url, QUERY_LINES[index])


def test_script_executes_and_produces_the_expected_graph_size(loaded):
    assert query(loaded, "g.V().count()") == [42]
    assert query(loaded, "g.E().count()") == [62]


def test_rerunning_the_script_without_replace_is_idempotent(loaded, doc):
    submit(loaded, build_statements(from_calm(doc), replace=False))
    assert (query(loaded, "g.V().count()"), query(loaded, "g.E().count()")) == ([42], [62])


def test_vertex_properties_round_trip(loaded):
    (props,) = query(
        loaded, "g.V('payments-platform/orders-db').valueMap('name','node_type','owner')"
    )
    assert props == {
        "name": ["orders-db"],
        "node_type": ["database"],
        "owner": ["@payments-platform/data-platform"],
    }
    ports = query(loaded, "g.V('payments-platform/orders-api').values('ports')")
    assert sorted(ports) == [80, 8080]


def test_g1_nodes_without_controls_is_empty(loaded):
    assert q(loaded, 0) == []


def test_g1b_unverified_controls(loaded):
    (grouped,) = q(loaded, 1)
    assert set(grouped["cache"]) == {
        "auth-required",
        "encryption-in-transit",
        "encryption-at-rest",
        "network-segmentation",
    }
    assert "orders-db" not in grouped


def test_g2_transitive_dependencies(loaded):
    assert set(q(loaded, 2)) == {
        "cache",
        "orders-db",
        "payments-service",
        "notification-worker",
        "mail-relay",
    }


def test_g3_cycle_reported_once(loaded):
    (cycle,) = q(loaded, 3)
    assert set(cycle) == {"orders-api", "payments-service", "notification-worker"}
    assert cycle[0] == cycle[-1]


def test_g4_unencrypted_relationships_match_cypher(loaded):
    rows = {(r["source"], r["target"]) for r in q(loaded, 4)}
    assert rows == {
        ("notification-worker", "mail-relay"),
        ("orders-api", "cache"),
        ("payments-service", "notification-worker"),
        ("public-gateway", "orders-api"),
        ("public-gateway", "storefront-web"),
        ("storefront-web", "orders-api"),
    }


def test_g5_internet_to_datastore_paths(loaded):
    paths = q(loaded, 5)
    assert len(paths) == 4 and all(p[0] == "public-gateway" for p in paths)
