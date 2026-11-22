from __future__ import annotations

import pytest

from graph import gremlin_exporter as gx
from graph import neo4j_loader as nl
from graph.model import NODE_LABELS, from_calm, safe_identifier

# --------------------------------------------------------------------------- graph model


def test_vertex_and_edge_counts(doc):
    model = from_calm(doc)
    controls = sum(len(n["controls"]) for n in doc["nodes"])
    assert len(model.vertices) == len(doc["nodes"]) + controls
    by_type = {}
    for e in model.edges:
        by_type[e.type] = by_type.get(e.type, 0) + 1
    assert by_type["CONNECTS_TO"] == 9
    assert by_type["HAS_CONTROL"] == controls
    assert by_type["COMPOSED_OF"] == 8  # every non-network component
    assert by_type["DEPLOYED_IN"] == 14  # 7 in the namespace + 7 in the compose network


def test_every_vertex_is_scoped_to_its_architecture(doc):
    model = from_calm(doc)
    assert model.architecture == "payments-platform"
    assert all(v.uid.startswith("payments-platform/") for v in model.vertices)
    assert all(v.props["architecture"] == "payments-platform" for v in model.vertices)
    assert all(e.props["architecture"] == "payments-platform" for e in model.edges)


def test_labels_come_from_the_allow_list(doc):
    model = from_calm(doc)
    allowed = {*NODE_LABELS.values(), "Control", "Component"}
    assert {v.label for v in model.vertices} <= allowed


def test_unknown_node_type_falls_back_to_component(doc):
    target = next(n for n in doc["nodes"] if n["unique-id"] == "orders-api")
    target["node-type"] = "serverless-function'; DROP"
    vertex = next(v for v in from_calm(doc).vertices if v.uid == "payments-platform/orders-api")
    assert vertex.label == "Component"


def test_property_values_are_flat_primitives(doc):
    for v in from_calm(doc).vertices:
        for value in v.props.values():
            assert isinstance(value, (str, int, float, bool, list))
    ctrl = next(v for v in from_calm(doc).vertices if v.label == "Control")
    assert ctrl.props["config_json"].startswith("{")  # nested config kept as JSON text


@pytest.mark.parametrize("bad", ["Service) DETACH DELETE n //", "a b", "1abc", "", "x-y"])
def test_unsafe_identifiers_are_refused(bad):
    with pytest.raises(ValueError):
        safe_identifier(bad)


# --------------------------------------------------------------------------- Cypher


def test_cypher_is_parameterised_and_idempotent(doc):
    model = from_calm(doc)
    statements = nl.build_statements(model, "run-1")
    for cypher, params in statements:
        assert "MERGE" in cypher or "DELETE" in cypher
        # no document value is ever spliced into the statement text
        assert "payments-platform" not in cypher
        assert "orders-api" not in cypher
        assert "run_id" in params or "$run_id" in cypher
    merges = [c for c, _ in statements if "MERGE" in c]
    assert merges and all(c.startswith("UNWIND $rows AS row") for c in merges)


def test_controls_are_loaded_after_their_nodes_and_edges_last(doc):
    cyphers = [c for c, _ in nl.build_statements(from_calm(doc), "r")]
    control = next(i for i, c in enumerate(cyphers) if "MERGE (n:Control" in c)
    nodes = [i for i, c in enumerate(cyphers) if "MERGE (n:CalmNode" in c]
    edges = [i for i, c in enumerate(cyphers) if "MATCH (a:CalmNode" in c]
    assert max(nodes) < control < min(edges)


def test_prune_statements_are_scoped_to_the_architecture(doc):
    statements = nl.build_statements(from_calm(doc), "r", prune=True)
    prune = [(c, p) for c, p in statements if "DELETE" in c]
    assert len(prune) == 3
    assert all(p == {"architecture": "payments-platform", "run_id": "r"} for _, p in prune)
    assert not [
        c for c, _ in nl.build_statements(from_calm(doc), "r", prune=False) if "DELETE" in c
    ]


def test_split_queries_reads_the_shipped_query_file():
    from pathlib import Path

    text = (Path(nl.__file__).with_name("sample_queries.cypher")).read_text(encoding="utf-8")
    queries = nl.split_queries(text)
    assert [name.split()[0] for name, _ in queries] == ["1", "1b", "2", "3", "4", "5"]
    assert all("MATCH" in q and not q.endswith(";") for _, q in queries)


# --------------------------------------------------------------------------- Gremlin


def test_groovy_string_escaping():
    assert gx.gstr("plain") == "'plain'"
    assert gx.gstr("it's") == "'it\\'s'"
    assert gx.gstr("a\\b") == "'a\\\\b'"
    assert gx.gstr("line1\nline2") == "'line1\\nline2'"
    assert gx.gstr("$HOME ${x}") == "'$HOME ${x}'"  # single-quoted Groovy never interpolates
    assert gx.gval(True) == "true" and gx.gval(8080) == "8080" and gx.gval("x") == "'x'"


def test_hostile_values_cannot_break_out_of_the_string_literal():
    payload = "x'); g.V().drop().iterate(); ('"
    literal = gx.gstr(payload)
    inner = literal[1:-1]
    assert "'" not in inner.replace("\\'", "")  # every quote is escaped


def test_script_is_one_self_contained_traversal_per_line(doc):
    model = from_calm(doc)
    statements = gx.build_statements(model)
    assert all("\n" not in s for s in statements)
    assert statements[0].startswith("g.V().has('architecture', 'payments-platform').drop()")
    assert all(s.startswith("g.") and s.endswith(".iterate()") for s in statements)
    assert len(statements) == 1 + len(model.vertices) + len(model.edges)


def test_vertex_upsert_idiom(doc):
    v = next(v for v in from_calm(doc).vertices if v.label == "Service")
    stmt = gx.vertex_statement(v)
    assert stmt.startswith(f"g.V('{v.uid}').fold().coalesce(__.unfold(), __.addV('Service')")
    assert f".property(T.id, '{v.uid}')" in stmt
    assert ".property(single, 'name'," in stmt


def test_multi_valued_vertex_properties_use_set_cardinality(doc):
    v = next(
        v for v in from_calm(doc).vertices if v.props.get("sources") and len(v.props["sources"]) > 1
    )
    assert gx.vertex_statement(v).count(".property(set, 'sources',") == len(v.props["sources"])


def test_edge_upsert_idiom_and_flattened_lists(doc):
    e = next(e for e in from_calm(doc).edges if e.type == "CONNECTS_TO")
    stmt = gx.edge_statement(e)
    assert (
        ".coalesce(__.inE('CONNECTS_TO').where(__.outV().as('s')), __.addE('CONNECTS_TO')" in stmt
    )
    assert ".property('tls'," in stmt
    assert ".property(set," not in stmt  # Neptune edges have no multi-properties
    assert ".property('evidence', '" in stmt


def test_replace_mode_is_optional(doc):
    model = from_calm(doc)
    assert gx.build_statements(model, replace=False)[0].startswith("g.V('payments-platform/")
    assert "drop()" in gx.render(model, "x.groovy")


def test_submit_refuses_non_local_endpoints():
    with pytest.raises(ValueError, match="local Gremlin Server only"):
        gx.query("https://my-cluster.cluster-abc.us-east-1.neptune.amazonaws.com:8182", "g.V()")


def test_untype_collapses_graphson():
    typed = {
        "@type": "g:List",
        "@value": [
            {"@type": "g:Map", "@value": ["a", {"@type": "g:Int64", "@value": 1}]},
            {"@type": "g:Path", "@value": {"objects": {"@type": "g:List", "@value": ["x", "y"]}}},
        ],
    }
    assert gx.untype(typed) == [{"a": 1}, ["x", "y"]]


def test_shipped_groovy_queries_are_single_line_traversals():
    from pathlib import Path

    text = Path(gx.__file__).with_name("sample_queries.groovy").read_text(encoding="utf-8")
    queries = [ln for ln in text.splitlines() if ln and not ln.startswith("//")]
    assert len(queries) == 6 and all(q.startswith("g.") for q in queries)
