"""Load a CALM document into Neo4j with idempotent Cypher ``MERGE`` statements.

* Constraints on ``uid`` make every MERGE an index seek and guarantee no duplicates.
* Statements are batched with ``UNWIND`` (one round trip per label / relationship type).
* The load is a *sync*: after the upserts, anything previously loaded for the same
  architecture that is no longer in the document is deleted (disable with ``--no-prune``).
* Labels and relationship types are interpolated, so they only come from the allow-lists in
  ``graph.model``; every value goes through query parameters.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from graph.model import GraphModel, Props, from_calm, safe_identifier

CONSTRAINTS = (
    "CREATE CONSTRAINT calm_node_uid IF NOT EXISTS FOR (n:CalmNode) REQUIRE n.uid IS UNIQUE",
    "CREATE CONSTRAINT calm_control_uid IF NOT EXISTS FOR (c:Control) REQUIRE c.uid IS UNIQUE",
    "CREATE INDEX calm_node_arch IF NOT EXISTS FOR (n:CalmNode) ON (n.architecture)",
)


def _vertex_statement(label: str) -> str:
    if label == "Control":
        return (
            "UNWIND $rows AS row "
            "MERGE (n:Control {uid: row.uid}) "
            "SET n += row.props, n.run_id = $run_id"
        )
    safe_identifier(label)
    return (
        "UNWIND $rows AS row "
        "MERGE (n:CalmNode {uid: row.uid}) "
        f"SET n += row.props, n:{label}, n.run_id = $run_id"
    )


def _edge_statement(edge_type: str) -> str:
    safe_identifier(edge_type)
    target_label = "Control" if edge_type == "HAS_CONTROL" else "CalmNode"
    return (
        "UNWIND $rows AS row "
        f"MATCH (a:CalmNode {{uid: row.source}}), (b:{target_label} {{uid: row.target}}) "
        f"MERGE (a)-[r:{edge_type} {{uid: row.uid}}]->(b) "
        "SET r += row.props, r.run_id = $run_id"
    )


PRUNE_EDGES = (
    "MATCH (:CalmNode {architecture: $architecture})-[r]->() WHERE r.run_id <> $run_id DELETE r"
)
PRUNE_NODES = (
    "MATCH (n:CalmNode {architecture: $architecture}) WHERE n.run_id <> $run_id DETACH DELETE n",
    "MATCH (n:Control {architecture: $architecture}) WHERE n.run_id <> $run_id DETACH DELETE n",
)


def build_statements(
    model: GraphModel, run_id: str, *, prune: bool = True
) -> list[tuple[str, dict[str, Any]]]:
    """Return (cypher, parameters) pairs, in execution order."""
    statements: list[tuple[str, dict[str, Any]]] = []
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in model.vertices:
        by_label[v.label].append({"uid": v.uid, "props": v.props})
    for label in sorted(by_label, key=lambda lb: (lb == "Control", lb)):  # controls after nodes
        statements.append((_vertex_statement(label), {"rows": by_label[label], "run_id": run_id}))

    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in model.edges:
        props: Props = {k: v for k, v in e.props.items()}
        by_type[e.type].append(
            {"uid": e.uid, "source": e.source, "target": e.target, "props": props}
        )
    for edge_type in sorted(by_type):
        statements.append(
            (_edge_statement(edge_type), {"rows": by_type[edge_type], "run_id": run_id})
        )

    if prune:
        params = {"architecture": model.architecture, "run_id": run_id}
        statements.append((PRUNE_EDGES, params))
        statements.extend((stmt, params) for stmt in PRUNE_NODES)
    return statements


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env reader (no extra dependency); never overrides real environment variables."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def load_into_neo4j(
    doc: dict[str, Any], uri: str, user: str, password: str, *, prune: bool = True
) -> dict[str, int]:
    from neo4j import GraphDatabase  # imported lazily so --dry-run needs no server

    model = from_calm(doc)
    run_id = uuid.uuid4().hex
    statements = build_statements(model, run_id, prune=prune)
    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        driver.verify_connectivity()
        with driver.session() as session:
            for stmt in CONSTRAINTS:
                session.run(stmt).consume()

            def work(tx: Any) -> None:
                for cypher, params in statements:
                    tx.run(cypher, **params).consume()

            session.execute_write(work)
    return {"vertices": len(model.vertices), "edges": len(model.edges)}


def split_queries(text: str) -> list[tuple[str, str]]:
    """Split sample_queries.cypher into (name, statement); ``// @query: name`` starts each."""
    queries: list[tuple[str, str]] = []
    name: str | None = None
    buf: list[str] = []

    def flush() -> None:
        statement = "\n".join(buf).strip().rstrip(";").strip()
        if name and statement:
            queries.append((name, statement))

    for line in text.splitlines():
        if line.startswith("// @query:"):
            flush()
            name, buf = line.split(":", 1)[1].strip(), []
        elif name:
            buf.append(line)
    flush()
    return queries


def run_report(
    uri: str, user: str, password: str, queries_file: Path, params: dict[str, Any]
) -> None:
    from neo4j import GraphDatabase

    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        for name, cypher in split_queries(queries_file.read_text(encoding="utf-8")):
            records, _, _ = driver.execute_query(cypher, parameters_=params)
            print(f"\n== {name} ({len(records)} rows)")
            for rec in records:
                print("  ", json.dumps(rec.data(), default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="calm-load-neo4j", description=__doc__.split("\n")[0])
    parser.add_argument("document", type=Path, help="CALM JSON document")
    parser.add_argument("--uri", help="bolt URI (default: $NEO4J_URI or bolt://localhost:7687)")
    parser.add_argument("--user", help="default: $NEO4J_USER or neo4j")
    parser.add_argument("--no-prune", action="store_true", help="upsert only; keep stale nodes")
    parser.add_argument("--dry-run", action="store_true", help="print the Cypher, touch nothing")
    parser.add_argument(
        "--report",
        action="store_true",
        help="after loading, run graph/sample_queries.cypher and print results",
    )
    parser.add_argument(
        "--queries", type=Path, default=Path(__file__).with_name("sample_queries.cypher")
    )
    parser.add_argument(
        "--service",
        default=None,
        help="service for the transitive-dependency query (default: first service)",
    )
    args = parser.parse_args(argv)

    doc = json.loads(args.document.read_text(encoding="utf-8"))
    if args.dry_run:
        for cypher, params in build_statements(from_calm(doc), "dry-run", prune=not args.no_prune):
            print(f"{cypher};\n// parameters: {len(params.get('rows', []))} rows\n")
        return 0

    load_dotenv()
    uri = args.uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = args.user or os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        print("error: set NEO4J_PASSWORD (see .env.example)", file=sys.stderr)
        return 2
    counts = load_into_neo4j(doc, uri, user, password, prune=not args.no_prune)
    print(f"loaded {counts['vertices']} vertices and {counts['edges']} edges into {uri}")
    if args.report:
        model = from_calm(doc)
        service = args.service or next(
            (v.props["unique_id"] for v in model.vertices if v.label == "Service"), ""
        )
        run_report(
            uri,
            user,
            password,
            args.queries,
            {"architecture": model.architecture, "service": service},
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
