from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path
from typing import Any

import pytest

from graph.neo4j_loader import load_dotenv
from scanner.calm_builder import discover

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_REPO = ROOT / "fixtures" / "sample-repo"
COMMITTED_DOC = ROOT / "architecture" / "payments-platform.actual.calm.json"
COMMITTED_INTENDED = ROOT / "architecture" / "payments-platform.intended.calm.json"
ARCHITECTURE_MD = FIXTURE_REPO / "docs" / "architecture" / "architecture.md"
DRIFTED_MD = ROOT / "tests" / "data" / "architecture-drifted.md"
# the path as the CLI receives it from the repository root (it is recorded in the document)
ARCHITECTURE_SOURCE = "fixtures/sample-repo/docs/architecture/architecture.md"


@pytest.fixture(scope="session")
def fixture_repo() -> Path:
    return FIXTURE_REPO


@pytest.fixture(scope="session")
def intended_result() -> tuple[dict[str, Any] | None, list, list]:
    from intent.builder import compile_markdown

    return compile_markdown(ARCHITECTURE_MD, source=ARCHITECTURE_SOURCE)


@pytest.fixture()
def intended(intended_result: tuple) -> dict[str, Any]:
    """A fresh deep copy of the intended document compiled from the fixture Markdown."""
    return json.loads(json.dumps(intended_result[0]))


@pytest.fixture(scope="session")
def discovered() -> tuple[dict[str, Any], list]:
    return discover(FIXTURE_REPO)


@pytest.fixture()
def doc(discovered: tuple[dict[str, Any], list]) -> dict[str, Any]:
    """A fresh deep copy of the document discovered from the fixture repository."""
    return json.loads(json.dumps(discovered[0]))


@pytest.fixture()
def write_repo(tmp_path: Path):
    """Create files under tmp_path from {relative path: content} and return the root."""

    def _write(files: dict[str, str]) -> Path:
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return tmp_path

    return _write


def _unavailable(reason: str) -> None:
    if os.environ.get("REQUIRE_INTEGRATION"):
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="session")
def neo4j_conn() -> dict[str, str]:
    from neo4j import GraphDatabase

    load_dotenv(ROOT / ".env")
    password = os.environ.get("NEO4J_PASSWORD")
    cfg = {
        "uri": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        "user": os.environ.get("NEO4J_USER", "neo4j"),
        "password": password or "",
    }
    if not password:
        _unavailable("NEO4J_PASSWORD not set")
    try:
        with GraphDatabase.driver(cfg["uri"], auth=(cfg["user"], cfg["password"])) as driver:
            driver.verify_connectivity()
    except Exception as exc:  # noqa: BLE001 - any connection problem means "unavailable"
        _unavailable(f"Neo4j unavailable: {exc.__class__.__name__}")
    return cfg


@pytest.fixture(scope="session")
def gremlin_url() -> str:
    from graph.gremlin_exporter import query

    url = os.environ.get("GREMLIN_URL", "http://127.0.0.1:8182")
    try:
        query(url, "g.V().limit(1).count()")
    except Exception as exc:  # noqa: BLE001
        _unavailable(f"Gremlin Server unavailable: {exc.__class__.__name__}")
    return url
