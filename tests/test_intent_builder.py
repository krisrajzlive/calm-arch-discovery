from __future__ import annotations

import json

from intent.builder import compile_markdown, main
from pipeline.calm_validator import evaluate
from scanner.calm_schema import load_requirement_schemas
from tests.conftest import (
    ARCHITECTURE_MD,
    ARCHITECTURE_SOURCE,
    COMMITTED_INTENDED,
    DRIFTED_MD,
    ROOT,
)


def test_fixture_document_compiles_to_a_schema_valid_document(intended_result):
    document, doc_issues, schema_issues = intended_result
    assert document is not None and doc_issues == []
    assert [i for i in schema_issues if i.severity == "error"] == []


def test_intended_document_shape(intended):
    meta = intended["metadata"]
    assert (meta["kind"], meta["environment"], meta["source"]) == (
        "intended",
        "production",
        ARCHITECTURE_SOURCE,
    )
    assert len(meta["waivers"]) == 3
    names = {n["name"] for n in intended["nodes"] if n["node-type"] != "system"}
    assert names == {
        "public-gateway",
        "storefront-web",
        "orders-api",
        "payments-service",
        "notification-worker",
        "orders-db",
        "cache",
    }
    assert "mail-relay" not in names
    connects = [r for r in intended["relationships"] if "connects" in r["relationship-type"]]
    assert len(connects) == 8
    by_id = {r["unique-id"]: r for r in connects}
    assert by_id["orders-api-to-cache"]["metadata"]["encrypted-in-transit"] == "required"
    assert (
        by_id["public-gateway-to-orders-api"]["metadata"]["encrypted-in-transit"] == "not-required"
    )


def test_every_control_is_declared_as_required_not_verified(intended):
    statuses = {
        req["config"]["status"]
        for node in intended["nodes"]
        for control in node["controls"].values()
        for req in control["requirements"]
    }
    assert statuses == {"required"}


def test_intended_document_passes_the_gate_and_control_requirements(intended):
    errors = [
        i
        for i in evaluate(intended, requirements=load_requirement_schemas())
        if i.severity == "error"
    ]
    assert errors == []


def test_output_is_deterministic():
    first = compile_markdown(ARCHITECTURE_MD, source=ARCHITECTURE_SOURCE)[0]
    second = compile_markdown(ARCHITECTURE_MD, source=ARCHITECTURE_SOURCE)[0]
    assert json.dumps(first) == json.dumps(second)


def test_committed_intended_document_is_not_stale(intended):
    committed = json.loads(COMMITTED_INTENDED.read_text(encoding="utf-8"))
    assert committed == intended, (
        "architecture/payments-platform.intended.calm.json is stale. Run: "
        f"calm-intent {ARCHITECTURE_SOURCE} -o architecture/payments-platform.intended.calm.json"
    )


def test_invalid_markdown_yields_no_document(tmp_path):
    bad = tmp_path / "bad.md"
    bad.write_text("---\nsystem: x\n---\n\n## Components\n\n| id | type |\n|---|---|\n", "utf-8")
    document, issues, _ = compile_markdown(bad)
    assert document is None and issues


def test_cli_writes_json_and_exits_zero(tmp_path, capsys):
    out = tmp_path / "intended.json"
    assert main([str(ARCHITECTURE_MD), "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["metadata"]["kind"] == "intended"
    assert "schema: valid" in capsys.readouterr().err


def test_cli_prints_file_line_message_and_exits_one(tmp_path, capsys):
    bad = tmp_path / "arch.md"
    text = ARCHITECTURE_MD.read_text(encoding="utf-8").replace("| ingress |", "| ingres |")
    bad.write_text(text, encoding="utf-8")
    assert main([str(bad)]) == 1
    err = capsys.readouterr().err
    assert "arch.md:" in err and "ingres" in err and "Did you mean 'ingress'?" in err


def test_cli_github_format_emits_annotations(tmp_path, capsys):
    bad = tmp_path / "arch.md"
    bad.write_text(
        ARCHITECTURE_MD.read_text(encoding="utf-8").replace("| ingress |", "| ingres |"),
        encoding="utf-8",
    )
    assert main([str(bad), "--format", "github"]) == 1
    assert "::error file=" in capsys.readouterr().err


def test_cli_missing_file_exits_two(tmp_path, capsys):
    assert main([str(tmp_path / "nope.md")]) == 2
    assert "not a file" in capsys.readouterr().err


def test_drifted_document_still_compiles():
    # drift is the *code* disagreeing with a valid document, not a malformed document
    document, issues, _ = compile_markdown(DRIFTED_MD)
    assert document is not None and issues == []
    assert ROOT.exists()
