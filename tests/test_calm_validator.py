from __future__ import annotations

import json
from pathlib import Path

from pipeline.calm_validator import evaluate, main
from tests.conftest import COMMITTED_DOC, ROOT

BAD_DOC = ROOT / "tests" / "data" / "node-without-controls.calm.json"


def run(capsys, *args: str) -> tuple[int, str]:
    code = main(list(args))
    return code, capsys.readouterr().out


def test_committed_architecture_passes_the_gate(capsys):
    code, out = run(capsys, str(COMMITTED_DOC))
    assert code == 0
    assert out.startswith("PASS")


def test_node_without_controls_fails_the_gate(capsys):
    code, out = run(capsys, str(BAD_DOC))
    assert code == 1
    assert "FAIL" in out and "node-without-controls" in out and "orders-api" in out


def test_gate_flags_a_control_with_no_requirements(doc):
    node = doc["nodes"][-1]
    cid = next(iter(node["controls"]))
    node["controls"][cid]["requirements"] = []
    assert any(i.code == "control-without-requirements" for i in evaluate(doc))


def test_every_node_type_is_held_to_the_rule(doc):
    for node in doc["nodes"]:
        saved = node.pop("controls")
        failing = [i for i in evaluate(doc) if i.code == "node-without-controls"]
        assert [i.message for i in failing] == [
            f"node '{node['unique-id']}' has no controls; attach at least one control"
        ]
        node["controls"] = saved


def test_unverified_controls_warn_by_default_and_fail_when_enforced(doc):
    default = evaluate(doc)
    assert any(i.code == "control-unverified" and i.severity == "warning" for i in default)
    assert not [i for i in default if i.severity == "error"]
    strict = evaluate(doc, fail_on_unverified=True)
    assert any(i.code == "control-unverified" and i.severity == "error" for i in strict)


def test_fail_on_unverified_flag_sets_exit_code(capsys):
    assert run(capsys, str(COMMITTED_DOC), "--fail-on-unverified")[0] == 1


def test_github_format_emits_workflow_annotations(capsys):
    code, out = run(capsys, str(BAD_DOC), "--format", "github")
    assert code == 1
    first = out.splitlines()[0]
    assert first.startswith("::error file=") and "title=node-without-controls" in first


def test_json_format_is_machine_readable(capsys):
    code, out = run(capsys, str(BAD_DOC), str(COMMITTED_DOC), "--format", "json")
    report = json.loads(out)
    assert code == 1 and report["passed"] is False
    assert [d["passed"] for d in report["documents"]] == [False, True]


def test_any_failing_document_fails_the_run(capsys):
    assert run(capsys, str(COMMITTED_DOC), str(BAD_DOC))[0] == 1


def test_unreadable_or_non_json_input_is_exit_code_2(capsys, tmp_path: Path):
    assert run(capsys, str(tmp_path / "missing.json"))[0] == 2
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert run(capsys, str(broken))[0] == 2


def test_schema_invalid_document_fails_even_with_controls(capsys, doc, tmp_path: Path):
    doc["nodes"][1]["node-type"] = 42
    path = tmp_path / "invalid.calm.json"
    path.write_text(json.dumps(doc))
    code, out = run(capsys, str(path))
    assert code == 1 and "schema" in out
