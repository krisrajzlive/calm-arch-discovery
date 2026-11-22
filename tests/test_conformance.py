from __future__ import annotations

import datetime as dt
import json

import pytest

from pipeline.conformance import evaluate, main, render_github, render_markdown
from tests.conftest import COMMITTED_DOC, COMMITTED_INTENDED, DRIFTED_MD

TODAY = dt.date(2026, 11, 22)


def run(actual, intended, today: dt.date = TODAY):
    return evaluate(actual, intended, today=today)


def keyed(report, *, waived: bool | None = None):
    return {(f.rule, f.subject) for f in report.findings if waived is None or f.waived is waived}


def node(doc, name):
    return next(n for n in doc["nodes"] if n["name"] == name)


def connect(doc, src, dst):
    return next(
        r
        for r in doc["relationships"]
        if r["unique-id"] == f"{src}-to-{dst}" and "connects" in r["relationship-type"]
    )


# --------------------------------------------------------------------------- the fixture


def test_fixture_conforms_with_exactly_the_three_documented_waivers(doc, intended):
    report = run(doc, intended)
    assert report.passed
    assert keyed(report, waived=True) == {
        ("encryption-violation", "orders-api -> cache"),
        ("control-not-evidenced", "notification-worker/container-hardening"),
        ("control-not-evidenced", "cache/network-segmentation"),
    }
    assert keyed(report, waived=False) == set()
    assert report.compared["components-approved"] == 7


def test_committed_documents_conform():
    actual = json.loads(COMMITTED_DOC.read_text(encoding="utf-8"))
    intended = json.loads(COMMITTED_INTENDED.read_text(encoding="utf-8"))
    assert run(actual, intended).passed


def test_local_only_component_is_out_of_scope(doc, intended):
    assert "mail-relay" in {n["name"] for n in doc["nodes"]}
    report = run(doc, intended)
    assert not any("mail-relay" in f.subject for f in report.findings)


def test_drifted_document_is_rejected(doc):
    from intent.builder import compile_markdown

    drifted = compile_markdown(DRIFTED_MD)[0]
    report = run(doc, drifted)
    assert not report.passed
    blocking = {(f.rule, f.subject) for f in report.blocking}
    assert blocking == {
        ("undeclared-component", "storefront-web"),
        ("undeclared-connection", "orders-api -> payments-service"),
    }
    # a connection that touches an undeclared component is not double reported
    assert not any("storefront-web ->" in s or "-> storefront-web" in s for _, s in blocking)


# --------------------------------------------------------------------------- each rule


def drop_node(document, name):
    """Remove a node and every relationship that mentions it, as a real edit would."""
    ident = node(document, name)["unique-id"]
    document["nodes"] = [n for n in document["nodes"] if n["unique-id"] != ident]
    kept = []
    for rel in document["relationships"]:
        kind = rel["relationship-type"]
        if "connects" in kind:
            ends = {kind["connects"]["source"]["node"], kind["connects"]["destination"]["node"]}
            if ident in ends:
                continue
        else:
            container = next(iter(kind.values()))
            container["nodes"] = [m for m in container["nodes"] if m != ident]
        kept.append(rel)
    document["relationships"] = kept


def test_undeclared_component_when_in_scope(doc, intended):
    drop_node(intended, "cache")
    report = run(doc, intended)
    assert ("undeclared-component", "cache") in keyed(report)
    assert not report.passed


def test_undeclared_component_in_another_environment_is_ignored(doc, intended):
    node(doc, "cache")["metadata"].update(environment="staging", environments=["staging"])
    drop_node(intended, "cache")
    assert ("undeclared-component", "cache") not in keyed(run(doc, intended))


def test_missing_component_is_only_a_warning(doc, intended):
    drop_node(doc, "cache")
    report = run(doc, intended)
    finding = next(f for f in report.findings if f.rule == "missing-component")
    assert (finding.subject, finding.severity) == ("cache", "warning")
    assert report.passed


def test_undeclared_connection(doc, intended):
    intended["relationships"] = [
        r for r in intended["relationships"] if r["unique-id"] != "orders-api-to-payments-service"
    ]
    report = run(doc, intended)
    assert ("undeclared-connection", "orders-api -> payments-service") in keyed(report)
    assert not report.passed


def test_missing_connection_is_only_a_warning(doc, intended):
    doc["relationships"] = [
        r for r in doc["relationships"] if r["unique-id"] != "orders-api-to-orders-db"
    ]
    report = run(doc, intended)
    assert ("missing-connection", "orders-api -> orders-db") in keyed(report)
    assert report.passed


def test_protocol_mismatch_warns(doc, intended):
    connect(doc, "orders-api", "orders-db")["protocol"] = "TCP"
    report = run(doc, intended)
    assert ("protocol-mismatch", "orders-api -> orders-db") in keyed(report)
    assert report.passed


def test_encryption_violation_blocks(doc, intended):
    connect(doc, "orders-api", "orders-db")["metadata"]["tls"] = False
    report = run(doc, intended)
    assert ("encryption-violation", "orders-api -> orders-db") in {
        (f.rule, f.subject) for f in report.blocking
    }


def test_unencrypted_is_fine_when_the_document_does_not_require_encryption(doc, intended):
    assert connect(doc, "public-gateway", "orders-api")["metadata"]["tls"] is False
    assert ("encryption-violation", "public-gateway -> orders-api") not in keyed(run(doc, intended))


def test_control_not_evidenced_blocks(doc, intended):
    cfg = node(doc, "orders-db")["controls"]["encryption-at-rest"]["requirements"][0]["config"]
    cfg["status"] = "unverified"
    report = run(doc, intended)
    assert ("control-not-evidenced", "orders-db/encryption-at-rest") in {
        (f.rule, f.subject) for f in report.blocking
    }


def test_control_missing_from_the_scan_blocks(doc, intended):
    del node(doc, "orders-db")["controls"]["encryption-at-rest"]
    report = run(doc, intended)
    finding = next(f for f in report.blocking if f.subject == "orders-db/encryption-at-rest")
    assert "no control" in finding.message


@pytest.mark.parametrize(
    ("document_owner", "code_owner", "mismatch"),
    [
        ("orders-squad", "@payments-platform/orders-squad", False),
        ("@payments-platform/orders-squad", "orders-squad", False),
        ("orders-squad", "@payments-platform/payments-core", True),
    ],
)
def test_owner_comparison_ignores_org_prefix(doc, intended, document_owner, code_owner, mismatch):
    node(intended, "orders-api")["metadata"]["owner"] = document_owner
    node(doc, "orders-api")["metadata"]["owner"] = code_owner
    report = run(doc, intended)
    assert (("owner-mismatch", "orders-api") in keyed(report)) is mismatch
    assert report.passed


# --------------------------------------------------------------------------- waivers


def test_waiver_expires_on_the_day_after_its_date(doc, intended):
    last_day = dt.date.fromisoformat("2029-12-31")
    assert run(doc, intended, last_day).passed
    after = run(doc, intended, last_day + dt.timedelta(days=1))
    assert not after.passed
    assert len(after.blocking) == 3
    assert all("expired on 2029-12-31" in f.message for f in after.blocking)


def test_waiver_must_match_rule_and_subject(doc, intended):
    intended["metadata"]["waivers"][0]["subject"] = "orders-api -> orders-db"
    report = run(doc, intended)
    assert not report.passed
    assert ("encryption-violation", "orders-api -> cache") in {
        (f.rule, f.subject) for f in report.blocking
    }
    assert any(f.rule == "waiver-unused" for f in report.findings)


def test_unused_waiver_warns_but_passes(doc, intended):
    intended["metadata"]["waivers"].append(
        {
            "rule": "owner-mismatch",
            "subject": "orders-api",
            "reason": "old",
            "owner": "@x",
            "expires": "2029-12-31",
        }
    )
    report = run(doc, intended)
    assert report.passed
    assert any(f.rule == "waiver-unused" and "owner-mismatch" in f.subject for f in report.findings)


# --------------------------------------------------------------------------- output


def test_renderers(doc, intended):
    drop_node(intended, "cache")
    report = run(doc, intended)
    github = render_github(report)
    assert github.startswith("::error file=") and "title=undeclared-component cache" in github
    markdown = render_markdown(report)
    assert (
        "Architecture conformance: FAIL" in markdown
        and "| FAIL | undeclared-component |" in markdown
    )


def test_waived_findings_are_notices_not_errors(doc, intended):
    github = render_github(run(doc, intended))
    assert "::notice file=" in github and "::error" not in github


# --------------------------------------------------------------------------- CLI


def write(tmp_path, name, document):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def test_cli_exit_codes(tmp_path, doc, intended, capsys):
    actual, wanted = write(tmp_path, "a.json", doc), write(tmp_path, "i.json", intended)
    assert main(["--actual", actual, "--intended", wanted, "--today", "2026-11-22"]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main(["--actual", actual, "--intended", wanted, "--today", "2031-01-01"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_rejects_swapped_arguments(tmp_path, doc, intended, capsys):
    actual, wanted = write(tmp_path, "a.json", doc), write(tmp_path, "i.json", intended)
    assert main(["--actual", wanted, "--intended", actual]) == 2
    assert "intended" in capsys.readouterr().err


def test_cli_missing_file_and_json_report(tmp_path, doc, intended, capsys):
    assert main(["--actual", str(tmp_path / "x.json"), "--intended", str(tmp_path / "y.json")]) == 2
    capsys.readouterr()
    actual, wanted = write(tmp_path, "a.json", doc), write(tmp_path, "i.json", intended)
    out = tmp_path / "report.json"
    assert main(["--actual", actual, "--intended", wanted, "--format", "json", "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["passed"] is True
