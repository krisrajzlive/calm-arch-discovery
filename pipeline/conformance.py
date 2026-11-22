"""Conformance gate: does the code still do what the architecture document says?

Compares two CALM documents:

* **intended**: compiled from the architecture Markdown by ``calm-intent`` (what was approved)
* **actual**: discovered from the repository by ``calm-discover`` (what the code does)

=========================  ========  ====================================================
rule                       severity  fires when
=========================  ========  ====================================================
undeclared-component       error     code has a workload the document does not list
undeclared-connection      error     code connects two declared components with no approval
encryption-violation       error     document requires encryption, code connects without TLS
control-not-evidenced      error     a required control has no ``verified`` evidence in code
missing-component          warning   document lists a component the scanner cannot find
missing-connection         warning   document lists a connection the scanner cannot find
protocol-mismatch          warning   same connection, different protocol
owner-mismatch             warning   document and CODEOWNERS disagree on the owner
waiver-unused              warning   a waiver matches nothing (remove it)
=========================  ========  ====================================================

A finding is *waived* by an unexpired entry in the document's ``Waivers`` table that matches its
rule and subject. An expired waiver no longer protects the finding, so debt cannot hide.
Exit code: 0 conformant, 1 any non-waived error, 2 unusable input.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

WORKLOAD_TYPES = {"service", "database", "webclient"}
ERROR, WARNING = "error", "warning"
# an undeclared actual node is only in scope when it can run in the intended environment
_ANY_ENV = {"all", "unspecified"}


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    waived: bool = False
    waiver: dict[str, str] | None = None

    @property
    def blocking(self) -> bool:
        return self.severity == ERROR and not self.waived


@dataclass
class Report:
    system: str
    environment: str
    source: str
    today: str
    findings: list[Finding]
    compared: dict[str, int]

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.blocking]

    @property
    def passed(self) -> bool:
        return not self.blocking


# --------------------------------------------------------------------------- extraction


def _owner(value: str | None) -> str:
    return (value or "").strip().lstrip("@").rsplit("/", 1)[-1]


def _config(node: dict[str, Any], control_id: str) -> dict[str, Any] | None:
    control = (node.get("controls") or {}).get(control_id)
    if not control:
        return None
    return ((control.get("requirements") or [{}])[0]).get("config") or {}


def _environments(node: dict[str, Any]) -> set[str]:
    meta = node.get("metadata") or {}
    return set(meta.get("environments") or [meta.get("environment") or "unspecified"])


def _connections(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    names = {n["unique-id"]: n["name"] for n in doc.get("nodes", [])}
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for rel in doc.get("relationships", []):
        connects = rel["relationship-type"].get("connects")
        if not connects:
            continue
        src = names.get(connects["source"]["node"])
        dst = names.get(connects["destination"]["node"])
        if src and dst:  # a dangling reference is reported by calm-gate, not here
            result[(src, dst)] = rel
    return result


def _workloads(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {n["name"]: n for n in doc.get("nodes", []) if n["node-type"] in WORKLOAD_TYPES}


# --------------------------------------------------------------------------- evaluation


def evaluate(actual: dict[str, Any], intended: dict[str, Any], *, today: dt.date) -> Report:
    meta = intended.get("metadata") or {}
    environment = meta.get("environment", "production")
    want, have = _workloads(intended), _workloads(actual)
    findings: list[Finding] = []

    def add(rule: str, severity: str, subject: str, message: str) -> None:
        findings.append(Finding(rule, severity, subject, message))

    # components
    in_scope = {
        name
        for name, node in have.items()
        if name in want or _environments(node) & ({environment} | _ANY_ENV)
    }
    for name in sorted(in_scope - want.keys()):
        sources = ", ".join((have[name].get("metadata") or {}).get("sources", [])) or "the repo"
        add(
            "undeclared-component",
            ERROR,
            name,
            f"'{name}' exists in the code ({sources}) but is not in the architecture document",
        )
    for name in sorted(want.keys() - have.keys()):
        add(
            "missing-component",
            WARNING,
            name,
            f"'{name}' is in the architecture document but no matching workload was discovered",
        )

    # owners and controls on declared components that exist in the code
    for name in sorted(want.keys() & have.keys()):
        w, h = want[name], have[name]
        approved, found = (
            (w.get("metadata") or {}).get("owner"),
            (h.get("metadata") or {}).get("owner"),
        )
        if _owner(approved) != _owner(found):
            add(
                "owner-mismatch",
                WARNING,
                name,
                f"document says owner '{approved}', CODEOWNERS says '{found}'",
            )
        for control_id in sorted(w.get("controls") or {}):
            config = _config(h, control_id)
            if config is None:
                add(
                    "control-not-evidenced",
                    ERROR,
                    f"{name}/{control_id}",
                    f"'{control_id}' is required for '{name}' but the scanner found no control",
                )
            elif config.get("status") != "verified":
                add(
                    "control-not-evidenced",
                    ERROR,
                    f"{name}/{control_id}",
                    f"'{control_id}' is required for '{name}' but the code does not evidence it",
                )

    # connections
    approved_links, found_links = _connections(intended), _connections(actual)
    for (src, dst), rel in sorted(found_links.items()):
        if src not in want or dst not in want:
            continue  # covered by undeclared-component, or out of scope for this environment
        subject = f"{src} -> {dst}"
        approved = approved_links.get((src, dst))
        if approved is None:
            add(
                "undeclared-connection",
                ERROR,
                subject,
                f"code connects {src} to {dst} over {rel.get('protocol')} "
                "but the document does not approve it",
            )
            continue
        if approved.get("protocol") != rel.get("protocol"):
            add(
                "protocol-mismatch",
                WARNING,
                subject,
                f"document says {approved.get('protocol')}, code uses {rel.get('protocol')}",
            )
        required = (approved.get("metadata") or {}).get("encrypted-in-transit") == "required"
        if required and not (rel.get("metadata") or {}).get("tls", False):
            add(
                "encryption-violation",
                ERROR,
                subject,
                f"document requires encryption for {subject} but the code connects without TLS "
                f"({rel.get('protocol')})",
            )
    for src, dst in sorted(approved_links):
        if (src, dst) not in found_links and src in have and dst in have:
            add(
                "missing-connection",
                WARNING,
                f"{src} -> {dst}",
                f"document approves {src} -> {dst} but no such dependency was discovered",
            )

    _apply_waivers(findings, meta.get("waivers") or [], today)
    findings.sort(key=lambda f: (f.severity != ERROR, f.waived, f.rule, f.subject))
    return Report(
        system=meta.get("name", ""),
        environment=environment,
        source=meta.get("source", ""),
        today=today.isoformat(),
        findings=findings,
        compared={
            "components-approved": len(want),
            "components-discovered-in-scope": len(in_scope),
            "connections-approved": len(approved_links),
            "connections-discovered": len(found_links),
        },
    )


def _apply_waivers(findings: list[Finding], waivers: list[dict[str, str]], today: dt.date) -> None:
    used: set[int] = set()
    for finding in findings:
        for index, waiver in enumerate(waivers):
            if waiver["rule"] != finding.rule or waiver["subject"] != finding.subject:
                continue
            used.add(index)
            expires = dt.date.fromisoformat(waiver["expires"])
            if expires >= today:
                finding.waived, finding.waiver = True, waiver
            else:
                finding.message += (
                    f" (waiver by {waiver['owner']} expired on {waiver['expires']}: "
                    f"{waiver['reason']})"
                )
            break
    for index, waiver in enumerate(waivers):
        if index not in used:
            findings.append(
                Finding(
                    "waiver-unused",
                    WARNING,
                    f"{waiver['rule']} {waiver['subject']}",
                    f"waiver '{waiver['rule']}' for '{waiver['subject']}' matches nothing; "
                    "delete it from the architecture document",
                )
            )


# --------------------------------------------------------------------------- rendering


def _state(f: Finding) -> str:
    if f.waived:
        return "waived"
    return "FAIL" if f.severity == ERROR else "warn"


def render_text(report: Report) -> str:
    lines = [
        f"conformance of '{report.system}' ({report.environment}) to {report.source or 'document'}"
    ]
    for f in report.findings:
        lines.append(f"  {_state(f):<6} {f.rule:<22} {f.subject}: {f.message}")
        if f.waiver:
            lines.append(
                f"         waived by {f.waiver['owner']} until {f.waiver['expires']}: "
                f"{f.waiver['reason']}"
            )
    errors, waived = len(report.blocking), sum(f.waived for f in report.findings)
    warnings = sum(f.severity == WARNING for f in report.findings)
    lines.append(
        f"{'PASS' if report.passed else 'FAIL'}: {errors} blocking, {waived} waived, "
        f"{warnings} warning(s); compared {report.compared['components-approved']} approved "
        f"components and {report.compared['connections-approved']} approved connections"
    )
    return "\n".join(lines)


def render_github(report: Report) -> str:
    lines = []
    for f in report.findings:
        level = "notice" if f.waived else f.severity
        message = f.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        lines.append(f"::{level} file={report.source},title={f.rule} {f.subject}::{message}")
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    verdict = "PASS" if report.passed else "FAIL"
    lines = [
        f"### Architecture conformance: {verdict}",
        "",
        f"`{report.system}` ({report.environment}) checked against `{report.source}` "
        f"on {report.today}.",
        "",
    ]
    if report.findings:
        lines += ["| status | rule | subject | detail |", "|---|---|---|---|"]
        for f in report.findings:
            detail = f.message.replace("|", "\\|")
            if f.waiver:
                detail += (
                    f". Waived by {f.waiver['owner']} until {f.waiver['expires']}: "
                    f"{f.waiver['reason']}".replace("|", "\\|")
                )
            lines.append(f"| {_state(f)} | {f.rule} | `{f.subject}` | {detail} |")
    else:
        lines.append("No findings: the code conforms to the document.")
    return "\n".join(lines) + "\n"


def render_json(report: Report) -> str:
    payload = asdict(report)
    payload["passed"] = report.passed
    return json.dumps(payload, indent=2) + "\n"


RENDERERS = {
    "text": render_text,
    "github": render_github,
    "markdown": render_markdown,
    "json": render_json,
}


def _load(path: Path, expect_kind: str | None) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    kind = (document.get("metadata") or {}).get("kind")
    if (kind == "intended") != (expect_kind == "intended"):
        raise ValueError(
            f"{path} is {'an intended' if kind == 'intended' else 'not an intended'} document "
            f"but was passed as --{'intended' if expect_kind == 'intended' else 'actual'}"
        )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="calm-conformance",
        description="Fail when the discovered architecture drifts from the approved document.",
    )
    parser.add_argument("--actual", type=Path, required=True, help="CALM from calm-discover")
    parser.add_argument("--intended", type=Path, required=True, help="CALM from calm-intent")
    parser.add_argument("--format", choices=sorted(RENDERERS), default="text")
    parser.add_argument("--today", help="override today's date (YYYY-MM-DD), for waiver expiry")
    parser.add_argument("-o", "--output", type=Path, help="also write the report here")
    args = parser.parse_args(argv)

    try:
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
        actual = _load(args.actual, "actual")
        intended = _load(args.intended, "intended")
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = evaluate(actual, intended, today=today)
    rendered = RENDERERS[args.format](report)
    if rendered:
        print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    if args.format == "github":
        print(render_text(report).splitlines()[-1], file=sys.stderr)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
