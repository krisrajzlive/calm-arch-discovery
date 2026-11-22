"""CALM gate for CI: exits 1 when an architecture document must not be merged.

A document fails the gate when any of these hold:

* it is not valid CALM 1.3 (JSON Schema), or references nodes that do not exist
* a control's config does not satisfy its ``requirement-url`` schema
* **any node has no controls** (the rule this gate exists for), or a control carries no
  requirement

Controls the scanner could not evidence (``status: unverified``) are reported as warnings;
``--fail-on-unverified`` promotes them to failures once a team is ready to enforce them.

Exit codes: 0 pass, 1 gate failed, 2 usage / unreadable input.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scanner.calm_schema import Issue, load_requirement_schemas, validate_document


def control_issues(doc: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    for i, node in enumerate(doc.get("nodes", [])):
        uid = node.get("unique-id", f"#{i}")
        controls = node.get("controls") or {}
        path = f"/nodes/{i}/controls"
        if not controls:
            issues.append(
                Issue(
                    "error",
                    "node-without-controls",
                    f"node '{uid}' has no controls; attach at least one control",
                    path,
                )
            )
            continue
        for cid, control in controls.items():
            if not (control or {}).get("requirements"):
                issues.append(
                    Issue(
                        "error",
                        "control-without-requirements",
                        f"control '{cid}' on node '{uid}' has no requirements",
                        f"{path}/{cid}",
                    )
                )
    return issues


def unverified_issues(doc: dict[str, Any], *, severity: str) -> list[Issue]:
    issues: list[Issue] = []
    for i, node in enumerate(doc.get("nodes", [])):
        for cid, control in (node.get("controls") or {}).items():
            for j, req in enumerate((control or {}).get("requirements") or []):
                if (req.get("config") or {}).get("status") == "unverified":
                    issues.append(
                        Issue(
                            severity,
                            "control-unverified",
                            f"node '{node.get('unique-id')}': control '{cid}' is not evidenced",
                            f"/nodes/{i}/controls/{cid}/requirements/{j}",
                        )
                    )
    return issues


def evaluate(
    doc: dict[str, Any],
    *,
    fail_on_unverified: bool = False,
    requirements: dict[str, dict[str, Any]] | None = None,
) -> list[Issue]:
    issues = validate_document(doc, requirements)
    issues += control_issues(doc)
    issues += unverified_issues(doc, severity="error" if fail_on_unverified else "warning")
    return issues


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _github(file: str, issue: Issue) -> str:
    level = "error" if issue.severity == "error" else "warning"
    where = f" {issue.path}" if issue.path else ""
    return f"::{level} file={file},title={issue.code}::{_escape(issue.message + where)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="calm-gate", description=__doc__.split("\n")[0])
    parser.add_argument("documents", nargs="+", type=Path, help="CALM JSON documents to check")
    parser.add_argument("--format", choices=("text", "github", "json"), default="text")
    parser.add_argument(
        "--fail-on-unverified",
        action="store_true",
        help="treat controls without evidence as failures",
    )
    parser.add_argument(
        "--requirements-dir", type=Path, help="directory of *.requirement.json (default: controls/)"
    )
    args = parser.parse_args(argv)

    requirements = load_requirement_schemas(args.requirements_dir)
    report: list[dict[str, Any]] = []
    failed = False
    for path in args.documents:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        issues = evaluate(
            doc, fail_on_unverified=args.fail_on_unverified, requirements=requirements
        )
        errors = [i for i in issues if i.severity == "error"]
        warnings = [i for i in issues if i.severity == "warning"]
        failed |= bool(errors)
        controls = sum(len(n.get("controls") or {}) for n in doc.get("nodes", []))
        report.append(
            {
                "file": str(path),
                "passed": not errors,
                "nodes": len(doc.get("nodes", [])),
                "controls": controls,
                "errors": len(errors),
                "warnings": len(warnings),
                "issues": [asdict(i) for i in issues],
            }
        )
        if args.format == "text":
            status = "FAIL" if errors else "PASS"
            print(
                f"{status} {path}: {len(doc.get('nodes', []))} nodes, {controls} controls, "
                f"{len(errors)} errors, {len(warnings)} warnings"
            )
            for issue in errors + warnings:
                print(f"  {issue}")
        elif args.format == "github":
            for issue in errors + warnings:
                print(_github(str(path), issue))
    if args.format == "json":
        print(json.dumps({"passed": not failed, "documents": report}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
