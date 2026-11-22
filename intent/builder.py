"""Turn an architecture Markdown document into the *intended* CALM document.

The intended document has the same shape as the one the scanner discovers, so the two can be
compared node by node, but it states what the architects approved:

* control config is ``{"status": "required"}`` (the scanner later has to prove it as ``verified``)
* ``connects`` relationships carry ``encrypted-in-transit: required | not-required``
* ``metadata.kind`` is ``intended`` and ``metadata.waivers`` lists the approved exceptions
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from intent.markdown import IntentDoc, parse
from intent.markdown import Issue as DocIssue
from scanner import __version__
from scanner.calm_builder import NODE_TYPE, ControlPolicy, load_policy, slug
from scanner.calm_schema import CALM_SCHEMA_URL, CALM_VERSION, validate_document

_KIND_ORDER = ["network", "ingress", "webclient", "service", "database"]


def _controls(policy: ControlPolicy, name: str, ids: list[str]) -> dict[str, Any]:
    return {
        control_id: {
            "description": policy.controls[control_id].description.format(name=name),
            "requirements": [
                {
                    "requirement-url": policy.requirement_url(control_id),
                    "config": {"status": "required"},
                }
            ],
        }
        for control_id in ids
    }


def build_intended_document(
    doc: IntentDoc, policy: ControlPolicy, *, source: str | None = None
) -> dict[str, Any]:
    """Build the CALM document from an already validated ``IntentDoc``."""
    system_id = slug(doc.system)
    by_component: dict[str, list[str]] = {}
    for row in doc.controls:
        by_component.setdefault(row["component"], []).append(row["control"])

    components = sorted(doc.components, key=lambda c: (_KIND_ORDER.index(c["type"]), c["id"]))
    system_node = {
        "unique-id": system_id,
        "node-type": "system",
        "name": doc.system,
        "description": f"System '{doc.system}' as approved in the architecture document.",
        "controls": _controls(policy, doc.system, ["ownership-governance"]),
        "metadata": {"owner": doc.owner or "unassigned", "environment": "all"},
    }
    nodes = [system_node]
    for comp in components:
        meta: dict[str, Any] = {"owner": comp["owner"], "environment": comp["environment"]}
        if comp["type"] == "ingress":
            meta["role"] = "ingress"
        nodes.append(
            {
                "unique-id": comp["id"],
                "node-type": NODE_TYPE[comp["type"]],
                "name": comp["id"],
                "description": comp["description"],
                "controls": _controls(policy, comp["id"], by_component.get(comp["id"], [])),
                "metadata": meta,
            }
        )

    relationships: list[dict[str, Any]] = []
    for conn in doc.connections:
        src, dst = conn["from"], conn["to"]
        meta = {"encrypted-in-transit": "required" if conn["encrypted"] else "not-required"}
        if conn["purpose"]:
            meta["purpose"] = conn["purpose"]
        relationships.append(
            {
                "unique-id": f"{src}-to-{dst}",
                "description": conn["purpose"] or f"{src} calls {dst} over {conn['protocol']}.",
                "protocol": conn["protocol"],
                "relationship-type": {
                    "connects": {"source": {"node": src}, "destination": {"node": dst}}
                },
                "metadata": meta,
            }
        )
    members = [c["id"] for c in components if c["type"] != "network"]
    if members:
        relationships.append(
            {
                "unique-id": f"{system_id}-composed-of",
                "description": f"{doc.system} is composed of its approved components.",
                "relationship-type": {"composed-of": {"container": system_id, "nodes": members}},
            }
        )

    meta_doc: dict[str, Any] = {
        "name": doc.system,
        "kind": "intended",
        "description": f"Architecture approved in '{source or doc.path}'.",
        "environment": doc.environment,
        "source": source or doc.path,
        "generated-by": {"tool": "calm-arch-discovery", "version": __version__},
        "calm-version": CALM_VERSION,
    }
    if doc.waivers:
        meta_doc["waivers"] = [
            {k: w[k] for k in ("rule", "subject", "reason", "owner", "expires")}
            for w in doc.waivers
        ]
    return {
        "$schema": CALM_SCHEMA_URL,
        "metadata": meta_doc,
        "nodes": nodes,
        "relationships": relationships,
    }


def compile_markdown(
    path: Path, policy: ControlPolicy | None = None, *, source: str | None = None
) -> tuple[dict[str, Any] | None, list[DocIssue], list[Any]]:
    """Parse + build + schema-validate. Returns (document or None, doc issues, schema issues)."""
    policy = policy or load_policy()
    text = path.read_text(encoding="utf-8")
    src = source or path.as_posix()
    parsed, issues = parse(text, src, list(policy.controls))
    if issues:
        return None, issues, []
    document = build_intended_document(parsed, policy, source=src)
    return document, [], validate_document(document)


def _format(path: str, issue: DocIssue, fmt: str) -> str:
    if fmt == "github":
        return f"::error file={path},line={issue.line}::{issue.message}"
    return f"{path}:{issue.line}: {issue.message}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="calm-intent",
        description="Compile an architecture Markdown document into an intended CALM document.",
    )
    parser.add_argument("markdown", type=Path, help="architecture document (.md)")
    parser.add_argument("-o", "--output", type=Path, help="write CALM JSON here (default: stdout)")
    parser.add_argument("--policy", type=Path, help="control policy YAML")
    parser.add_argument("--format", choices=["text", "github"], default="text")
    args = parser.parse_args(argv)

    if not args.markdown.is_file():
        print(f"error: {args.markdown} is not a file", file=sys.stderr)
        return 2
    path = args.markdown.as_posix()
    document, issues, schema_issues = compile_markdown(args.markdown, load_policy(args.policy))
    if issues:
        for issue in issues:
            print(_format(path, issue, args.format), file=sys.stderr)
        print(f"{len(issues)} problem(s) in {path}; no CALM document written", file=sys.stderr)
        return 1
    errors = [i for i in schema_issues if i.severity == "error"]
    for issue in schema_issues:
        print(issue, file=sys.stderr)
    if errors or document is None:
        return 1
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    links = sum(1 for r in document["relationships"] if "connects" in r["relationship-type"])
    print(
        f"compiled {len(document['nodes'])} nodes, {links} connections, "
        f"{len(document.get('metadata', {}).get('waivers', []))} waivers; schema: valid"
        + (f" -> {args.output}" if args.output else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
