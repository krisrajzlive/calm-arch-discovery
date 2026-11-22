"""CALM document validation.

Three layers, mirroring what ``calm validate`` (FINOS calm-cli) does:

1. **Structure** - the document is validated against the CALM 1.3 JSON Schema
   (``schemas/calm/1.3/meta/core.json`` and its ``control.json`` / ``interface.json`` /
   ``flow.json`` siblings, vendored so validation works offline).
2. **Semantics** - rules a JSON Schema cannot express: unique ids across the document,
   relationships that reference nodes that exist, control ids that match CALM's key pattern.
3. **Control requirements** - each control's ``config`` is validated against the JSON Schema
   named by its ``requirement-url`` (resolved from the local ``controls/`` directory).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from scanner import REPO_ROOT

CALM_VERSION = "1.3"
CALM_SCHEMA_URL = f"https://calm.finos.org/release/{CALM_VERSION}/meta/calm.json"
CORE_SCHEMA_URL = f"https://calm.finos.org/release/{CALM_VERSION}/meta/core.json"
CONTROL_ID = re.compile(r"^[a-zA-Z0-9-]+$")


def schema_dir() -> Path:
    return Path(
        os.environ.get("CALM_SCHEMA_DIR", REPO_ROOT / "schemas" / "calm" / CALM_VERSION / "meta")
    )


def controls_dir() -> Path:
    return Path(os.environ.get("CALM_CONTROLS_DIR", REPO_ROOT / "controls"))


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" | "warning"
    code: str
    message: str
    path: str = ""

    def __str__(self) -> str:
        where = f" [{self.path}]" if self.path else ""
        return f"{self.severity.upper()} {self.code}{where}: {self.message}"


def _load_registry() -> Registry:
    registry: Registry = Registry()
    for path in sorted(schema_dir().glob("*.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        registry = registry.with_resource(contents.get("$id", path.as_uri()), resource)
    return registry


_REGISTRY: Registry | None = None


def _registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _load_registry()
    return _REGISTRY


def load_requirement_schemas(directory: Path | None = None) -> dict[str, dict[str, Any]]:
    """Map ``$id`` URL -> control requirement schema for every ``*.requirement.json``."""
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted((directory or controls_dir()).glob("*.requirement.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        schemas[schema.get("$id", path.as_uri())] = schema
    return schemas


def _pointer(parts: Any) -> str:
    return "/" + "/".join(str(p) for p in parts) if parts else ""


def structural_issues(doc: dict[str, Any]) -> list[Issue]:
    declared = doc.get("$schema")
    issues: list[Issue] = []
    if declared is not None and declared != CALM_SCHEMA_URL:
        issues.append(
            Issue(
                "error",
                "unsupported-schema",
                f"$schema is {declared!r}; this tool validates against {CALM_SCHEMA_URL}",
                "/$schema",
            )
        )
    core = _registry().get_or_retrieve(CORE_SCHEMA_URL).value.contents
    validator = Draft202012Validator(core, registry=_registry())
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        issues.append(Issue("error", "schema", err.message, _pointer(err.absolute_path)))
    return issues


def _node_ids(doc: dict[str, Any]) -> set[str]:
    return {
        n["unique-id"] for n in doc.get("nodes", []) if isinstance(n, dict) and "unique-id" in n
    }


def semantic_issues(doc: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    seen: dict[str, str] = {}
    for kind in ("nodes", "relationships"):
        for i, item in enumerate(doc.get(kind, [])):
            uid = item.get("unique-id") if isinstance(item, dict) else None
            if uid is None:
                continue
            if uid in seen:
                issues.append(
                    Issue(
                        "error",
                        "duplicate-id",
                        f"unique-id {uid!r} already used by {seen[uid]}",
                        f"/{kind}/{i}",
                    )
                )
            seen[uid] = f"/{kind}/{i}"

    nodes = _node_ids(doc)

    def need(ref: Any, path: str) -> None:
        if isinstance(ref, str) and ref not in nodes:
            issues.append(Issue("error", "dangling-reference", f"unknown node {ref!r}", path))

    for i, rel in enumerate(doc.get("relationships", [])):
        rtype = rel.get("relationship-type", {}) if isinstance(rel, dict) else {}
        base = f"/relationships/{i}/relationship-type"
        if "connects" in rtype:
            c = rtype["connects"]
            need((c.get("source") or {}).get("node"), f"{base}/connects/source/node")
            need((c.get("destination") or {}).get("node"), f"{base}/connects/destination/node")
        for key in ("deployed-in", "composed-of"):
            if key in rtype:
                need(rtype[key].get("container"), f"{base}/{key}/container")
                for n in rtype[key].get("nodes", []):
                    need(n, f"{base}/{key}/nodes")
        if "interacts" in rtype:
            need(rtype["interacts"].get("actor"), f"{base}/interacts/actor")
            for n in rtype["interacts"].get("nodes", []):
                need(n, f"{base}/interacts/nodes")

    for i, node in enumerate(doc.get("nodes", [])):
        for cid in (node.get("controls") or {}) if isinstance(node, dict) else []:
            if not CONTROL_ID.match(cid):
                issues.append(
                    Issue(
                        "error",
                        "control-id",
                        f"control id {cid!r} must match {CONTROL_ID.pattern}",
                        f"/nodes/{i}/controls",
                    )
                )
    return issues


def requirement_issues(
    doc: dict[str, Any], requirements: dict[str, dict[str, Any]] | None = None
) -> list[Issue]:
    """Validate each inline control ``config`` against its ``requirement-url`` schema."""
    schemas = requirements if requirements is not None else load_requirement_schemas()
    issues: list[Issue] = []
    for i, node in enumerate(doc.get("nodes", [])):
        if not isinstance(node, dict):
            continue
        for cid, control in (node.get("controls") or {}).items():
            for j, req in enumerate((control or {}).get("requirements") or []):
                path = f"/nodes/{i}/controls/{cid}/requirements/{j}"
                url = req.get("requirement-url")
                if url not in schemas:
                    issues.append(
                        Issue(
                            "warning",
                            "requirement-unresolved",
                            f"requirement-url {url!r} not found in controls/",
                            path,
                        )
                    )
                    continue
                if "config" not in req:
                    continue  # config-url form: resolved remotely by calm-cli
                validator = Draft202012Validator(schemas[url])
                for err in validator.iter_errors(req["config"]):
                    issues.append(
                        Issue(
                            "error",
                            "control-config",
                            f"{node.get('unique-id')}/{cid}: {err.message}",
                            f"{path}/config{_pointer(err.absolute_path)}",
                        )
                    )
    return issues


def validate_document(
    doc: dict[str, Any], requirements: dict[str, dict[str, Any]] | None = None
) -> list[Issue]:
    """Run all three validation layers and return every issue found."""
    issues = structural_issues(doc)
    if not any(i.severity == "error" for i in issues):
        # semantic checks assume a structurally sound document
        issues.extend(semantic_issues(doc))
        issues.extend(requirement_issues(doc, requirements))
    return issues
