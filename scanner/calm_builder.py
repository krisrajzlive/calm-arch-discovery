"""Assemble a CALM document from a repository scan and validate it.

Mapping (see README, "How this maps to the CALM spec"):

=====================  ==============================================================
Discovered              CALM
=====================  ==============================================================
workload / ingress      node, ``node-type: service``
datastore               node, ``node-type: database``
frontend                node, ``node-type: webclient``
namespace / network     node, ``node-type: network`` + ``deployed-in`` relationship
repository (system)     node, ``node-type: system`` + ``composed-of`` relationship
runtime dependency      ``connects`` relationship with a ``protocol``
security expectation    ``controls`` on the node (requirement-url + inline config)
=====================  ==============================================================
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from scanner import REPO_ROOT, __version__
from scanner.calm_schema import CALM_SCHEMA_URL, CALM_VERSION, Issue, validate_document
from scanner.models import Component, ComponentKind, Link, ScanResult
from scanner.repo_scanner import scan_repository

DEFAULT_POLICY = REPO_ROOT / "policy" / "control-policy.yaml"

NODE_TYPE: dict[str, str] = {
    "service": "service",
    "ingress": "service",
    "database": "database",
    "webclient": "webclient",
    "network": "network",
    "system": "system",
}
_KIND_ORDER = ["system", "network", "ingress", "webclient", "service", "database"]


class ControlDefinition(BaseModel):
    description: str


class ControlPolicy(BaseModel):
    requirement_base_url: str = Field(alias="requirement-base-url")
    controls: dict[str, ControlDefinition]
    required_by_kind: dict[str, list[str]] = Field(alias="required-by-kind")

    def requirement_url(self, control_id: str) -> str:
        return f"{self.requirement_base_url.rstrip('/')}/{control_id}.requirement.json"


def load_policy(path: Path | None = None) -> ControlPolicy:
    data = yaml.safe_load((path or DEFAULT_POLICY).read_text(encoding="utf-8"))
    return ControlPolicy.model_validate(data)


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unnamed"


class CalmBuilder:
    def __init__(self, scan: ScanResult, policy: ControlPolicy, *, include_revision: bool = False):
        self.scan = scan
        self.policy = policy
        self.include_revision = include_revision
        self.ids: dict[str, str] = {}  # component key -> CALM unique-id
        self._used: set[str] = set()

    # ---- ids

    def _unique(self, base: str) -> str:
        candidate, n = base, 2
        while candidate in self._used:
            candidate, n = f"{base}-{n}", n + 1
        self._used.add(candidate)
        return candidate

    def _assign_ids(self) -> None:
        system = self.scan.system_name
        self.ids["__system__"] = self._unique(slug(system))
        for key in self.scan.components:
            self.ids[key] = self._unique(slug(key))

    # ---- controls

    def _inbound(self, key: str) -> list[Link]:
        return [link for link in self.scan.links if link.target == key]

    def _link_id(self, link: Link) -> str:
        return f"{self.ids[link.source]}-to-{self.ids[link.target]}"

    def _control_config(self, control_id: str, key: str, comp: Component) -> dict[str, Any]:
        sec = comp.security
        net = self.scan.components.get(f"ns-{comp.namespace}") if comp.namespace else None
        if control_id == "auth-required":
            mechanism = sec.auth_mechanism or ("mtls" if sec.mesh_mtls else None)
            evidence = sec.auth_evidence or (sec.mesh_evidence if sec.mesh_mtls else [])
            return {
                "status": "verified" if mechanism else "unverified",
                "mechanism": mechanism or "none-detected",
                "evidence": list(evidence),
            }
        if control_id == "encryption-in-transit":
            inbound = self._inbound(key)
            gaps = [self._link_id(link) for link in inbound if not link.tls]
            evidence = [f"{self._link_id(link)}: {link.protocol}" for link in inbound if link.tls]
            evidence += sec.tls_termination_evidence
            vacuous = not inbound and not sec.tls_termination_evidence
            if vacuous and comp.kind != "ingress":
                evidence = ["no inbound connections discovered"]
            ok = not gaps and bool(evidence)
            return {
                "status": "verified" if ok else "unverified",
                "evidence": evidence,
                "gaps": gaps,
            }
        if control_id == "encryption-at-rest":
            cfg: dict[str, Any] = {
                "status": "verified" if sec.encryption_at_rest_evidence else "unverified",
                "evidence": list(sec.encryption_at_rest_evidence),
            }
            if sec.storage_class:
                cfg["storage-class"] = sec.storage_class
            return cfg
        if control_id == "network-segmentation":
            policies = list(sec.network_policies)
            if comp.kind == "network":
                ok = sec.default_deny
            else:
                if net is not None and net.security.default_deny:
                    policies += net.security.network_policies
                ok = bool(policies)
            return {
                "status": "verified" if ok else "unverified",
                "evidence": policies,
                "policies": policies,
            }
        if control_id == "container-hardening":
            ok = sec.run_as_non_root is True and sec.allow_privilege_escalation is False
            cfg = {
                "status": "verified" if ok else "unverified",
                "evidence": list(sec.hardening_evidence),
            }
            for field, value in (
                ("run-as-non-root", sec.run_as_non_root),
                ("allow-privilege-escalation", sec.allow_privilege_escalation),
                ("read-only-root-filesystem", sec.read_only_root_filesystem),
            ):
                if value is not None:
                    cfg[field] = value
            return cfg
        if control_id == "ownership-governance":
            ok = bool(self.scan.codeowners_path and self.scan.system_owner)
            cfg = {
                "status": "verified" if ok else "unverified",
                "evidence": [self.scan.codeowners_path] if ok else [],
            }
            if self.scan.system_owner:
                cfg["owner"] = self.scan.system_owner
            return cfg
        return {"status": "unverified", "evidence": []}

    def _controls(
        self, kind: ComponentKind, name: str, key: str, comp: Component
    ) -> dict[str, Any]:
        controls: dict[str, Any] = {}
        for control_id in self.policy.required_by_kind.get(kind, []):
            definition = self.policy.controls[control_id]
            controls[control_id] = {
                "description": definition.description.format(name=name),
                "requirements": [
                    {
                        "requirement-url": self.policy.requirement_url(control_id),
                        "config": self._control_config(control_id, key, comp),
                    }
                ],
            }
        return controls

    # ---- nodes

    @staticmethod
    def _display_name(key: str, comp: Component) -> str:
        if comp.kind == "network" and key.startswith("ns-"):
            return f"{key[3:]} namespace"
        if comp.kind == "network" and key.startswith("net-"):
            return f"{key[4:]} network"
        return key

    def _owner(self, comp: Component) -> str:
        return comp.owner or self.scan.system_owner or "unassigned"

    def _node(self, key: str, comp: Component) -> dict[str, Any]:
        name = self._display_name(key, comp)
        meta: dict[str, Any] = {
            "owner": self._owner(comp),
            "environment": comp.environments[0] if comp.environments else "unspecified",
        }
        if len(comp.environments) > 1:
            meta["environments"] = list(comp.environments)
        for field, value in (
            ("technology", comp.technology),
            ("image", comp.image),
            ("namespace", comp.namespace),
            ("ports", sorted(comp.ports) or None),
            ("exposure", comp.exposure),
            ("role", "ingress" if comp.kind == "ingress" else None),
            ("external-endpoints", sorted(comp.external_endpoints) or None),
            ("sources", sorted(comp.sources) or None),
            (
                "dependencies",
                [d.model_dump(exclude_none=True) for d in comp.dependencies] or None,
            ),
        ):
            if value is not None:
                meta[field] = value
        sources = ", ".join(sorted(comp.sources)) or "dependency manifests"
        description = comp.description or (
            f"{comp.kind.capitalize()} '{name}'"
            + (f" ({comp.technology})" if comp.technology else "")
            + f", discovered in {sources}."
        )
        return {
            "unique-id": self.ids[key],
            "node-type": NODE_TYPE[comp.kind],
            "name": name,
            "description": description,
            "controls": self._controls(comp.kind, name, key, comp),
            "metadata": meta,
        }

    def _system_node(self) -> dict[str, Any]:
        name = self.scan.system_name
        comp = Component(name=name, kind="system", owner=self.scan.system_owner)
        sources = [self.scan.codeowners_path] if self.scan.codeowners_path else []
        meta: dict[str, Any] = {
            "owner": self.scan.system_owner or "unassigned",
            "environment": "all",
            "sources": sources,
        }
        if self.scan.system_dependencies:
            meta["dependencies"] = [
                d.model_dump(exclude_none=True) for d in self.scan.system_dependencies
            ]
        return {
            "unique-id": self.ids["__system__"],
            "node-type": "system",
            "name": name,
            "description": f"System '{name}' as discovered from repository '{self.scan.root}'.",
            "controls": self._controls("system", name, "__system__", comp),
            "metadata": meta,
        }

    # ---- relationships

    def _connects(self, link: Link) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "tls": link.tls,
            "confidence": link.confidence,
            "evidence": link.evidence,
        }
        if link.application_protocol:
            meta["application-protocol"] = link.application_protocol
        if link.port:
            meta["port"] = link.port
        src, dst = self.ids[link.source], self.ids[link.target]
        return {
            "unique-id": self._link_id(link),
            "description": f"{src} calls {dst} over {link.protocol}.",
            "protocol": link.protocol,
            "relationship-type": {
                "connects": {"source": {"node": src}, "destination": {"node": dst}}
            },
            "metadata": meta,
        }

    def _relationships(self) -> list[dict[str, Any]]:
        rels = [self._connects(link) for link in self.scan.links]
        for net_key, members in self.scan.containers.items():
            if net_key not in self.ids or not members:
                continue
            rels.append(
                {
                    "unique-id": f"deployed-in-{self.ids[net_key]}",
                    "description": f"Components deployed in {self.ids[net_key]}.",
                    "relationship-type": {
                        "deployed-in": {
                            "container": self.ids[net_key],
                            "nodes": [self.ids[m] for m in members if m in self.ids],
                        }
                    },
                }
            )
        members = [self.ids[k] for k, c in self.scan.components.items() if c.kind != "network"]
        if members:
            rels.append(
                {
                    "unique-id": f"{self.ids['__system__']}-composed-of",
                    "description": (
                        f"{self.scan.system_name} is composed of its services and datastores."
                    ),
                    "relationship-type": {
                        "composed-of": {"container": self.ids["__system__"], "nodes": members}
                    },
                }
            )
        return rels

    # ---- document

    def build(self) -> dict[str, Any]:
        self._assign_ids()
        ordered = sorted(
            self.scan.components.items(), key=lambda kv: (_KIND_ORDER.index(kv[1].kind), kv[0])
        )
        nodes = [self._system_node()] + [self._node(k, c) for k, c in ordered]
        meta: dict[str, Any] = {
            "name": self.scan.system_name,
            "description": f"Architecture discovered from repository '{self.scan.root}'.",
            "generated-by": {"tool": "calm-arch-discovery", "version": __version__},
            "calm-version": CALM_VERSION,
        }
        if self.include_revision and self.scan.revision:
            meta["source-revision"] = self.scan.revision
        if self.scan.warnings:
            meta["scan-warnings"] = self.scan.warnings
        return {
            "$schema": CALM_SCHEMA_URL,
            "metadata": meta,
            "nodes": nodes,
            "relationships": self._relationships(),
        }


def build_calm_document(
    scan: ScanResult, policy: ControlPolicy | None = None, *, include_revision: bool = False
) -> dict[str, Any]:
    return CalmBuilder(scan, policy or load_policy(), include_revision=include_revision).build()


def discover(
    repo: Path | str,
    *,
    name: str | None = None,
    excludes: list[str] | None = None,
    policy_path: Path | None = None,
    include_revision: bool = False,
) -> tuple[dict[str, Any], list[Issue]]:
    """Scan ``repo``, build the CALM document and validate it against the CALM schema."""
    scan = scan_repository(repo, name=name, excludes=excludes or [])
    doc = build_calm_document(scan, load_policy(policy_path), include_revision=include_revision)
    return doc, validate_document(doc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="calm-discover",
        description="Discover architecture in a repository and emit a CALM JSON document.",
    )
    parser.add_argument("repo", type=Path, help="repository (or directory) to scan")
    parser.add_argument(
        "-o", "--output", type=Path, help="write the CALM JSON here (default: stdout)"
    )
    parser.add_argument(
        "--name", help="system name (default: app.kubernetes.io/part-of label or folder)"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="repo-relative glob to skip; repeatable",
    )
    parser.add_argument(
        "--policy", type=Path, help="control policy YAML (default: policy/control-policy.yaml)"
    )
    parser.add_argument(
        "--include-revision",
        action="store_true",
        help="record the HEAD commit in metadata (makes output differ per commit)",
    )
    args = parser.parse_args(argv)

    if not args.repo.is_dir():
        print(f"error: {args.repo} is not a directory", file=sys.stderr)
        return 2
    doc, issues = discover(
        args.repo,
        name=args.name,
        excludes=args.exclude,
        policy_path=args.policy,
        include_revision=args.include_revision,
    )
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)

    errors = [i for i in issues if i.severity == "error"]
    for issue in issues:
        print(issue, file=sys.stderr)
    links = sum(1 for r in doc["relationships"] if "connects" in r["relationship-type"])
    print(
        f"discovered {len(doc['nodes'])} nodes, {len(doc['relationships'])} relationships "
        f"({links} connects); schema: {'INVALID' if errors else 'valid'}"
        + (f" -> {args.output}" if args.output else ""),
        file=sys.stderr,
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
