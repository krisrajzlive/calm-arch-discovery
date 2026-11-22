"""Extract a labelled property graph from a CALM document.

Both loaders consume this model, so the Neo4j graph and the Neptune graph always have the
same shape:

====================================  ================================================
CALM                                  property graph
====================================  ================================================
node (``node-type: service``)         ``(:CalmNode:Service {unique_id, name, owner ...})``
node ``controls``                     ``(:Control)`` linked with ``[:HAS_CONTROL]``
``connects`` relationship             ``(a)-[:CONNECTS_TO {protocol, tls ...}]->(b)``
``deployed-in`` relationship          ``(member)-[:DEPLOYED_IN]->(container)``
``composed-of`` relationship          ``(container)-[:COMPOSED_OF]->(member)``
``interacts`` relationship            ``(actor)-[:INTERACTS_WITH]->(node)``
====================================  ================================================

Every vertex and edge carries ``architecture`` (the document's ``metadata.name``) so several
architectures can live in one database, and ``uid`` = ``<architecture>/<unique-id>``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# CALM node-type -> vertex label. Labels are interpolated into statements (they cannot be bound
# as parameters), so they come from this fixed allow-list and never from document content.
NODE_LABELS: dict[str, str] = {
    "system": "System",
    "service": "Service",
    "database": "Database",
    "webclient": "WebClient",
    "network": "Network",
    "actor": "Actor",
    "ecosystem": "Ecosystem",
    "ldap": "Ldap",
    "data-asset": "DataAsset",
}
DEFAULT_LABEL = "Component"
EDGE_TYPES = ("CONNECTS_TO", "DEPLOYED_IN", "COMPOSED_OF", "INTERACTS_WITH", "HAS_CONTROL")
_SAFE_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

Props = dict[str, Any]


def safe_identifier(value: str) -> str:
    """Defence in depth: refuse anything that is not a plain label / relationship name."""
    if not _SAFE_IDENT.match(value):
        raise ValueError(f"unsafe graph identifier: {value!r}")
    return value


@dataclass
class Vertex:
    uid: str
    label: str
    props: Props


@dataclass
class Edge:
    uid: str
    type: str
    source: str
    target: str
    props: Props = field(default_factory=dict)


@dataclass
class GraphModel:
    architecture: str
    vertices: list[Vertex] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)


def _scalar(value: Any) -> Any:
    """Property values must be primitives or flat lists of primitives."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
        return value
    return json.dumps(value, sort_keys=True)


def _prune(props: Props) -> Props:
    return {k: _scalar(v) for k, v in props.items() if v is not None}


def from_calm(doc: dict[str, Any]) -> GraphModel:
    arch = str((doc.get("metadata") or {}).get("name") or "default")
    model = GraphModel(architecture=arch)

    def uid(unique_id: str) -> str:
        return f"{arch}/{unique_id}"

    for node in doc.get("nodes", []):
        meta = node.get("metadata") or {}
        props = _prune(
            {
                "unique_id": node["unique-id"],
                "name": node["name"],
                "node_type": node["node-type"],
                "description": node.get("description"),
                "architecture": arch,
                "owner": meta.get("owner"),
                "environment": meta.get("environment"),
                "technology": meta.get("technology"),
                "image": meta.get("image"),
                "exposure": meta.get("exposure"),
                "role": meta.get("role"),
                "namespace": meta.get("namespace"),
                "ports": meta.get("ports"),
                "sources": meta.get("sources"),
            }
        )
        label = NODE_LABELS.get(node["node-type"], DEFAULT_LABEL)
        model.vertices.append(Vertex(uid(node["unique-id"]), label, props))

        for control_id, control in sorted((node.get("controls") or {}).items()):
            req = (control.get("requirements") or [{}])[0]
            config = req.get("config") or {}
            control_uid = uid(f"{node['unique-id']}/{control_id}")
            model.vertices.append(
                Vertex(
                    control_uid,
                    "Control",
                    _prune(
                        {
                            "control_id": control_id,
                            "description": control.get("description"),
                            "status": config.get("status"),
                            "requirement_url": req.get("requirement-url"),
                            "evidence": config.get("evidence"),
                            "config_json": json.dumps(config, sort_keys=True),
                            "architecture": arch,
                            "node_id": node["unique-id"],
                        }
                    ),
                )
            )
            model.edges.append(
                Edge(
                    f"{control_uid}#has",
                    "HAS_CONTROL",
                    uid(node["unique-id"]),
                    control_uid,
                    {"architecture": arch},
                )
            )

    for rel in doc.get("relationships", []):
        rtype = rel["relationship-type"]
        rid = rel["unique-id"]
        meta = rel.get("metadata") or {}
        if "connects" in rtype:
            c = rtype["connects"]
            model.edges.append(
                Edge(
                    uid(rid),
                    "CONNECTS_TO",
                    uid(c["source"]["node"]),
                    uid(c["destination"]["node"]),
                    _prune(
                        {
                            "unique_id": rid,
                            "architecture": arch,
                            "protocol": rel.get("protocol"),
                            "tls": bool(meta.get("tls", False)),
                            "application_protocol": meta.get("application-protocol"),
                            "port": meta.get("port"),
                            "confidence": meta.get("confidence"),
                            "evidence": meta.get("evidence"),
                        }
                    ),
                )
            )
        elif "deployed-in" in rtype:
            d = rtype["deployed-in"]
            for member in d["nodes"]:
                model.edges.append(
                    Edge(
                        uid(f"{rid}/{member}"),
                        "DEPLOYED_IN",
                        uid(member),
                        uid(d["container"]),
                        {"architecture": arch},
                    )
                )
        elif "composed-of" in rtype:
            d = rtype["composed-of"]
            for member in d["nodes"]:
                model.edges.append(
                    Edge(
                        uid(f"{rid}/{member}"),
                        "COMPOSED_OF",
                        uid(d["container"]),
                        uid(member),
                        {"architecture": arch},
                    )
                )
        elif "interacts" in rtype:
            d = rtype["interacts"]
            for member in d["nodes"]:
                model.edges.append(
                    Edge(
                        uid(f"{rid}/{member}"),
                        "INTERACTS_WITH",
                        uid(d["actor"]),
                        uid(member),
                        {"architecture": arch},
                    )
                )
    return model
