"""Typed intermediate model produced by the repository scanner.

The scanner records *facts* found in the repository; ``calm_builder`` turns those facts
into CALM nodes, relationships and controls. Keeping the two apart means the CALM mapping
can change without re-parsing the repository.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ComponentKind = Literal["service", "ingress", "database", "webclient", "network", "system"]
Confidence = Literal["declared", "inferred"]
# Values of the CALM 1.x `protocol` enum (calm.finos.org/release/1.3/meta/core.json).
CalmProtocol = Literal[
    "HTTP",
    "HTTPS",
    "FTP",
    "SFTP",
    "JDBC",
    "WebSocket",
    "SocketIO",
    "LDAP",
    "AMQP",
    "TLS",
    "mTLS",
    "TCP",
]


class Dependency(BaseModel):
    name: str
    version: str | None = None
    ecosystem: Literal["pypi", "npm"]


class SecurityFacts(BaseModel):
    """Security-relevant facts evidenced in the repository for one component."""

    run_as_non_root: bool | None = None
    allow_privilege_escalation: bool | None = None
    read_only_root_filesystem: bool | None = None
    hardening_evidence: list[str] = Field(default_factory=list)
    auth_mechanism: str | None = None
    auth_evidence: list[str] = Field(default_factory=list)
    storage_class: str | None = None
    encryption_at_rest_evidence: list[str] = Field(default_factory=list)
    network_policies: list[str] = Field(default_factory=list)
    default_deny: bool = False
    mesh_mtls: bool = False
    mesh_evidence: list[str] = Field(default_factory=list)
    # ingress only: TLS terminated for inbound internet traffic
    tls_termination_evidence: list[str] = Field(default_factory=list)


class Component(BaseModel):
    name: str
    kind: ComponentKind
    description: str = ""
    technology: str | None = None
    image: str | None = None
    ports: list[int] = Field(default_factory=list)
    owner: str | None = None
    environments: list[str] = Field(default_factory=list)
    namespace: str | None = None
    exposure: Literal["public", "internal"] = "internal"
    external_endpoints: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    # directories that hold this component's own source / dependency manifests
    directories: list[str] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    security: SecurityFacts = Field(default_factory=SecurityFacts)

    def add_source(self, path: str) -> None:
        if path not in self.sources:
            self.sources.append(path)

    def add_environment(self, env: str | None) -> None:
        if env and env not in self.environments:
            self.environments.append(env)


class Link(BaseModel):
    """A directed runtime dependency: ``source`` calls ``target``."""

    source: str
    target: str
    protocol: CalmProtocol
    tls: bool = False
    application_protocol: str | None = None
    port: int | None = None
    confidence: Confidence = "declared"
    evidence: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    root: str
    system_name: str
    components: dict[str, Component] = Field(default_factory=dict)
    links: list[Link] = Field(default_factory=list)
    # network component key (Kubernetes namespace / compose network) -> member component keys
    containers: dict[str, list[str]] = Field(default_factory=dict)
    codeowners_path: str | None = None
    system_owner: str | None = None
    system_dependencies: list[Dependency] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    revision: str | None = None
