"""Repository scanner.

Walks a Git repository (or any directory) and discovers:

* Kubernetes workloads, Services, Ingresses, NetworkPolicies, PVCs and ConfigMaps
* docker-compose services, networks and ``depends_on`` edges
* ``requirements*.txt`` / ``package.json`` dependencies, attached to the component that owns
  the directory they live in
* ownership from labels and CODEOWNERS

and returns a :class:`~scanner.models.ScanResult`. Nothing here knows about CALM; see
``calm_builder`` for the mapping.
"""

from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote

import yaml

from scanner.knowledge import (
    AUTH_ENV,
    DATASTORE_TECH,
    ENVIRONMENT_LABELS,
    HOST_ENV,
    IMAGE_TECH,
    NPM_BACKEND,
    NPM_CLIENT_LIBS,
    NPM_FRONTEND,
    OWNER_LABELS,
    PY_CLIENT_LIBS,
    SCHEMES,
    TECH_PROTOCOL,
    TLS_QUERY,
)
from scanner.models import Component, ComponentKind, Dependency, Link, ScanResult

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".terraform",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
MAX_FILE_BYTES = 2_000_000
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
CODEOWNERS_LOCATIONS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")

_VAR = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
_URL = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*)://([^\s\"'<>]+)")
_REQ = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(===|==|~=|!=|>=|<=|>|<)\s*([^\s;,#]+))?"
)
_COMPOSE_NAME = re.compile(r"(docker-)?compose([.-][\w.-]+)?\.ya?ml", re.IGNORECASE)
_REQUIREMENTS_NAME = re.compile(r"requirements([-_.][\w.-]*)?\.txt", re.IGNORECASE)
_NON_RUNTIME = ("dev", "test", "lint", "docs", "ci")


# --------------------------------------------------------------------------- file discovery


def list_repo_files(root: Path, excludes: Sequence[str] = ()) -> tuple[list[str], str | None]:
    """Return (sorted repo-relative posix paths, HEAD revision or None).

    Uses GitPython (tracked + untracked-but-not-ignored files, so ``.gitignore`` is honoured).
    Falls back to a directory walk when ``root`` is not inside a Git repository.
    """
    files, revision = _git_files(root)
    if files is None:
        files = _walk_files(root)
        revision = None
    kept = [f for f in files if not any(fnmatch.fnmatch(f, pat) for pat in excludes)]
    return sorted(kept), revision


def _git_files(root: Path) -> tuple[list[str] | None, str | None]:
    try:
        import git  # GitPython raises ImportError when no git executable is available
    except ImportError:
        return None, None
    try:
        repo = git.Repo(root, search_parent_directories=True)
    except (git.InvalidGitRepositoryError, git.NoSuchPathError):
        return None, None
    top = Path(repo.working_tree_dir).resolve()  # type: ignore[arg-type]
    root = root.resolve()
    raw = repo.git.ls_files("--cached", "--others", "--exclude-standard", "-z", "--", str(root))
    files: list[str] = []
    for rel in raw.split("\0"):
        if not rel:
            continue
        path = top / rel
        if path.is_file() and not set(path.relative_to(root).parts) & SKIP_DIRS:
            files.append(path.relative_to(root).as_posix())
    try:
        revision: str | None = repo.head.commit.hexsha
    except ValueError:  # repository without commits
        revision = None
    return files, revision


def _walk_files(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        out.extend((Path(dirpath, f).relative_to(root)).as_posix() for f in filenames)
    return out


# --------------------------------------------------------------------------- parsing helpers


def parse_requirements(text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-")) or "://" in line:
            continue
        m = _REQ.match(line)
        if not m:
            continue
        name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
        op, ver = m.group(2), m.group(3)
        version = ver if op in ("==", "===") else (f"{op}{ver}" if op else None)
        deps.append(Dependency(name=name, version=version, ecosystem="pypi"))
    return deps


def parse_package_json(text: str) -> list[Dependency]:
    data = json.loads(text)
    deps = data.get("dependencies") or {}
    return [Dependency(name=n, version=str(v), ecosystem="npm") for n, v in sorted(deps.items())]


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int | None
    protocol: str
    tls: bool
    application_protocol: str | None


def extract_endpoints(value: str) -> list[Endpoint]:
    """Find connection URLs in an environment value. ``${VAR}`` placeholders are neutralised."""
    text = _VAR.sub("x", value)
    found: list[Endpoint] = []
    for m in _URL.finditer(text):
        scheme = m.group(1).lower()
        if scheme not in SCHEMES:
            continue
        protocol, tls, app = SCHEMES[scheme]
        authority_and_tail = m.group(2)
        authority = re.split(r"[/?#]", authority_and_tail, maxsplit=1)[0]
        tail = authority_and_tail[len(authority) :]
        query = tail.partition("?")[2].partition("#")[0]
        if not tls and TLS_QUERY.search(unquote(query)):
            tls = True
        for hostport in authority.rsplit("@", 1)[-1].split(","):
            host, _, port = hostport.strip().partition(":")
            if host:
                found.append(
                    Endpoint(
                        host.lower(), int(port) if port.isdigit() else None, protocol, tls, app
                    )
                )
    return found


def tech_from_image(image: str | None) -> str | None:
    if not image:
        return None
    repo = image.rsplit("@", 1)[0].rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
    for segment in reversed(repo.lower().split("/")):
        if segment in IMAGE_TECH:
            return IMAGE_TECH[segment]
    return None


def parse_codeowners(text: str) -> list[tuple[str, str]]:
    rules: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            rules.append((parts[0], parts[1]))
    return rules


def codeowner_for(rules: list[tuple[str, str]], path: str) -> tuple[str, str] | None:
    """Last matching rule wins (GitHub semantics, simplified glob support)."""
    hit: tuple[str, str] | None = None
    for pattern, owner in rules:
        if _codeowners_match(pattern, path):
            hit = (pattern, owner)
    return hit


def _codeowners_match(pattern: str, path: str) -> bool:
    if pattern == "*":
        return True
    anchored = pattern.startswith("/")
    pat = pattern.strip("/")
    if not any(c in pat for c in "*?["):
        wanted = "/" + pat + "/"
        haystack = "/" + path + "/"
        return haystack.startswith(wanted) if anchored else wanted in haystack
    return fnmatch.fnmatch(path, pat) or (
        not anchored and fnmatch.fnmatch(PurePosixPath(path).name, pat)
    )


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _label(labels: dict[str, Any] | None, keys: Iterable[str]) -> str | None:
    for key in keys:
        if labels and labels.get(key):
            return str(labels[key])
    return None


def _all(values: list[bool | None]) -> bool | None:
    if values and all(v is True for v in values):
        return True
    if any(v is False for v in values):
        return False
    return None


# --------------------------------------------------------------------------- resolver


class _Resolver:
    """Maps hostnames used in URLs to component keys (Kubernetes DNS + compose names)."""

    def __init__(self) -> None:
        self._by_ns: dict[tuple[str | None, str], str] = {}
        self._global: dict[str, str] = {}

    def register(self, alias: str, key: str, ns: str | None = None) -> None:
        alias = alias.lower()
        self._by_ns[(ns, alias)] = key
        self._global.setdefault(alias, key)

    def resolve(self, host: str, from_ns: str | None) -> str | None:
        parts = host.lower().rstrip(".").split(".")
        name = parts[0]
        host_ns = (
            parts[1] if len(parts) > 1 and parts[1] not in {"svc", "cluster", "local"} else None
        )
        for ns in (host_ns, from_ns, None):
            hit = self._by_ns.get((ns, name))
            if hit:
                return hit
        return self._global.get(name) if len(parts) == 1 else self._global.get(".".join(parts))


# --------------------------------------------------------------------------- scanner


class RepoScanner:
    def __init__(
        self, root: Path, *, name: str | None = None, excludes: Sequence[str] = ()
    ) -> None:
        self.root = root.resolve()
        self.name_override = name
        self.files, self.revision = list_repo_files(self.root, excludes)
        self.warnings: list[str] = []
        self.components: dict[str, Component] = {}
        self.links: dict[tuple[str, str], Link] = {}
        self.resolver = _Resolver()
        self.namespaces: dict[str, list[str]] = {}
        self.networks: dict[str, list[str]] = {}
        self._pod_labels: dict[str, tuple[str | None, dict[str, str]]] = {}
        self._pending_env: list[tuple[str, str | None, str, list[tuple[str, str, bool]]]] = []
        self._codeowners: list[tuple[str, str]] = []
        self._codeowners_path: str | None = None
        self._part_of: str | None = None

    # ---- public API

    def scan(self) -> ScanResult:
        self._load_codeowners()
        k8s_docs: list[tuple[str, dict[str, Any]]] = []
        compose_docs: list[tuple[str, dict[str, Any]]] = []
        for rel in self.files:
            name = PurePosixPath(rel).name
            if name.lower().endswith((".yaml", ".yml")):
                docs = self._load_yaml(rel)
                if _COMPOSE_NAME.fullmatch(name):
                    compose_docs.extend((rel, d) for d in docs if "services" in d)
                else:
                    k8s_docs.extend(
                        (rel, d)
                        for d in self._flatten(docs)
                        if "apiVersion" in d
                        and "kind" in d
                        and isinstance(d.get("metadata"), dict)
                        and d["metadata"].get("name")
                    )
        self._scan_kubernetes(k8s_docs)
        for rel, doc in compose_docs:
            self._scan_compose(rel, doc)
        self._resolve_env_links()
        self._apply_mesh()
        system_deps = self._attach_dependency_manifests()
        self._infer_links_from_libraries()
        self._classify_frontends()
        self._assign_owners()
        system_name = self.name_override or self._part_of or self.root.name
        owner = next((o for pat, o in reversed(self._codeowners) if pat == "*"), None)
        containers = {f"ns-{ns}": m for ns, m in self.namespaces.items()}
        containers.update(self.networks)
        return ScanResult(
            root=self.root.name,
            system_name=system_name,
            components=dict(sorted(self.components.items())),
            links=sorted(self.links.values(), key=lambda link: (link.source, link.target)),
            containers={k: sorted(set(v)) for k, v in sorted(containers.items())},
            codeowners_path=self._codeowners_path,
            system_owner=owner,
            system_dependencies=system_deps,
            warnings=self.warnings,
            revision=self.revision,
        )

    # ---- loading

    def _read(self, rel: str) -> str | None:
        path = self.root / rel
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                self.warnings.append(f"{rel}: skipped (larger than {MAX_FILE_BYTES} bytes)")
                return None
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            self.warnings.append(f"{rel}: unreadable ({exc.__class__.__name__})")
            return None

    def _load_yaml(self, rel: str) -> list[dict[str, Any]]:
        text = self._read(rel)
        if text is None:
            return []
        if "{{" in text:
            if re.search(r"^(apiVersion|services):", text, re.MULTILINE):
                self.warnings.append(f"{rel}: skipped (templated YAML, render it first)")
            return []
        try:
            return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError:
            self.warnings.append(f"{rel}: skipped (invalid YAML)")
            return []

    @staticmethod
    def _flatten(docs: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for doc in docs:
            if doc.get("kind") == "List":
                yield from (i for i in doc.get("items") or [] if isinstance(i, dict))
            else:
                yield doc

    def _load_codeowners(self) -> None:
        for candidate in CODEOWNERS_LOCATIONS:
            if candidate in self.files:
                text = self._read(candidate)
                if text is not None:
                    self._codeowners = parse_codeowners(text)
                    self._codeowners_path = candidate
                    return

    # ---- component registry

    def _component(
        self, name: str, kind: ComponentKind, ns: str | None
    ) -> tuple[str, Component, bool]:
        key = name
        existing = self.components.get(key)
        if existing and existing.namespace and ns and existing.namespace != ns:
            key = f"{ns}-{name}"
            existing = self.components.get(key)
        if existing:
            return key, existing, False
        comp = Component(name=key, kind=kind, namespace=ns)
        self.components[key] = comp
        return key, comp, True

    def _add_link(
        self,
        source: str,
        target: str,
        ep: Endpoint | None,
        *,
        protocol: str | None = None,
        tls: bool = False,
        port: int | None = None,
        confidence: str = "declared",
        evidence: str,
    ) -> None:
        if source == target:
            return
        existing = self.links.get((source, target))
        if existing and not (existing.confidence == "inferred" and confidence == "declared"):
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)
            return
        prior_evidence = existing.evidence if existing else []
        if ep:
            link = Link(
                source=source,
                target=target,
                protocol=ep.protocol,  # type: ignore[arg-type]
                tls=ep.tls,
                application_protocol=ep.application_protocol,
                port=ep.port,
                confidence=confidence,
                evidence=[evidence],  # type: ignore[arg-type]
            )
        else:
            link = Link(
                source=source,
                target=target,
                protocol=protocol or "TCP",  # type: ignore[arg-type]
                tls=tls,
                port=port,
                confidence=confidence,  # type: ignore[arg-type]
                evidence=[evidence],
            )
        link.evidence.extend(e for e in prior_evidence if e not in link.evidence)
        self.links[(source, target)] = link

    # ---- Kubernetes

    def _scan_kubernetes(self, docs: list[tuple[str, dict[str, Any]]]) -> None:
        by_kind: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for rel, doc in docs:
            by_kind.setdefault(str(doc["kind"]), []).append((rel, doc))

        ns_labels = {
            d["metadata"]["name"]: (d["metadata"].get("labels") or {})
            for _, d in by_kind.get("Namespace", [])
            if isinstance(d.get("metadata"), dict) and "name" in d["metadata"]
        }
        configmaps = {
            (d["metadata"].get("namespace", "default"), d["metadata"]["name"]): d.get("data") or {}
            for _, d in by_kind.get("ConfigMap", [])
        }
        encrypted_classes = {
            d["metadata"]["name"]
            for _, d in by_kind.get("StorageClass", [])
            if str((d.get("parameters") or {}).get("encrypted", "")).lower() == "true"
        }
        pvc_class = {
            (d["metadata"].get("namespace", "default"), d["metadata"]["name"]): (
                d.get("spec") or {}
            ).get("storageClassName")
            for _, d in by_kind.get("PersistentVolumeClaim", [])
        }

        for rel, doc in (item for kind in WORKLOAD_KINDS for item in by_kind.get(kind, [])):
            self._k8s_workload(rel, doc, ns_labels, configmaps, encrypted_classes, pvc_class)

        for _rel, doc in by_kind.get("Service", []):
            self._k8s_service(doc)
        for rel, doc in by_kind.get("NetworkPolicy", []):
            self._k8s_network_policy(rel, doc)
        for rel, doc in by_kind.get("Ingress", []):
            self._k8s_ingress(rel, doc, ns_labels)

        ns_source = {d["metadata"]["name"]: r for r, d in by_kind.get("Namespace", [])}
        for ns in self.namespaces:
            _, comp, _ = self._component(f"ns-{ns}", "network", ns)
            comp.description = f"Kubernetes namespace '{ns}'."
            comp.add_environment(_label(ns_labels.get(ns), ENVIRONMENT_LABELS))
            if ns in ns_source:
                comp.add_source(ns_source[ns])

    @staticmethod
    def _k8s_hardening(spec: dict[str, Any]) -> tuple[bool | None, bool | None, bool | None]:
        pod_sc = spec.get("securityContext") or {}
        nonroot: list[bool | None] = []
        no_escalation: list[bool | None] = []
        read_only: list[bool | None] = []
        for c in spec.get("containers") or []:
            sc = c.get("securityContext") or {}
            nr = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            uid = sc.get("runAsUser", pod_sc.get("runAsUser"))
            if nr is None and isinstance(uid, int):
                nr = uid != 0
            nonroot.append(nr)
            ape = sc.get("allowPrivilegeEscalation")
            no_escalation.append(None if ape is None else not ape)
            ro = sc.get("readOnlyRootFilesystem")
            read_only.append(ro)
        return _all(nonroot), _all(no_escalation), _all(read_only)

    def _k8s_workload(
        self,
        rel: str,
        doc: dict[str, Any],
        ns_labels: dict[str, dict[str, str]],
        configmaps: dict[tuple[str, str], dict[str, Any]],
        encrypted_classes: set[str],
        pvc_class: dict[tuple[str, str], str | None],
    ) -> None:
        meta = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        template = spec.get("template") or {}
        pod_spec = template.get("spec") or {}
        containers = pod_spec.get("containers") or []
        if not meta.get("name") or not containers:
            return
        ns = meta.get("namespace", "default")
        primary = next(
            (c for c in containers if tech_from_image(c.get("image")) in DATASTORE_TECH),
            containers[0],
        )
        tech = tech_from_image(primary.get("image"))
        kind: ComponentKind = "database" if tech in DATASTORE_TECH else "service"
        key, comp, _ = self._component(meta["name"], kind, ns)
        comp.namespace = comp.namespace or ns
        comp.technology = comp.technology or tech
        comp.image = comp.image or primary.get("image")
        comp.add_source(rel)
        labels = {
            **(meta.get("labels") or {}),
            **((template.get("metadata") or {}).get("labels") or {}),
        }
        self._pod_labels[key] = (ns, labels)
        self._part_of = self._part_of or labels.get("app.kubernetes.io/part-of")
        comp.add_environment(
            _label(meta.get("labels"), ENVIRONMENT_LABELS)
            or _label(ns_labels.get(ns), ENVIRONMENT_LABELS)
        )
        comp.owner = comp.owner or _label(meta.get("labels"), OWNER_LABELS)
        for c in containers:
            for port in c.get("ports") or []:
                p = port.get("containerPort")
                if isinstance(p, int) and p not in comp.ports:
                    comp.ports.append(p)
        self.namespaces.setdefault(ns, []).append(key)
        self.resolver.register(meta["name"], key, ns)

        # hardening
        nonroot, no_escalation, read_only = self._k8s_hardening(pod_spec)
        sec = comp.security
        sec.run_as_non_root = nonroot
        sec.allow_privilege_escalation = None if no_escalation is None else not no_escalation
        sec.read_only_root_filesystem = read_only
        if nonroot is not None or no_escalation is not None:
            sec.hardening_evidence.append(
                f"{rel}: runAsNonRoot={nonroot}, allowPrivilegeEscalation="
                f"{sec.allow_privilege_escalation}"
            )

        # service mesh (mTLS between meshed workloads)
        annotations = (template.get("metadata") or {}).get("annotations") or {}
        if (
            annotations.get("linkerd.io/inject") == "enabled"
            or str(annotations.get("sidecar.istio.io/inject", "")).lower() == "true"
        ):
            sec.mesh_mtls = True
            sec.mesh_evidence.append(f"{rel}: service-mesh sidecar injection annotation")

        # encryption at rest
        claims: list[str | None] = [
            (t.get("spec") or {}).get("storageClassName")
            for t in spec.get("volumeClaimTemplates") or []
        ]
        for vol in pod_spec.get("volumes") or []:
            claim = (vol.get("persistentVolumeClaim") or {}).get("claimName")
            if claim:
                claims.append(pvc_class.get((ns, claim)))
        for sc_name in filter(None, claims):
            sec.storage_class = sec.storage_class or sc_name
            if sc_name in encrypted_classes or "encrypt" in sc_name.lower():
                sec.encryption_at_rest_evidence.append(f"{rel}: storageClassName={sc_name}")

        # authentication evidence
        env_pairs = list(self._k8s_env(primary, ns, configmaps))
        for c in containers:
            if c is not primary:
                env_pairs.extend(self._k8s_env(c, ns, configmaps))
        self._record_auth(comp, rel, env_pairs)
        self._pending_env.append((key, ns, rel, env_pairs))

    @staticmethod
    def _k8s_env(
        container: dict[str, Any], ns: str, configmaps: dict[tuple[str, str], dict[str, Any]]
    ) -> Iterator[tuple[str, str, bool]]:
        """Yield (name, value, from_secret) for every env var of a container."""
        for item in container.get("env") or []:
            name = item.get("name")
            if not name:
                continue
            if "value" in item:
                yield name, str(item["value"]), False
                continue
            ref = item.get("valueFrom") or {}
            if "secretKeyRef" in ref:
                yield name, "", True
            elif "configMapKeyRef" in ref:
                data = configmaps.get((ns, ref["configMapKeyRef"].get("name", "")), {})
                value = data.get(ref["configMapKeyRef"].get("key", ""))
                if value is not None:
                    yield name, str(value), False
        for source in container.get("envFrom") or []:
            cm = (source.get("configMapRef") or {}).get("name")
            for k, v in configmaps.get((ns, cm or ""), {}).items():
                yield k, str(v), False

    def _record_auth(
        self, comp: Component, rel: str, env_pairs: list[tuple[str, str, bool]]
    ) -> None:
        sec = comp.security
        for name, value, from_secret in env_pairs:
            if AUTH_ENV.search(name) and (value or from_secret):
                sec.auth_mechanism = "oidc-jwt"
                sec.auth_evidence.append(f"{rel}: env {name}")
            elif (
                comp.kind == "database"
                and from_secret
                and "PASSWORD" in name.upper()
                and sec.auth_mechanism is None
            ):
                sec.auth_mechanism = "password-secret"
                sec.auth_evidence.append(f"{rel}: env {name} from secretKeyRef")

    def _k8s_service(self, doc: dict[str, Any]) -> None:
        meta = doc.get("metadata") or {}
        selector = (doc.get("spec") or {}).get("selector") or {}
        ns = meta.get("namespace", "default")
        if not meta.get("name") or not selector:
            return
        for key, (comp_ns, labels) in self._pod_labels.items():
            if comp_ns == ns and all(labels.get(k) == v for k, v in selector.items()):
                self.resolver.register(meta["name"], key, ns)
                for port in (doc.get("spec") or {}).get("ports") or []:
                    p = port.get("port")
                    if isinstance(p, int) and p not in self.components[key].ports:
                        self.components[key].ports.append(p)

    def _k8s_network_policy(self, rel: str, doc: dict[str, Any]) -> None:
        meta = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        ns = meta.get("namespace", "default")
        match = (spec.get("podSelector") or {}).get("matchLabels") or {}
        name = meta.get("name", "unnamed")
        denies_all = (
            not match and "Ingress" in (spec.get("policyTypes") or []) and not spec.get("ingress")
        )
        for key, (comp_ns, labels) in self._pod_labels.items():
            if comp_ns != ns:
                continue
            if all(labels.get(k) == v for k, v in match.items()):
                sec = self.components[key].security
                sec.network_policies.append(f"{rel}: NetworkPolicy {name}")
        if denies_all:
            net = self.components.get(f"ns-{ns}")
            if net is None:
                _, net, _ = self._component(f"ns-{ns}", "network", ns)
            net.security.default_deny = True
            net.security.network_policies.append(f"{rel}: NetworkPolicy {name} (default deny)")

    def _k8s_ingress(
        self, rel: str, doc: dict[str, Any], ns_labels: dict[str, dict[str, str]]
    ) -> None:
        meta = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        ns = meta.get("namespace", "default")
        key, comp, _ = self._component(meta.get("name", "ingress"), "ingress", ns)
        comp.technology = comp.technology or "kubernetes-ingress"
        comp.exposure = "public"
        comp.add_source(rel)
        comp.add_environment(
            _label(meta.get("labels"), ENVIRONMENT_LABELS)
            or _label(ns_labels.get(ns), ENVIRONMENT_LABELS)
        )
        comp.owner = comp.owner or _label(meta.get("labels"), OWNER_LABELS)
        self._part_of = self._part_of or (meta.get("labels") or {}).get("app.kubernetes.io/part-of")
        self.namespaces.setdefault(ns, []).append(key)
        tls_hosts = [h for t in spec.get("tls") or [] for h in t.get("hosts") or []]
        for t in spec.get("tls") or []:
            comp.security.tls_termination_evidence.append(
                f"{rel}: tls secret {t.get('secretName', '(none)')}"
            )
        annotations = meta.get("annotations") or {}
        backend_https = (
            str(annotations.get("nginx.ingress.kubernetes.io/backend-protocol", "")).upper()
            == "HTTPS"
        )
        for rule in spec.get("rules") or []:
            for path in ((rule.get("http") or {}).get("paths")) or []:
                svc = ((path.get("backend") or {}).get("service") or {}).get("name")
                target = self.resolver.resolve(svc, ns) if svc else None
                if not target:
                    continue
                self.components[target].exposure = "public"
                host = rule.get("host")
                evidence = f"{rel}: ingress rule {host or '*'}{path.get('path', '/')} -> {svc}"
                self._add_link(
                    key,
                    target,
                    None,
                    protocol="HTTPS" if backend_https else "HTTP",
                    tls=backend_https,
                    evidence=evidence,
                )
        if not tls_hosts and spec.get("rules"):
            comp.description = "Public Kubernetes ingress without TLS configuration."

    # ---- docker-compose

    def _scan_compose(self, rel: str, doc: dict[str, Any]) -> None:
        base = PurePosixPath(rel).parent
        services = doc.get("services") or {}
        compose_networks: dict[str, list[str]] = {}
        pending: list[tuple[str, str, list[tuple[str, str, bool]], list[str]]] = []
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            image = svc.get("image")
            tech = tech_from_image(image)
            kind: ComponentKind = "database" if tech in DATASTORE_TECH else "service"
            key, comp, _ = self._component(str(name), kind, None)
            comp.technology = comp.technology or tech
            comp.image = comp.image or image
            comp.add_source(rel)
            comp.add_environment("local")
            for alias in (str(name), svc.get("container_name"), svc.get("hostname")):
                if alias:
                    self.resolver.register(str(alias), key)
            build = svc.get("build")
            context = build if isinstance(build, str) else (build or {}).get("context")
            if context:
                directory = posixpath.normpath(str(base / context))
                if directory not in comp.directories:
                    comp.directories.append(directory)
            for port in svc.get("ports") or []:
                p = self._compose_container_port(port)
                if p and p not in comp.ports:
                    comp.ports.append(p)
            labels = svc.get("labels")
            if isinstance(labels, list):
                labels = dict(str(x).split("=", 1) for x in labels if "=" in str(x))
            comp.owner = comp.owner or _label(labels, OWNER_LABELS)

            env_pairs = list(self._compose_env(svc.get("environment")))
            self._compose_hardening(comp, rel, svc)
            self._record_auth(comp, rel, env_pairs)
            nets = svc.get("networks") or []
            for net in nets if isinstance(nets, list) else list(nets):
                compose_networks.setdefault(str(net), []).append(key)
            depends = svc.get("depends_on") or []
            pending.append(
                (
                    key,
                    rel,
                    env_pairs,
                    [str(d) for d in (depends if isinstance(depends, list) else depends.keys())],
                )
            )

        for net, members in compose_networks.items():
            nkey, ncomp, _ = self._component(f"net-{net}", "network", None)
            ncomp.description = f"docker-compose network '{net}'."
            ncomp.add_source(rel)
            ncomp.add_environment("local")
            self.networks.setdefault(nkey, [])
            self.networks[nkey] = sorted(set(self.networks[nkey]) | set(members))

        for key, rel_path, env_pairs, depends in pending:
            self._pending_env.append((key, None, rel_path, env_pairs))
            for dep in depends:
                target = self.resolver.resolve(dep, None)
                if target and target != key:
                    tech = self.components[target].technology
                    self._add_link(
                        key,
                        target,
                        None,
                        protocol=TECH_PROTOCOL.get(tech or "", "TCP"),
                        confidence="inferred",
                        evidence=f"{rel_path}: depends_on {dep}",
                    )

    @staticmethod
    def _compose_container_port(port: Any) -> int | None:
        if isinstance(port, int):
            return port
        if isinstance(port, dict):
            target = port.get("target")
            return int(target) if isinstance(target, int) else None
        tail = str(port).split(":")[-1].split("/")[0]
        return int(tail) if tail.isdigit() else None

    @staticmethod
    def _compose_env(env: Any) -> Iterator[tuple[str, str, bool]]:
        if isinstance(env, dict):
            for k, v in env.items():
                yield str(k), "" if v is None else str(v), False
        elif isinstance(env, list):
            for item in env:
                k, _, v = str(item).partition("=")
                yield k, v, False

    @staticmethod
    def _compose_hardening(comp: Component, rel: str, svc: dict[str, Any]) -> None:
        sec = comp.security
        if sec.run_as_non_root is not None or sec.hardening_evidence:
            return  # Kubernetes (production) evidence wins over local compose settings
        user = str(svc.get("user", "")).split(":")[0]
        if user:
            sec.run_as_non_root = user not in ("root", "0")
        opts = [str(o) for o in svc.get("security_opt") or []]
        if "no-new-privileges:true" in opts or "no-new-privileges=true" in opts:
            sec.allow_privilege_escalation = False
        if svc.get("read_only") is True:
            sec.read_only_root_filesystem = True
        if sec.run_as_non_root is not None or sec.allow_privilege_escalation is not None:
            sec.hardening_evidence.append(f"{rel}: user={user or '-'}, security_opt={opts or '-'}")

    # ---- env -> links

    def _resolve_env_links(self) -> None:
        for source, ns, rel, env_pairs in self._pending_env:
            values = {n: v for n, v, _ in env_pairs}
            for name, value, _ in env_pairs:
                if not value:
                    continue
                endpoints = extract_endpoints(value)
                for ep in endpoints:
                    target = self.resolver.resolve(ep.host, ns)
                    if target:
                        self._add_link(source, target, ep, evidence=f"{rel}: env {name}")
                    elif "." in ep.host and not ep.host.replace(".", "").isdigit():
                        ext = self.components[source].external_endpoints
                        if ep.host not in ext:
                            ext.append(ep.host)
                if not endpoints and HOST_ENV.search(name):
                    host, _, port_s = value.partition(":")
                    target = self.resolver.resolve(host, ns)
                    if target and re.fullmatch(r"[A-Za-z0-9_.-]+", host):
                        prefix = HOST_ENV.sub("", name)
                        port_value = port_s or values.get(
                            f"{prefix}_PORT" if prefix else "PORT", ""
                        )
                        tech = self.components[target].technology
                        self._add_link(
                            source,
                            target,
                            None,
                            protocol=TECH_PROTOCOL.get(tech or "", "TCP"),
                            port=int(port_value) if port_value.isdigit() else None,
                            evidence=f"{rel}: env {name}",
                        )

    def _apply_mesh(self) -> None:
        for link in self.links.values():
            src, dst = self.components[link.source], self.components[link.target]
            if (
                src.security.mesh_mtls
                and dst.security.mesh_mtls
                and link.protocol in ("HTTP", "TCP", "HTTPS")
            ):
                link.application_protocol = link.application_protocol or link.protocol.lower()
                link.protocol = "mTLS"
                link.tls = True
                link.evidence.append("both endpoints are service-mesh members (automatic mTLS)")

    # ---- dependency manifests

    def _attach_dependency_manifests(self) -> list[Dependency]:
        system: list[Dependency] = []
        for rel in self.files:
            path = PurePosixPath(rel)
            if _REQUIREMENTS_NAME.fullmatch(path.name) and not any(
                t in path.name.lower() for t in _NON_RUNTIME
            ):
                text = self._read(rel)
                deps = parse_requirements(text) if text is not None else []
            elif path.name == "package.json":
                text = self._read(rel)
                try:
                    deps = parse_package_json(text) if text is not None else []
                except (json.JSONDecodeError, AttributeError):
                    self.warnings.append(f"{rel}: skipped (invalid package.json)")
                    continue
            else:
                continue
            owner = self._component_for_directory(path.parent.as_posix())
            if owner is None and (self.root / path.parent / "Dockerfile").exists():
                kind: ComponentKind = "service"
                _, owner, _ = self._component(path.parent.name or self.root.name, kind, None)
                owner.description = f"Service discovered from {rel}."
            if owner is None:
                system.extend(d for d in deps if d not in system)
                continue
            owner.add_source(rel)
            if path.parent.as_posix() not in owner.directories:
                owner.directories.append(path.parent.as_posix())
            owner.dependencies.extend(d for d in deps if d not in owner.dependencies)
        return system

    def _component_for_directory(self, directory: str) -> Component | None:
        for comp in self.components.values():
            if directory in comp.directories:
                return comp
        base = PurePosixPath(directory).name
        for comp in self.components.values():
            if comp.kind in ("service", "webclient", "database") and _slug(comp.name) == _slug(
                base
            ):
                return comp
        return None

    def _infer_links_from_libraries(self) -> None:
        by_tech: dict[str, list[str]] = {}
        for key, comp in self.components.items():
            if comp.technology and comp.kind in ("database", "service"):
                by_tech.setdefault(comp.technology, []).append(key)
        for key, comp in self.components.items():
            wanted: dict[str, str] = {}
            for dep in comp.dependencies:
                libs = PY_CLIENT_LIBS if dep.ecosystem == "pypi" else NPM_CLIENT_LIBS
                if dep.name in libs:
                    wanted.setdefault(libs[dep.name], dep.name)
            for tech, lib in wanted.items():
                targets = [t for t in by_tech.get(tech, []) if t != key]
                declared = any(
                    self.components[t].technology == tech for (s, t) in self.links if s == key
                )
                if len(targets) == 1 and not declared:
                    self._add_link(
                        key,
                        targets[0],
                        None,
                        protocol=TECH_PROTOCOL.get(tech, "TCP"),
                        confidence="inferred",
                        evidence=f"dependency manifest: client library '{lib}' for {tech}",
                    )

    def _classify_frontends(self) -> None:
        for comp in self.components.values():
            if comp.kind != "service":
                continue
            npm = {d.name for d in comp.dependencies if d.ecosystem == "npm"}
            if npm & NPM_FRONTEND and not npm & NPM_BACKEND:
                comp.kind = "webclient"

    # ---- ownership

    def _assign_owners(self) -> None:
        for comp in self.components.values():
            if comp.owner:
                continue
            candidates = [*comp.directories, *comp.sources]
            best: tuple[str, str] | None = None
            for candidate in candidates:
                hit = codeowner_for(self._codeowners, candidate)
                if hit and hit[0] != "*":
                    best = hit
                    break
                best = best or hit
            if best:
                comp.owner = best[1]


def scan_repository(
    root: Path | str, *, name: str | None = None, excludes: Sequence[str] = ()
) -> ScanResult:
    """Scan ``root`` and return the discovered components and links."""
    return RepoScanner(Path(root), name=name, excludes=excludes).scan()
