from __future__ import annotations

import git
import pytest

from scanner.repo_scanner import (
    codeowner_for,
    extract_endpoints,
    list_repo_files,
    parse_codeowners,
    parse_package_json,
    parse_requirements,
    scan_repository,
    tech_from_image,
)

# --------------------------------------------------------------------------- pure parsers


def test_parse_requirements_handles_pins_extras_markers_and_noise():
    deps = parse_requirements(
        """
        # comment
        FastAPI==0.115.6
        psycopg[binary]==3.2.3
        requests>=2.31 ; python_version >= "3.9"
        My_Package.name~=1.4
        bare-name
        -r other.txt
        git+https://example.com/x.git#egg=x
        """
    )
    by_name = {d.name: d.version for d in deps}
    assert by_name == {
        "fastapi": "0.115.6",
        "psycopg": "3.2.3",
        "requests": ">=2.31",
        "my-package-name": "~=1.4",
        "bare-name": None,
    }


def test_parse_package_json_reads_runtime_dependencies_only():
    deps = parse_package_json(
        '{"dependencies": {"react": "^18", "axios": "^1"}, "devDependencies": {"vite": "^5"}}'
    )
    assert [(d.name, d.ecosystem) for d in deps] == [("axios", "npm"), ("react", "npm")]


@pytest.mark.parametrize(
    ("value", "protocol", "tls", "host", "port"),
    [
        ("postgresql://u:p@db:5432/x?sslmode=require", "JDBC", True, "db", 5432),
        ("postgresql://u:p@db:5432/x", "JDBC", False, "db", 5432),
        ("jdbc:postgresql://db:5432/x", "JDBC", False, "db", 5432),
        ("postgresql://u:${PW:-local}@db:5432/x", "JDBC", False, "db", 5432),
        ("https://api.internal/v1", "HTTPS", True, "api.internal", None),
        ("http://orders-api:8080/x", "HTTP", False, "orders-api", 8080),
        ("rediss://cache:6380/0", "TLS", True, "cache", 6380),
        ("redis://cache:6379/0", "TCP", False, "cache", 6379),
        ("amqps://u:p@mq:5671", "AMQP", True, "mq", 5671),
        ("mongodb+srv://u:p@cluster.example.net/db", "TCP", True, "cluster.example.net", None),
    ],
)
def test_extract_endpoints(value, protocol, tls, host, port):
    (ep,) = extract_endpoints(value)
    assert (ep.protocol, ep.tls, ep.host, ep.port) == (protocol, tls, host, port)


def test_extract_endpoints_multi_host_and_unknown_scheme():
    hosts = [e.host for e in extract_endpoints("mongodb://a:27017,b:27017/db")]
    assert hosts == ["a", "b"]
    assert extract_endpoints("foo://bar:1") == []
    assert extract_endpoints("no url here") == []


@pytest.mark.parametrize(
    ("image", "tech"),
    [
        ("postgres:16.4", "postgres"),
        ("bitnami/postgresql:16", "postgres"),
        ("registry.example.com/team/redis@sha256:abc", "redis"),
        ("localhost:5000/mongo", "mongodb"),
        ("mcr.microsoft.com/mssql/server:2022", "sqlserver"),
        ("registry.example.com/payments/orders-api:2.4.1", None),
        (None, None),
    ],
)
def test_tech_from_image(image, tech):
    assert tech_from_image(image) == tech


def test_codeowners_last_match_wins_and_globs():
    rules = parse_codeowners(
        """
        *                      @org/maintainers
        /services/orders-api/  @org/orders
        *.md                   @org/docs
        /k8s/db.yaml           @org/data   # trailing comment
        """
    )
    assert codeowner_for(rules, "services/orders-api/requirements.txt") == (
        "/services/orders-api/",
        "@org/orders",
    )
    assert codeowner_for(rules, "services/other/x.py") == ("*", "@org/maintainers")
    assert codeowner_for(rules, "README.md") == ("*.md", "@org/docs")
    assert codeowner_for(rules, "k8s/db.yaml") == ("/k8s/db.yaml", "@org/data")
    assert codeowner_for([], "anything") is None


# --------------------------------------------------------------------------- the fixture repo


def test_fixture_components(fixture_repo):
    scan = scan_repository(fixture_repo)
    kinds = {name: c.kind for name, c in scan.components.items()}
    assert kinds == {
        "cache": "database",
        "mail-relay": "service",
        "net-backend": "network",
        "notification-worker": "service",
        "ns-payments": "network",
        "orders-api": "service",
        "orders-db": "database",
        "payments-service": "service",
        "public-gateway": "ingress",
        "storefront-web": "webclient",
    }
    assert scan.system_name == "payments-platform"
    assert scan.system_owner == "@payments-platform/maintainers"
    assert scan.warnings == []


def test_fixture_links_and_protocol_evidence(fixture_repo):
    scan = scan_repository(fixture_repo)
    links = {(link.source, link.target): link for link in scan.links}
    assert set(links) == {
        ("notification-worker", "mail-relay"),
        ("notification-worker", "orders-api"),
        ("orders-api", "cache"),
        ("orders-api", "orders-db"),
        ("orders-api", "payments-service"),
        ("payments-service", "notification-worker"),
        ("public-gateway", "orders-api"),
        ("public-gateway", "storefront-web"),
        ("storefront-web", "orders-api"),
    }
    # production (Kubernetes) evidence beats the plaintext local compose URL for the same pair
    db = links[("orders-api", "orders-db")]
    assert (db.protocol, db.tls) == ("JDBC", True)
    # both ends are mesh members: the http URL is upgraded to mTLS
    mesh = links[("orders-api", "payments-service")]
    assert (mesh.protocol, mesh.tls, mesh.application_protocol) == ("mTLS", True, "http")
    assert links[("orders-api", "cache")].tls is False
    assert links[("payments-service", "notification-worker")].protocol == "HTTP"
    assert all(link.confidence == "declared" for link in links.values())


def test_fixture_merges_compose_and_kubernetes_and_attaches_dependencies(fixture_repo):
    scan = scan_repository(fixture_repo)
    api = scan.components["orders-api"]
    assert api.environments == ["production", "local"]
    assert {"docker-compose.yml", "k8s/orders-api.yaml"} <= set(api.sources)
    assert "services/orders-api/requirements.txt" in api.sources
    assert {d.name for d in api.dependencies} >= {"fastapi", "psycopg", "redis"}
    assert api.owner == "@payments-platform/orders-squad"
    assert scan.components["mail-relay"].environments == ["local"]  # compose only
    web = scan.components["storefront-web"]
    assert web.dependencies and web.dependencies[0].ecosystem == "npm"
    assert scan.components["public-gateway"].owner == "platform-edge"  # label beats CODEOWNERS


def test_fixture_external_endpoints_are_recorded_not_modelled(fixture_repo):
    scan = scan_repository(fixture_repo)
    assert "idp.example.com" in scan.components["orders-api"].external_endpoints
    assert "api.psp-gateway.example.net" in scan.components["payments-service"].external_endpoints
    assert "idp.example.com" not in scan.components  # no node for third-party hosts


def test_fixture_security_facts(fixture_repo):
    comps = scan_repository(fixture_repo).components
    api, db, cache = (
        comps["orders-api"].security,
        comps["orders-db"].security,
        comps["cache"].security,
    )
    assert (api.run_as_non_root, api.allow_privilege_escalation) == (True, False)
    assert api.auth_mechanism == "oidc-jwt"
    assert db.auth_mechanism == "password-secret"
    assert db.storage_class == "gp3-encrypted" and db.encryption_at_rest_evidence
    assert db.network_policies and comps["payments-service"].security.network_policies
    assert cache.run_as_non_root is None and not cache.network_policies
    assert comps["public-gateway"].security.tls_termination_evidence


def test_exclude_globs(fixture_repo):
    scan = scan_repository(fixture_repo, excludes=["k8s/*"])
    assert "public-gateway" not in scan.components
    assert all(c.environments in (["local"], []) for c in scan.components.values())


# --------------------------------------------------------------------------- synthetic repos


def test_configmap_env_resolution_and_bare_host_vars(write_repo):
    root = write_repo(
        {
            "k8s/app.yaml": """
                apiVersion: v1
                kind: ConfigMap
                metadata: {name: app-config, namespace: shop}
                data:
                  DB_HOST: shop-db
                  DB_PORT: "5432"
                ---
                apiVersion: apps/v1
                kind: Deployment
                metadata: {name: api, namespace: shop}
                spec:
                  selector: {matchLabels: {app: api}}
                  template:
                    metadata: {labels: {app: api}}
                    spec:
                      containers:
                        - name: api
                          image: example/api:1
                          envFrom:
                            - configMapRef: {name: app-config}
                ---
                apiVersion: apps/v1
                kind: StatefulSet
                metadata: {name: shop-db, namespace: shop}
                spec:
                  selector: {matchLabels: {app: shop-db}}
                  template:
                    metadata: {labels: {app: shop-db}}
                    spec:
                      containers:
                        - {name: pg, image: "postgres:16"}
            """
        }
    )
    scan = scan_repository(root)
    (link,) = scan.links
    assert (link.source, link.target, link.protocol, link.port) == ("api", "shop-db", "JDBC", 5432)


def test_inferred_link_from_client_library_when_target_is_unambiguous(write_repo):
    root = write_repo(
        {
            "docker-compose.yml": """
                services:
                  api: {build: ./api}
                  db: {image: "postgres:16"}
            """,
            "api/requirements.txt": "psycopg2-binary==2.9.9\n",
        }
    )
    scan = scan_repository(root)
    (link,) = scan.links
    assert (link.source, link.target, link.protocol, link.confidence) == (
        "api",
        "db",
        "JDBC",
        "inferred",
    )
    assert "psycopg2-binary" in link.evidence[0]


def test_declared_env_link_replaces_inferred_depends_on(write_repo):
    root = write_repo(
        {
            "docker-compose.yml": """
                services:
                  api:
                    image: example/api
                    depends_on: [cache]
                    environment: {CACHE_URL: "rediss://cache:6380"}
                  cache: {image: "redis:7"}
            """
        }
    )
    (link,) = scan_repository(root).links
    assert (link.confidence, link.protocol, link.tls) == ("declared", "TLS", True)
    assert any("depends_on" in e for e in link.evidence)


def test_unmatched_manifest_with_dockerfile_becomes_a_service(write_repo):
    root = write_repo(
        {
            "tools/worker/Dockerfile": "FROM python:3.12\n",
            "tools/worker/requirements.txt": "httpx==0.27.2\n",
            "requirements.txt": "pyyaml==6.0.3\n",
        }
    )
    scan = scan_repository(root)
    assert "worker" in scan.components
    assert [d.name for d in scan.system_dependencies] == ["pyyaml"]


def test_templated_and_invalid_yaml_are_reported_not_crashed_on(write_repo):
    root = write_repo(
        {
            "chart/deploy.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\nname: {{ .Values.name }}\n"
            ),
            "bad.yaml": "key: [unclosed\n",
            ".github/workflows/ci.yml": "jobs:\n  x:\n    if: ${{ github.ref }}\n",
        }
    )
    scan = scan_repository(root)
    assert any("chart/deploy.yaml" in w and "templated" in w for w in scan.warnings)
    assert any("bad.yaml" in w and "invalid YAML" in w for w in scan.warnings)
    assert not any("ci.yml" in w for w in scan.warnings)  # GitHub expressions are not Helm


def test_cross_namespace_name_collision_gets_distinct_components(write_repo):
    workload = """
        apiVersion: apps/v1
        kind: Deployment
        metadata: {{name: api, namespace: {ns}}}
        spec:
          selector: {{matchLabels: {{app: api}}}}
          template:
            metadata: {{labels: {{app: api}}}}
            spec:
              containers: [{{name: api, image: "example/api:1"}}]
    """
    root = write_repo(
        {
            "a.yaml": workload.format(ns="team-a"),
            "b.yaml": workload.format(ns="team-b"),
        }
    )
    scan = scan_repository(root)
    assert {"api", "team-b-api"} <= set(scan.components)


# --------------------------------------------------------------------------- file discovery


def test_git_discovery_honours_gitignore(tmp_path):
    repo = git.Repo.init(tmp_path)
    (tmp_path / ".gitignore").write_text("secret.yaml\n")
    (tmp_path / "keep.yaml").write_text("a: 1\n")
    (tmp_path / "secret.yaml").write_text("a: 1\n")
    files, revision = list_repo_files(tmp_path)
    assert "keep.yaml" in files and "secret.yaml" not in files
    assert revision is None  # no commits yet
    repo.index.add(["keep.yaml", ".gitignore"])
    repo.index.commit("init")
    assert list_repo_files(tmp_path)[1] == repo.head.commit.hexsha


def test_directory_walk_fallback_skips_vendor_dirs(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text("{}")
    (tmp_path / "a.yaml").write_text("a: 1\n")
    files, revision = list_repo_files(tmp_path)
    assert files == ["a.yaml"] and revision is None
