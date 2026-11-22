# calm-arch-discovery

**Architecture-as-code from the repository you already have.** `calm-arch-discovery` scans a Git
repository (Kubernetes manifests, docker-compose, `requirements.txt`, `package.json`, CODEOWNERS),
emits a [FINOS CALM](https://calm.finos.org) architecture document, loads it into a graph
(Neo4j via Cypher, Amazon Neptune via Gremlin) and turns the result into **CI gates** that block a
merge: Semgrep (SAST), Trivy (SCA) and a CALM gate that fails when a node has no controls.

```
 repo ──► scanner/repo_scanner.py ──► scanner/calm_builder.py ──► CALM 1.3 JSON ─┬─► graph/neo4j_loader.py     (Cypher MERGE)
 (k8s, compose,   facts, not CALM        nodes · relationships ·                │
  deps, CODEOWNERS)                      controls · schema-validated            ├─► graph/gremlin_exporter.py (Neptune .groovy)
                                                                                │
                                                                                └─► pipeline/calm_validator.py ─► GitHub Actions gate
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt && pip install --no-deps -e .

# 1. discover -> CALM (validated against the CALM 1.3 JSON Schema before it is written)
calm-discover fixtures/sample-repo -o architecture/payments-platform.calm.json

# 2. gate it (exit 1 if any node lacks controls, or the document is not valid CALM)
calm-gate architecture/payments-platform.calm.json

# 3. Neo4j: load + run the queries in graph/sample_queries.cypher
cp .env.example .env                                   # set NEO4J_PASSWORD
docker compose up -d neo4j
calm-load-neo4j architecture/payments-platform.calm.json --report

# 4. Neptune: generate the Gremlin script (no AWS account needed)
calm-export-gremlin architecture/payments-platform.calm.json -o architecture/payments-platform.groovy
```

Scan any repository, including this one:
`calm-discover . --exclude "fixtures/*" --exclude "tests/*" --name calm-arch-discovery`.
Neo4j Browser is at <http://localhost:7474>. Output is deterministic (no timestamps), so the
committed document can be diffed in CI; add `--include-revision` to stamp the Git commit.

## How this maps to the CALM spec

CALM ([spec & docs](https://calm.finos.org), [source](https://github.com/finos/architecture-as-code))
describes an architecture as JSON: **nodes**, **relationships** between them, **controls**, and
**metadata**. This tool targets release **1.3**
([`core.json`](https://calm.finos.org/release/1.3/meta/core.json)); the schemas are vendored in
`schemas/calm/1.3/` so validation works offline.

| CALM concept | What the scanner emits | Evidence |
|---|---|---|
| [Node](https://calm.finos.org/core-concepts/nodes/) `unique-id`, `node-type`, `name`, `description` | `service` (workloads, ingress), `database` (postgres/redis/... images), `webclient` (React/Vue/... without a server framework), `network` (Kubernetes namespace, compose network), `system` (the repository) | `Deployment` / `StatefulSet` / `DaemonSet`, `Ingress`, compose `services`, `package.json` |
| Node [`metadata`](https://calm.finos.org/core-concepts/metadata/) | `owner`, `environment` (`production`, `local`), technology, image, ports, exposure, sources, dependencies, external endpoints | labels, CODEOWNERS (last match wins), namespace labels, `requirements*.txt`, `package.json` |
| [Relationship](https://calm.finos.org/core-concepts/relationships/) `connects` + `protocol` | one per runtime dependency; `metadata` adds `tls`, `application-protocol`, `port`, `confidence`, `evidence` | connection URLs in env vars / ConfigMaps (`postgresql://...?sslmode=require`), Ingress rules, `depends_on`, client libraries |
| Relationship `deployed-in` | namespace / compose network -> its workloads | `metadata.namespace`, `networks:` |
| Relationship `composed-of` | system -> every service and datastore | - |
| [Controls](https://calm.finos.org/core-concepts/controls/) `requirements[].requirement-url` + inline `config` | controls selected by `policy/control-policy.yaml`, each pointing at a JSON Schema in `controls/` | see below |

**Controls are evidence-based, not asserted.** Policy says which controls a kind of node must have
(`auth-required`, `encryption-in-transit`, `encryption-at-rest`, `network-segmentation`,
`container-hardening`, `ownership-governance`). The scanner attaches each one with
`status: verified` plus the file that proves it (a `NetworkPolicy`, `runAsNonRoot`, an encrypted
`storageClassName`, an OIDC issuer variable, mesh injection, CODEOWNERS) or `status: unverified`
when the repository gives no proof. Every `config` is validated against the schema named by its
`requirement-url` (the same thing `calm validate` does), so a control cannot silently drift from
its definition.

Two spec details worth knowing:

* CALM's `protocol` enum has no gRPC. gRPC is modelled as `HTTP`/`HTTPS`/`mTLS` plus
  `application-protocol: gRPC`, and "is it encrypted" is answered by the `tls` flag, which also
  captures what the enum cannot (`sslmode=require` on JDBC, automatic mesh mTLS).
* The release `meta/` files are meta-schemas. The structural check validates a document against
  `core.json` (the shape of a CALM architecture) and adds semantic rules a JSON Schema cannot
  express: unique ids, dangling references, control-id format, control config vs requirement.
  The official `@finos/calm-cli` is run as a second, independent validator in CI.

## Graph model

One extraction (`graph/model.py`) feeds both dialects, so Neo4j and Neptune hold the same graph:
`(:CalmNode:Service {unique_id, name, owner, ...})`, `(:Control {control_id, status})`,
`-[:CONNECTS_TO {protocol, tls, confidence}]->`, `-[:DEPLOYED_IN]->`, `-[:COMPOSED_OF]->`,
`-[:HAS_CONTROL]->`. Everything carries `architecture`, so several documents can share a database.

* **Cypher** (`graph/neo4j_loader.py`): uniqueness constraints, `UNWIND ... MERGE` batches, every
  value bound as a parameter (labels and relationship types come from allow-lists), and a *sync*
  load that prunes what the document no longer contains. Reloading is idempotent.
* **Gremlin** (`graph/gremlin_exporter.py`): one self-contained, idempotent traversal per line
  using Neptune's get-or-create idiom `g.V(id).fold().coalesce(unfold(), addV(...))`,
  application-supplied ids, edges upserted with `inE(label).where(outV().as('s'))`. The generated
  script was executed against an Apache TinkerPop Gremlin Server (not a Neptune cluster) in the
  integration tests; see `docker compose --profile gremlin up -d gremlin`.

### The same questions in both languages

| Question | Cypher (`graph/sample_queries.cypher`) | Gremlin (`graph/sample_queries.groovy`) |
|---|---|---|
| Nodes with no controls (what the CI gate enforces) | `WHERE NOT (n)-[:HAS_CONTROL]->(:Control)` | `.not(__.out('HAS_CONTROL'))` |
| Controls the repository cannot evidence | `(n)-[:HAS_CONTROL]->(c {status:'unverified'})` + `collect()` | `hasLabel('Control').has('status','unverified').group().by(__.in('HAS_CONTROL')...)` |
| Transitive dependencies of a service | `-[:CONNECTS_TO*1..10]->` | `repeat(out('CONNECTS_TO').simplePath()).emit().dedup()` |
| Circular dependency chains | `(a)-[:CONNECTS_TO*1..8]->(a)` anchored on the smallest id | `repeat(...simplePath()).emit().out().where(eq('a')).path().dedup().by(unfold().dedup().order().fold())` |
| Unencrypted relationships | `WHERE NOT r.protocol IN [...] AND NOT r.tls` | `has('tls', false).not(has('protocol', within(...)))` |
| Internet -> datastore paths | `(ingress)-[:CONNECTS_TO*1..6]->(:database)` over simple paths | `repeat(out().simplePath()).emit(hasLabel('Database')).path()` |

Cypher gives relationship-uniqueness for free (cycles terminate); in Gremlin `simplePath()` is the
explicit cycle guard. Run against the fixture, both return the same cycle
(`orders-api -> payments-service -> notification-worker -> orders-api`) and the same six
unencrypted connections.

## Security gate (`.github/workflows/security-gate.yml`)

Security as a pipeline, not a document. Each job fails the build; `security-gate` aggregates them
and is the one check to require in branch protection.

| Job | Tool | Blocks when |
|---|---|---|
| `sast-semgrep` | Semgrep, `p/python` + `p/owasp-top-ten` + `.semgrep/` (project rules: unsafe `yaml.load`, `shell=True`, Cypher built from f-strings) | any finding of severity **ERROR** |
| `sca-trivy` | Trivy on `requirements.txt` (exact pins incl. transitive) | any **HIGH / CRITICAL** CVE |
| `calm-gate` | `calm-gate` + official `calm-cli --strict` | invalid CALM, dangling references, a control config that violates its requirement schema, **any node without controls**, or a committed architecture that no longer matches the repository (drift) |
| `test` | ruff, pytest, Neo4j service | lint / unit / integration failures |
| `gate-self-test` | all of the above, on known-bad input in `tests/negative-controls/` and `tests/data/` | a gate **passes** something it must reject |

The self-test job exists because a scanner that silently scans nothing passes forever. (Semgrep's
default ignore list skips `tests/`; `.semgrepignore` replaces it explicitly.) Actions are pinned to
commit SHAs and kept current by Dependabot. `--fail-on-unverified` promotes "no evidence for this
control" from a warning to a failure when a team is ready to enforce it.

Run the gates locally:

```bash
semgrep scan --config p/python --config p/owasp-top-ten --config .semgrep/ --severity ERROR --error \
  --exclude tests/negative-controls scanner graph pipeline tests
trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 requirements.txt
calm-gate architecture/payments-platform.calm.json
npx @finos/calm-cli@1.74.0 validate -a architecture/payments-platform.calm.json -u calm-url-mapping.json --strict
```

## Tests

```bash
pytest -m "not integration"                  # 100 unit tests, no services needed
docker compose up -d neo4j && docker compose --profile gremlin up -d gremlin
pytest -m integration                        # 21 tests: loader, prune, idempotency, every query on both engines
```

## Layout

```
scanner/        repo_scanner.py (facts) · calm_builder.py (CALM mapping) · calm_schema.py (validation) · models.py
graph/          model.py · neo4j_loader.py · gremlin_exporter.py · sample_queries.cypher / .groovy · gremlin-server/
pipeline/       calm_validator.py (CI gate)
controls/       one JSON Schema per control requirement (requirement-url targets)
policy/         control-policy.yaml (which node kinds need which controls)
schemas/calm/   vendored CALM 1.3 meta-schemas (Apache-2.0, FINOS)
architecture/   committed output for the fixture repository: CALM JSON + Neptune script
fixtures/       sample-repo: Kubernetes manifests, docker-compose, dependency manifests
tests/          unit tests, integration tests, negative controls
```

## Limits

* Discovery is static analysis of what is committed: no cluster access, no Helm rendering
  (templated files are skipped with a warning), no service-mesh policy resolution beyond
  injection annotations. Relationships inferred only from a client library are marked
  `confidence: inferred`.
* `verified` means "evidenced in the repository", not "proven in production".
* The Neptune script is verified on TinkerPop, which shares the Gremlin semantics but not
  Neptune's engine. For bulk loads of large graphs, use Neptune's CSV bulk loader instead.

CALM and its schemas are a [FINOS](https://www.finos.org) project under the Apache-2.0 licence.
