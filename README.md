# calm-arch-discovery

**Architecture-as-code from the repository you already have.** `calm-arch-discovery` scans a Git
repository (Kubernetes manifests, docker-compose, `requirements.txt`, `package.json`, CODEOWNERS),
emits a [FINOS CALM](https://calm.finos.org) architecture document, loads it into a graph
(Neo4j via Cypher, Amazon Neptune via Gremlin) and turns the result into **CI gates** that block a
merge: Semgrep (SAST), Trivy (SCA) and a CALM gate that fails when a node has no controls.

Architects do not write JSON, so the *approved* architecture is a **Markdown document in the same
repository** (see [Architecture as Markdown](#architecture-as-markdown)). The tool compiles it to an
*intended* CALM document, discovers the *actual* one from the code, and a **conformance gate**
fails the build when the code no longer does what the document says.

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
calm-discover fixtures/sample-repo -o architecture/payments-platform.actual.calm.json

# 2. gate it (exit 1 if any node lacks controls, or the document is not valid CALM)
calm-gate architecture/payments-platform.actual.calm.json

# 3. compile the architects' Markdown into the intended CALM, then check the code conforms to it
calm-intent fixtures/sample-repo/docs/architecture/architecture.md -o architecture/payments-platform.intended.calm.json
calm-conformance --actual architecture/payments-platform.actual.calm.json \
                 --intended architecture/payments-platform.intended.calm.json

# 4. Neo4j: load + run the queries in graph/sample_queries.cypher
cp .env.example .env                                   # set NEO4J_PASSWORD
docker compose up -d neo4j
calm-load-neo4j architecture/payments-platform.actual.calm.json --report

# 5. Neptune: generate the Gremlin script (no AWS account needed)
calm-export-gremlin architecture/payments-platform.actual.calm.json -o architecture/payments-platform.groovy
```

Scan any repository, including this one:
`calm-discover . --exclude "fixtures/*" --exclude "tests/*" --name calm-arch-discovery`.
Neo4j Browser is at <http://localhost:7474>. Output is deterministic (no timestamps), so the
committed document can be diffed in CI; add `--include-revision` to stamp the Git commit.

## Architecture as Markdown

The approved architecture lives beside the code, in a Markdown file that is reviewed like any other
pull request (CODEOWNERS makes the architecture group the required approver of `docs/architecture/`).
Prose, diagrams and rationale are free-form; the tool reads only four tables and the front matter.
Full format, rules and waiver workflow: [`docs/architecture-authoring.md`](docs/architecture-authoring.md).

```markdown
---
system: payments-platform
environment: production
---
## Components
| id | type | owner | description |
|---|---|---|---|
| orders-api | service | orders-squad | Order lifecycle |
| orders-db | database | data-platform | System of record |

## Connections
| from | to | protocol | encrypted | purpose |
|---|---|---|---|---|
| orders-api | orders-db | JDBC | required | Persist orders |

## Controls
| component | control |
|---|---|
| orders-api | auth-required |
| orders-db | encryption-at-rest |

## Waivers
| rule | subject | reason | owner | expires |
|---|---|---|---|---|
| control-not-evidenced | orders-db/encryption-at-rest | Storage class rollout, PLAT-9 | @org/data-platform | 2026-12-31 |
```

```
 architecture.md ──► calm-intent ──► intended CALM ──┐
 (architects, PR-reviewed)                           ├─► calm-conformance ──► pass / fail the merge
 code ──► calm-discover ──► actual CALM ─────────────┘
```

| Rule | Severity | Fires when |
|---|---|---|
| `undeclared-component` | error | the code has a workload the document does not list |
| `undeclared-connection` | error | the code connects two declared components with no approved connection |
| `encryption-violation` | error | the document requires encryption and the code connects without TLS |
| `control-not-evidenced` | error | a control the document requires has no `verified` evidence in the repository |
| `missing-component`, `missing-connection`, `protocol-mismatch`, `owner-mismatch`, `waiver-unused` | warning | the document and the code disagree in a way a human should look at |

* **Errors are the contract, warnings are hygiene.** A *waiver* (rule + subject + reason + owner +
  expiry date) downgrades one error to a visible, owned exception. When it expires the gate fails
  again, so debt cannot hide. The fixture's waivers are dated 2029 only to keep it green.
* **Scoped by environment.** Only components that run in the document's `environment` are
  compared, so a local-only helper such as `mail-relay` needs no entry.
* **Mistakes are reported with file and line** (`architecture.md:30: type 'ingres' ... Did you mean
  'ingress'?`) and as GitHub annotations, because the people fixing them are not developers.
* The intended document is a normal CALM document (`metadata.kind: intended`) and goes through the
  same schema validation, `calm-gate` and official `calm-cli` checks. In the graph it is loaded as
  architecture `<name>-intended`, so it sits beside the discovered graph and never replaces it.

## Governance: who owns what

Three artifacts, three owners. The **ADR** records *why* a decision was made, the **architecture
document** records *what* was approved, and the **code** is what actually runs. CI compares the
last two on every pull request. The first is linked from the document by reference (the tool does
not parse ADRs yet).

| Artifact | Answers | Lives in | Owner | Changed by | Checked by |
|---|---|---|---|---|---|
| ADR | *Why* did we choose this, and what did we reject? | `docs/adr/NNNN-title.md` (convention; this repo has none yet) | Architecture group | Architect, via PR | Human review only |
| Architecture document | *What* is approved: components, connections, controls, waivers | `docs/architecture/architecture.md` | Architecture group | Architect (or the squad proposing a change), via PR | `calm-intent` (format), CODEOWNERS (approval) |
| Code, manifests, dependencies | *What actually runs* | service folders, `k8s/`, `docker-compose.yml` | The squad named in CODEOWNERS | Squad, via PR | `calm-discover`, Semgrep, Trivy |
| Control policy and requirement schemas | *What "evidenced" means* per control | `policy/`, `controls/` | Security | Security, via PR | `calm-gate`, `calm-cli` |
| Generated CALM + Neptune script | Machine-readable view of both sides | `architecture/*.calm.json`, `*.groovy` | Nobody: regenerated, never hand-edited | `calm-intent` / `calm-discover` | Drift check |
| Gates and workflow | The rules above, as code | `.github/workflows/`, `pipeline/`, `intent/` | Platform / tool maintainers | Platform, via PR | `gate-self-test` negative controls |
| Waiver | A time-boxed, owned exception | `Waivers` table in the architecture document | The waiver's `owner` (a squad) | Squad proposes, architects approve | `calm-conformance` (expiry, unused) |

### Responsibilities (R = does it, A = accountable, C = consulted, I = informed)

| Activity | Architecture group | Delivery squad | Security | Platform / tool maintainers | Repo admin |
|---|---|---|---|---|---|
| Write and supersede ADRs | A / R | C | C | I | |
| Maintain `architecture.md` (components, connections, controls) | A / R | C (proposes changes) | C | I | |
| Implement the change and the evidence for its controls | I | A / R | C | | |
| Raise a waiver (reason, owner, expiry) | C | R | C | | |
| Approve a waiver | A / R | C | C | | |
| Remove a waiver before it expires | A | R | I | | |
| Triage conformance **warnings** | I | A / R | | | |
| Define controls and what counts as evidence | C | I | A / R | C | |
| Change a gate, rule or the workflow | C | I | C | A / R | |
| Configure branch protection and CODEOWNERS | C | I | C | C | A / R |

### Lifecycle: from decision to compliance

```
 1 Decide        2 Record          3 Implement        4 Verify (every PR)        5 Operate         6 Retire
 ADR proposed -> architecture.md -> code, manifests -> Semgrep · Trivy ·       -> waivers expire, -> superseding ADR,
 -> accepted      PR, architects    and control         calm-intent · calm-       warnings triaged   component removed
                  approve           evidence            discover · conformance
```

| # | Stage | What happens | Who | Automated check | Blocks the merge |
|---|---|---|---|---|---|
| 1 | **Decide** | A change is proposed as an ADR (`proposed`), discussed, then `accepted` or rejected. Rejected options stay in the record. | Architecture group, with the squad | none | n/a |
| 2 | **Record** | The architect edits `architecture.md` (new component, connection or control) and links the ADR in the prose or in a row's `purpose` / `reason`. | Architecture group | `calm-intent`: valid tables, known components, protocols and controls, with file and line errors | yes, on a malformed document |
| 3 | **Implement** | The squad changes code, manifests and dependencies, and adds the proof for each required control (`NetworkPolicy`, `runAsNonRoot`, TLS URL, encrypted storage class). | Delivery squad | none at authoring time | n/a |
| 4 | **Verify** | On every PR: SAST, SCA, schema and control checks, drift check, and **conformance** of the code against the document. | CI | `security-gate` (all jobs) | yes |
| 5 | **Operate** | Warnings (`missing-*`, `owner-mismatch`, `waiver-unused`) are triaged by the squad. A waiver reaching its expiry date turns the gate red again. | Squad; architects on waiver renewal | `calm-conformance` | errors yes, warnings no |
| 6 | **Retire** | A superseding ADR is accepted, the component is removed from the document and the code in the same PR. A stale document entry shows as `missing-component`. | Architecture group and squad | `calm-conformance` | warning only |

**Which order is allowed.** Document-first (approve, then build) is the normal path. Code-first
also works, but the same PR must carry the document change, because the gate fails on any
component or connection the document does not approve. That is what routes every architectural
change through the architecture group, whichever side moved first.

### Where enforcement stands today

| Control | Status |
|---|---|
| Document is well-formed; code conforms to it; artifacts are not stale; SAST, SCA, CALM checks | **Automated** in `security-gate` |
| `security-gate` must pass before merge | **Needs a repo setting.** Branch protection on `main` is not configured today, so the check reports but does not block. |
| Architecture group must approve changes to `docs/architecture/` | **Needs a root CODEOWNERS entry** (`/docs/architecture/  @org/architects`) **plus** "require review from Code Owners". Only the fixture has a CODEOWNERS today, and that is test data. |
| ADR content, status and linkage to the document | **Convention.** No ADR is parsed or checked yet. |
| A waiver that expired while nobody opened a PR | Surfaces on the next PR or push. There is no scheduled run yet, so an idle repo stays green. |

Until the two repo settings are in place the gates are advisory; with them, the table above is
enforced rather than agreed.

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
| `calm-gate` | `calm-intent`, `calm-discover`, `calm-gate`, `calm-conformance` + official `calm-cli --strict` on both documents | invalid CALM, dangling references, a control config that violates its requirement schema, **any node without controls**, a committed artifact that no longer matches its source (drift), or **code that does not conform to the architecture document** |
| `test` | ruff, pytest, Neo4j service | lint / unit / integration failures |
| `gate-self-test` | all of the above, on known-bad input in `tests/negative-controls/` and `tests/data/` (including a drifted architecture document, expired waivers and a malformed Markdown table) | a gate **passes** something it must reject |

The self-test job exists because a scanner that silently scans nothing passes forever. (Semgrep's
default ignore list skips `tests/`; `.semgrepignore` replaces it explicitly.) Actions are pinned to
commit SHAs and kept current by Dependabot. `--fail-on-unverified` promotes "no evidence for this
control" from a warning to a failure when a team is ready to enforce it.

Run the gates locally:

```bash
semgrep scan --config p/python --config p/owasp-top-ten --config .semgrep/ --severity ERROR --error \
  --exclude tests/negative-controls scanner graph pipeline intent tests
trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 requirements.txt
calm-gate architecture/payments-platform.actual.calm.json architecture/payments-platform.intended.calm.json
calm-conformance --actual architecture/payments-platform.actual.calm.json --intended architecture/payments-platform.intended.calm.json
npx @finos/calm-cli@1.74.0 validate -a architecture/payments-platform.intended.calm.json -u calm-url-mapping.json --strict
```

## Tests

```bash
pytest -m "not integration"                  # 162 unit tests, no services needed
docker compose up -d neo4j && docker compose --profile gremlin up -d gremlin
pytest -m integration                        # 21 tests: loader, prune, idempotency, every query on both engines
```

## Layout

```
scanner/        repo_scanner.py (facts) · calm_builder.py (CALM mapping) · calm_schema.py (validation) · models.py
graph/          model.py · neo4j_loader.py · gremlin_exporter.py · sample_queries.cypher / .groovy · gremlin-server/
intent/         markdown.py (architecture .md -> validated tables) · builder.py (-> intended CALM, calm-intent)
pipeline/       calm_validator.py (calm-gate) · conformance.py (calm-conformance: code vs document)
controls/       one JSON Schema per control requirement (requirement-url targets)
policy/         control-policy.yaml (which node kinds need which controls)
schemas/calm/   vendored CALM 1.3 meta-schemas (Apache-2.0, FINOS)
architecture/   committed output for the fixture repository: actual + intended CALM JSON, Neptune script
docs/           architecture-authoring.md (guide for the people who write the architecture document)
fixtures/       sample-repo: Kubernetes manifests, docker-compose, dependency manifests,
                docs/architecture/architecture.md (the approved architecture)
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
