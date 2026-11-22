# Writing the architecture document

For architects and reviewers. You do not need to know CALM, JSON or Python.

The approved architecture is one Markdown file in the repository, for example
[`fixtures/sample-repo/docs/architecture/architecture.md`](../fixtures/sample-repo/docs/architecture/architecture.md).
CI compiles it, compares it with what the code actually does, and fails the pull request when the
two disagree. Changing the architecture is therefore a pull request that changes this file, and
CODEOWNERS makes the architecture group its required approver.

## What the tool reads

Everything in the file is yours (prose, diagrams, decision records, links) except:

1. the **front matter** at the very top, and
2. the pipe tables under four `##` headings: **Components**, **Connections**, **Controls**,
   **Waivers**. Tables under any other heading, and anything inside a code fence, are ignored.

````markdown
---
system: payments-platform        # required: the system's name
environment: production          # optional, default production
owner: "@org/architects"         # optional
---
````

## The four tables

Every table needs a header row and a separator row (`|---|---|`). Extra columns are ignored.
Cell text can use backticks, bold and links; write a literal pipe as `\|`.

### Components

| column | meaning |
|---|---|
| `id` | lowercase kebab-case, unique: it is the component's name everywhere |
| `type` | `service`, `ingress`, `database`, `webclient` or `network` |
| `owner` | the accountable team; `orders-squad` and `@org/orders-squad` are treated as the same |
| `description` | one line |
| `environment` | *optional.* Defaults to the front matter's environment |

### Connections

| column | meaning |
|---|---|
| `from`, `to` | declared component ids |
| `protocol` | `HTTP`, `HTTPS`, `FTP`, `SFTP`, `JDBC`, `WebSocket`, `SocketIO`, `LDAP`, `AMQP`, `TLS`, `mTLS`, `TCP` (the CALM protocol list; gRPC is written as `HTTPS` or `mTLS`) |
| `encrypted` | `required` or `not-required` |
| `purpose` | *optional.* Why the connection exists |

### Controls

One row per `component` / `control` pair. Every component needs at least one. Controls available
today: `auth-required`, `encryption-in-transit`, `encryption-at-rest`, `network-segmentation`,
`container-hardening`, `ownership-governance` (defined in `policy/control-policy.yaml`).
Listing a control means: **the repository must contain evidence of it** (a `NetworkPolicy`, a
non-root `securityContext`, an encrypted storage class, TLS on the connection, and so on).

### Waivers

A waiver is a time-boxed, owned exception to one finding.

| column | meaning |
|---|---|
| `rule` | the rule being waived (table below) |
| `subject` | what it applies to: a component id, `a -> b` for a connection, or `component/control` |
| `reason` | why, with a ticket reference |
| `owner` | who is accountable for removing it |
| `expires` | an ISO date, `2027-03-31`. The waiver protects the finding **through** that date; afterwards the gate fails again |

## What the gate checks

| Rule | Severity | Fires when | Typical fix |
|---|---|---|---|
| `undeclared-component` | error | the code runs something the document does not list | add the component (with review) or remove it from the code |
| `undeclared-connection` | error | the code connects two declared components and the document does not approve it | approve the connection in the document, or remove the call |
| `encryption-violation` | error | `encrypted: required` but the code connects without TLS | enable TLS, or waive with an expiry |
| `control-not-evidenced` | error | a listed control has no evidence in the repository | add the manifest/config that proves it, or waive with an expiry |
| `missing-component` | warning | the document lists a component the scanner cannot find | remove it, or check the manifests are committed |
| `missing-connection` | warning | the document approves a connection the scanner cannot find | remove it; the scanner may not see every call |
| `protocol-mismatch` | warning | same connection, different protocol | correct whichever is wrong |
| `owner-mismatch` | warning | document and CODEOWNERS name different owners | align them |
| `waiver-unused` | warning | a waiver matches nothing | delete the row |

Components that do not run in the document's `environment` (for example a local-only mail catcher)
are out of scope; you do not need to list them. A connection that touches an undeclared component
is reported once, as an undeclared component.

## Reading a failure

Mistakes in the document name the file and line, and suggest the likely correction:

```
architecture.md:30: type 'ingres' for 'public-gateway' is not one of service, ingress, ...  Did you mean 'ingress'?
```

Conformance findings appear as annotations on the pull request and as a table in the job summary.
You can run both steps on your machine:

```bash
calm-intent docs/architecture/architecture.md -o /tmp/intended.calm.json
calm-discover . -o /tmp/actual.calm.json
calm-conformance --actual /tmp/actual.calm.json --intended /tmp/intended.calm.json
```

## Review workflow

1. The change author edits the document in the same pull request as the code.
2. CODEOWNERS requests the architecture group (`/docs/architecture/  @org/architects`).
3. The gate fails until code and document agree, so an unapproved dependency cannot merge, and an
   approved change cannot be forgotten in the document.
4. Waivers are reviewed like any other line: the reason, the owner and a short expiry are the
   approval record. Prefer a quarter over a year.

Branch protection must require the `security-gate` check and code-owner review for this to be a
control rather than a convention.

## Starting from a Word document

Teams with an existing `.docx` can bootstrap the prose with
`pandoc architecture.docx -t gfm -o architecture.md`, then add the front matter and the four tables
by hand. This conversion has **not been tested in this repository** (pandoc is not part of the
toolchain here); check how your tool renders tables before relying on it. The tables are the part
that matters, and they are short enough to retype.

## Limits

* The scanner reads committed files only: Kubernetes manifests, docker-compose, dependency
  manifests. A runtime dependency that exists only in application code, or in a rendered Helm
  chart, is not seen, which is why `missing-*` are warnings and `undeclared-*` are errors.
* "Evidenced" means found in the repository, not proven in production.
* Decision records (ADRs) are not parsed yet. Link them from the prose.
