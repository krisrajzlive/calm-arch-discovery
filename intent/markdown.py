"""Parse an architecture document written in Markdown.

Architects keep a normal Markdown file (prose, diagrams, anything); the tool reads only
the pipe tables under four ``##`` headings and the YAML front matter:

* ``## Components``   id | type | owner | description            (| environment)
* ``## Connections``  from | to | protocol | encrypted            (| purpose)
* ``## Controls``     component | control
* ``## Waivers``      rule | subject | reason | owner | expires

Everything else is ignored. Errors are reported with the line number of the offending row
so a non-developer can fix the document without reading a stack trace.
"""

from __future__ import annotations

import datetime as dt
import difflib
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

COMPONENT_TYPES = ("service", "ingress", "database", "webclient", "network")
PROTOCOLS = {
    p.lower(): p
    for p in (
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
    )
}
# rule ids produced by pipeline/conformance.py that a waiver may reference
WAIVABLE_RULES = (
    "undeclared-component",
    "missing-component",
    "undeclared-connection",
    "missing-connection",
    "encryption-violation",
    "protocol-mismatch",
    "control-not-evidenced",
    "owner-mismatch",
)
_ENCRYPTED = {
    "required": True,
    "yes": True,
    "true": True,
    "no": False,
    "not-required": False,
    "optional": False,
    "false": False,
}
_KEBAB = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SECTIONS = {
    "components": ("id", "type", "owner", "description"),
    "connections": ("from", "to", "protocol", "encrypted"),
    "controls": ("component", "control"),
    "waivers": ("rule", "subject", "reason", "owner", "expires"),
}


@dataclass(frozen=True)
class Issue:
    line: int
    message: str

    def __str__(self) -> str:
        return f"line {self.line}: {self.message}"


@dataclass
class IntentDoc:
    path: str
    system: str = ""
    environment: str = "production"
    owner: str | None = None
    components: list[dict[str, Any]] = field(default_factory=list)
    connections: list[dict[str, Any]] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    waivers: list[dict[str, Any]] = field(default_factory=list)


def norm_subject(subject: str) -> str:
    """Canonical form of a connection subject: ``a -> b`` (accepts ``→`` and any spacing)."""
    if "->" in subject.replace("→", "->"):
        parts = subject.replace("→", "->").split("->")
        return " -> ".join(p.strip() for p in parts)
    return subject.strip()


def _clean(cell: str) -> str:
    text = cell.strip().replace("\\|", "|")
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # [text](url) -> text
    return text.replace("`", "").replace("**", "").replace("__", "").strip()


def _split_row(line: str) -> list[str]:
    body = line.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    return [_clean(c) for c in re.split(r"(?<!\\)\|", body)]


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-+:?", c) for c in cells)


def _suggest(value: str, candidates: list[str] | tuple[str, ...]) -> str:
    close = difflib.get_close_matches(value, list(candidates), n=1)
    return f" Did you mean '{close[0]}'?" if close else ""


def _front_matter(lines: list[str], issues: list[Issue]) -> tuple[dict[str, Any], int]:
    if not lines or lines[0].strip() != "---":
        issues.append(
            Issue(
                1,
                "document must start with front matter ('---' ... '---') "
                "declaring at least 'system:'",
            )
        )
        return {}, 0
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            try:
                data = yaml.safe_load("\n".join(lines[1:i])) or {}
            except yaml.YAMLError:
                issues.append(Issue(1, "front matter is not valid YAML"))
                return {}, i + 1
            if not isinstance(data, dict):
                issues.append(Issue(1, "front matter must be 'key: value' pairs"))
                return {}, i + 1
            return data, i + 1
    issues.append(Issue(1, "front matter is not closed with '---'"))
    return {}, 0


def _read_tables(lines: list[str], start: int, issues: list[Issue]) -> dict[str, list[dict]]:
    """Return {section: [row dict with '_line']} for the four known sections."""
    rows: dict[str, list[dict]] = {name: [] for name in SECTIONS}
    section: str | None = None
    in_fence = False
    i = start
    while i < len(lines):
        line = lines[i]
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
            i += 1
            continue
        if in_fence:
            i += 1
            continue
        heading = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if heading:
            level, title = len(heading.group(1)), heading.group(2).strip().lower()
            if level <= 2:
                section = title if level == 2 and title in SECTIONS else None
            i += 1
            continue
        if section and line.lstrip().startswith("|"):
            block = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                block.append((i + 1, lines[i]))
                i += 1
            _read_table(section, block, rows, issues)
            continue
        i += 1
    return rows


def _read_table(section: str, block: list[tuple[int, str]], rows: dict, issues: list[Issue]):
    first_line = block[0][0]
    header = [c.lower() for c in _split_row(block[0][1])]
    if len(block) < 2 or not _is_separator(_split_row(block[1][1])):
        issues.append(
            Issue(
                first_line,
                f"'{section}' table needs a header row followed by a separator row like |---|---|",
            )
        )
        return
    missing = [c for c in SECTIONS[section] if c not in header]
    if missing:
        issues.append(
            Issue(
                first_line,
                f"'{section}' table is missing column(s): "
                f"{', '.join(missing)} (found: {', '.join(header)})",
            )
        )
        return
    for lineno, raw in block[2:]:
        cells = _split_row(raw)
        if len(cells) != len(header):
            issues.append(
                Issue(
                    lineno,
                    f"row has {len(cells)} cells but the header has "
                    f"{len(header)}; check for a stray '|'",
                )
            )
            continue
        row = dict(zip(header, cells, strict=True))
        row["_line"] = lineno
        rows[section].append(row)


def parse(text: str, path: str, known_controls: list[str]) -> tuple[IntentDoc, list[Issue]]:
    """Parse and validate. Returns the document and *every* issue found (not just the first)."""
    issues: list[Issue] = []
    lines = text.splitlines()
    meta, body_start = _front_matter(lines, issues)
    doc = IntentDoc(path=path)
    system = meta.get("system")
    if system is not None and (not isinstance(system, str) or not system.strip()):
        issues.append(Issue(1, "front matter 'system' must be a non-empty name"))
    elif system is None and not issues:
        issues.append(Issue(1, "front matter must declare 'system: <name>'"))
    doc.system = str(system or "").strip()
    doc.environment = str(meta.get("environment") or "production")
    doc.owner = str(meta["owner"]) if meta.get("owner") else None

    rows = _read_tables(lines, body_start, issues)
    _components(rows["components"], doc, issues)
    # a component with a typo in another column is still *declared*; do not cascade errors
    ids = {row["id"] for row in rows["components"]}
    _connections(rows["connections"], doc, ids, issues)
    _controls(rows["controls"], doc, ids, known_controls, issues)
    _waivers(rows["waivers"], doc, issues)
    if not rows["components"] and not any(i.message.startswith("'components'") for i in issues):
        issues.append(Issue(1, "no '## Components' table found; list the system's components"))
    return doc, sorted(issues, key=lambda i: i.line)


def _components(rows: list[dict], doc: IntentDoc, issues: list[Issue]) -> None:
    seen: dict[str, int] = {}
    for row in rows:
        line, cid = row["_line"], row["id"]
        if not _KEBAB.match(cid):
            suggestion = re.sub(r"[^a-z0-9]+", "-", cid.lower()).strip("-") or "component-name"
            issues.append(
                Issue(line, f"id '{cid}' must be lowercase kebab-case, e.g. '{suggestion}'")
            )
            continue
        if cid in seen:
            issues.append(Issue(line, f"component '{cid}' is already declared on line {seen[cid]}"))
            continue
        seen[cid] = line
        ctype = row["type"].lower()
        if ctype not in COMPONENT_TYPES:
            issues.append(
                Issue(
                    line,
                    f"type '{row['type']}' for '{cid}' is not one of "
                    f"{', '.join(COMPONENT_TYPES)}.{_suggest(ctype, COMPONENT_TYPES)}",
                )
            )
            continue
        for column in ("owner", "description"):
            if not row[column] or row[column] == "-":
                issues.append(Issue(line, f"'{cid}' needs a {column}"))
        doc.components.append(
            {
                "id": cid,
                "type": ctype,
                "owner": row["owner"],
                "description": row["description"],
                "environment": row.get("environment") or doc.environment,
                "line": line,
            }
        )


def _connections(rows: list[dict], doc: IntentDoc, ids: set[str], issues: list[Issue]) -> None:
    seen: dict[tuple[str, str], int] = {}
    for row in rows:
        line, src, dst = row["_line"], row["from"], row["to"]
        ok = True
        for label, value in (("from", src), ("to", dst)):
            if value not in ids:
                issues.append(
                    Issue(
                        line,
                        f"'{label}' component '{value}' is not declared in "
                        f"Components.{_suggest(value, sorted(ids))}",
                    )
                )
                ok = False
        protocol = PROTOCOLS.get(row["protocol"].lower())
        if protocol is None:
            issues.append(
                Issue(
                    line,
                    f"protocol '{row['protocol']}' is not a CALM protocol "
                    f"({', '.join(PROTOCOLS.values())})."
                    f"{_suggest(row['protocol'].lower(), list(PROTOCOLS))}",
                )
            )
            ok = False
        encrypted = _ENCRYPTED.get(row["encrypted"].lower())
        if encrypted is None:
            issues.append(
                Issue(
                    line,
                    f"'encrypted' must be 'required' or 'not-required', got '{row['encrypted']}'",
                )
            )
            ok = False
        if ok and src == dst:
            issues.append(Issue(line, f"'{src}' cannot connect to itself"))
            ok = False
        if ok and (src, dst) in seen:
            issues.append(
                Issue(
                    line,
                    f"connection {src} -> {dst} is already declared on line {seen[(src, dst)]}",
                )
            )
            ok = False
        if ok:
            seen[(src, dst)] = line
            doc.connections.append(
                {
                    "from": src,
                    "to": dst,
                    "protocol": protocol,
                    "encrypted": encrypted,
                    "purpose": row.get("purpose", ""),
                    "line": line,
                }
            )


def _controls(
    rows: list[dict], doc: IntentDoc, ids: set[str], known: list[str], issues: list[Issue]
) -> None:
    seen: set[tuple[str, str]] = set()
    for row in rows:
        line, comp, control = row["_line"], row["component"], row["control"]
        if comp not in ids:
            issues.append(
                Issue(
                    line,
                    f"component '{comp}' is not declared in Components."
                    f"{_suggest(comp, sorted(ids))}",
                )
            )
            continue
        if control not in known:
            issues.append(
                Issue(
                    line,
                    f"unknown control '{control}'. Known controls: "
                    f"{', '.join(known)}.{_suggest(control, known)}",
                )
            )
            continue
        if (comp, control) in seen:
            issues.append(Issue(line, f"control '{control}' is already listed for '{comp}'"))
            continue
        seen.add((comp, control))
        doc.controls.append({"component": comp, "control": control, "line": line})
    with_controls = {c["component"] for c in doc.controls}
    for comp in doc.components:
        if comp["id"] not in with_controls:
            issues.append(
                Issue(
                    comp["line"],
                    f"component '{comp['id']}' has no row in the "
                    "Controls table; every component needs at least "
                    "one control",
                )
            )


def _waivers(rows: list[dict], doc: IntentDoc, issues: list[Issue]) -> None:
    for row in rows:
        line = row["_line"]
        problems = []
        if row["rule"] not in WAIVABLE_RULES:
            problems.append(
                f"rule '{row['rule']}' cannot be waived. Waivable rules: "
                f"{', '.join(WAIVABLE_RULES)}.{_suggest(row['rule'], WAIVABLE_RULES)}"
            )
        for column in ("subject", "reason", "owner"):
            if not row[column] or row[column] == "-":
                problems.append(f"a waiver needs a {column}")
        try:
            expires = dt.date.fromisoformat(row["expires"])
        except ValueError:
            problems.append(f"'expires' must be a date like 2027-03-31, got '{row['expires']}'")
            expires = None
        for problem in problems:
            issues.append(Issue(line, problem))
        if not problems and expires:
            doc.waivers.append(
                {
                    "rule": row["rule"],
                    "subject": norm_subject(row["subject"]),
                    "reason": row["reason"],
                    "owner": row["owner"],
                    "expires": expires.isoformat(),
                    "line": line,
                }
            )
