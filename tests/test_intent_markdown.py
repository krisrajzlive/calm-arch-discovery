from __future__ import annotations

import textwrap

from intent.markdown import norm_subject, parse

KNOWN = ["auth-required", "encryption-in-transit", "container-hardening"]

VALID = textwrap.dedent(
    """\
    ---
    system: shop
    environment: production
    owner: "@shop/architects"
    ---

    # Shop

    ## Components

    | id | type | owner | description |
    |---|---|---|---|
    | web | service | web-team | The web tier |
    | db | database | data-team | The store |

    ## Connections

    | from | to | protocol | encrypted | purpose |
    |---|---|---|---|---|
    | web | db | JDBC | required | Persist |

    ## Controls

    | component | control |
    |---|---|
    | web | auth-required |
    | db | encryption-in-transit |

    ## Waivers

    | rule | subject | reason | owner | expires |
    |---|---|---|---|---|
    | encryption-violation | web → db | rollout | @shop/data | 2027-03-31 |
    """
)


def run(text: str = VALID):
    return parse(text, "doc.md", KNOWN)


def messages(text: str) -> list[str]:
    return [str(i) for i in run(text)[1]]


def test_valid_document_parses_cleanly():
    doc, issues = run()
    assert issues == []
    assert (doc.system, doc.environment, doc.owner) == ("shop", "production", "@shop/architects")
    assert [c["id"] for c in doc.components] == ["web", "db"]
    assert doc.connections[0]["protocol"] == "JDBC" and doc.connections[0]["encrypted"] is True
    assert [c["control"] for c in doc.controls] == ["auth-required", "encryption-in-transit"]


def test_waiver_subject_is_normalised_to_ascii_arrow():
    doc, _ = run()
    assert doc.waivers[0]["subject"] == "web -> db"
    assert norm_subject("a→b") == "a -> b"
    assert norm_subject("a  ->   b") == "a -> b"
    assert norm_subject("cache/network-segmentation") == "cache/network-segmentation"


def test_environment_defaults_to_production():
    doc, issues = run(VALID.replace("environment: production\n", ""))
    assert issues == [] and doc.environment == "production"


def test_prose_and_diagrams_around_the_tables_are_ignored():
    text = VALID.replace(
        "# Shop", "# Shop\n\nSome prose with a | pipe.\n\n```mermaid\ngraph TD\n```"
    )
    assert messages(text) == []


def test_tables_inside_code_fences_are_ignored():
    fenced = "```\n| web | ghost | HTTP | required |\n```\n"
    doc, issues = run(VALID.replace("## Controls", fenced + "\n## Controls"))
    assert issues == [] and len(doc.connections) == 1


def test_headings_other_than_the_four_are_ignored():
    text = VALID.replace(
        "## Controls",
        "## Notes\n\n| id | type |\n|---|---|\n| x | y |\n\n## Controls",
    )
    assert messages(text) == []


def test_markup_in_cells_is_stripped_and_escaped_pipes_survive():
    text = VALID.replace(
        "| web | service | web-team | The web tier |",
        "| `web` | **service** | [web-team](https://x.example) | a \\| b |",
    )
    doc, issues = run(text)
    assert issues == []
    assert doc.components[0]["owner"] == "web-team"
    assert doc.components[0]["description"] == "a | b"


def test_missing_front_matter_is_reported_on_line_one():
    issues = run("## Components\n")[1]
    assert issues[0].line == 1 and "front matter" in issues[0].message


def test_front_matter_without_system():
    assert any("system" in m for m in messages(VALID.replace("system: shop\n", "")))


def test_unclosed_front_matter():
    assert any("not closed" in m for m in messages("---\nsystem: shop\n"))


def test_errors_carry_the_line_of_the_offending_row():
    text = VALID.replace(
        "| web | db | JDBC | required | Persist |", "| web | dbb | JDBC | required | Persist |"
    )
    (issue,) = run(text)[1]
    assert VALID.splitlines()[issue.line - 1].startswith("| web | db | JDBC")
    assert "'dbb'" in issue.message and "Did you mean 'db'?" in issue.message


def test_all_problems_are_reported_not_just_the_first():
    text = VALID.replace(
        "| web | db | JDBC | required | Persist |", "| web | web | JDBC | maybe | Persist |"
    ).replace("| db | database |", "| Db_Two | databse |")
    found = messages(text)
    assert len(found) >= 3
    assert any("kebab-case" in m for m in found)
    assert any("encrypted" in m for m in found)


def test_unknown_component_type_suggests_a_fix():
    found = messages(VALID.replace("| db | database |", "| db | databse |"))
    assert any("Did you mean 'database'?" in m for m in found)


def test_a_typo_in_one_column_does_not_cascade_into_other_tables():
    found = messages(VALID.replace("| db | database |", "| db | databse |"))
    assert len(found) == 1


def test_duplicate_component_and_connection():
    dup_c = VALID.replace(
        "| db | database | data-team | The store |",
        "| db | database | data-team | The store |\n| db | database | x | y |",
    )
    assert any("already declared" in m for m in messages(dup_c))
    dup_k = VALID.replace(
        "| web | db | JDBC | required | Persist |",
        "| web | db | JDBC | required | Persist |\n| web | db | TCP | required | again |",
    )
    assert any("already declared" in m for m in messages(dup_k))


def test_self_connection_rejected():
    found = messages(VALID.replace("| web | db | JDBC", "| web | web | JDBC"))
    assert any("itself" in m for m in found)


def test_unknown_protocol_and_control():
    assert any("not a CALM protocol" in m for m in messages(VALID.replace("JDBC", "gRPC")))
    found = messages(VALID.replace("| web | auth-required |", "| web | auth-requird |"))
    assert any("Did you mean 'auth-required'?" in m for m in found)


def test_every_component_needs_a_control():
    found = messages(VALID.replace("| db | encryption-in-transit |\n", ""))
    assert any("'db' has no row in the Controls table" in m for m in found)


def test_wrong_columns_and_cell_count():
    assert any(
        "missing column" in m for m in messages(VALID.replace("| from | to |", "| src | to |"))
    )
    assert any(
        "cells" in m
        for m in messages(
            VALID.replace(
                "| db | database | data-team | The store |", "| db | database | data-team |"
            )
        )
    )


def test_table_without_separator_row():
    assert any(
        "separator" in m
        for m in messages(VALID.replace("|---|---|---|---|---|\n| web | db", "| web | db"))
    )


def test_waiver_validation():
    bad_rule = VALID.replace("encryption-violation", "everything-is-fine")
    assert any("cannot be waived" in m for m in messages(bad_rule))
    assert any(
        "'expires' must be a date" in m for m in messages(VALID.replace("2027-03-31", "soon"))
    )
    assert any("needs a reason" in m for m in messages(VALID.replace("rollout", "-")))


def test_no_components_table():
    text = "---\nsystem: shop\n---\n\n# Empty\n"
    assert any("no '## Components' table" in m for m in messages(text))


def test_issues_are_sorted_by_line():
    issues = run(VALID.replace("JDBC", "gRPC").replace("auth-required", "nope"))[1]
    assert [i.line for i in issues] == sorted(i.line for i in issues)
