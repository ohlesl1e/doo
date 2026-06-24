"""Layer 2 — static double-`WHERE` guard over `src/` (issue #156).

The cheap, drift-proof net for the #157 bug class. `CypherFragment.and_(...)`
and `for_engagement(...).where_clause` already emit a full ``WHERE …`` clause;
the #157 regression then started a *second* literal ``WHERE`` on a following
line of the same f-string, which Neo4j rejects (`Invalid input 'WHERE'`).

This test walks the AST of every module under `src/` and flags any single
f-string (`JoinedStr`) where a literal ``WHERE`` token follows an interpolated
`WHERE`-emitting fragment — a ``…and_(…)`` call, a ``…where_clause`` attribute,
or a `for_engagement(…)` value — *with no intervening clause keyword*. That gap
is the bug: `MATCH (…) <fragment-WHERE>` immediately followed by a second
literal ``WHERE`` is illegal Cypher.

A ``WHERE`` that follows a fresh ``MATCH`` / ``WITH`` / ``UNWIND`` / ``CALL`` /
``MERGE`` / ``OPTIONAL MATCH`` is *legitimate* (it scopes the new clause), so
those are not flagged — that is why the existing valid multi-clause queries in
`src/` (e.g. the C3 pivot query, `load_evidence`) stay green.

Unlike the Layer-1 registry (`tests/test_cypher_syntax_smoke.py`), this needs no
Neo4j and runs even under `DOO_SKIP_TESTCONTAINERS`, and it covers *new* call
sites automatically with zero per-site maintenance. It is a heuristic: it
catches the exact #157 double-`WHERE` shape, not every possible template error
(that is Layer 1's job).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"

# Clause keywords that open a NEW reading-clause scope, so a `WHERE` after one of
# them is legitimate (it attaches to that fresh clause, not the fragment's MATCH).
# `OPTIONAL MATCH` is covered by `MATCH`.
_CLAUSE_RESET = re.compile(
    r"\b(?:MATCH|WITH|UNWIND|CALL|MERGE|CREATE|RETURN|FOREACH)\b",
    re.IGNORECASE,
)
_LITERAL_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)


def _python_files() -> list[Path]:
    return sorted(_SRC.rglob("*.py"))


def _interpolates_where_fragment(node: ast.expr) -> bool:
    """True if `node` is an expression that already renders a `WHERE` clause.

    Matches the two `for_engagement` ergonomics:
      * ``<x>.and_(...)``                 (CypherFragment.and_ -> 'WHERE … AND …')
      * ``<x>.where_clause`` / ``for_engagement(...)``  (the raw 'WHERE …')
    """

    # `<x>.and_(...)`
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "and_"
    ):
        return True
    # `<x>.where_clause`
    if isinstance(node, ast.Attribute) and node.attr == "where_clause":
        return True
    # `for_engagement(...)` interpolated directly (its repr/str is the WHERE)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "for_engagement"
    ):
        return True
    return False


def _joinedstr_has_double_where(node: ast.JoinedStr) -> bool:
    """True iff a literal `WHERE` follows a fragment-WHERE with no clause reset.

    Walks the f-string parts in source order. Interpolating a `WHERE`-emitting
    fragment opens an "already has a WHERE on this clause" scope; a literal
    clause keyword (`MATCH`/`WITH`/…) closes it. A literal `WHERE` seen while the
    scope is open is the #157 double-`WHERE` bug.
    """

    in_fragment_where = False
    for part in node.values:
        if isinstance(part, ast.FormattedValue):
            if _interpolates_where_fragment(part.value):
                in_fragment_where = True
            continue
        if not isinstance(part, ast.Constant) or not isinstance(part.value, str):
            continue
        text = part.value
        if not in_fragment_where:
            continue
        # Within this literal chunk, a clause reset before any WHERE clears the
        # scope; a WHERE before any reset (or with no reset) is the offender.
        where_m = _LITERAL_WHERE.search(text)
        reset_m = _CLAUSE_RESET.search(text)
        if where_m and (reset_m is None or where_m.start() < reset_m.start()):
            return True
        if reset_m is not None:
            in_fragment_where = False
    return False


def _double_where_offenders(tree: ast.AST) -> list[int]:
    """Line numbers of f-strings exhibiting the #157 double-`WHERE` shape."""

    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr) and _joinedstr_has_double_where(node)
    ]


def test_no_double_where_in_src() -> None:
    """No `src/` f-string both interpolates a WHERE-fragment and adds a literal WHERE.

    Reintroducing the #157 double-`WHERE` (e.g. reverting `cc61f22` in
    `liveness.py`) makes this fail, naming the file + line, with no Neo4j needed.
    """

    failures: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for lineno in _double_where_offenders(tree):
            rel = path.relative_to(_SRC.parent)
            failures.append(f"{rel}:{lineno}")

    assert not failures, (
        "double-`WHERE` Cypher template(s) found (a `for_engagement`/`.and_` "
        "fragment already emits WHERE; fold extra predicates into `.and_(...)` "
        "instead of starting a second literal WHERE — see #157):\n  "
        + "\n  ".join(failures)
    )


def test_guard_detects_the_157_shape() -> None:
    """The detector fires on a synthetic double-`WHERE` f-string (self-test).

    Guards the guard: proves `_double_where_offenders` actually recognises the
    #157 shape, so a future refactor can't silently neuter it into a no-op.
    """

    bad = ast.parse(
        'q = f"""\n'
        "MATCH (r:RequestObservation)\n"
        '{frag.and_("r.status = \'active\'")}\n'
        "WHERE r.response_status = 200\n"
        'RETURN r"""\n'
    )
    assert _double_where_offenders(bad), "detector failed to flag the #157 shape"

    good = ast.parse(
        'q = f"""\n'
        "MATCH (r:RequestObservation)\n"
        '{frag.and_("r.status = \'active\' AND r.response_status = 200")}\n'
        'RETURN r"""\n'
    )
    assert not _double_where_offenders(good), "detector flagged a correct single-WHERE query"
