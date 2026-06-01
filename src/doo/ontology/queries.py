"""Engagement-scoped Cypher query helpers (ADR-0017).

ADR-0017 mandates the query convention: *all consumer-facing Cypher starts from
the `Engagement` root or filters explicitly on `engagement_id`.* This module
provides the `for_engagement` helper that makes that convention idiomatic, so
code review can catch deviations (a query that forgets the filter is a
cross-engagement data-leak risk per ADR-0017's "Why `Host` is scoped" section).

`for_engagement(engagement_id)` returns a `CypherFragment`: a parameterised
`WHERE` clause plus the `$engagement_id` parameter binding. Callers compose the
fragment into their own `MATCH`, keeping the engagement-id value out of the
query string (parameterised, never interpolated).

Usage:

    frag = for_engagement(eng_id)
    cypher = f"MATCH (n:Endpoint) {frag.where_clause} RETURN n"
    session.run(cypher, **frag.parameters)

The fragment binds the match variable name (default ``n``) so callers matching
under a different alias stay correct:

    frag = for_engagement(eng_id, var="e")
    cypher = f"MATCH (e:Endpoint) {frag.where_clause} RETURN e"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from doo.ids import EngagementId

_PARAM_NAME = "engagement_id"


@dataclass(frozen=True, slots=True)
class CypherFragment:
    """A parameterised Cypher fragment scoped to one Engagement.

    `where_clause` is a ready-to-concatenate `WHERE n.engagement_id =
    $engagement_id` string (with the configured variable name). `parameters`
    carries the bound value to pass to `session.run(cypher, **fragment.parameters)`.
    Keeping the value in `parameters` (never in the string) preserves Neo4j
    query-plan caching and prevents injection.
    """

    where_clause: str
    parameters: dict[str, Any]

    def and_(self, predicate: str) -> str:
        """Append an additional predicate with `AND`, sharing the same WHERE.

        Convenience for the common "engagement scope + extra filter" case:

            frag.and_("n.status = 'active'")  ->  "WHERE n.engagement_id = $engagement_id AND n.status = 'active'"
        """

        return f"{self.where_clause} AND {predicate}"


def for_engagement(engagement_id: EngagementId, *, var: str = "n") -> CypherFragment:
    """Return the engagement-scoping `WHERE` fragment for match variable `var`.

    Per ADR-0017 this is the required convention for every consumer-facing
    scoped read. `var` is the alias used in the caller's `MATCH` (default
    ``n``). The `engagement_id` value is bound as a parameter, never
    interpolated into the string.
    """

    return CypherFragment(
        where_clause=f"WHERE {var}.{_PARAM_NAME} = ${_PARAM_NAME}",
        parameters={_PARAM_NAME: engagement_id},
    )
