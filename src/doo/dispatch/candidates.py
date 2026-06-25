"""Re-dispatch candidates: approved TestCases stuck on a credential problem (ADR-0053, #171).

The closer for #166's self-healing story. After #168 (verify-on-first-use) and
#170 (the watermark guard) stop the dead-token storm, this read surfaces what is
*stuck* and whether it can be re-run yet — a **derived** view (no stored state),
the dispatch analog of a coverage gap.

A candidate is an `approved`, `active` TestCase that was attempted, failed on a
credential problem, and never reached a clean `ok` primary. The two failure
shapes are both graph-visible (no ledger needed):

- **auth_invalid** — an `EXECUTED_AS{request_role:'primary', dispatch_status:'auth_invalid'}` edge.
- **auth_unverified** (#168) — a `liveness` edge with **no** primary edge at all
  (uniquely: `replay_invalid` keeps its primary edge; `waiting_on_rotation`, #170,
  always sits atop a prior `auth_invalid` edge).

Each candidate is classified by the **rotation watermark** (the same rule as
`rotation.is_waiting_on_rotation`): `eligible` iff the slot has an `active`
declared `AuthContext` whose `first_seen` is later than the last failure — i.e.
the credential precondition has demonstrably cleared. `eligible` candidates are
what `doo dispatch redispatch --rerun` re-sends; the rest are waiting on rotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from doo.ids import EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient


@dataclass(frozen=True, slots=True)
class RedispatchCandidate:
    """One approved TestCase stuck on a credential problem (ADR-0053, #171)."""

    key_hash: TestCaseKeyHash
    test_class: str
    principal: str
    slot: str
    failure_kind: str  # "auth_invalid" | "auth_unverified"
    eligible: bool  # slot rotated past the failure → re-dispatchable now
    last_fail: datetime | None


def _to_native(value: object) -> datetime | None:
    """Neo4j `DateTime` → stdlib `datetime` (mirrors finding.py's coercion)."""

    if value is None:
        return None
    to_native = getattr(value, "to_native", None)
    if callable(to_native):
        native = to_native()
        return native if isinstance(native, datetime) else None
    return value if isinstance(value, datetime) else None


def list_redispatch_candidates(
    neo4j: Neo4jClient, *, engagement_id: EngagementId
) -> list[RedispatchCandidate]:
    """List approved TestCases stuck on a credential problem, classified by watermark.

    Graph-only and recomputed each call (no stored state). Empty-rows-safe for the
    Cypher syntax registry double.
    """

    rows = neo4j.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid})
        WHERE t.status = 'active' AND t.review_status = 'approved'
          AND t.attacker_principal IS NOT NULL AND t.attacker_slot IS NOT NULL
          AND NOT EXISTS {
            MATCH (t)-[ok:EXECUTED_AS {request_role: 'primary'}]->()
            WHERE ok.dispatch_status = 'ok'
          }
        WITH t,
          EXISTS {
            MATCH (t)-[ai:EXECUTED_AS {request_role: 'primary'}]->()
            WHERE ai.dispatch_status = 'auth_invalid'
          } AS has_authinvalid,
          EXISTS { MATCH (t)-[pr:EXECUTED_AS {request_role: 'primary'}]->() } AS has_primary,
          EXISTS { MATCH (t)-[lv:EXECUTED_AS {request_role: 'liveness'}]->() } AS has_liveness
        WHERE has_authinvalid OR (has_liveness AND NOT has_primary)
        MATCH (t)-[x:EXECUTED_AS]->()
        WHERE (x.request_role = 'primary' AND x.dispatch_status = 'auth_invalid')
           OR x.request_role = 'liveness'
        WITH t, has_authinvalid, max(x.at) AS last_fail
        OPTIONAL MATCH (p:Principal {engagement_id: $eid, label: t.attacker_principal})
                       <-[:OF_PRINCIPAL]-(ac:AuthContext)
        WHERE ac.tier = 'declared' AND coalesce(ac.slot, ac.token_kind) = t.attacker_slot
          AND ac.status = 'active' AND ac.first_seen > last_fail
        WITH t, has_authinvalid, last_fail, count(ac) AS rotated_since
        RETURN t.key_hash AS key_hash, t.test_class AS test_class,
               t.attacker_principal AS principal, t.attacker_slot AS slot,
               (CASE WHEN has_authinvalid THEN 'auth_invalid' ELSE 'auth_unverified' END)
                 AS failure_kind,
               last_fail AS last_fail, (rotated_since > 0) AS eligible
        ORDER BY key_hash
        """,
        eid=str(engagement_id),
    )
    return [
        RedispatchCandidate(
            key_hash=TestCaseKeyHash(str(r["key_hash"])),
            test_class=str(r["test_class"]),
            principal=str(r["principal"]),
            slot=str(r["slot"]),
            failure_kind=str(r["failure_kind"]),
            eligible=bool(r["eligible"]),
            last_fail=_to_native(r["last_fail"]),
        )
        for r in rows
    ]


__all__ = ["RedispatchCandidate", "list_redispatch_candidates"]
