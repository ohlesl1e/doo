"""Rotation-watermark read: is a failed TestCase still waiting on a rotation? (ADR-0053, #170).

The anti-storm guard for re-dispatch. After a TestCase's `primary` came back
`auth_invalid`, re-running it is pointless until the attacker credential **slot**
has rotated — otherwise the send hits the same dead token and storms (the #166
incident: dozens of authz tests, 2–5 `auth_invalid` attempts each).

The **rotation watermark** is the `first_seen` of the slot's newest `active`
declared `AuthContext` generation. An `auth_invalid` `primary` edge is
re-dispatch-eligible only when a newer-than-`edge.at` active generation exists —
i.e. the credential precondition that caused the failure has demonstrably cleared.
No stored state: the verdict is derived at query time from `EXECUTED_AS.at` and
`AuthContext.first_seen`/`status` (both Neo4j datetimes, directly comparable).

Graph-only (ADR-0053 scope): keys off prior `auth_invalid` *primary edges*. The
post-#168 `auth_unverified` refusal writes no primary edge; it is already
storm-bounded by #168's per-run cached pre-flight probe and surfaced by #171's
ledger-aware candidate report.
"""

from __future__ import annotations

from doo.ids import EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient


def is_waiting_on_rotation(
    neo4j: Neo4jClient,
    *,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
    principal_label: str,
    slot: str,
) -> bool:
    """True iff this TestCase failed `auth_invalid` and its slot has not rotated since.

    Returns False when the TestCase has no prior `auth_invalid` `primary` edge (first
    run, or already tested clean) or when an `active` declared `AuthContext` on the
    slot is newer than the last failure (rotation cleared the precondition). The
    single `execute_read` always yields one row (the `OPTIONAL MATCH` keeps the
    no-failure case alive); empty rows (the syntax-registry double) read as False.
    """

    rows = neo4j.execute_read(
        """
        OPTIONAL MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
                       -[x:EXECUTED_AS {request_role: 'primary'}]->()
        WHERE x.dispatch_status = 'auth_invalid'
        WITH max(x.at) AS last_fail
        OPTIONAL MATCH (p:Principal {engagement_id: $eid, label: $plabel})
                       <-[:OF_PRINCIPAL]-(ac:AuthContext)
        WHERE last_fail IS NOT NULL AND ac.tier = 'declared'
          AND coalesce(ac.slot, ac.token_kind) = $slot
          AND ac.status = 'active' AND ac.first_seen > last_fail
        RETURN last_fail AS last_fail, count(ac) AS rotated_since
        """,
        eid=str(engagement_id),
        kh=str(key_hash),
        plabel=principal_label,
        slot=slot,
    )
    if not rows:
        return False
    row = rows[0]
    return row["last_fail"] is not None and row["rotated_since"] == 0


__all__ = ["is_waiting_on_rotation"]
