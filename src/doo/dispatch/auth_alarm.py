"""Dispatch-side early warning: auth failures climbing, nothing rotating (#183).

The complement to ADR-0054 / #182 (which co-launches the auth-helper and surfaces
its *death*). This covers the quieter failure: the auth-helper was never started,
or its `refresh:` is broken, so an expired credential is never rotated. The slot's
tests fail `auth_invalid` / `auth_unverified` (correctly fail-safe — never a silent
"boundary held") but the tester may not realise the root cause is "nothing is
rotating," not "the target is solid."

`detect_stalled_auth_slots` derives, per attacker slot, this run's auth-failure
count from the in-memory `(DispatchTestCase, RunOutcome)` pairs, and for any slot
at/over `AUTH_STALL_THRESHOLD` asks the graph whether a declared `AuthContext` on
that slot has rotated since the run armed (the rotation axis used by
`rotation.py`). No rotation → the slot is **stalled** and gets an advisory.

**Advisory only** — this never halts a run; only the kill-switch halts dispatch
(CLAUDE.md hard rule / ADR-0054). The CLI surfaces it loudly in the run summary.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from doo.dispatch.executor.evidence import DispatchTestCase
from doo.dispatch.models import RunOutcome
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger

log = get_logger(__name__)

# At/over this many auth failures on one slot in a single run — with no rotation
# since the run armed — the auth-helper looks down. Advisory threshold (#183).
AUTH_STALL_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class StalledSlot:
    """One attacker credential slot whose auth failures climbed with no rotation."""

    principal_label: str
    slot: str
    auth_failures: int


def _is_auth_failure(outcome: RunOutcome) -> bool:
    """True iff this outcome is an auth failure (dead/unverified attacker creds).

    Either the post-#168 pre-flight refusal (`auth_unverified`, no primary edge) or
    a `primary` that came back `auth_invalid` on the wire.
    """

    if outcome.outcome == "auth_unverified":
        return True
    return any(
        role == "primary" and status == "auth_invalid"
        for role, status, _obs in outcome.sends
    )


def detect_stalled_auth_slots(
    neo4j: Neo4jClient,
    *,
    engagement_id: EngagementId,
    armed_at: datetime,
    selected: Sequence[DispatchTestCase],
    outcomes: Sequence[RunOutcome],
    threshold: int = AUTH_STALL_THRESHOLD,
) -> tuple[StalledSlot, ...]:
    """Slots whose auth failures this run reached `threshold` with NO rotation since.

    Counts auth failures per `(attacker_principal, attacker_slot)` from the
    in-memory pairs, then for each slot at/over `threshold` runs one small graph
    read: did an `active` declared `AuthContext` on that slot get a `first_seen`
    after `armed_at`? If not, the helper is likely down and the slot is stalled.
    Advisory only — the caller surfaces it, never halts (#183).
    """

    tc_by_key = {tc.key_hash: tc for tc in selected}
    counts: dict[tuple[str, str], int] = {}
    for o in outcomes:
        if not _is_auth_failure(o):
            continue
        tc = tc_by_key.get(o.key_hash)
        if tc is None or tc.attacker_principal is None or tc.attacker_slot is None:
            continue
        key = (tc.attacker_principal, tc.attacker_slot)
        counts[key] = counts.get(key, 0) + 1

    stalled: list[StalledSlot] = []
    for (principal, slot), n in sorted(counts.items()):
        if n < threshold:
            continue
        if _rotated_since(
            neo4j,
            engagement_id=engagement_id,
            principal_label=principal,
            slot=slot,
            since=armed_at,
        ):
            continue  # the helper IS rotating — no alarm.
        stalled.append(
            StalledSlot(principal_label=principal, slot=slot, auth_failures=n)
        )

    if stalled:
        log.warning(
            "dispatch.auth_stall.detected",
            engagement_id=engagement_id,
            slots=[(s.principal_label, s.slot, s.auth_failures) for s in stalled],
        )
    return tuple(stalled)


def _rotated_since(
    neo4j: Neo4jClient,
    *,
    engagement_id: EngagementId,
    principal_label: str,
    slot: str,
    since: datetime,
) -> bool:
    """True iff an `active` declared `AuthContext` on this slot is newer than `since`.

    The rotation axis from `rotation.py`: `(principal, slot)` → `active` `declared`
    `AuthContext` with `first_seen > since`. `OPTIONAL MATCH` keeps the no-rotation
    case a single row; the empty-rows registry double reads as False.
    """

    rows = neo4j.execute_read(
        """
        OPTIONAL MATCH (p:Principal {engagement_id: $eid, label: $plabel})
                       <-[:OF_PRINCIPAL]-(ac:AuthContext)
        WHERE ac.tier = 'declared'
          AND coalesce(ac.slot, ac.token_kind) = $slot
          AND ac.status = 'active' AND ac.first_seen > $since
        RETURN count(ac) AS rotated_since
        """,
        eid=str(engagement_id),
        plabel=principal_label,
        slot=slot,
        since=since,
    )
    if not rows:
        return False
    return int(rows[0]["rotated_since"]) > 0


__all__ = ["AUTH_STALL_THRESHOLD", "StalledSlot", "detect_stalled_auth_slots"]
