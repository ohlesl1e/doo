"""`doo engagement migrate-testcase-keys` (ADR-0049 / #120).

Backfill `(attacker_principal, attacker_slot)` on pre-ADR-0049 TestCases and
recompute `key_hash`. On collision (≥2 old TestCases collapse to one new key —
rotation churn), keep the most-recently-reviewed and retract the rest with a
`MERGED_INTO` edge. Idempotent: a second run finds 0 rows.

Kept in its own module so the diff to `src/doo/cli.py` is a single import + a
single `register_migrate_testcase_keys(engagement_app)` call (mirrors
`cli_keepalive.py`; T4 also edits `cli.py` so the registration footprint is
intentionally tiny).
"""

from __future__ import annotations

import dataclasses
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import typer

from doo.canonical.identity import auth_context_id, compute_anonymous_auth_hash
from doo.events.slice4 import compute_testcase_key_hash
from doo.ids import (
    EngagementId,
    ParameterId,
    Sha256Hex,
    TestCaseKeyHash,
    TrustBoundaryId,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import bind_correlation, configure_logging, get_logger
from doo.planner.review import JsonFileReviewLedger, ReviewLedger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Plan (pure read).
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class _OldRow:
    """One pre-ADR-0049 `TestCase` row + its resolved Principal label / slot."""

    key_hash: str
    test_class: str
    target_endpoint_id: str | None
    target_parameter_id: str | None
    target_trust_boundary_id: str | None
    payload_class: str
    payload_hash: str
    auth_context_id: str
    last_seen: object  # neo4j datetime (kept opaque; only ordered)
    label: str | None
    slot: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class MigrationPlan:
    """Outcome of `plan_migration` — what `apply_migration` will write.

    `migrated`: `(old_key, new_key, attacker_principal, attacker_slot)` for the
    survivor of each new-key group. `retracted`: `(loser_old_key,
    survivor_new_key)` pairs (rotation churn). `unresolved`: rows whose
    `auth_context_id` no longer resolves to a Principal — surfaced for the
    operator, never silently rewritten.
    """

    migrated: list[tuple[str, str, str, str]]
    retracted: list[tuple[str, str]]
    unresolved: list[tuple[str, str]]


#: Fetch every active pre-ADR-0049 TestCase (`attacker_principal IS NULL`) and
#: join out to its AuthContext → Principal so `(label, slot)` can be resolved.
FETCH_CYPHER = """
MATCH (tc:TestCase {engagement_id: $eid})
WHERE tc.attacker_principal IS NULL AND tc.status = 'active'
OPTIONAL MATCH (ac:AuthContext {engagement_id: $eid, id: tc.auth_context_id})
               -[:OF_PRINCIPAL]->(p:Principal)
RETURN tc.key_hash AS key_hash, tc.test_class AS test_class,
       tc.target_endpoint_id AS target_endpoint_id,
       tc.target_parameter_id AS target_parameter_id,
       tc.target_trust_boundary_id AS target_trust_boundary_id,
       tc.payload_class AS payload_class, tc.payload_hash AS payload_hash,
       tc.auth_context_id AS auth_context_id, tc.last_seen AS last_seen,
       p.label AS label, coalesce(ac.slot, ac.token_kind) AS slot
"""


def _resolve_attacker(
    row: _OldRow, *, anonymous_id: str
) -> tuple[str, str] | None:
    """Resolve `(attacker_principal, attacker_slot)` for one pre-0049 row.

    Anonymous-context tests map to the `("anonymous", "anonymous")` sentinel.
    Otherwise the AuthContext's Principal label + slot (falling back to
    `token_kind` per T1's backfill) are used. A dangling `auth_context_id`
    (no Principal) is `None` → reported as `unresolved`.
    """

    if row.auth_context_id == anonymous_id:
        return ("anonymous", "anonymous")
    if row.label is None:
        return None
    return (row.label, row.slot or "")


def pick_survivor(
    rows: list[_OldRow],
    *,
    engagement_id: EngagementId,
    ledger: ReviewLedger | None,
) -> _OldRow:
    """Pick the survivor of a new-key collision group.

    Preference: the row most recently *reviewed* (ledger `latest_for(...).timestamp`),
    else the row with the latest `last_seen`, else lexicographically-smallest
    old `key_hash` (so the choice is deterministic on a tie).
    """

    def sort_key(r: _OldRow) -> tuple[int, Any, str]:
        # Ledger timestamp wins; fall back to graph `last_seen`; then lex key.
        if ledger is not None:
            ev = ledger.latest_for(engagement_id, TestCaseKeyHash(r.key_hash))
            if ev is not None:
                return (2, ev.timestamp, r.key_hash)
        if r.last_seen is not None:
            # Negate by reversing tier: keep the *latest* last_seen.
            return (1, r.last_seen, r.key_hash)
        return (0, datetime.min, r.key_hash)

    # Highest tier, then latest timestamp, then *smallest* key_hash on a tie.
    ordered = sorted(rows, key=lambda r: (sort_key(r)[0], sort_key(r)[1]), reverse=True)
    best_tier, best_ts = sort_key(ordered[0])[0], sort_key(ordered[0])[1]
    tied = [r for r in ordered if sort_key(r)[0] == best_tier and sort_key(r)[1] == best_ts]
    return min(tied, key=lambda r: r.key_hash)


def plan_migration(
    neo4j: Neo4jClient,
    engagement_id: EngagementId,
    *,
    ledger: ReviewLedger | None = None,
) -> MigrationPlan:
    """Compute the ADR-0049 re-key plan (read-only).

    Groups pre-0049 TestCases by their *new* `key_hash`; per group the survivor
    is `pick_survivor`'s choice and the rest are scheduled for retraction with a
    `MERGED_INTO` edge to the survivor. Rows whose `auth_context_id` no longer
    resolves to a Principal are surfaced as `unresolved` and left untouched.
    """

    anon_id = str(auth_context_id(engagement_id, compute_anonymous_auth_hash()))
    raw = neo4j.execute_read(FETCH_CYPHER, eid=str(engagement_id))
    rows = [
        _OldRow(
            key_hash=str(r["key_hash"]),
            test_class=str(r["test_class"]),
            target_endpoint_id=r["target_endpoint_id"],
            target_parameter_id=r["target_parameter_id"],
            target_trust_boundary_id=r["target_trust_boundary_id"],
            payload_class=str(r["payload_class"]),
            payload_hash=str(r["payload_hash"]),
            auth_context_id=str(r["auth_context_id"]),
            last_seen=r["last_seen"],
            label=r["label"],
            slot=r["slot"],
        )
        for r in raw
    ]

    by_new_key: dict[str, list[tuple[_OldRow, str, str]]] = defaultdict(list)
    unresolved: list[tuple[str, str]] = []
    for row in rows:
        attacker = _resolve_attacker(row, anonymous_id=anon_id)
        if attacker is None:
            unresolved.append((row.key_hash, row.auth_context_id))
            continue
        principal, slot = attacker
        new_key = compute_testcase_key_hash(
            engagement_id=engagement_id,
            test_class=row.test_class,  # type: ignore[arg-type]
            target_endpoint_id=row.target_endpoint_id,
            target_parameter_id=(
                ParameterId(row.target_parameter_id)
                if row.target_parameter_id is not None
                else None
            ),
            target_trust_boundary_id=(
                TrustBoundaryId(row.target_trust_boundary_id)
                if row.target_trust_boundary_id is not None
                else None
            ),
            payload_class=row.payload_class,  # type: ignore[arg-type]
            payload_hash=Sha256Hex(row.payload_hash),
            attacker_principal=principal,
            attacker_slot=slot,
        )
        by_new_key[str(new_key)].append((row, principal, slot))

    migrated: list[tuple[str, str, str, str]] = []
    retracted: list[tuple[str, str]] = []
    for nk, group in by_new_key.items():
        survivor = pick_survivor(
            [r for (r, _, _) in group], engagement_id=engagement_id, ledger=ledger
        )
        principal, slot = next((p, s) for (r, p, s) in group if r is survivor)
        migrated.append((survivor.key_hash, nk, principal, slot))
        for r, _, _ in group:
            if r is not survivor:
                retracted.append((r.key_hash, nk))

    return MigrationPlan(
        migrated=sorted(migrated),
        retracted=sorted(retracted),
        unresolved=sorted(unresolved),
    )


# ---------------------------------------------------------------------------
# Apply (writes).
# ---------------------------------------------------------------------------


def apply_migration(
    neo4j: Neo4jClient, engagement_id: EngagementId, plan: MigrationPlan
) -> None:
    """Apply a `MigrationPlan` to Neo4j (idempotent given the same plan).

    Three passes so the `MERGED_INTO` edge can target the survivor by its
    *new* key:

    1. Mark every loser `status='retracted'` (so pass-2's uniqueness guard
       never picks a loser as the colliding `other`).
    2. Per survivor: guarded re-key — if a *different* node already owns the
       new `(engagement_id, key_hash)` (the schema constraint at
       `schema.py:131`), retract into it instead of `SET`.
    3. Wire `MERGED_INTO` from each loser (matched by old key) to its
       survivor (matched by new key).
    """

    eid = str(engagement_id)

    # Pass 1: retract losers (status only — edge wired in pass 3).
    for loser_old, _ in plan.retracted:
        neo4j.execute_write(
            """
            MATCH (l:TestCase {engagement_id: $eid, key_hash: $loser})
            SET l.status = 'retracted',
                l.retracted_reason = 'adr-0049-key-migration'
            """,
            eid=eid,
            loser=loser_old,
        )

    # Pass 2: guarded re-key of survivors. If `other` already holds the new key
    # (e.g. a post-0049 proposal landed first), fold this row into it instead.
    for old, new, principal, slot in plan.migrated:
        rows = neo4j.execute_write(
            """
            MATCH (tc:TestCase {engagement_id: $eid, key_hash: $old})
            OPTIONAL MATCH (other:TestCase {engagement_id: $eid, key_hash: $new})
            WHERE other.key_hash <> $old
            WITH tc, other
            CALL {
              WITH tc, other
              WITH tc, other WHERE other IS NULL
              SET tc.attacker_principal = $principal,
                  tc.attacker_slot = $slot,
                  tc.key_hash = $new
              RETURN 'migrated' AS outcome
            UNION
              WITH tc, other
              WITH tc, other WHERE other IS NOT NULL
              SET tc.status = 'retracted',
                  tc.retracted_reason = 'adr-0049-key-migration'
              MERGE (tc)-[:MERGED_INTO]->(other)
              RETURN 'folded' AS outcome
            }
            RETURN outcome
            """,
            eid=eid,
            old=old,
            new=new,
            principal=principal,
            slot=slot,
        )
        log.info(
            "engagement.migrate.testcase",
            engagement_id=eid,
            old_key=old,
            new_key=new,
            outcome=rows[0]["outcome"] if rows else "noop",
        )

    # Pass 3: lineage edge loser→survivor (survivor now has its new key).
    for loser_old, survivor_new in plan.retracted:
        neo4j.execute_write(
            """
            MATCH (l:TestCase {engagement_id: $eid, key_hash: $loser})
            MATCH (w:TestCase {engagement_id: $eid, key_hash: $winner})
            MERGE (l)-[:MERGED_INTO]->(w)
            """,
            eid=eid,
            loser=loser_old,
            winner=survivor_new,
        )


# ---------------------------------------------------------------------------
# CLI registration.
# ---------------------------------------------------------------------------


def _build_neo4j() -> Neo4jClient:  # pragma: no cover - needs live Neo4j
    from doo.cli_env import connect_neo4j_or_exit

    return connect_neo4j_or_exit(
        os.environ.get("DOO_NEO4J_URI", "bolt://localhost:7687"),
        os.environ.get("DOO_NEO4J_USER", "neo4j"),
        os.environ.get("DOO_NEO4J_PASSWORD", "password"),
    )


def _build_ledger() -> JsonFileReviewLedger:  # pragma: no cover - filesystem
    """Default review ledger: `~/.doo/review_ledger.json` (or `DOO_REVIEW_LEDGER_PATH`)."""

    override = os.environ.get("DOO_REVIEW_LEDGER_PATH")
    if override:
        return JsonFileReviewLedger(Path(override))
    home = Path(os.path.expanduser("~"))
    return JsonFileReviewLedger(home / ".doo" / "review_ledger.json")


def register_migrate_testcase_keys(engagement_app: typer.Typer) -> None:
    """Register `doo engagement migrate-testcase-keys` onto the engagement group.

    Called from `cli.py` with a single line (mirrors `register_keepalive`).
    """

    @engagement_app.command("migrate-testcase-keys")
    def migrate_testcase_keys(  # noqa: D401 - Typer command body
        engagement_id: str = typer.Option(
            ..., "-e", "--engagement-id", help="Engagement to re-key."
        ),
        apply: bool = typer.Option(
            False, "--apply", help="Write changes (default: dry-run)."
        ),
    ) -> None:
        """Backfill `(attacker_principal, attacker_slot)` + recompute `key_hash`
        on pre-ADR-0049 TestCases. Idempotent; default is dry-run."""

        configure_logging()
        bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())
        eid = EngagementId(engagement_id)
        log.info("engagement.migrate.invoked", engagement_id=eid, apply=apply)

        neo4j = _build_neo4j()
        ledger = _build_ledger()
        plan = plan_migration(neo4j, eid, ledger=ledger)

        collisions = len({new for _, new in plan.retracted})
        typer.echo(
            f"migrated {len(plan.migrated)} · collisions {collisions} · "
            f"retracted {len(plan.retracted)} · unresolved {len(plan.unresolved)}"
        )
        for key, ac in plan.unresolved:
            typer.secho(
                f"  unresolved: key_hash={key} auth_context_id={ac}",
                fg=typer.colors.YELLOW,
            )
        if not apply:
            typer.echo("dry-run; pass --apply to write")
            return
        apply_migration(neo4j, eid, plan)
        typer.echo(
            f"applied: migrated={len(plan.migrated)} retracted={len(plan.retracted)}"
        )
