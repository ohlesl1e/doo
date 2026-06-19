"""`InterpreterMode` strategy: what the confirm loop may do with `follow_ups` (ADR-0042/0045).

Two orthogonal axes govern a dispatch run (ADR-0042): `arming` (does a human press
go?) and `interpreter` (may the agent expand the target set in-run?). The MVP ships
**`confirm`** only — the Interpreter judges the one approved TestCase and any
`follow_ups` it surfaces go back through the slice-3 Validator to `proposed` for
human review; nothing it proposes dispatches in-run. **`freelance`** (the agent
acts on its own new hypotheses in-run, staging-only) is a *designed-for seam*, not
an implementation: the slot exists and raises with the ADR-0042 constraint.

Adding `freelance` later is a new strategy class, not a refactor of the driver.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from doo.dispatch.interpreter.loop import INTERPRETER_PROMPT_VERSION
from doo.dispatch.interpreter.models import FollowUpProposal
from doo.ids import AuthContextId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.commit import commit_testcase
from doo.planner.models import PlannerProposal
from doo.planner.validator import DiscardedProposal, validate
from doo.setup.config import InterpreterMode as InterpreterModeLiteral

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class FollowUpOutcome:
    """How many of a verdict's follow-ups were committed vs. discarded."""

    committed: int
    discarded: int


def _resolve_attacker_identity(
    neo4j: Neo4jClient, engagement_id: EngagementId, ac_id: AuthContextId
) -> tuple[str, str]:
    """Resolve `(attacker_principal, attacker_slot)` from an `AuthContext` (ADR-0049).

    Follow-ups inherit the parent TestCase's attacker identity via its
    `auth_context_id`; the rotation-stable `(principal_label, slot)` pair is read
    from the graph. Falls back to `("anonymous", "anonymous")` when the AC is
    anonymous or unresolvable (the follow-up is then keyed as an anon test).
    """

    frag = for_engagement(engagement_id, var="ac")
    rows = neo4j.execute_read(
        f"""
        MATCH (ac:AuthContext {{id: $acid}})-[:OF_PRINCIPAL]->(p:Principal)
        {frag.where_clause}
        RETURN coalesce(ac.is_anonymous, false) AS anon,
               p.label AS p_label, p.identity_key AS identity_key,
               coalesce(ac.slot, ac.token_kind) AS slot
        LIMIT 1
        """,
        acid=str(ac_id),
        **frag.parameters,
    )
    if not rows or bool(rows[0]["anon"]):
        return "anonymous", "anonymous"
    row = rows[0]
    principal = str(row["p_label"]) if row["p_label"] else str(row["identity_key"])
    slot = str(row["slot"]) if row["slot"] is not None else "anonymous"
    return principal, slot


class InterpreterMode(Protocol):
    """Strategy for handling the Interpreter's `follow_ups` (ADR-0042).

    Concrete strategies carry a `mode` attribute for introspection; the Protocol
    only requires the behaviour (`handle_follow_ups`).
    """

    def handle_follow_ups(
        self,
        follow_ups: tuple[FollowUpProposal, ...],
        *,
        neo4j: Neo4jClient,
        engagement_id: EngagementId,
        auth_context_id: AuthContextId,
        default_target_endpoint_id: str | None,
        now: datetime,
    ) -> FollowUpOutcome: ...


@dataclass(frozen=True, slots=True)
class ConfirmMode:
    """The MVP strategy: follow-ups → slice-3 Validator → `proposed` (human review).

    Each follow-up is mapped to a `PlannerProposal` (`generator="interpreter"`,
    `mode="llm"`, so `source="llm-interpreter"`) targeting either the current
    TestCase's endpoint (`target_handle="TARGET"`) or a named endpoint id, then run
    through the SAME `validate()` (scope / target-XOR / dedup) and `commit_testcase`
    as a Planner proposal. An invalid / out-of-scope / unresolvable follow-up is
    discarded-and-logged, never committed (ADR-0040). Nothing dispatches in-run.
    """

    mode: InterpreterModeLiteral = "confirm"

    def handle_follow_ups(
        self,
        follow_ups: tuple[FollowUpProposal, ...],
        *,
        neo4j: Neo4jClient,
        engagement_id: EngagementId,
        auth_context_id: AuthContextId,
        default_target_endpoint_id: str | None,
        now: datetime,
    ) -> FollowUpOutcome:
        committed = discarded = 0
        attacker_principal, attacker_slot = _resolve_attacker_identity(
            neo4j, engagement_id, auth_context_id
        )
        for fu in follow_ups:
            target = (
                default_target_endpoint_id
                if fu.target_handle == "TARGET"
                else fu.target_handle
            )
            if not target:
                discarded += 1
                log.warning(
                    "interpreter.follow_up_no_target",
                    engagement_id=engagement_id,
                    handle=fu.target_handle,
                )
                continue
            proposal = PlannerProposal(
                engagement_id=engagement_id,
                generator="interpreter",
                mode="llm",
                test_class=fu.test_class,
                payload_class=fu.payload_class,
                auth_context_id=auth_context_id,
                attacker_principal=attacker_principal,
                attacker_slot=attacker_slot,
                target_endpoint_id=target,
                expected_yield=0.5,
                confidence_method="llm-self-reported",
                justification=fu.justification,
                expected_outcome=fu.expected_outcome,
            )
            result = validate(neo4j, proposal)
            if isinstance(result, DiscardedProposal):
                discarded += 1
                log.info(
                    "interpreter.follow_up_discarded",
                    engagement_id=engagement_id,
                    code=result.code,
                    reason=result.reason,
                )
                continue
            commit_testcase(
                neo4j, result, now=now, code_version=INTERPRETER_PROMPT_VERSION
            )
            committed += 1
            log.info(
                "interpreter.follow_up_committed",
                engagement_id=engagement_id,
                key_hash=result.key_hash,
                test_class=fu.test_class,
            )
        return FollowUpOutcome(committed=committed, discarded=discarded)


@dataclass(frozen=True, slots=True)
class FreelanceMode:
    """The staging-only seam (ADR-0042): NOT implemented — the slot raises.

    `freelance` would let the agent act on its own new hypotheses in-run; the MVP
    forbids it. Construction is allowed (the driver may select it) but using it
    raises with the ADR-0042 constraint message.
    """

    mode: InterpreterModeLiteral = "freelance"

    def handle_follow_ups(
        self,
        follow_ups: tuple[FollowUpProposal, ...],
        *,
        neo4j: Neo4jClient,
        engagement_id: EngagementId,
        auth_context_id: AuthContextId,
        default_target_endpoint_id: str | None,
        now: datetime,
    ) -> FollowUpOutcome:
        raise NotImplementedError(
            "interpreter=freelance is a designed-for seam, not implemented in the "
            "MVP (ADR-0042: only review+confirm is representable on production, and "
            "the agent may not expand the target set in-run). Use interpreter=confirm."
        )


def select_interpreter_mode(mode: InterpreterModeLiteral) -> InterpreterMode:
    """Pick the strategy for a run's `interpreter` mode (ADR-0042)."""

    if mode == "confirm":
        return ConfirmMode()
    if mode == "freelance":
        return FreelanceMode()
    raise ValueError(f"unknown interpreter mode {mode!r}")  # unreachable (Literal)


__all__ = [
    "InterpreterMode",
    "ConfirmMode",
    "FreelanceMode",
    "FollowUpOutcome",
    "select_interpreter_mode",
]
