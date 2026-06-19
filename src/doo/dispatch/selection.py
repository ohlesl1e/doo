"""Selection predicate over `approved` `TestCase`s (ADR-0042).

A dispatch run drains a tester-chosen selection: filter by `generator` /
`test_class`, order by `expected_yield` desc, cap at `--limit N`. The run-level
gate keeps the human decision count proportional to *intent* ("the C2 set,
top-50"), not test count — and gives the C2 fan-out cap (grill-queue deferral)
its natural home without a planner-side hack.

Reads the graph (engagement-scoped, ADR-0017); produces `DispatchTestCase`
projections the constructor consumes.
"""

from __future__ import annotations

from doo.dispatch.executor.evidence import DispatchTestCase
from doo.dispatch.models import DispatchSelection
from doo.ids import AuthContextId, EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.queries import for_engagement


def select_testcases(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    selection: DispatchSelection,
) -> list[DispatchTestCase]:
    """Load the `approved` `TestCase`s matching `selection`, ordered by `expected_yield`.

    Only `review_status = approved` (ADR-0040: approval is "cleared for dispatch
    *consideration*"; this run is the fresh consent). `status = active` (retracted
    nodes excluded). The `generator` / `test_class` filters are AND-composed when
    both set; empty tuples mean "no filter."
    """

    frag = for_engagement(engagement_id, var="t")
    predicates = ["t.status = 'active'", "t.review_status = 'approved'"]
    params: dict[str, object] = dict(frag.parameters)
    if selection.generators:
        predicates.append("t.generator IN $generators")
        params["generators"] = list(selection.generators)
    if selection.test_classes:
        predicates.append("t.test_class IN $test_classes")
        params["test_classes"] = list(selection.test_classes)
    where = frag.and_(" AND ".join(predicates))
    limit = f"LIMIT {int(selection.limit)}" if selection.limit is not None else ""

    rows = client.execute_read(
        f"""
        MATCH (t:TestCase)
        {where}
        RETURN t.key_hash AS key_hash,
               t.test_class AS test_class,
               t.payload_class AS payload_class,
               t.auth_context_id AS auth_context_id,
               t.attacker_principal AS attacker_principal,
               t.attacker_slot AS attacker_slot,
               t.target_endpoint_id AS target_endpoint_id,
               t.target_parameter_id AS target_parameter_id,
               t.target_trust_boundary_id AS target_trust_boundary_id,
               coalesce(t.hold, []) AS hold,
               coalesce(t.replay_hazards, []) AS replay_hazards,
               coalesce(t.hazard_source_hints, []) AS hazard_source_hints,
               coalesce(t.expected_yield, 0.0) AS expected_yield,
               t.generator AS generator,
               coalesce(t.confidence, 0.99) AS confidence
        ORDER BY t.expected_yield DESC, t.key_hash ASC
        {limit}
        """,
        **params,
    )
    return [
        DispatchTestCase(
            engagement_id=engagement_id,
            key_hash=TestCaseKeyHash(str(r["key_hash"])),
            test_class=str(r["test_class"]),
            payload_class=str(r["payload_class"]),
            auth_context_id=AuthContextId(str(r["auth_context_id"])),
            target_endpoint_id=r["target_endpoint_id"],
            target_parameter_id=r["target_parameter_id"],
            target_trust_boundary_id=r["target_trust_boundary_id"],
            hold=tuple(r["hold"] or ()),
            replay_hazards=tuple(r["replay_hazards"] or ()),
            hazard_source_hints=tuple(r["hazard_source_hints"] or ()),
            expected_yield=float(r["expected_yield"]),
            generator=r["generator"],
            confidence=float(r["confidence"]),
            attacker_principal=r["attacker_principal"],
            attacker_slot=r["attacker_slot"],
        )
        for r in rows
    ]
