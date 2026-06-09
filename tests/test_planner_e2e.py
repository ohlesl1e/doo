"""End-to-end planner-spine tests over the Neo4j testcontainer (issue #60).

Asserts external behaviour over a seeded graph (the slice-2 coverage-test style):

- **propose**: an in-scope dead endpoint becomes a `forced_browsing` `TestCase`
  committed at `review_status = proposed` with the ADR-0036 provenance
  (`source = deterministic-c1`, `payload_class = no-payload`, `payload_hash =
  sha256("")`, anonymous AuthContext); an out-of-scope endpoint is discarded.
- **Validator paths**: discard on unresolvable target + out-of-scope; idempotent
  re-commit is a no-op (same node, count unchanged).
- **review lifecycle + ledger**: proposed -> approved / rejected; the audit-ledger
  event shape; denormalised node fields; permanent vs defer; the re-surface
  predicate (a deferred reject re-surfaces when target confidence rises).
- **end-to-end**: propose -> prioritised review -> approve some / reject some.

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from doo.canonical.identity import auth_context_id, compute_anonymous_auth_hash
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.schema import apply_schema
from doo.planner.commit import fetch_testcase
from doo.planner.review import (
    InMemoryReviewLedger,
    ReviewError,
    fetch_target_evidence,
    review_testcase,
)
from doo.planner.models import PayloadSpec, PlannerProposal
from doo.planner.service import propose, review_queue
from doo.planner.validator import DiscardedProposal, validate
from doo.setup.loader import PlannedMutation

_SCOPE_RULES = {
    "host_patterns": ["shop.example.com"],
    "allowed_methods": ["*"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(),
        neo4j_container.username,
        neo4j_container.password,
    )
    with client.driver.session() as session:
        apply_schema(session, edition=client.server_edition())
    try:
        yield client
    finally:
        client.close()


def _cross(now: datetime) -> dict[str, object]:
    return {
        "source": "manual",
        "source_id": None,
        "confidence": 1.0,
        "confidence_method": "manual",
        "first_seen": now,
        "last_seen": now,
        "ingested_at": now,
        "status": "active",
    }


def _seed_engagement(neo4j: Neo4jClient, engagement_id: str) -> None:
    now = datetime.now(UTC)
    state = Neo4jGraphState(neo4j)
    cross = _cross(now)
    state.apply_mutations(
        (
            PlannedMutation(
                kind="scope_create",
                properties={
                    "content_hash": f"scope-{engagement_id}",
                    "rules": _SCOPE_RULES,
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_create",
                properties={
                    "id": engagement_id,
                    "name": engagement_id,
                    "description": None,
                    "time_window": None,
                    "kill_switch": {"backend": "redis"},
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_under_scope",
                properties={
                    "engagement_id": engagement_id,
                    "scope_content_hash": f"scope-{engagement_id}",
                },
            ),
        )
    )


def _add_host(
    neo4j: Neo4jClient, *, engagement_id: str, host_id: str, hostname: str
) -> None:
    now = datetime.now(UTC)
    neo4j.execute_write(
        """
        MERGE (h:Host {engagement_id: $eid, id: $hid})
        ON CREATE SET h.scheme = 'https', h.canonical_hostname = $hostname,
                      h.port = null, h.is_ip_literal = false, h += $props
        """,
        eid=engagement_id,
        hid=host_id,
        hostname=hostname,
        props=_cross(now),
    )


def _add_dead_endpoint(
    neo4j: Neo4jClient,
    *,
    engagement_id: str,
    endpoint_id: str,
    host_id: str,
    method: str,
    path_template: str,
    last_seen: datetime | None = None,
) -> None:
    """An active Endpoint with NO HIT edge — what C1 surfaces."""

    now = datetime.now(UTC)
    props = _cross(now)
    if last_seen is not None:
        props = {**props, "last_seen": last_seen}
    neo4j.execute_write(
        """
        MERGE (e:Endpoint {engagement_id: $eid, method: $method,
                           host_id: $hid, path_template: $pt})
        ON CREATE SET e.id = $epid, e += $props
        WITH e
        MATCH (h:Host {engagement_id: $eid, id: $hid})
        MERGE (e)-[:ON_HOST]->(h)
        """,
        eid=engagement_id,
        epid=endpoint_id,
        method=method,
        hid=host_id,
        pt=path_template,
        props=props,
    )


def _count_testcases(neo4j: Neo4jClient, engagement_id: str) -> int:
    rows = neo4j.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid}) RETURN count(t) AS n",
        eid=engagement_id,
    )
    return int(rows[0]["n"])


# ---------------------------------------------------------------------------
# propose
# ---------------------------------------------------------------------------


def test_propose_commits_forced_browsing_for_dead_endpoint(neo4j_client) -> None:
    eid = "eng-planner-propose"
    _seed_engagement(neo4j_client, eid)
    _add_host(neo4j_client, engagement_id=eid, host_id="h1", hostname="shop.example.com")
    _add_dead_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-admin",
        host_id="h1",
        method="GET",
        path_template="/admin/dashboard",
    )
    # An out-of-scope dead endpoint must be discarded by the validator, not committed.
    _add_host(neo4j_client, engagement_id=eid, host_id="h2", hostname="sso.partner.test")
    _add_dead_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-oos",
        host_id="h2",
        method="GET",
        path_template="/login",
    )

    result = propose(neo4j_client, engagement_id=EngagementId(eid))

    assert result.committed == 1
    assert result.created == 1
    # The out-of-scope candidate was surfaced by C1 (in-scope filter inside run_c1
    # already excludes it), so the only discards (if any) are not the in-scope one.
    assert _count_testcases(neo4j_client, eid) == 1

    key_hash = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key_hash)
    assert node is not None
    assert node.test_class == "forced_browsing"
    assert node.payload_class == "no-payload"
    assert node.source == "deterministic-c1"
    assert node.review_status == "proposed"
    assert node.target_endpoint_id == "ep-admin"

    # payload_hash = sha256("") and anonymous AuthContext (ADR-0007/0036).
    rows = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k}) "
        "RETURN t.payload_hash AS ph, t.auth_context_id AS ac, t.confidence AS c, "
        "t.expected_yield AS y, t.confidence_method AS cm",
        eid=eid,
        k=key_hash,
    )
    assert rows[0]["ph"] == hashlib.sha256(b"").hexdigest()
    assert rows[0]["ac"] == auth_context_id(
        EngagementId(eid), compute_anonymous_auth_hash()
    )
    # confidence = validity (high); expected_yield is the separate hunch.
    assert rows[0]["c"] > rows[0]["y"]
    assert rows[0]["cm"] == "heuristic"

    # The TARGETS_ENDPOINT edge wired to the right endpoint (XOR).
    edge = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k})"
        "-[:TARGETS_ENDPOINT]->(e:Endpoint) RETURN e.id AS id",
        eid=eid,
        k=key_hash,
    )
    assert edge[0]["id"] == "ep-admin"


def test_propose_is_idempotent(neo4j_client) -> None:
    eid = "eng-planner-idem"
    _seed_engagement(neo4j_client, eid)
    _add_host(neo4j_client, engagement_id=eid, host_id="h1", hostname="shop.example.com")
    _add_dead_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-1",
        host_id="h1",
        method="GET",
        path_template="/a",
    )
    first = propose(neo4j_client, engagement_id=EngagementId(eid))
    assert first.created == 1 and first.idempotent == 0
    before = _count_testcases(neo4j_client, eid)

    second = propose(neo4j_client, engagement_id=EngagementId(eid))
    assert second.created == 0 and second.idempotent == 1
    # No new node — content-addressed no-op (ADR-0007).
    assert _count_testcases(neo4j_client, eid) == before == 1


# ---------------------------------------------------------------------------
# Validator discard paths
# ---------------------------------------------------------------------------


def _proposal(eid: str, endpoint_id: str) -> PlannerProposal:
    return PlannerProposal(
        engagement_id=EngagementId(eid),
        generator="c1",
        mode="deterministic",
        test_class="forced_browsing",
        payload_class="no-payload",
        payload_spec=PayloadSpec(kind="none"),
        auth_context_id=auth_context_id(EngagementId(eid), compute_anonymous_auth_hash()),
        target_endpoint_id=endpoint_id,
        expected_yield=0.4,
        justification="test",
        expected_outcome="something",
    )


def test_validator_discards_unresolvable_target(neo4j_client) -> None:
    eid = "eng-planner-unresolvable"
    _seed_engagement(neo4j_client, eid)
    outcome = validate(neo4j_client, _proposal(eid, "ep-does-not-exist"))
    assert isinstance(outcome, DiscardedProposal)
    assert outcome.code == "unresolvable_target"


def test_validator_discards_out_of_scope_target(neo4j_client) -> None:
    eid = "eng-planner-oos"
    _seed_engagement(neo4j_client, eid)
    _add_host(neo4j_client, engagement_id=eid, host_id="h2", hostname="sso.partner.test")
    _add_dead_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-oos",
        host_id="h2",
        method="GET",
        path_template="/login",
    )
    outcome = validate(neo4j_client, _proposal(eid, "ep-oos"))
    assert isinstance(outcome, DiscardedProposal)
    assert outcome.code == "out_of_scope"


# ---------------------------------------------------------------------------
# Review lifecycle + ledger
# ---------------------------------------------------------------------------


def _propose_one(neo4j_client, eid: str, path: str = "/admin") -> str:
    _seed_engagement(neo4j_client, eid)
    _add_host(neo4j_client, engagement_id=eid, host_id="h1", hostname="shop.example.com")
    _add_dead_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-1",
        host_id="h1",
        method="GET",
        path_template=path,
    )
    result = propose(neo4j_client, engagement_id=EngagementId(eid))
    return str(result.committed_key_hashes[0])


def test_review_approve_records_ledger_and_denormalises(neo4j_client) -> None:
    eid = "eng-planner-approve"
    key_hash = _propose_one(neo4j_client, eid)
    ledger = InMemoryReviewLedger()

    evidence = fetch_target_evidence(neo4j_client, EngagementId(eid), key_hash)  # type: ignore[arg-type]
    result = review_testcase(
        neo4j_client,
        ledger,
        engagement_id=EngagementId(eid),
        key_hash=key_hash,  # type: ignore[arg-type]
        decision="approve",
        actor="alice",
        reason="looks worth probing",
        evidence=evidence,
    )
    assert result.prior_status == "proposed"
    assert result.new_status == "approved"

    # Ledger event shape (ADR-0040).
    events = ledger.events_for(EngagementId(eid), key_hash)  # type: ignore[arg-type]
    assert len(events) == 1
    ev = events[0]
    assert ev.actor == "alice"
    assert ev.decision == "approve"
    assert ev.disposition is None
    assert ev.prior_status == "proposed" and ev.new_status == "approved"

    # Denormalised node fields.
    node = fetch_testcase(neo4j_client, EngagementId(eid), key_hash)  # type: ignore[arg-type]
    assert node is not None and node.review_status == "approved"
    rows = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k}) "
        "RETURN t.reviewed_by AS by, t.review_reason AS reason",
        eid=eid,
        k=key_hash,
    )
    assert rows[0]["by"] == "alice"
    assert rows[0]["reason"] == "looks worth probing"


def test_review_reject_requires_disposition(neo4j_client) -> None:
    eid = "eng-planner-reject-nodisp"
    key_hash = _propose_one(neo4j_client, eid)
    ledger = InMemoryReviewLedger()
    evidence = fetch_target_evidence(neo4j_client, EngagementId(eid), key_hash)  # type: ignore[arg-type]
    with pytest.raises(ReviewError):
        review_testcase(
            neo4j_client,
            ledger,
            engagement_id=EngagementId(eid),
            key_hash=key_hash,  # type: ignore[arg-type]
            decision="reject",
            actor="alice",
            disposition=None,
            evidence=evidence,
        )


def test_rejected_kept_and_permanent_never_resurfaces(neo4j_client) -> None:
    eid = "eng-planner-permanent"
    key_hash = _propose_one(neo4j_client, eid)
    ledger = InMemoryReviewLedger()
    evidence = fetch_target_evidence(neo4j_client, EngagementId(eid), key_hash)  # type: ignore[arg-type]
    review_testcase(
        neo4j_client,
        ledger,
        engagement_id=EngagementId(eid),
        key_hash=key_hash,  # type: ignore[arg-type]
        decision="reject",
        actor="alice",
        reason="not applicable",
        disposition="permanent",
        evidence=evidence,
    )
    # Node is KEPT (not deleted) with review_status = rejected.
    node = fetch_testcase(neo4j_client, EngagementId(eid), key_hash)  # type: ignore[arg-type]
    assert node is not None and node.review_status == "rejected"
    # Not in the proposed queue, and a permanent reject never re-surfaces.
    q = review_queue(neo4j_client, ledger, engagement_id=EngagementId(eid))
    assert q == []


def test_deferred_reject_resurfaces_on_confidence_rise(neo4j_client) -> None:
    eid = "eng-planner-defer"
    _seed_engagement(neo4j_client, eid)
    _add_host(neo4j_client, engagement_id=eid, host_id="h1", hostname="shop.example.com")
    # Endpoint last seen ~120 days ago: at rejection time its decayed confidence
    # is low. We reject 'defer', then make the endpoint fresh so confidence rises.
    stale = datetime.now(UTC) - timedelta(days=120)
    _add_dead_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-1",
        host_id="h1",
        method="GET",
        path_template="/admin",
        last_seen=stale,
    )
    result = propose(neo4j_client, engagement_id=EngagementId(eid))
    key_hash = str(result.committed_key_hashes[0])
    ledger = InMemoryReviewLedger()

    # Reject 'defer' against the stale (low-confidence) evidence.
    evidence = fetch_target_evidence(neo4j_client, EngagementId(eid), key_hash)  # type: ignore[arg-type]
    assert evidence.effective_confidence < 0.2
    review_testcase(
        neo4j_client,
        ledger,
        engagement_id=EngagementId(eid),
        key_hash=key_hash,  # type: ignore[arg-type]
        decision="reject",
        actor="alice",
        reason="not worth it yet",
        disposition="defer",
        evidence=evidence,
    )
    # Still suppressed while nothing changed.
    assert review_queue(neo4j_client, ledger, engagement_id=EngagementId(eid)) == []

    # Evidence materially improves: bump the endpoint's last_seen to now.
    neo4j_client.execute_write(
        "MATCH (e:Endpoint {engagement_id: $eid, id: 'ep-1'}) SET e.last_seen = $now",
        eid=eid,
        now=datetime.now(UTC),
    )
    q = review_queue(neo4j_client, ledger, engagement_id=EngagementId(eid))
    assert len(q) == 1
    assert q[0].resurfaced is True
    assert q[0].resurfaced_reason is not None


# ---------------------------------------------------------------------------
# End-to-end: propose -> prioritised review -> approve some / reject some
# ---------------------------------------------------------------------------


def test_end_to_end_propose_then_review(neo4j_client) -> None:
    eid = "eng-planner-e2e"
    _seed_engagement(neo4j_client, eid)
    _add_host(neo4j_client, engagement_id=eid, host_id="h1", hostname="shop.example.com")
    for i, path in enumerate(["/admin", "/secret", "/internal"]):
        _add_dead_endpoint(
            neo4j_client,
            engagement_id=eid,
            endpoint_id=f"ep-{i}",
            host_id="h1",
            method="GET",
            path_template=path,
        )

    result = propose(neo4j_client, engagement_id=EngagementId(eid))
    assert result.committed == 3

    ledger = InMemoryReviewLedger()
    queue = review_queue(neo4j_client, ledger, engagement_id=EngagementId(eid))
    assert len(queue) == 3
    # Deterministically prioritised (descending score), all proposed.
    scores = [v.priority_score for v in queue]
    assert scores == sorted(scores, reverse=True)
    assert all(v.review_status == "proposed" for v in queue)

    # Approve the first, reject the second (defer), leave the third.
    first, second = queue[0].key_hash, queue[1].key_hash
    review_testcase(
        neo4j_client,
        ledger,
        engagement_id=EngagementId(eid),
        key_hash=first,
        decision="approve",
        actor="alice",
        evidence=fetch_target_evidence(neo4j_client, EngagementId(eid), first),
    )
    review_testcase(
        neo4j_client,
        ledger,
        engagement_id=EngagementId(eid),
        key_hash=second,
        decision="reject",
        actor="bob",
        disposition="defer",
        reason="low value",
        evidence=fetch_target_evidence(neo4j_client, EngagementId(eid), second),
    )

    # Only the untouched proposal remains in the queue.
    remaining = review_queue(neo4j_client, ledger, engagement_id=EngagementId(eid))
    assert [v.review_status for v in remaining] == ["proposed"]
    assert len(remaining) == 1

    # Ledger has exactly the two decisions; nothing dispatched (no EXECUTED_AS).
    assert len(ledger.events_for(EngagementId(eid), first)) == 1
    assert len(ledger.events_for(EngagementId(eid), second)) == 1
    exec_edges = neo4j_client.execute_read(
        "MATCH (:TestCase {engagement_id: $eid})-[r:EXECUTED_AS]->() RETURN count(r) AS n",
        eid=eid,
    )
    assert int(exec_edges[0]["n"]) == 0
