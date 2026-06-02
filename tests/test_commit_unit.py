"""Unit tests for the L3 commit orchestrator: idempotency + scope gate.

Uses fakes (no docker) for the Neo4j client, idempotency store, and stream
client so the orchestration logic is tested in isolation. The live Neo4j path is
exercised by the E2E integration test.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from doo.canonical.value_objects import AuthContextCue, HostRef
from doo.events.l2 import RequestObservation
from doo.ids import EngagementId, L2EventId, ObservationId, SourceId
from doo.ontology.commit import (
    CommitOrchestrator,
    EngagementScopeViolation,
)

ENG = EngagementId("eng-commit")
TRACE = "a" * 32
SPAN = "b" * 16


class _FakeNeo4j:
    """In-memory fake: records writes and answers the cohort/endpoint reads the
    re-templating pass issues, so the orchestration logic is testable without
    docker. The live re-templating SQL is exercised by the E2E integration test.
    """

    def __init__(self) -> None:
        self.writes: list[str] = []
        # The single committed observation, surfaced back to the cohort read.
        self._cohort: list[dict[str, object]] = []

    def execute_write(self, cypher: str, **params: object) -> list[dict[str, object]]:
        self.writes.append(cypher)
        # When the RO node is committed, remember it so the cohort read returns it.
        if "MERGE (r:RequestObservation" in cypher:
            self._cohort.append(
                {
                    "id": params["observation_id"],
                    "path": params["concrete_path"],
                    "qnames": params.get("query_param_names") or [],
                }
            )
        return []

    def execute_read(self, cypher: str, **params: object) -> list[dict[str, object]]:
        if "MATCH (r:RequestObservation" in cypher:
            return list(self._cohort)
        if "MATCH (e:Endpoint" in cypher and "RETURN e.id AS id" in cypher:
            return []  # no pre-existing endpoints in the fake
        if "OPTIONAL MATCH (:RequestObservation)-[hit:HIT]" in cypher:
            return [{"hits": 0}]
        return []


class _FakeIdempotency:
    def __init__(self) -> None:
        self.claimed: set[str] = set()

    def claim(self, key: str) -> bool:
        if key in self.claimed:
            return False
        self.claimed.add(key)
        return True


class _FakeStreams:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, object]]] = []

    def publish(self, stream: str, payload: dict[str, object]) -> str:
        self.published.append((stream, payload))
        return f"0-{len(self.published)}"


def _observation(engagement_id: EngagementId = ENG, source_id: str = "0|t") -> RequestObservation:
    return RequestObservation(
        event_id=L2EventId("e" * 32),
        trace_id=TRACE,  # type: ignore[arg-type]
        span_id=SPAN,  # type: ignore[arg-type]
        engagement_id=engagement_id,
        envelope_event_id=uuid4(),
        source="har",
        source_id=SourceId(source_id),
        ingested_at=datetime.now(UTC),
        observed_at=datetime.now(UTC),
        confidence=1.0,
        observation_id=ObservationId(f"{engagement_id}:har:{source_id}"),
        method="GET",
        host=HostRef(scheme="https", canonical_hostname="shop.example.com", port=None),
        concrete_path="/products",
        auth_context_cue=AuthContextCue(is_anonymous=True),
        response_status=200,
        response_size_bytes=10,
    )


def _orchestrator(
    *, expected: EngagementId | None = None
) -> tuple[CommitOrchestrator, _FakeNeo4j, _FakeIdempotency, _FakeStreams]:
    neo4j = _FakeNeo4j()
    idem = _FakeIdempotency()
    streams = _FakeStreams()
    orch = CommitOrchestrator(
        neo4j=neo4j,  # type: ignore[arg-type]
        idempotency=idem,
        streams=streams,  # type: ignore[arg-type]
        expected_engagement_id=expected,
    )
    return orch, neo4j, idem, streams


def test_first_commit_writes_nodes_and_emits_l3_events() -> None:
    orch, neo4j, _idem, streams = _orchestrator()
    result = orch.commit(_observation())
    assert result.idempotent_noop is False
    # Host, Endpoint, AuthContext+Principal, RequestObservation -> writes happened.
    assert len(neo4j.writes) >= 3
    # Five NodeCreated events emitted on l3-events.
    assert len(streams.published) == 5
    assert all(s == "l3-events" for s, _ in streams.published)
    # trace_id propagated into the emitted L3 events.
    assert all(p["trace_id"] == TRACE for _, p in streams.published)


def test_redelivery_of_same_semantic_key_is_noop() -> None:
    orch, neo4j, _idem, streams = _orchestrator()
    orch.commit(_observation())
    writes_after_first = len(neo4j.writes)
    published_after_first = len(streams.published)

    second = orch.commit(_observation())  # same source_id -> same semantic key
    assert second.idempotent_noop is True
    assert len(neo4j.writes) == writes_after_first  # no new writes
    assert len(streams.published) == published_after_first  # no new events


def test_scope_gate_refuses_mismatched_engagement() -> None:
    orch, neo4j, _idem, _streams = _orchestrator(expected=EngagementId("eng-A"))
    with pytest.raises(EngagementScopeViolation):
        orch.commit(_observation(engagement_id=EngagementId("eng-B")))
    assert neo4j.writes == []  # refused before any write


def test_scope_gate_allows_matching_engagement() -> None:
    orch, _neo4j, _idem, _streams = _orchestrator(expected=ENG)
    result = orch.commit(_observation(engagement_id=ENG))
    assert result.idempotent_noop is False
