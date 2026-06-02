"""L3 commit orchestrator (slice-1 T2).

Consumes `L2Event`s and commits them to Neo4j, with:

- **Semantic-key idempotency** (ADR-0016): a Redis `SETNX` on
  `commit:{engagement_id}:{event_kind}:{source}:{source_id}`. The first commit of
  a semantic key wins; re-delivered events (parser-replay, at-least-once stream
  delivery) short-circuit to a no-op. This is distinct from L1's blob-hash key
  and L2's per-emission `event_id`.
- **Commit-time engagement-scoping gate** (ADR-0017): the inbound event's
  `engagement_id` is the only engagement any node may be stamped with this
  commit; entity resolution stamps exactly that id, and the resolvers never
  create cross-engagement edges (every MATCH is engagement-scoped). The gate
  here is a defensive assertion before any write.
- **L3Event emission**: each commit pushes structural `NodeCreated` events onto
  `l3-events` so consumers (planner/coverage/audit) can compose meaning.

`trace_id` propagates unchanged from the envelope through L2 into the emitted
L3 events (ADR-0018); this layer derives a child `span_id`.

No LLM here — deterministic commit only (CLAUDE.md hard rule).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from doo.events.l2 import L2Event, ParseFailure, RequestObservation, ResponseArtifact
from doo.events.l3 import (
    EdgeCreated,
    L3Event,
    NodeCreated,
    NodeUpdated,
    PropertyChange,
)
from doo.ids import CommitId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import L3_EVENTS_STREAM, StreamClient
from doo.observability.ids import new_span_id
from doo.observability.logging import bind_correlation, get_logger
from doo.ontology.resolve import (
    commit_parse_failure,
    commit_request_observation,
    commit_response_artifact,
    resolve_auth_context,
    resolve_host,
)
from doo.ontology.templating import RetemplateResult, retemplate_cohort

log = get_logger(__name__)


class IdempotencyStore(Protocol):
    """Duck-type for the semantic-key store (Redis `SETNX`).

    `claim` returns True if this process is the first to claim the key (the
    commit should proceed) and False if the key already existed (no-op).
    """

    def claim(self, key: str) -> bool: ...


class RedisSetNX:
    """Redis-backed `IdempotencyStore` using `SET key 1 NX`.

    Keys persist for the engagement's lifetime by default (no TTL) so a
    parser-replay weeks later still no-ops; pass `ttl_seconds` to bound them.
    """

    def __init__(self, client: object, *, ttl_seconds: int | None = None) -> None:
        self._client = client
        self._ttl = ttl_seconds

    def claim(self, key: str) -> bool:
        # redis-py `set(..., nx=True)` returns True on set, None if it existed.
        result = self._client.set(key, "1", nx=True, ex=self._ttl)  # type: ignore[attr-defined]
        return bool(result)


def semantic_key(engagement_id: EngagementId, event_kind: str, source: str, source_id: str) -> str:
    """ADR-0016 semantic idempotency key: `commit:{eng}:{kind}:{source}:{source_id}`."""

    return f"commit:{engagement_id}:{event_kind}:{source}:{source_id}"


class EngagementScopeViolation(Exception):
    """A commit attempted to stamp a node with a mismatched engagement_id."""


@dataclass(frozen=True, slots=True)
class CommitResult:
    """Outcome of committing one `L2Event`."""

    commit_id: CommitId
    engagement_id: EngagementId
    event_kind: str
    source_id: str
    idempotent_noop: bool
    node_ids: tuple[str, ...] = ()
    l3_events: tuple[L3Event, ...] = field(default_factory=tuple)


class CommitOrchestrator:
    """Commits `L2Event`s to the graph with idempotency + scope enforcement."""

    def __init__(
        self,
        *,
        neo4j: Neo4jClient,
        idempotency: IdempotencyStore,
        streams: StreamClient,
        expected_engagement_id: EngagementId | None = None,
    ) -> None:
        self._neo4j = neo4j
        self._idempotency = idempotency
        self._streams = streams
        # When set, every committed event must match this engagement (the
        # commit-time scoping gate; ADR-0017). The worker sets it per-envelope.
        self._expected_engagement_id = expected_engagement_id

    def commit(self, event: L2Event) -> CommitResult:
        """Commit one event; idempotent on its semantic key (ADR-0016)."""

        commit_id = CommitId(new_span_id() + new_span_id())
        span_id = new_span_id()
        bind_correlation(
            trace_id=event.trace_id, span_id=span_id, engagement_id=event.engagement_id
        )

        # --- Commit-time engagement-scoping gate (ADR-0017). ---
        if (
            self._expected_engagement_id is not None
            and event.engagement_id != self._expected_engagement_id
        ):
            raise EngagementScopeViolation(
                f"event engagement_id {event.engagement_id!r} != expected "
                f"{self._expected_engagement_id!r}; cross-engagement commit refused"
            )

        key = semantic_key(
            event.engagement_id, event.kind, event.source, event.source_id
        )
        if not self._idempotency.claim(key):
            log.info("commit.idempotent_noop", semantic_key=key, kind=event.kind)
            return CommitResult(
                commit_id=commit_id,
                engagement_id=event.engagement_id,
                event_kind=event.kind,
                source_id=event.source_id,
                idempotent_noop=True,
            )

        if isinstance(event, RequestObservation):
            result = self._commit_request_observation(event, commit_id, span_id)
        elif isinstance(event, ResponseArtifact):
            result = self._commit_response_artifact(event, commit_id, span_id)
        elif isinstance(event, ParseFailure):
            result = self._commit_parse_failure(event, commit_id, span_id)
        else:  # pragma: no cover - the union is exhaustive above
            log.warning("commit.unsupported_event_kind", kind=event.kind)
            return CommitResult(
                commit_id=commit_id,
                engagement_id=event.engagement_id,
                event_kind=event.kind,
                source_id=event.source_id,
                idempotent_noop=False,
            )

        for l3_event in result.l3_events:
            self._streams.publish(L3_EVENTS_STREAM, l3_event.model_dump(mode="json"))
        log.info(
            "commit.applied",
            kind=event.kind,
            commit_id=commit_id,
            node_count=len(result.node_ids),
        )
        return result

    def _commit_request_observation(
        self, obs: RequestObservation, commit_id: CommitId, span_id: str
    ) -> CommitResult:
        host_node_id = resolve_host(
            self._neo4j,
            engagement_id=obs.engagement_id,
            host=obs.host,
            observed_at=obs.observed_at,
            ingested_at=obs.ingested_at,
        )
        auth = resolve_auth_context(
            self._neo4j,
            engagement_id=obs.engagement_id,
            observed_at=obs.observed_at,
            ingested_at=obs.ingested_at,
            cue=obs.auth_context_cue,
        )
        # Commit the observation node + its non-HIT edges first, so the
        # re-templating pass sees it in the cohort it reads back.
        commit_request_observation(
            self._neo4j,
            obs=obs,
            host_node_id=host_node_id,
            auth_context_node_id=auth.auth_context_id,
        )
        # Endpoint identity is a revisable inference (ADR-0004): re-template the
        # whole (method, host) cohort, which owns Endpoint creation, HIT
        # re-grouping, and Parameter aggregation.
        retemplate = retemplate_cohort(
            self._neo4j,
            engagement_id=obs.engagement_id,
            method=obs.method,
            host_node_id=host_node_id,
            observed_at=obs.observed_at,
            ingested_at=obs.ingested_at,
            primary_concrete_path=obs.concrete_path,
        )

        base_node_ids = (
            host_node_id,
            str(auth.auth_context_id),
            str(auth.principal_id),
            str(obs.observation_id),
        )
        node_ids = base_node_ids + retemplate.endpoint_ids + retemplate.parameter_ids
        l3_events = (
            self._node_created("Host", host_node_id, obs, commit_id, span_id),
            self._node_created(
                "AuthContext", str(auth.auth_context_id), obs, commit_id, span_id
            ),
            self._node_created(
                "Principal", str(auth.principal_id), obs, commit_id, span_id
            ),
            self._node_created(
                "RequestObservation", str(obs.observation_id), obs, commit_id, span_id
            ),
        ) + self._templating_events(retemplate, obs, commit_id, span_id)
        return CommitResult(
            commit_id=commit_id,
            engagement_id=obs.engagement_id,
            event_kind=obs.kind,
            source_id=obs.source_id,
            idempotent_noop=False,
            node_ids=node_ids,
            l3_events=l3_events,
        )

    def _templating_events(
        self,
        retemplate: RetemplateResult,
        obs: RequestObservation,
        commit_id: CommitId,
        span_id: str,
    ) -> tuple[L3Event, ...]:
        """Translate a re-templating result into l3-events.

        `node_created` for every Endpoint/Parameter MERGEd this pass, and
        `node_updated` carrying `{path_template: {old, new}}` for each Endpoint
        whose template was revised by fresh evidence (ADR-0004 re-templating).
        Re-emitting NodeCreated for already-present nodes is acceptable —
        consumers treat l3-events as idempotent structural facts.
        """

        events: list[L3Event] = []
        for eid in retemplate.endpoint_ids:
            events.append(self._node_created("Endpoint", eid, obs, commit_id, span_id))
        for pid in retemplate.parameter_ids:
            events.append(self._node_created("Parameter", pid, obs, commit_id, span_id))
        for change in retemplate.template_changes:
            events.append(
                NodeUpdated(
                    commit_id=commit_id,
                    trace_id=obs.trace_id,
                    span_id=span_id,  # type: ignore[arg-type]
                    engagement_id=obs.engagement_id,
                    emitted_at=datetime.now(UTC),
                    node_type="Endpoint",
                    node_id=change.endpoint_id,
                    changed_properties={
                        "path_template": PropertyChange(
                            old=change.old_template, new=change.new_template
                        )
                    },
                )
            )
        return tuple(events)

    def _commit_response_artifact(
        self, artifact: ResponseArtifact, commit_id: CommitId, span_id: str
    ) -> CommitResult:
        """Commit a `ResponseArtifact` node + its `YIELDED` edge from the parent RO.

        Idempotency is already enforced upstream by the semantic-key `SETNX` in
        `commit` (the artifact's deterministic `source_id`), so by the time we are
        here this is a first-delivery commit. The MERGE in `commit_response_artifact`
        is still identity-keyed for correctness under any unexpected replay.
        """

        commit_response_artifact(self._neo4j, artifact=artifact)
        l3_events: tuple[L3Event, ...] = (
            self._node_created(
                "ResponseArtifact", str(artifact.artifact_id), artifact, commit_id, span_id
            ),
            EdgeCreated(
                commit_id=commit_id,
                trace_id=artifact.trace_id,
                span_id=span_id,  # type: ignore[arg-type]
                engagement_id=artifact.engagement_id,
                emitted_at=datetime.now(UTC),
                edge_type="YIELDED",
                from_node=str(artifact.request_observation_id),
                to_node=str(artifact.artifact_id),
                properties={"engagement_id": artifact.engagement_id},
            ),
        )
        return CommitResult(
            commit_id=commit_id,
            engagement_id=artifact.engagement_id,
            event_kind=artifact.kind,
            source_id=artifact.source_id,
            idempotent_noop=False,
            node_ids=(str(artifact.artifact_id),),
            l3_events=l3_events,
        )

    def _commit_parse_failure(
        self, pf: ParseFailure, commit_id: CommitId, span_id: str
    ) -> CommitResult:
        commit_parse_failure(self._neo4j, pf=pf)
        l3_events = (
            self._node_created(
                "ParseFailure", str(pf.observation_id), pf, commit_id, span_id
            ),
        )
        return CommitResult(
            commit_id=commit_id,
            engagement_id=pf.engagement_id,
            event_kind=pf.kind,
            source_id=pf.source_id,
            idempotent_noop=False,
            node_ids=(str(pf.observation_id),),
            l3_events=l3_events,
        )

    @staticmethod
    def _node_created(
        node_type: str,
        node_id: str,
        event: RequestObservation | ParseFailure | ResponseArtifact,
        commit_id: CommitId,
        span_id: str,
    ) -> NodeCreated:
        return NodeCreated(
            commit_id=commit_id,
            trace_id=event.trace_id,
            span_id=span_id,  # type: ignore[arg-type]
            engagement_id=event.engagement_id,
            emitted_at=datetime.now(UTC),
            node_type=node_type,
            node_id=node_id,
            properties={"source_id": event.source_id},
        )
