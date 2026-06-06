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

from doo.events.l2 import L2Event, ParseFailure, RequestObservation
from doo.events.l3 import (
    EdgeCreated,
    L3Event,
    NodeCreated,
    NodeUpdated,
    PropertyChange,
)
from doo.ids import CommitId, EngagementId, HostId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import L3_EVENTS_STREAM, StreamClient
from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import bind_correlation, get_logger
from doo.ontology.identity_reconcile import reconcile_observed_identities
from doo.ontology.promotion import PromotionResult, promote_values
from doo.ontology.resolve import (
    commit_parse_failure,
    commit_request_observation,
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


@dataclass(frozen=True, slots=True)
class FlushResult:
    """Outcome of a `flush()`: dirty cohorts re-templated + the Endpoint/Parameter
    nodes touched (ADR-0022), plus the `ObservedValue`s promoted from inline value
    candidates and the `YIELDED_VALUE` edges wired (ADR-0023)."""

    cohorts: int = 0
    endpoints: int = 0
    parameters: int = 0
    retracted: int = 0
    observed_values: int = 0
    yielded_value_edges: int = 0
    # ADR-0029: synthetic discovered Principals upgraded from observed-response
    # identity, and synthetic Principals left orphaned (retracted) by that upgrade.
    observed_identity_upgrades: int = 0
    principals_retracted: int = 0
    # ADR-0029 amendment: observed identities attached as aliases to non-synthetic
    # Principals (enrichment — e.g. a JWT-keyed Principal's `/me` email).
    observed_identity_aliases: int = 0


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
        # ADR-0032: per-engagement `identity_key` override cache. Read once per
        # engagement from the Engagement node; avoids a per-observation query.
        self._identity_key_cache: dict[EngagementId, str | None] = {}

    def _get_preferred_claim(self, engagement_id: EngagementId) -> str | None:
        """Return the cached `auth.identity_key` for this engagement (ADR-0032).

        Read once per engagement from the Engagement node (a cheap property
        lookup) and stored in a dict keyed by engagement_id. Avoids a per-
        observation graph read for a value that never changes mid-engagement.
        """

        if engagement_id not in self._identity_key_cache:
            from doo.ontology.graph_state import Neo4jGraphState

            self._identity_key_cache[engagement_id] = Neo4jGraphState(
                self._neo4j
            ).get_identity_key(engagement_id)
        return self._identity_key_cache[engagement_id]

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
            preferred_claim = self._get_preferred_claim(event.engagement_id)
            result = self._commit_request_observation(event, commit_id, span_id, preferred_claim)
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
        self,
        obs: RequestObservation,
        commit_id: CommitId,
        span_id: str,
        preferred_claim: str | None = None,
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
            preferred_claim=preferred_claim,
        )
        # Commit the observation node + its non-HIT edges. Endpoint inference
        # (HIT grouping, path templating, Parameter aggregation) is DEFERRED to
        # `flush()` per ADR-0022: the observation is left un-HIT, which is exactly
        # what marks its cohort dirty. Commit stays O(1); flush re-templates the
        # cohort once per drain instead of once per observation (was O(N^2)).
        commit_request_observation(
            self._neo4j,
            obs=obs,
            host_node_id=host_node_id,
            auth_context_node_id=auth.auth_context_id,
        )
        node_ids = (
            host_node_id,
            str(auth.auth_context_id),
            str(auth.principal_id),
            str(obs.observation_id),
        )
        l3_events: tuple[L3Event, ...] = (
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
        )
        return CommitResult(
            commit_id=commit_id,
            engagement_id=obs.engagement_id,
            event_kind=obs.kind,
            source_id=obs.source_id,
            idempotent_noop=False,
            node_ids=node_ids,
            l3_events=l3_events,
        )

    # --- Deferred endpoint inference (ADR-0022): flush ----------------------

    def flush(self) -> FlushResult:
        """Re-template dirty cohorts and promote inline value candidates (ADR-0022/0023).

        `commit` leaves each `RequestObservation` un-HIT and its extracted values
        inline; this is the deferred-inference step. It:

        - finds every `(engagement_id, method, host_id)` cohort with an un-HIT
          observation and re-templates it (attaching `HIT`s, creating/retracting
          `Endpoint`s, aggregating `Parameter`s); and
        - promotes inline value candidates into `ObservedValue`s for every affected
          engagement, wiring `YIELDED_VALUE` edges (the ADR-0023 promotion pass).

        Both steps emit structural `l3-events`. Dirtiness is derived from the graph,
        so flush is crash-safe and idempotent: a fully-templated, fully-promoted
        graph has no dirty cohorts and re-promotes nothing (identity-keyed MERGEs).
        """

        dirty = self._find_dirty_cohorts()
        cohorts = endpoints = parameters = retracted = 0
        engagements: set[EngagementId] = set()
        for engagement_id, method, host_node_id in dirty:
            engagements.add(engagement_id)
            now = datetime.now(UTC)
            retemplate = retemplate_cohort(
                self._neo4j,
                engagement_id=engagement_id,
                method=method,
                host_node_id=host_node_id,
                observed_at=now,
                ingested_at=now,
            )
            trace_id = new_trace_id()
            span_id = new_span_id()
            commit_id = CommitId(new_span_id() + new_span_id())
            for l3_event in self._flush_events(
                retemplate, engagement_id, trace_id, span_id, commit_id
            ):
                self._streams.publish(L3_EVENTS_STREAM, l3_event.model_dump(mode="json"))
            cohorts += 1
            endpoints += len(retemplate.endpoint_ids)
            parameters += len(retemplate.parameter_ids)
            retracted += len(retemplate.retracted_endpoint_ids)

        # --- ADR-0023 promotion pass: inline value candidates -> ObservedValue. ---
        observed_values = yielded_value_edges = 0
        for engagement_id in sorted(engagements):
            now = datetime.now(UTC)
            promotion = promote_values(
                self._neo4j,
                engagement_id=engagement_id,
                observed_at=now,
                ingested_at=now,
            )
            trace_id = new_trace_id()
            span_id = new_span_id()
            commit_id = CommitId(new_span_id() + new_span_id())
            for l3_event in self._promotion_events(
                promotion, engagement_id, trace_id, span_id, commit_id
            ):
                self._streams.publish(L3_EVENTS_STREAM, l3_event.model_dump(mode="json"))
            observed_values += len(promotion.promoted)
            yielded_value_edges += promotion.edges

        # --- ADR-0029: upgrade synthetic discovered Principals from observed
        # response identity (headers/self-endpoint bodies), collapsing reissued
        # opaque credentials for one actor. ---
        identity_upgrades = principals_retracted = identity_aliases = 0
        for engagement_id in sorted(engagements):
            now = datetime.now(UTC)
            preferred_claim = self._get_preferred_claim(engagement_id)
            reconcile = reconcile_observed_identities(
                self._neo4j,
                engagement_id=engagement_id,
                observed_at=now,
                ingested_at=now,
                preferred_claim=preferred_claim,
            )
            identity_upgrades += reconcile.upgrades
            principals_retracted += reconcile.retracted
            identity_aliases += reconcile.aliases

        if cohorts or observed_values:
            log.info(
                "flush.applied",
                cohorts=cohorts,
                endpoints=endpoints,
                parameters=parameters,
                retracted=retracted,
                observed_values=observed_values,
                yielded_value_edges=yielded_value_edges,
                observed_identity_upgrades=identity_upgrades,
                principals_retracted=principals_retracted,
                observed_identity_aliases=identity_aliases,
            )
        return FlushResult(
            cohorts=cohorts,
            endpoints=endpoints,
            parameters=parameters,
            retracted=retracted,
            observed_values=observed_values,
            yielded_value_edges=yielded_value_edges,
            observed_identity_upgrades=identity_upgrades,
            principals_retracted=principals_retracted,
            observed_identity_aliases=identity_aliases,
        )

    def _promotion_events(
        self,
        promotion: PromotionResult,
        engagement_id: EngagementId,
        trace_id: str,
        span_id: str,
        commit_id: CommitId,
    ) -> tuple[L3Event, ...]:
        """`l3-events` for one engagement's promotion pass: a `node_created` per
        `ObservedValue` and an `edge_created` per `YIELDED_VALUE` (ADR-0023)."""

        events: list[L3Event] = []
        for pv in promotion.promoted:
            events.append(
                NodeCreated(
                    commit_id=commit_id,
                    trace_id=trace_id,  # type: ignore[arg-type]
                    span_id=span_id,  # type: ignore[arg-type]
                    engagement_id=engagement_id,
                    emitted_at=datetime.now(UTC),
                    node_type="ObservedValue",
                    node_id=str(pv.observed_value_id),
                    properties={"via": "promotion", "kind": pv.kind},
                )
            )
            for observation_id in pv.yielded_from:
                events.append(
                    EdgeCreated(
                        commit_id=commit_id,
                        trace_id=trace_id,  # type: ignore[arg-type]
                        span_id=span_id,  # type: ignore[arg-type]
                        engagement_id=engagement_id,
                        emitted_at=datetime.now(UTC),
                        edge_type="YIELDED_VALUE",
                        from_node=observation_id,
                        to_node=str(pv.observed_value_id),
                        properties={"engagement_id": engagement_id},
                    )
                )
            for observation_id in pv.sent_from:
                events.append(
                    EdgeCreated(
                        commit_id=commit_id,
                        trace_id=trace_id,  # type: ignore[arg-type]
                        span_id=span_id,  # type: ignore[arg-type]
                        engagement_id=engagement_id,
                        emitted_at=datetime.now(UTC),
                        edge_type="SENT_VALUE",
                        from_node=observation_id,
                        to_node=str(pv.observed_value_id),
                        properties={"engagement_id": engagement_id},
                    )
                )
        return tuple(events)

    def _find_dirty_cohorts(self) -> list[tuple[EngagementId, str, HostId]]:
        """Distinct `(engagement, method, host)` cohorts with un-HIT observations."""

        rows = self._neo4j.execute_read(
            """
            MATCH (r:RequestObservation)-[:ON_HOST]->(h:Host)
            WHERE NOT (r)-[:HIT]->(:Endpoint)
            RETURN DISTINCT r.engagement_id AS eng, r.method AS method, h.id AS host_id
            """
        )
        return [
            (EngagementId(str(r["eng"])), str(r["method"]), HostId(str(r["host_id"])))
            for r in rows
        ]

    def _flush_events(
        self,
        retemplate: RetemplateResult,
        engagement_id: EngagementId,
        trace_id: str,
        span_id: str,
        commit_id: CommitId,
    ) -> tuple[L3Event, ...]:
        """`l3-events` for one flushed cohort: NodeCreated per Endpoint/Parameter,
        NodeUpdated per revised `path_template` (ADR-0004 re-templating)."""

        events: list[L3Event] = []
        for eid in retemplate.endpoint_ids:
            events.append(
                self._flush_node_created(
                    "Endpoint", eid, engagement_id, trace_id, span_id, commit_id
                )
            )
        for pid in retemplate.parameter_ids:
            events.append(
                self._flush_node_created(
                    "Parameter", pid, engagement_id, trace_id, span_id, commit_id
                )
            )
        for change in retemplate.template_changes:
            events.append(
                NodeUpdated(
                    commit_id=commit_id,
                    trace_id=trace_id,  # type: ignore[arg-type]
                    span_id=span_id,  # type: ignore[arg-type]
                    engagement_id=engagement_id,
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

    @staticmethod
    def _flush_node_created(
        node_type: str,
        node_id: str,
        engagement_id: EngagementId,
        trace_id: str,
        span_id: str,
        commit_id: CommitId,
    ) -> NodeCreated:
        return NodeCreated(
            commit_id=commit_id,
            trace_id=trace_id,  # type: ignore[arg-type]
            span_id=span_id,  # type: ignore[arg-type]
            engagement_id=engagement_id,
            emitted_at=datetime.now(UTC),
            node_type=node_type,
            node_id=node_id,
            properties={"via": "flush"},
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
        event: RequestObservation | ParseFailure,
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
