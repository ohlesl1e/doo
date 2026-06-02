"""Entity resolution (slice-1 T2, deep module D — minimal subset).

Deterministic resolvers that MERGE the observation- and inference-layer nodes a
single `RequestObservation` implies, all engagement-scoped per ADR-0017:

- `resolve_host` — Host identity `(engagement_id, scheme, canonical_hostname,
  port)`; engagement-scoped (two engagements observing the same hostname get two
  Host nodes).
- `resolve_auth_context` — anonymous singleton only: exactly one anonymous
  AuthContext + one anonymous Principal per engagement (CONTEXT.md / ADR-0010).
- `commit_request_observation` — the RequestObservation node plus its non-`HIT`
  structural edges (`OBSERVED_UNDER` to AuthContext, `ON_HOST` to Host). The
  revisable `HIT` -> Endpoint grouping is owned by `ontology/templating.py`.
- `commit_parse_failure` — the ParseFailure node with a back-ref edge to the
  envelope (recorded as a property; the envelope is an L1 artifact, not a graph
  node, so the back-ref is `envelope_event_id`).

Every MERGE stamps the seven cross-cutting fields + `status` (ADR-0005). Writes
go through the injected `Neo4jClient`. The commit-time scoping gate
(`assert_engagement`) lives in `commit.py` and wraps these.

No LLM here — deterministic resolution only (CLAUDE.md hard rule).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from doo.canonical.identity import (
    ANONYMOUS_TOKEN_KIND,
    anonymous_principal_identity_key,
    auth_context_id,
    compute_anonymous_auth_hash,
    host_id,
    principal_id,
)
from doo.canonical.value_objects import HostRef
from doo.events.l2 import ParseFailure, RequestObservation
from doo.ids import (
    AuthContextId,
    EngagementId,
    HostId,
    ObservationId,
    PrincipalId,
)
from doo.infra.neo4j_driver import Neo4jClient

# Source tag for these structural commits: the originating ingestion source.
# Slice-1 only ingests HAR, so observations carry `source = "har"`. Inference
# nodes (Endpoint) created deterministically carry `deterministic-templating`.


def cross_cutting(
    *,
    source: str,
    source_id: str | None,
    observed_at: datetime,
    ingested_at: datetime,
    confidence: float = 1.0,
) -> dict[str, object]:
    """The seven ADR-0005 fields + status, as a Cypher params dict.

    `first_seen`/`last_seen` are the event time (`observed_at`); `ingested_at` is
    transaction time. Confidence is 1.0 for clean deterministic facts; the
    templating pass passes a lower value for cold-start inferences.
    """

    return {
        "source": source,
        "source_id": source_id,
        "confidence": confidence,
        "confidence_method": "heuristic",
        "first_seen": observed_at,
        "last_seen": observed_at,
        "ingested_at": ingested_at,
        "status": "active",
    }


@dataclass(frozen=True, slots=True)
class AnonymousIdentity:
    """The per-engagement anonymous singleton (AuthContext + Principal)."""

    auth_context_id: AuthContextId
    principal_id: PrincipalId


def resolve_host(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    host: HostRef,
    observed_at: datetime,
    ingested_at: datetime,
) -> HostId:
    """MERGE the engagement-scoped `Host` node; return its id (ADR-0017)."""

    node_id = host_id(engagement_id, host)
    props = cross_cutting(
        source="har", source_id=None, observed_at=observed_at, ingested_at=ingested_at
    )
    # MERGE on the deterministic `id` (a hash of the full identity tuple) rather
    # than on the tuple itself: Neo4j forbids null properties in a MERGE key, and
    # `port` is null for scheme-default ports. The tuple is set as properties so
    # the `(engagement_id, scheme, canonical_hostname, port)` uniqueness
    # constraint still backs non-null-port hosts; `id` backs idempotency for all.
    client.execute_write(
        """
        MERGE (h:Host {engagement_id: $engagement_id, id: $id})
        ON CREATE SET h.scheme = $scheme, h.canonical_hostname = $canonical_hostname,
                      h.port = $port, h.is_ip_literal = $is_ip_literal, h += $props
        ON MATCH SET h.last_seen = $props.last_seen
        """,
        engagement_id=engagement_id,
        scheme=host.scheme,
        canonical_hostname=host.canonical_hostname,
        port=host.port,
        id=node_id,
        is_ip_literal=host.is_ip_literal,
        props=props,
    )
    return node_id


def resolve_auth_context(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> AnonymousIdentity:
    """MERGE the anonymous singleton: one AuthContext + one Principal per engagement.

    Both MERGE on engagement-scoped identity, so re-running is a no-op and the
    singleton invariant holds (CONTEXT.md: anonymous is a singleton per
    Engagement).
    """

    auth_hash = compute_anonymous_auth_hash()
    ac_id = auth_context_id(engagement_id, auth_hash)
    p_key = anonymous_principal_identity_key()
    p_id = principal_id(engagement_id, p_key)

    ac_props = cross_cutting(
        source="har", source_id=None, observed_at=observed_at, ingested_at=ingested_at
    )
    p_props = cross_cutting(
        source="har", source_id=None, observed_at=observed_at, ingested_at=ingested_at
    )
    client.execute_write(
        """
        MERGE (p:Principal {engagement_id: $engagement_id, identity_key: $identity_key})
        ON CREATE SET p.id = $principal_id, p.tier = 'discovered', p.is_anonymous = true,
                      p += $p_props
        ON MATCH SET p.last_seen = $p_props.last_seen
        MERGE (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        ON CREATE SET ac.id = $auth_context_id, ac.token_kind = $token_kind,
                      ac.is_anonymous = true, ac += $ac_props
        ON MATCH SET ac.last_seen = $ac_props.last_seen
        MERGE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        engagement_id=engagement_id,
        identity_key=p_key,
        principal_id=p_id,
        auth_hash=auth_hash,
        auth_context_id=ac_id,
        token_kind=ANONYMOUS_TOKEN_KIND,
        ac_props=ac_props,
        p_props=p_props,
    )
    return AnonymousIdentity(auth_context_id=ac_id, principal_id=p_id)


def commit_request_observation(
    client: Neo4jClient,
    *,
    obs: RequestObservation,
    host_node_id: HostId,
    auth_context_node_id: AuthContextId,
) -> ObservationId:
    """MERGE the `RequestObservation` node and its non-`HIT` structural edges.

    Edges created here: `OBSERVED_UNDER` -> AuthContext, `ON_HOST` -> Host.
    Identity `(engagement_id, observation_id)`, so re-delivery converges.

    The `HIT` -> Endpoint edge is **not** created here. `HIT` is the revisable
    grouping inference (ADR-0004); it is owned by the re-templating pass
    (`ontology/templating.py`) which decides the path-template over the whole
    `(method, host)` cohort and re-groups `HIT` edges as evidence accumulates.

    The observed query-parameter names are stored on the node (`query_param_names`)
    so the L3 Parameter-aggregation pass can roll them up without re-reading the
    object store; path-position Parameters come from templating.
    """

    props = cross_cutting(
        source=obs.source,
        source_id=obs.source_id,
        observed_at=obs.observed_at,
        ingested_at=obs.ingested_at,
    )
    query_param_names = [p.name for p in obs.query_params]
    client.execute_write(
        """
        MERGE (r:RequestObservation {engagement_id: $engagement_id,
                                     observation_id: $observation_id})
        ON CREATE SET r.id = $observation_id, r.method = $method,
                      r.concrete_path = $concrete_path, r.query_string = $query_string,
                      r.query_param_names = $query_param_names,
                      r.response_status = $response_status,
                      r.envelope_event_id = $envelope_event_id,
                      r += $props
        ON MATCH SET r.last_seen = $props.last_seen
        WITH r
        MATCH (h:Host {engagement_id: $engagement_id, id: $host_id})
        MATCH (ac:AuthContext {engagement_id: $engagement_id, id: $auth_context_id})
        MERGE (r)-[:ON_HOST]->(h)
        MERGE (r)-[:OBSERVED_UNDER]->(ac)
        """,
        engagement_id=obs.engagement_id,
        observation_id=obs.observation_id,
        method=obs.method,
        concrete_path=obs.concrete_path,
        query_string=obs.query_string,
        query_param_names=query_param_names,
        response_status=obs.response_status,
        envelope_event_id=str(obs.envelope_event_id),
        host_id=host_node_id,
        auth_context_id=auth_context_node_id,
        props=props,
    )
    return obs.observation_id


def commit_parse_failure(client: Neo4jClient, *, pf: ParseFailure) -> ObservationId:
    """MERGE the `ParseFailure` node with its envelope back-ref (provenance).

    The originating L1 envelope is not a graph node, so the back-ref is the
    `envelope_event_id` property (CONTEXT.md ParseFailure term). Identity is
    `(engagement_id, observation_id)`.
    """

    props = cross_cutting(
        source=pf.source,
        source_id=pf.source_id,
        observed_at=pf.observed_at,
        ingested_at=pf.ingested_at,
    )
    client.execute_write(
        """
        MERGE (f:ParseFailure {engagement_id: $engagement_id,
                               observation_id: $observation_id})
        ON CREATE SET f.id = $observation_id,
                      f.envelope_event_id = $envelope_event_id,
                      f.error_kind = $error_kind, f.error_message = $error_message,
                      f.location_hint = $location_hint,
                      f += $props
        ON MATCH SET f.last_seen = $props.last_seen
        """,
        engagement_id=pf.engagement_id,
        observation_id=pf.observation_id,
        envelope_event_id=str(pf.envelope_event_id),
        error_kind=pf.error_kind,
        error_message=pf.error_message,
        location_hint=pf.location_hint,
        props=props,
    )
    return pf.observation_id
