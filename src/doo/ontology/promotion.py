"""Flush-time `ObservedValue` promotion pass (ADR-0023, the ADR-0022 seam).

The graph-touching counterpart of the pure `canonical/promotion.py` decision,
mirroring `canonical/templating.py` ↔ `ontology/templating.py`. It runs beside
cohort re-templating at flush (ADR-0022): there is no mid-drain reader, so
`ObservedValue`s appear at flush alongside endpoints.

For one engagement it:

1. Reads every `RequestObservation`'s inline value candidates (ADR-0023) from the
   graph and groups the occurrences by `value_hash` (engagement-scoped).
2. For each value whose occurrence kinds clear the shape-allowlist
   (`canonical.promotion.should_promote` — `{secret, token, internal_hostname,
   email}` in #14), MERGEs one `ObservedValue` (identity `(engagement_id,
   value_hash)`; ADR-0009) and wires a `YIELDED_VALUE {location, extractor}` edge
   from every observation that surfaced it.
3. Stamps the seven cross-cutting fields (ADR-0005) on the node and edge.

High-cardinality identifiers / URLs do **not** promote here — they stay inline
candidate occurrences (the 277k collapse). Secret discipline (ADR-0015): a secret
`ObservedValue` carries `value_hash` + length + preview only; the raw value is not
in the candidate and never reaches the graph.

The pass is **idempotent + re-runnable** (ADR-0023): MERGE on
`(engagement_id, value_hash)` and on the `YIELDED_VALUE` edge means re-running over
an unchanged graph creates nothing new. No LLM (CLAUDE.md hard rule).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from doo.canonical.identity import observed_value_id
from doo.canonical.promotion import should_promote
from doo.canonical.values import CandidateKind
from doo.ids import EngagementId, ObservedValueId, Sha256Hex
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.resolve import cross_cutting

# ObservedValue promotion provenance tag (ONTOLOGY.md Step 5 source vocab).
_PROMOTION_SOURCE = "deterministic-promotion"


@dataclass(frozen=True, slots=True)
class _CandidateRow:
    """One inline candidate occurrence read back from an observation."""

    observation_id: str
    value_hash: Sha256Hex
    kind: CandidateKind
    extractor: str
    location: str
    value: str | None
    value_length: int | None
    value_preview: str | None


@dataclass(frozen=True, slots=True)
class PromotedValue:
    """One `ObservedValue` MERGEd by the pass, for L3-event emission."""

    observed_value_id: ObservedValueId
    value_hash: Sha256Hex
    kind: CandidateKind
    yielded_from: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PromotionResult:
    """Outcome of one engagement's promotion pass."""

    promoted: tuple[PromotedValue, ...] = ()
    edges: int = 0


def promote_values(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> PromotionResult:
    """Promote allowlisted inline candidates into `ObservedValue`s for one engagement.

    Idempotent + re-runnable: identity-keyed MERGEs mean a re-run over an unchanged
    graph adds nothing. Returns the promoted values + edge count for L3 events.
    """

    rows = _read_candidates(client, engagement_id)
    if not rows:
        return PromotionResult()

    # Group occurrences by value_hash (engagement-scoped already by the query).
    by_hash: dict[Sha256Hex, list[_CandidateRow]] = {}
    for row in rows:
        by_hash.setdefault(row.value_hash, []).append(row)

    promoted: list[PromotedValue] = []
    edge_count = 0
    for value_hash, occurrences in sorted(by_hash.items()):
        kinds = [o.kind for o in occurrences]
        if not should_promote(kinds):
            continue
        # A value's kind is stable across its occurrences (the hash includes the
        # normalisation, and secret/non-secret never collide); take the first.
        kind = occurrences[0].kind
        ov_id = observed_value_id(engagement_id, value_hash)
        _merge_observed_value(
            client,
            engagement_id=engagement_id,
            observed_value_node_id=ov_id,
            value_hash=value_hash,
            occurrences=occurrences,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        yielded_from = sorted({o.observation_id for o in occurrences})
        edge_count += len(yielded_from)
        promoted.append(
            PromotedValue(
                observed_value_id=ov_id,
                value_hash=value_hash,
                kind=kind,
                yielded_from=tuple(yielded_from),
            )
        )
    return PromotionResult(promoted=tuple(promoted), edges=edge_count)


def _read_candidates(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_CandidateRow]:
    """Read every observation's inline value candidates for one engagement.

    Candidates are stored as a list of JSON-serialised `ValueCandidate`s on the
    `RequestObservation` (see `resolve.commit_request_observation`); this UNWINDs
    and parses them. Only `output`-role candidates are considered for promotion in
    #14.
    """

    rows = client.execute_read(
        """
        MATCH (r:RequestObservation {engagement_id: $engagement_id})
        WHERE r.value_candidates IS NOT NULL
        UNWIND r.value_candidates AS vc
        RETURN r.id AS observation_id, vc AS candidate
        """,
        engagement_id=engagement_id,
    )
    out: list[_CandidateRow] = []
    for row in rows:
        candidate = json.loads(str(row["candidate"]))
        if candidate.get("role", "output") != "output":
            continue
        location = _location_of(candidate)
        out.append(
            _CandidateRow(
                observation_id=str(row["observation_id"]),
                value_hash=Sha256Hex(str(candidate["value_hash"])),
                kind=candidate["kind"],
                extractor=str(candidate["extractor"]),
                location=location,
                value=candidate.get("value"),
                value_length=candidate.get("value_length"),
                value_preview=candidate.get("value_preview"),
            )
        )
    return out


def _location_of(candidate: dict[str, object]) -> str:
    """A human-readable location string for the `YIELDED_VALUE` edge property.

    Header candidates carry the header name; body candidates carry the RFC 6901
    JSON pointer or byte offsets — whichever is present.
    """

    if candidate.get("section") == "header":
        return f"header:{candidate.get('header_name')}"
    pointer = candidate.get("json_pointer")
    if pointer:
        return f"body:{pointer}"
    return f"body:{candidate.get('byte_start')}:{candidate.get('byte_end')}"


def _merge_observed_value(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_value_node_id: ObservedValueId,
    value_hash: Sha256Hex,
    occurrences: list[_CandidateRow],
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """MERGE one `ObservedValue` + its `YIELDED_VALUE` edges (identity-keyed).

    Identity `(engagement_id, value_hash)` (ADR-0009). For secret kinds only the
    hash + length + preview are stored (ADR-0015); non-secret kinds carry the raw
    `value`. Each contributing observation gets one `YIELDED_VALUE {location,
    extractor}` edge, MERGEd so re-runs do not duplicate it.
    """

    first = occurrences[0]
    props = cross_cutting(
        source=_PROMOTION_SOURCE,
        source_id=None,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    # One distinct (observation_id, location, extractor) edge per occurrence.
    edge_rows = [
        {
            "observation_id": o.observation_id,
            "location": o.location,
            "extractor": o.extractor,
        }
        for o in occurrences
    ]
    client.execute_write(
        """
        MERGE (v:ObservedValue {engagement_id: $engagement_id, value_hash: $value_hash})
        ON CREATE SET v.id = $id, v.kind = $kind, v.value = $value,
                      v.value_length = $value_length, v.value_preview = $value_preview,
                      v += $props
        ON MATCH SET v.last_seen = $props.last_seen
        WITH v
        UNWIND $edges AS edge
        MATCH (r:RequestObservation {engagement_id: $engagement_id, id: edge.observation_id})
        MERGE (r)-[y:YIELDED_VALUE {location: edge.location, extractor: edge.extractor}]->(v)
        ON CREATE SET y.engagement_id = $engagement_id
        """,
        engagement_id=engagement_id,
        value_hash=value_hash,
        id=observed_value_node_id,
        kind=first.kind,
        value=first.value,
        value_length=first.value_length,
        value_preview=first.value_preview,
        edges=edge_rows,
        props=props,
    )
