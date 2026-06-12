"""Flush-time `ObservedValue` promotion pass (ADR-0023, the ADR-0022 seam).

The graph-touching counterpart of the pure `canonical/promotion.py` decision,
mirroring `canonical/templating.py` ↔ `ontology/templating.py`. It runs beside
cohort re-templating at flush (ADR-0022): there is no mid-drain reader, so
`ObservedValue`s appear at flush alongside endpoints.

For one engagement it:

1. Reads every `RequestObservation`'s inline value candidates (ADR-0023) from the
   graph — both `output` (response) and `input` (request-parameter) roles — and
   groups the occurrences by `value_hash` (engagement-scoped).
2. For each value that clears a promotion signal
   (`canonical.promotion.should_promote`), MERGEs one `ObservedValue` (identity
   `(engagement_id, value_hash)`; ADR-0009) and wires, per occurrence:
   - `(:RequestObservation)-[:YIELDED_VALUE {location, extractor}]->(:ObservedValue)`
     from every observation that **surfaced** it (an `output` occurrence), and
   - `(:RequestObservation)-[:SENT_VALUE {parameter_name}]->(:ObservedValue)`
     from every observation that **sent** it as a request parameter (an `input`
     occurrence) — the leak-to-input pivot (#16).

   Three signals fire here: the shape-allowlist (`{secret, token,
   internal_hostname, email}`, #14), **multiplicity ≥2** (#15) over *distinct*
   observations regardless of role, and **leak-to-input** (#16) — a value seen as
   both an output and an input.
3. Stamps the seven cross-cutting fields (ADR-0005) on the node and edges.

A non-allowlisted value seen as a single non-pivot occurrence does **not** promote
— it stays an inline candidate (the 277k collapse: 100 distinct list ids are 100
single-occurrence hashes). A value seen *only* as an input (never an output) is not
promoted by leak-to-input alone — it still needs multiplicity / allowlist. Secret
discipline (ADR-0015): a secret `ObservedValue` carries `value_hash` + length +
preview only; the raw value is not in the candidate and never reaches the graph.

The pass is **idempotent + re-runnable** (ADR-0023): MERGE on
`(engagement_id, value_hash)` and on each `YIELDED_VALUE` / `SENT_VALUE` edge means
re-running over an unchanged graph creates nothing new. No LLM (CLAUDE.md hard rule).
"""

from __future__ import annotations

import json
from collections.abc import Callable
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
    role: str
    extractor: str
    location: str
    parameter_name: str | None
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
    sent_from: tuple[str, ...] = ()


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
    on_value: Callable[[int, int], None] | None = None,
) -> PromotionResult:
    """Promote inline candidates clearing a signal into `ObservedValue`s for one engagement.

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
    items = sorted(by_hash.items())
    total = len(items)
    report = on_value or (lambda _done, _total: None)
    report(0, total)
    for i, (value_hash, occurrences) in enumerate(items, start=1):
        report(i, total)
        kinds = [o.kind for o in occurrences]
        roles = [o.role for o in occurrences]
        # Distinct observations carrying this value (any role) — the multiplicity
        # count. Counting *distinct* observation ids means the same value twice in
        # one response is 1, not 2.
        distinct_obs = {o.observation_id for o in occurrences}
        if not should_promote(
            kinds, distinct_observations=len(distinct_obs), roles=roles
        ):
            continue
        # Split occurrences by role for the two edge types. YIELDED_VALUE fans out
        # to producing (output) observations; SENT_VALUE to consuming (input) ones.
        output_occ = [o for o in occurrences if o.role == "output"]
        input_occ = [o for o in occurrences if o.role == "input"]
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
            output_occ=output_occ,
            input_occ=input_occ,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        yielded_from = sorted({o.observation_id for o in output_occ})
        sent_from = sorted({o.observation_id for o in input_occ})
        edge_count += len(output_occ) + len(input_occ)
        promoted.append(
            PromotedValue(
                observed_value_id=ov_id,
                value_hash=value_hash,
                kind=kind,
                yielded_from=tuple(yielded_from),
                sent_from=tuple(sent_from),
            )
        )
    return PromotionResult(promoted=tuple(promoted), edges=edge_count)


def _read_candidates(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_CandidateRow]:
    """Read every observation's inline value candidates for one engagement.

    Candidates are stored as a list of JSON-serialised `ValueCandidate`s on the
    `RequestObservation` (see `resolve.commit_request_observation`); this UNWINDs
    and parses them. Both `output` (response) and `input` (request-parameter, #16)
    roles are returned; the role drives which edge type the merge wires.
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
        role = candidate.get("role", "output")
        out.append(
            _CandidateRow(
                observation_id=str(row["observation_id"]),
                value_hash=Sha256Hex(str(candidate["value_hash"])),
                kind=candidate["kind"],
                role=role,
                extractor=str(candidate["extractor"]),
                location=_location_of(candidate),
                parameter_name=candidate.get("parameter_name"),
                value=candidate.get("value"),
                value_length=candidate.get("value_length"),
                value_preview=candidate.get("value_preview"),
            )
        )
    return out


def _location_of(candidate: dict[str, object]) -> str:
    """A human-readable location string for the `YIELDED_VALUE` edge property.

    Header candidates carry the header name; body candidates carry the RFC 6901
    JSON pointer or byte offsets — whichever is present. Input candidates carry the
    parameter name.
    """

    if candidate.get("role") == "input":
        return f"param:{candidate.get('parameter_name')}"
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
    output_occ: list[_CandidateRow],
    input_occ: list[_CandidateRow],
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """MERGE one `ObservedValue` + its `YIELDED_VALUE` / `SENT_VALUE` edges (identity-keyed).

    Identity `(engagement_id, value_hash)` (ADR-0009). For secret kinds only the
    hash + length + preview are stored (ADR-0015); non-secret kinds carry the raw
    `value`. Each output occurrence gets one `YIELDED_VALUE {location, extractor}`
    edge; each input occurrence one `SENT_VALUE {parameter_name}` edge — both MERGEd
    so re-runs do not duplicate them.
    """

    # Carry a non-secret raw value if any occurrence has one (input + output of the
    # same value share a value_hash; secret occurrences carry value=None).
    repr_occ = next((o for o in occurrences if o.value is not None), occurrences[0])
    props = cross_cutting(
        source=_PROMOTION_SOURCE,
        source_id=None,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    yielded_rows = [
        {
            "observation_id": o.observation_id,
            "location": o.location,
            "extractor": o.extractor,
        }
        for o in output_occ
    ]
    sent_rows = [
        {
            "observation_id": o.observation_id,
            "parameter_name": o.parameter_name,
            "extractor": o.extractor,
        }
        for o in input_occ
    ]
    # 1) MERGE the node + its YIELDED_VALUE edges (the producing observations).
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
        kind=repr_occ.kind,
        value=repr_occ.value,
        value_length=repr_occ.value_length,
        value_preview=repr_occ.value_preview,
        edges=yielded_rows,
        props=props,
    )
    # 2) MERGE the SENT_VALUE edges (the consuming observations; the pivot, #16).
    if sent_rows:
        client.execute_write(
            """
            MATCH (v:ObservedValue {engagement_id: $engagement_id, value_hash: $value_hash})
            UNWIND $edges AS edge
            MATCH (r:RequestObservation {engagement_id: $engagement_id, id: edge.observation_id})
            MERGE (r)-[s:SENT_VALUE {parameter_name: edge.parameter_name}]->(v)
            ON CREATE SET s.engagement_id = $engagement_id, s.extractor = edge.extractor
            """,
            engagement_id=engagement_id,
            value_hash=value_hash,
            edges=sent_rows,
        )
