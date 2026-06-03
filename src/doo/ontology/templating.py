"""Endpoint re-templating + Parameter aggregation (slice-1 T3, deep module).

This is the L3 graph-touching counterpart of the pure `canonical/templating.py`
algorithm. On every committed `RequestObservation` it reconciles the whole
`(engagement_id, method, host_id)` cohort:

1. Read every `RequestObservation` in the cohort (concrete paths + observed
   query-parameter names) from the graph.
2. Run the deterministic templating algorithm over the full concrete-path
   corpus (`canonical.templating.template_paths`).
3. For each inferred `path_template`, MERGE its `Endpoint` node and re-point the
   `HIT` edges of the observations that template to it. **Observations never
   move** (ADR-0004): only the revisable `HIT` grouping is re-pointed.
4. Supersede `Endpoint` nodes that no longer carry any `HIT` (an earlier
   mis-templating that fresh evidence overturned): mark `status = "retracted"`
   per ADR-0001's retraction discipline — the node and its provenance are kept,
   never deleted.
5. Aggregate `Parameter` nodes keyed `(engagement_id, endpoint_id, location,
   name)` — path positions from the template, query names rolled up over the
   cohort — with `HAS_PARAMETER` edges from the Endpoint and `HIT`-counted rollups.

The pass is **idempotent**: re-running over an unchanged cohort MERGEs the same
nodes/edges and re-points nothing. When an existing Endpoint's `path_template`
is revised, a `node_updated` L3 event with
`changed_properties = {path_template: {old, new}}` is emitted.

No LLM here — deterministic re-templating only (CLAUDE.md hard rule). Endpoint
identity stays `(engagement_id, method, host_id, path_template)` (ADR-0017).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from doo.canonical.identity import endpoint_id, parameter_id
from doo.canonical.templating import TemplatedPath, template_paths
from doo.ids import EngagementId, HostId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.resolve import cross_cutting

# Endpoint/Parameter inference provenance tag (ONTOLOGY.md Step 5 source vocab).
_TEMPLATING_SOURCE = "deterministic-templating"


@dataclass(frozen=True, slots=True)
class TemplateChange:
    """An existing Endpoint whose `path_template` was revised by fresh evidence."""

    endpoint_id: str
    old_template: str
    new_template: str


@dataclass(frozen=True, slots=True)
class RetemplateResult:
    """Outcome of one cohort re-templating pass, for L3-event emission.

    `endpoint_ids` / `parameter_ids` are every node MERGEd this pass (created or
    matched); `template_changes` drive `node_updated` events; `retracted_endpoint_ids`
    are endpoints superseded (status flipped to retracted) by re-grouping.
    """

    endpoint_ids: tuple[str, ...] = ()
    parameter_ids: tuple[str, ...] = ()
    template_changes: tuple[TemplateChange, ...] = ()
    retracted_endpoint_ids: tuple[str, ...] = ()
    primary_endpoint_id: str | None = None


@dataclass(frozen=True, slots=True)
class _CohortObservation:
    observation_id: str
    concrete_path: str
    query_param_names: tuple[str, ...]
    body_param_names: tuple[str, ...]


def retemplate_cohort(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    method: str,
    host_node_id: HostId,
    observed_at: datetime,
    ingested_at: datetime,
    primary_concrete_path: str | None = None,
) -> RetemplateResult:
    """Re-template one `(engagement_id, method, host_id)` cohort end to end.

    `primary_concrete_path`, when given, identifies which Endpoint the
    just-committed observation maps to (returned as `primary_endpoint_id`) so the
    caller can report it.
    """

    method_u = method.upper()
    cohort = _read_cohort(client, engagement_id, method_u, host_node_id)
    if not cohort:
        return RetemplateResult()

    templated = template_paths([o.concrete_path for o in cohort])

    # --- 1. Snapshot existing endpoints for this cohort (for change detection). ---
    existing = _read_existing_endpoints(client, engagement_id, method_u, host_node_id)

    # --- 2. Group observations by their inferred template; MERGE endpoints. ---
    by_template: dict[str, list[_CohortObservation]] = {}
    template_meta: dict[str, TemplatedPath] = {}
    for obs in cohort:
        tp = templated[obs.concrete_path]
        by_template.setdefault(tp.path_template, []).append(obs)
        template_meta[tp.path_template] = tp

    endpoint_ids: list[str] = []
    parameter_ids: list[str] = []
    live_endpoint_ids: set[str] = set()
    primary_endpoint_id: str | None = None

    for template, members in sorted(by_template.items()):
        tp = template_meta[template]
        eid = endpoint_id(engagement_id, method_u, host_node_id, template)
        live_endpoint_ids.add(eid)
        endpoint_ids.append(eid)
        _merge_endpoint(
            client,
            engagement_id=engagement_id,
            endpoint_node_id=eid,
            method=method_u,
            host_node_id=host_node_id,
            path_template=template,
            confidence=tp.confidence,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        # Re-point HIT edges for exactly this template's observations.
        _regroup_hits(
            client,
            engagement_id=engagement_id,
            endpoint_node_id=eid,
            observation_ids=[m.observation_id for m in members],
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        # --- 3. Parameter aggregation: path positions + query names. ---
        param_ids = _aggregate_parameters(
            client,
            engagement_id=engagement_id,
            endpoint_node_id=eid,
            templated=tp,
            members=members,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        parameter_ids.extend(param_ids)

        if primary_concrete_path is not None and any(
            m.concrete_path == primary_concrete_path for m in members
        ):
            primary_endpoint_id = eid

    # --- 4. Supersede endpoints that lost all their observations (re-grouping). ---
    retracted: list[str] = []
    changes: list[TemplateChange] = []
    for old in existing:
        if old.endpoint_id in live_endpoint_ids:
            continue
        # An existing endpoint with no live HIT after re-grouping: its template
        # was overturned. Mark retracted (provenance preserved; ADR-0001).
        if _endpoint_has_no_hits(client, engagement_id, old.endpoint_id):
            _retract_endpoint(client, engagement_id, old.endpoint_id, ingested_at)
            retracted.append(old.endpoint_id)
            # Surface the revision as a property change against the surviving
            # template that absorbed this endpoint's observations, if any.
            new_template = _successor_template(old.path_template, by_template.keys())
            if new_template is not None:
                changes.append(
                    TemplateChange(
                        endpoint_id=old.endpoint_id,
                        old_template=old.path_template,
                        new_template=new_template,
                    )
                )

    return RetemplateResult(
        endpoint_ids=tuple(endpoint_ids),
        parameter_ids=tuple(parameter_ids),
        template_changes=tuple(changes),
        retracted_endpoint_ids=tuple(retracted),
        primary_endpoint_id=primary_endpoint_id,
    )


@dataclass(frozen=True, slots=True)
class _ExistingEndpoint:
    endpoint_id: str
    path_template: str


def _read_cohort(
    client: Neo4jClient, engagement_id: EngagementId, method: str, host_node_id: HostId
) -> list[_CohortObservation]:
    rows = client.execute_read(
        """
        MATCH (r:RequestObservation {engagement_id: $engagement_id, method: $method})
              -[:ON_HOST]->(h:Host {engagement_id: $engagement_id, id: $host_id})
        RETURN r.id AS id, r.concrete_path AS path,
               r.query_param_names AS qnames, r.body_param_names AS bnames
        ORDER BY r.id
        """,
        engagement_id=engagement_id,
        method=method,
        host_id=host_node_id,
    )
    out: list[_CohortObservation] = []
    for row in rows:
        qnames = row.get("qnames") or []
        bnames = row.get("bnames") or []
        out.append(
            _CohortObservation(
                observation_id=str(row["id"]),
                concrete_path=str(row["path"]),
                query_param_names=tuple(str(q) for q in qnames),
                body_param_names=tuple(str(b) for b in bnames),
            )
        )
    return out


def _read_existing_endpoints(
    client: Neo4jClient, engagement_id: EngagementId, method: str, host_node_id: HostId
) -> list[_ExistingEndpoint]:
    rows = client.execute_read(
        """
        MATCH (e:Endpoint {engagement_id: $engagement_id, method: $method,
                           host_id: $host_id})
        RETURN e.id AS id, e.path_template AS template
        """,
        engagement_id=engagement_id,
        method=method,
        host_id=host_node_id,
    )
    return [
        _ExistingEndpoint(endpoint_id=str(r["id"]), path_template=str(r["template"]))
        for r in rows
    ]


def _merge_endpoint(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    endpoint_node_id: str,
    method: str,
    host_node_id: HostId,
    path_template: str,
    confidence: float,
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """MERGE one `Endpoint` (identity-keyed) + its `ON_HOST` edge, re-activating it.

    If the node had previously been retracted by an earlier re-grouping and the
    same template re-emerges, it is re-activated (`status = "active"`) — the
    revisable inference is allowed to flip back (ADR-0004).
    """

    props = cross_cutting(
        source=_TEMPLATING_SOURCE,
        source_id=None,
        observed_at=observed_at,
        ingested_at=ingested_at,
        confidence=confidence,
    )
    client.execute_write(
        """
        MERGE (e:Endpoint {engagement_id: $engagement_id, method: $method,
                           host_id: $host_id, path_template: $path_template})
        ON CREATE SET e.id = $id, e.path_template_confidence = $confidence, e += $props
        ON MATCH SET e.last_seen = $props.last_seen, e.status = 'active',
                     e.path_template_confidence = $confidence
        WITH e
        MATCH (h:Host {engagement_id: $engagement_id, id: $host_id})
        MERGE (e)-[:ON_HOST]->(h)
        """,
        engagement_id=engagement_id,
        method=method,
        host_id=host_node_id,
        path_template=path_template,
        id=endpoint_node_id,
        confidence=confidence,
        props=props,
    )


def _regroup_hits(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    endpoint_node_id: str,
    observation_ids: list[str],
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """Point each member observation's single `HIT` edge at `endpoint_node_id`.

    `HIT` is N:1 and revisable (ADR-0004): each RO HITs exactly one Endpoint at a
    time. We delete any stale `HIT` from these observations to *other* endpoints,
    then MERGE the correct one. Observations themselves are untouched.
    """

    client.execute_write(
        """
        MATCH (target:Endpoint {engagement_id: $engagement_id, id: $endpoint_id})
        UNWIND $observation_ids AS oid
        MATCH (r:RequestObservation {engagement_id: $engagement_id, id: oid})
        // Drop any stale HIT to a different endpoint (re-grouping).
        OPTIONAL MATCH (r)-[stale:HIT]->(other:Endpoint)
        WHERE other.id <> $endpoint_id
        DELETE stale
        WITH r, target
        MERGE (r)-[:HIT]->(target)
        """,
        engagement_id=engagement_id,
        endpoint_id=endpoint_node_id,
        observation_ids=observation_ids,
    )


def _aggregate_parameters(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    endpoint_node_id: str,
    templated: TemplatedPath,
    members: list[_CohortObservation],
    observed_at: datetime,
    ingested_at: datetime,
) -> list[str]:
    """MERGE the Endpoint's path/query/body `Parameter` nodes and `HAS_PARAMETER` edges.

    Identity `(engagement_id, endpoint_id, location, name)`. Path Parameters come
    from the template's inferred positions; query and body Parameters are the union
    of the observed query- / body-parameter names across the cohort members (T5
    extends T3's aggregation to `location="body"`). Idempotent: re-running MERGEs the
    same nodes/edges. Returns the Parameter node ids touched.
    """

    specs: list[tuple[str, str, float, str | None]] = []  # (location, name, conf, shape)
    for p in templated.parameters:
        specs.append(("path", p.name, p.confidence, p.shape))
    seen_query: set[str] = set()
    for m in members:
        for name in m.query_param_names:
            if name in seen_query:
                continue
            seen_query.add(name)
            specs.append(("query", name, 1.0, None))
    seen_body: set[str] = set()
    for m in members:
        for name in m.body_param_names:
            if name in seen_body:
                continue
            seen_body.add(name)
            specs.append(("body", name, 1.0, None))

    touched: list[str] = []
    for location, name, confidence, shape in specs:
        pid = parameter_id(engagement_id, endpoint_node_id, location, name)
        touched.append(pid)
        props = cross_cutting(
            source=_TEMPLATING_SOURCE if location == "path" else "har",
            source_id=None,
            observed_at=observed_at,
            ingested_at=ingested_at,
            confidence=confidence,
        )
        client.execute_write(
            """
            MATCH (e:Endpoint {engagement_id: $engagement_id, id: $endpoint_id})
            MERGE (p:Parameter {engagement_id: $engagement_id, endpoint_id: $endpoint_id,
                                location: $location, name: $name})
            ON CREATE SET p.id = $id, p.value_shape = $shape, p += $props
            ON MATCH SET p.last_seen = $props.last_seen
            MERGE (e)-[:HAS_PARAMETER]->(p)
            """,
            engagement_id=engagement_id,
            endpoint_id=endpoint_node_id,
            location=location,
            name=name,
            id=pid,
            shape=shape,
            props=props,
        )
    return touched


def _endpoint_has_no_hits(
    client: Neo4jClient, engagement_id: EngagementId, endpoint_node_id: str
) -> bool:
    rows = client.execute_read(
        """
        MATCH (e:Endpoint {engagement_id: $engagement_id, id: $endpoint_id})
        OPTIONAL MATCH (:RequestObservation)-[hit:HIT]->(e)
        RETURN count(hit) AS hits
        """,
        engagement_id=engagement_id,
        endpoint_id=endpoint_node_id,
    )
    return int(rows[0]["hits"]) == 0 if rows else True


def _retract_endpoint(
    client: Neo4jClient,
    engagement_id: EngagementId,
    endpoint_node_id: str,
    ingested_at: datetime,
) -> None:
    """Flip an orphaned Endpoint to `status = "retracted"` (ADR-0001).

    The node and all its provenance are preserved — retraction is a flag, never a
    delete. Coverage/planner queries filter on `status = "active"`.
    """

    client.execute_write(
        """
        MATCH (e:Endpoint {engagement_id: $engagement_id, id: $endpoint_id})
        SET e.status = 'retracted', e.retracted_at = $retracted_at
        """,
        engagement_id=engagement_id,
        endpoint_id=endpoint_node_id,
        retracted_at=ingested_at,
    )


def _successor_template(
    old_template: str, live_templates: Iterable[str]
) -> str | None:
    """Best-effort: which live template absorbed an overturned literal template.

    Match by replacing exactly one literal segment of `old_template` with a
    parameter token, looking for a live template of the same arity. Used only to
    populate the `node_updated` event's `new` value; `None` when ambiguous.
    """

    old_segs = old_template.split("/")
    for cand in live_templates:
        cand_segs = cand.split("/")
        if len(cand_segs) != len(old_segs):
            continue
        diffs = [
            i
            for i in range(len(old_segs))
            if old_segs[i] != cand_segs[i]
        ]
        if len(diffs) == 1 and cand_segs[diffs[0]].startswith("{"):
            return cand
    return None
