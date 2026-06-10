"""Flush-time `Tenant` inference pass (ADR-0008, the ADR-0022 seam).

The graph-touching counterpart to the tenant-detection decision, mirroring
`ontology/promotion.py` / `ontology/templating.py`. It runs at flush (ADR-0022)
beside cohort re-templating and value promotion: there is no mid-drain reader, so
`Tenant` nodes appear at flush alongside endpoints.

`Tenant` is an inference-layer node (ADR-0008). In black-box mode tenants are
inferred from observations; the fully-deterministic signal is a **tenant
identifier in a URL position**, recognised two ways (see `_tenant_segments`):

1. a tenant-shaped segment placeholder (`{org_id}`, `{tenant_id}`,
   `{workspace_id}`, `{account_id}`) — the most precise signal; and
2. a generic parameter (`{id}`) whose preceding segment is a tenant collection
   literal (`/orgs/{id}/…`) — robust to a slice-1 templating collapse that renames
   the placeholder to `{id}` on sparse corpora (issue #61).

In both cases the concrete value is taken from `RequestObservation.concrete_path`
at that segment, and both map to the same `Tenant.kind` so the two signals
converge to one node. This is the signal the slice-3 tenant `TrustBoundary`
consumer needs (ADR-0039): two tenants that share an `Endpoint`.

Per ADR-0008 a `Tenant` is content-addressed on `(engagement_id, kind,
normalized_value)` and carries `DERIVED_FROM` edges to its evidencing
observations plus the standard cross-cutting fields. Each evidencing
observation's `Principal` gains an `OF_TENANT` edge (M:N — multi-org membership
is normal).

The pass is **idempotent + re-runnable** (identity-keyed MERGEs): re-running over
an unchanged graph creates nothing new. No LLM (CLAUDE.md hard rule). Header- and
body-field tenant signals (ADR-0008) are a deliberate later extension behind this
same seam; the URL-position signal is sufficient for the slice-3 boundary
consumer and is the most precise of the four.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from doo.canonical.identity import tenant_id
from doo.ids import EngagementId, TenantId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.resolve import cross_cutting

# Tenant inference provenance tag (deterministic, no LLM).
_TENANT_SOURCE = "deterministic-tenant"

# `code_version` for the tenant inference algorithm (ADR-0005). Bumped when the
# detection heuristic changes so stale inferences are identifiable. /2 adds the
# collection-literal signal (issue #61) alongside the placeholder-name signal.
_TENANT_CODE_VERSION = "tenant-inference/2"

# Tenant-shaped path-segment placeholders, mapped to the `Tenant.kind` they
# evidence. The segment name (templating's `{<base>_id}` convention, e.g.
# `orgs` -> `org_id`) is the most precise URL-position tenant signal (ADR-0008).
TENANT_SEGMENT_KINDS: dict[str, str] = {
    "org_id": "org_id",
    "tenant_id": "tenant_id",
    "workspace_id": "workspace",
    "account_id": "account_namespace",
}

# Tenant-shaped **collection literals** — the resource-type segment that *precedes*
# a tenant identifier in a URL (`/orgs/{id}/...`), mapped to the same `Tenant.kind`
# as the corresponding placeholder above so both signals converge to one node.
#
# Why this second signal (the robust fix for issue #61): the placeholder-name
# signal above only fires when slice-1 templating happens to *name* the parameter
# `{org_id}`. But templating derives that name from the preceding collection
# literal and degrades it to the generic `{id}` whenever the predecessor is
# unusable — a cold-start single observation, a preceding parameterised segment, or
# a version segment (`canonical/templating.py::_param_name`). On a sparse corpus a
# route like `/orgs/42/projects` + `/orgs/43/projects` can therefore template to
# `/orgs/{id}/projects`, and the tenant signal must not hinge on that incidental
# naming. The durable, templating-collapse-proof signal is the **collection literal
# still standing in the template** (`orgs`) immediately before an id-shaped value
# position; we read the concrete tenant value from that position regardless of
# whether the placeholder is `{org_id}` or `{id}`. `Tenant.kind` is keyed off the
# literal, so `/orgs/{org_id}/...` and `/orgs/{id}/...` resolve to the *same*
# `Tenant(org_id, 42)` identity (ADR-0008) — idempotent across a templating revision
# that renames the placeholder.
TENANT_COLLECTION_KINDS: dict[str, str] = {
    "orgs": "org_id",
    "organizations": "org_id",
    "tenants": "tenant_id",
    "workspaces": "workspace",
    "accounts": "account_namespace",
}


@dataclass(frozen=True, slots=True)
class _TenantOccurrence:
    """One tenant identifier observed in a URL position of one observation."""

    observation_id: str
    principal_id: str
    kind: str
    normalized_value: str


@dataclass(frozen=True, slots=True)
class InferredTenant:
    """One `Tenant` MERGEd by the pass, for result reporting / L3 events."""

    tenant_node_id: TenantId
    kind: str
    normalized_value: str
    derived_from: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TenantResult:
    """Outcome of one engagement's tenant inference pass."""

    tenants: tuple[InferredTenant, ...] = ()
    of_tenant_edges: int = 0


def infer_tenants(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> TenantResult:
    """Infer `Tenant` nodes from URL-position tenant identifiers for one engagement.

    Idempotent + re-runnable (identity-keyed MERGEs). Returns the tenants MERGEd
    plus the `OF_TENANT` edge count.
    """

    occurrences = _read_url_position_tenants(client, engagement_id)
    if not occurrences:
        return TenantResult()

    # Group by tenant identity (kind, normalized_value) — engagement-scoped.
    by_identity: dict[tuple[str, str], list[_TenantOccurrence]] = {}
    for occ in occurrences:
        by_identity.setdefault((occ.kind, occ.normalized_value), []).append(occ)

    tenants: list[InferredTenant] = []
    of_tenant_edges = 0
    for (kind, normalized_value), occs in sorted(by_identity.items()):
        t_id = tenant_id(engagement_id, kind, normalized_value)
        observation_ids = sorted({o.observation_id for o in occs})
        principal_ids = sorted({o.principal_id for o in occs})
        _merge_tenant(
            client,
            engagement_id=engagement_id,
            tenant_node_id=t_id,
            kind=kind,
            normalized_value=normalized_value,
            observation_ids=observation_ids,
            principal_ids=principal_ids,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        of_tenant_edges += len(principal_ids)
        tenants.append(
            InferredTenant(
                tenant_node_id=t_id,
                kind=kind,
                normalized_value=normalized_value,
                derived_from=tuple(observation_ids),
            )
        )
    return TenantResult(tenants=tuple(tenants), of_tenant_edges=of_tenant_edges)


def _read_url_position_tenants(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_TenantOccurrence]:
    """Read tenant identifiers sitting in URL positions for one engagement.

    Joins each `RequestObservation` to the `Endpoint` it `HIT`, recovers the
    path-template segments, and extracts the concrete value at every tenant
    identifier position from the observation's `concrete_path`. A tenant position
    is recognised by either signal in `_tenant_segments`: a tenant-shaped
    placeholder name (`{org_id}`) or a generic parameter following a tenant
    collection literal (`/orgs/{id}/…`). The Cypher `WHERE` only pre-filters
    Endpoints carrying *some* tenant signal (placeholder name OR collection
    literal); the precise per-segment decision is finished in Python. The Principal
    comes from the observation's AuthContext (`OBSERVED_UNDER` → `OF_PRINCIPAL`).

    Done in Cypher down to the per-observation (template, concrete_path) pair;
    the segment alignment + signal matching is finished in Python (clearer than
    list-zipping in Cypher and trivially testable).
    """

    rows = client.execute_read(
        """
        MATCH (r:RequestObservation {engagement_id: $engagement_id})-[:HIT]->
              (e:Endpoint {engagement_id: $engagement_id})
        WHERE e.status = 'active'
          AND (
            // signal 1: a tenant-shaped placeholder name (`{org_id}` etc.)
            any(seg IN split(e.path_template, '/') WHERE seg IN $placeholders)
            // signal 2: a tenant collection literal (`orgs` etc.), robust to a
            // templating collapse that renamed the placeholder to `{id}`.
            OR any(seg IN split(e.path_template, '/') WHERE seg IN $collections)
          )
        MATCH (r)-[:OBSERVED_UNDER]->(:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        WHERE p.status IS NULL OR p.status = 'active'
        RETURN r.id AS observation_id, r.concrete_path AS concrete_path,
               e.path_template AS path_template, p.id AS principal_id
        """,
        engagement_id=engagement_id,
        placeholders=[f"{{{name}}}" for name in TENANT_SEGMENT_KINDS],
        collections=list(TENANT_COLLECTION_KINDS),
    )
    out: list[_TenantOccurrence] = []
    for row in rows:
        template = str(row["path_template"])
        concrete = str(row["concrete_path"])
        principal_id = row["principal_id"]
        if principal_id is None:
            continue
        for kind, value in _tenant_segments(template, concrete):
            out.append(
                _TenantOccurrence(
                    observation_id=str(row["observation_id"]),
                    principal_id=str(principal_id),
                    kind=kind,
                    normalized_value=value,
                )
            )
    return out


def _tenant_segments(template: str, concrete: str) -> list[tuple[str, str]]:
    """Align a path template to a concrete path; yield (tenant_kind, value).

    Two tenant signals are recognised at a parameterised position (templates and
    concrete paths are aligned by segment index; a length mismatch — a templating
    revision lagging a re-ingest — yields nothing for that observation rather than
    a wrong value):

    1. **placeholder name** — a tenant-shaped placeholder segment (`{org_id}` etc.)
       maps directly via `TENANT_SEGMENT_KINDS`. The most precise signal, but it
       only fires when templating named the parameter tenant-shaped.
    2. **collection literal** — any parameterised segment (`{...}`, whatever its
       name) whose *preceding* template segment is a tenant collection literal
       (`orgs`, `workspaces`, …) maps via `TENANT_COLLECTION_KINDS`, taking the
       concrete value at the parameter position. This is robust to a templating
       collapse that renamed the placeholder to the generic `{id}` (issue #61): the
       collection literal survives the collapse, so `/orgs/{id}/projects` still
       yields `Tenant(org_id, 42)`. The position being a `{...}` parameter is itself
       templating's multiplicity evidence that it is a varying identifier slot, so
       the concrete value need not match an id-shape regex — a slug workspace id
       (`ws-a`) is as valid a tenant identifier as an integer org id.

    Both signals key off the same `Tenant.kind`, so `/orgs/{org_id}/…` and
    `/orgs/{id}/…` converge to one node (ADR-0008). When both fire on one segment
    (a tenant-shaped placeholder that *also* follows a known collection literal) the
    kinds agree, and downstream identity de-duplication collapses the two emitted
    occurrences to one tenant.
    """

    t_segs = [s for s in template.split("/") if s != ""]
    c_segs = [s for s in concrete.split("/") if s != ""]
    if len(t_segs) != len(c_segs):
        return []
    out: list[tuple[str, str]] = []
    for i, (t_seg, c_seg) in enumerate(zip(t_segs, c_segs, strict=True)):
        if not (t_seg.startswith("{") and t_seg.endswith("}")) or c_seg == "":
            continue
        # Signal 1: tenant-shaped placeholder name.
        name = t_seg[1:-1]
        if name in TENANT_SEGMENT_KINDS:
            out.append((TENANT_SEGMENT_KINDS[name], c_seg))
            continue
        # Signal 2: a generic placeholder (`{id}`) preceded by a tenant collection
        # literal. The position is already a templated parameter, so its concrete
        # value is the tenant identifier whatever its lexical shape.
        preceding = t_segs[i - 1] if i > 0 else None
        if preceding is not None and preceding in TENANT_COLLECTION_KINDS:
            out.append((TENANT_COLLECTION_KINDS[preceding], c_seg))
    return out


def _merge_tenant(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    tenant_node_id: TenantId,
    kind: str,
    normalized_value: str,
    observation_ids: list[str],
    principal_ids: list[str],
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """MERGE one `Tenant` + its `DERIVED_FROM` + `OF_TENANT` edges (identity-keyed).

    Identity `(engagement_id, kind, normalized_value)` (ADR-0008). Each evidencing
    observation gets a `DERIVED_FROM` edge (lineage backbone, ADR-0001); each
    evidencing observation's Principal gets an `OF_TENANT` edge (M:N). All MERGEd
    so re-runs add nothing.
    """

    props = cross_cutting(
        source=_TENANT_SOURCE,
        source_id=None,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    props["inferred_at"] = ingested_at
    props["code_version"] = _TENANT_CODE_VERSION
    client.execute_write(
        """
        MERGE (t:Tenant {engagement_id: $engagement_id, kind: $kind,
                         normalized_value: $normalized_value})
        ON CREATE SET t.id = $tenant_id, t += $props
        ON MATCH SET t.last_seen = $props.last_seen, t.status = 'active'
        WITH t
        UNWIND $observation_ids AS oid
        MATCH (r:RequestObservation {engagement_id: $engagement_id, id: oid})
        MERGE (t)-[df:DERIVED_FROM]->(r)
        ON CREATE SET df.engagement_id = $engagement_id
        WITH DISTINCT t
        UNWIND $principal_ids AS pid
        MATCH (p:Principal {engagement_id: $engagement_id, id: pid})
        MERGE (p)-[ot:OF_TENANT]->(t)
        ON CREATE SET ot.engagement_id = $engagement_id
        """,
        engagement_id=engagement_id,
        kind=kind,
        normalized_value=normalized_value,
        tenant_id=tenant_node_id,
        observation_ids=observation_ids,
        principal_ids=principal_ids,
        props=props,
    )
