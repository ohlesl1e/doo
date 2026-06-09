"""Flush-time `Tenant` inference pass (ADR-0008, the ADR-0022 seam).

The graph-touching counterpart to the tenant-detection decision, mirroring
`ontology/promotion.py` / `ontology/templating.py`. It runs at flush (ADR-0022)
beside cohort re-templating and value promotion: there is no mid-drain reader, so
`Tenant` nodes appear at flush alongside endpoints.

`Tenant` is an inference-layer node (ADR-0008). In black-box mode tenants are
inferred from observations; the highest-precision, fully-deterministic signal is
a **tenant identifier in a URL position** — an `Endpoint` whose `path_template`
carries a tenant-shaped segment placeholder (`{org_id}`, `{tenant_id}`,
`{workspace_id}`, `{account_id}`), with the concrete value taken from the
`RequestObservation.concrete_path` at that segment. This is the signal the
slice-3 tenant `TrustBoundary` consumer needs (ADR-0039): two tenants that share
an `Endpoint`.

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
# detection heuristic changes so stale inferences are identifiable.
_TENANT_CODE_VERSION = "tenant-inference/1"

# Tenant-shaped path-segment placeholders, mapped to the `Tenant.kind` they
# evidence. The segment name (templating's `{<base>_id}` convention, e.g.
# `orgs` -> `org_id`) is the most precise URL-position tenant signal (ADR-0008).
TENANT_SEGMENT_KINDS: dict[str, str] = {
    "org_id": "org_id",
    "tenant_id": "tenant_id",
    "workspace_id": "workspace",
    "account_id": "account_namespace",
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

    Joins each `RequestObservation` to the `Endpoint` it `HIT` and that
    Endpoint's host, recovers the path-template segments, and — for every
    tenant-shaped placeholder (`{org_id}` etc.) — extracts the concrete value at
    that segment from the observation's `concrete_path`. The Principal comes from
    the observation's AuthContext (`OBSERVED_UNDER` → `OF_PRINCIPAL`).

    Done in Cypher down to the per-observation (template, concrete_path) pair;
    the segment alignment + placeholder matching is finished in Python (clearer
    than list-zipping in Cypher and trivially testable).
    """

    rows = client.execute_read(
        """
        MATCH (r:RequestObservation {engagement_id: $engagement_id})-[:HIT]->
              (e:Endpoint {engagement_id: $engagement_id})
        WHERE e.status = 'active'
          AND any(seg IN split(e.path_template, '/') WHERE seg IN $placeholders)
        MATCH (r)-[:OBSERVED_UNDER]->(:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        WHERE p.status IS NULL OR p.status = 'active'
        RETURN r.id AS observation_id, r.concrete_path AS concrete_path,
               e.path_template AS path_template, p.id AS principal_id
        """,
        engagement_id=engagement_id,
        placeholders=[f"{{{name}}}" for name in TENANT_SEGMENT_KINDS],
    )
    out: list[_TenantOccurrence] = []
    for row in rows:
        template = str(row["path_template"])
        concrete = str(row["concrete_path"])
        principal_id = row["principal_id"]
        if principal_id is None:
            continue
        for placeholder_name, value in _tenant_segments(template, concrete):
            kind = TENANT_SEGMENT_KINDS[placeholder_name]
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
    """Align a path template to a concrete path; yield (placeholder_name, value).

    For each tenant-shaped placeholder segment (`{org_id}` etc.) in the template,
    return the concrete value at the same position. Templates and concrete paths
    are aligned by segment index; a length mismatch (a templating revision lagging
    a re-ingest) yields nothing for that observation rather than a wrong value.
    """

    t_segs = [s for s in template.split("/") if s != ""]
    c_segs = [s for s in concrete.split("/") if s != ""]
    if len(t_segs) != len(c_segs):
        return []
    out: list[tuple[str, str]] = []
    for t_seg, c_seg in zip(t_segs, c_segs, strict=True):
        if t_seg.startswith("{") and t_seg.endswith("}"):
            name = t_seg[1:-1]
            if name in TENANT_SEGMENT_KINDS and c_seg != "":
                out.append((name, c_seg))
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
