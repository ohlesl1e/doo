"""Deterministic C2 context-pack assembly (ADR-0037, S2a).

The planner's *one* non-deterministic step is the LLM proposal; everything that
feeds it is deterministic code. This module is the feed: it turns one C2 coverage
gap (`C2Result` — endpoint reached as principal A but not as B) into the typed,
id-free `ContextPack` the LLM reasons over.

The pack is bounded and secret-free (ADR-0015/0037): targets and auth contexts are
addressed by pack-local handles (`T1`, `A1`) never raw node ids; response bodies
never appear (the gap carries only metadata); token material never appears (only
the AuthContext tier + claim *names*). `to_llm_payload()` strips the real ids out
again before serialisation — they live on the typed objects purely so the resolver
can map a returned handle back to a concrete id.

`assemble_c2_pack` returns `None` for a gap it cannot turn into a proposable test
(no resolvable attacker AuthContext for the B side) — the generator records that as
a skip rather than calling the model with an incomplete pack.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from doo.coverage.models import C2Result
from doo.ids import AuthContextId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.models import (
    ContextPack,
    PackAuthContext,
    PackExemplar,
    PackTarget,
)

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _AuthView:
    """One resolved AuthContext for a principal (the resolver's id + LLM context)."""

    auth_context_id: AuthContextId
    tier: str | None
    claims_summary: str | None


def _summarise_claims(bearer_claims_json: str | None) -> str | None:
    """A secret-free one-liner of an AuthContext's bearer claims (names only).

    The token's *claim names* (e.g. `sub, role, org_id`) orient the LLM without
    ever leaking a value (ADR-0015). Returns None when there are no claims.
    """

    if not bearer_claims_json:
        return None
    try:
        claims = json.loads(bearer_claims_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(claims, dict) or not claims:
        return None
    return "claims: " + ", ".join(sorted(str(k) for k in claims))


def _fetch_principal_auth(
    client: Neo4jClient, engagement_id: EngagementId, principal_id: str
) -> _AuthView | None:
    """Resolve one active AuthContext for a principal (the replay token handle).

    A principal may hold several AuthContexts; we pick one deterministically,
    preferring a real (non-anonymous) token over the anonymous singleton, then by
    `id` for stability. Returns None when the principal has no active AuthContext
    (a Principal is always created from one, so this is the defensive empty case).
    """

    frag = for_engagement(engagement_id, var="ac")
    rows = client.execute_read(
        f"""
        MATCH (ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {{id: $principal_id}})
        {frag.and_("ac.status = 'active' AND p.status = 'active'")}
        RETURN ac.id AS id,
               ac.tier AS tier,
               ac.is_anonymous AS is_anonymous,
               ac.bearer_claims AS bearer_claims
        ORDER BY coalesce(ac.is_anonymous, false) ASC, ac.tier ASC, ac.id ASC
        LIMIT 1
        """,
        principal_id=principal_id,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    return _AuthView(
        auth_context_id=AuthContextId(str(row["id"])),
        tier=str(row["tier"]) if row["tier"] is not None else None,
        claims_summary=_summarise_claims(row["bearer_claims"]),
    )


def _fetch_exemplar(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    endpoint_id: str,
    principal_id: str,
) -> PackExemplar | None:
    """One concrete 2xx request principal A made to the endpoint (the replay shape).

    Returns the concrete request path so the LLM can see the literal object ids it
    must hold (`hold`); request/response bodies and query *values* are deliberately
    excluded (ADR-0015) — only the path the attacker would replay. None when no
    concrete path was captured.
    """

    frag = for_engagement(engagement_id, var="r")
    rows = client.execute_read(
        f"""
        MATCH (r:RequestObservation)-[:HIT]->(e:Endpoint {{id: $endpoint_id}}),
              (r)-[:OBSERVED_UNDER]->(:AuthContext)-[:OF_PRINCIPAL]
                ->(p:Principal {{id: $principal_id}})
        {frag.and_("r.status = 'active' AND e.status = 'active'")}
          AND r.response_status >= 200 AND r.response_status <= 299
          AND r.concrete_path IS NOT NULL
        RETURN r.concrete_path AS concrete_path
        ORDER BY r.response_status DESC
        LIMIT 1
        """,
        endpoint_id=endpoint_id,
        principal_id=principal_id,
        **frag.parameters,
    )
    if not rows or rows[0]["concrete_path"] is None:
        return None
    return PackExemplar(concrete_path=str(rows[0]["concrete_path"]))


def assemble_c2_pack(
    client: Neo4jClient,
    *,
    gap: C2Result,
    principal_ids: dict[str, str],
    code_version: str,
    now: datetime,
) -> ContextPack | None:
    """Build the `ContextPack` for one C2 gap, or None when it is unproposable.

    The A side (reached, 2xx) and B side (did not reach) become the two pack auth
    contexts; B is marked `is_attacker_candidate` — the principal a replay would
    swap in. The endpoint is the single holdable target (`T1`). Returns None when
    the B side has no resolvable AuthContext (nothing to replay as) — the caller
    treats that as a skipped gap, not a model call.

    `principal_ids` maps a coverage display label to its Principal id (the B side's
    id is not on the gap when B never reached the endpoint). `code_version` /
    `now` stamp the pack for the audit trail.
    """

    eid = gap.engagement_id
    a_pid = gap.evidence_a.principal_id
    b_pid = principal_ids.get(gap.principal_b_label)
    if b_pid is None:
        log.warning(
            "planner.assemble.b_principal_unresolved",
            engagement_id=eid,
            endpoint_id=gap.endpoint_id,
            b_label=gap.principal_b_label,
        )
        return None

    b_auth = _fetch_principal_auth(client, eid, b_pid)
    if b_auth is None:
        log.warning(
            "planner.assemble.no_attacker_auth",
            engagement_id=eid,
            endpoint_id=gap.endpoint_id,
            b_label=gap.principal_b_label,
        )
        return None
    a_auth = _fetch_principal_auth(client, eid, a_pid)
    if a_auth is None:
        # A reached with a 2xx, so it has an AuthContext; absence means a retraction
        # raced the assembly. Without the A context the replay has no baseline.
        log.warning(
            "planner.assemble.no_victim_auth",
            engagement_id=eid,
            endpoint_id=gap.endpoint_id,
            a_label=gap.principal_a_label,
        )
        return None

    target = PackTarget(
        handle="T1",
        kind="endpoint",
        method=gap.method,
        path_template=gap.path_template,
        endpoint_id=gap.endpoint_id,
    )
    a_ctx = PackAuthContext(
        handle="A1",
        principal_label=gap.principal_a_label,
        tier=a_auth.tier,
        claims_summary=a_auth.claims_summary,
        is_attacker_candidate=False,
        auth_context_id=a_auth.auth_context_id,
    )
    b_ctx = PackAuthContext(
        handle="A2",
        principal_label=gap.principal_b_label,
        tier=b_auth.tier,
        claims_summary=b_auth.claims_summary,
        is_attacker_candidate=True,
        auth_context_id=b_auth.auth_context_id,
    )
    exemplar = _fetch_exemplar(client, eid, endpoint_id=gap.endpoint_id, principal_id=a_pid)

    return ContextPack(
        engagement_id=eid,
        candidate_kind="C2",
        candidate_reason=(
            f"C2 presence gap: {gap.method} {gap.host}{gap.path_template} reached "
            f"(2xx) as {gap.principal_a_label} but not as {gap.principal_b_label}"
        ),
        endpoint_method=gap.method,
        endpoint_path_template=gap.path_template,
        targets=(target,),
        auth_contexts=(a_ctx, b_ctx),
        exemplar=exemplar,
        code_version=code_version,
        generated_at=now,
    )
