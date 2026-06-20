"""Deterministic C2 / C2b context-pack assembly (ADR-0037, S2a/S2b).

The planner's *one* non-deterministic step is the LLM proposal; everything that
feeds it is deterministic code. This module is the feed: it turns one authz
coverage gap into the typed, id-free `ContextPack` the LLM reasons over.

- `assemble_c2_pack` — a **C2 presence gap** (`C2Result`: endpoint reached as
  principal A but not as B). Two auth contexts (A reached, B did not); B is the
  single attacker candidate.
- `assemble_c2b_pack` — a **C2b content-differential gap** (`C2bResult`: ≥2
  principals ALL reached the endpoint with a 2xx but their bodies differ — the
  BOLA/IDOR hotspot). Here *any* reaching principal could be attacker or victim, so
  **every** reaching principal is a pack auth context; the **armable** ones
  (`ARMABLE_ATTACKER_TIERS` — declared- or anonymous-tier; credentials the tester
  controls or can omit — ADR-0010/0048/0049, #131) are marked
  `is_attacker_candidate=True`, discovered-tier ones stay in the pack as
  evidence/victim context only, and the LLM picks which armable one to replay as.

The pack is bounded and secret-free (ADR-0015/0037): targets and auth contexts are
addressed by pack-local handles (`T1`, `A1`) never raw node ids; response bodies
never appear (the gap carries only metadata); token material never appears (only
the AuthContext tier + claim *names*). `to_llm_payload()` strips the real ids out
again before serialisation — they live on the typed objects purely so the resolver
can map a returned handle back to a concrete id.

An assembler returns `None` for a gap it cannot turn into a proposable test (no
resolvable AuthContext) — the generator records that as a skip rather than calling
the model with an incomplete pack.

`fetch_reaching_observation_hazards` is the **deterministic** replay-hazard read
(ADR-0041): it pulls one reaching 2xx observation's stored `value_candidates` and
runs the `replay_hazards` detector (no LLM). The generator stamps the result onto
the resolved proposal — replay-breakers are endpoint-level request features, so the
detector runs once over a reaching observation, not per auth context.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from doo.canonical.trust_boundary import CapabilityKind, stronger_capability_side
from doo.coverage.models import C2bResult, C2Result, C3Result, PrincipalEvidence
from doo.events.observation import ValueCandidate
from doo.ids import (
    AuthContextId,
    EngagementId,
    ParameterId,
    Sha256Hex,
    TrustBoundaryId,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.models import (
    ARMABLE_ATTACKER_TIERS,
    ContextPack,
    PackAuthContext,
    PackExemplar,
    PackTarget,
    ReplayHazardRole,
)
from doo.planner.replay_hazards import (
    hazards_for_value_candidates,
    source_hints_for_value_candidates,
)

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _AuthView:
    """One resolved AuthContext for a principal (the resolver's id + LLM context)."""

    auth_context_id: AuthContextId
    tier: str | None
    claims_summary: str | None
    # ADR-0049: the credential slot (rotation-stable attacker-identity half).
    # `None` ⇔ un-armable as the attacker side. The Cypher projections in this
    # module are responsible for that contract: the `coalesce(ac.slot,
    # ac.token_kind)` fallback (for pre-ADR-0049 declared nodes) is gated on
    # `ac.tier` so a discovered-tier AC never surfaces a non-None slot (#129).
    # `tier='anonymous'` resolves to the `'anonymous'` sentinel — armable
    # (the dispatcher's no-auth short-circuit), reserved in `setup/config.py`.
    slot: str | None = None


def _summarise_claims(identity_claims_json: object) -> str | None:
    """A secret-free one-liner of an AuthContext's bearer claims (names only).

    The token's *claim names* (e.g. `sub, role, org_id`) orient the LLM without
    ever leaking a value (ADR-0015). Returns None when there are no claims.
    """

    if not identity_claims_json:
        return None
    try:
        claims = json.loads(str(identity_claims_json))
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(claims, dict) or not claims:
        return None
    return "claims: " + ", ".join(sorted(str(k) for k in claims))


def _fetch_principal_auth(
    client: Neo4jClient,
    engagement_id: EngagementId,
    principal_id: str,
    *,
    prefer_token_kind: str | None = None,
) -> _AuthView | None:
    """Resolve one active AuthContext for a principal (the replay token handle).

    A principal may hold several AuthContexts; we pick one deterministically,
    preferring a real (non-anonymous) token over the anonymous singleton, then a
    declared/anonymous AC over a discovered one (`ac.tier ASC`), then — when
    `prefer_token_kind` is set (ADR-0050) — an AC of that `token_kind` over any
    other, with the AC whose `slot` literal *equals* the kind (the ADR-0049
    default-slot convention) preferred among same-kind ACs. When the Principal
    declares ≥2 slots of the same kind and neither's `slot` equals the kind, the
    `ac.id` tie-break decides — deterministic but arbitrary; document in the
    proposal's justification if it matters. `prefer_token_kind=None` (the C2/C2b
    callers) keeps the pre-ADR-0050 ordering exactly.

    Returns None when the principal has no active AuthContext (a Principal is
    always created from one, so this is the defensive empty case).
    """

    frag = for_engagement(engagement_id, var="ac")
    # `prefer_token_kind` adds two boolean DESC terms ahead of the `ac.id`
    # tie-break; with `$kind = null` both compare against null → null → all rows
    # tie on those terms → ordering collapses to the pre-ADR-0050 shape.
    rows = client.execute_read(
        f"""
        MATCH (ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {{id: $principal_id}})
        {frag.and_("ac.status = 'active' AND p.status = 'active'")}
        RETURN ac.id AS id,
               ac.tier AS tier,
               ac.is_anonymous AS is_anonymous,
               ac.identity_claims AS identity_claims,
               CASE ac.tier
                 WHEN 'declared' THEN coalesce(ac.slot, ac.token_kind)
                 WHEN 'anonymous' THEN 'anonymous'
               END AS slot
        ORDER BY coalesce(ac.is_anonymous, false) ASC,
                 ac.tier ASC,
                 (ac.token_kind = $kind) DESC,
                 (coalesce(ac.slot, ac.token_kind) = $kind) DESC,
                 ac.id ASC
        LIMIT 1
        """,
        principal_id=principal_id,
        kind=prefer_token_kind,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    return _AuthView(
        auth_context_id=AuthContextId(str(row["id"])),
        tier=str(row["tier"]) if row["tier"] is not None else None,
        claims_summary=_summarise_claims(row["identity_claims"]),
        slot=str(row["slot"]) if row["slot"] is not None else None,
    )


def _fetch_send_as_auth(
    client: Neo4jClient, engagement_id: EngagementId, endpoint_id: str
) -> tuple[_AuthView, str] | None:
    """Resolve one identity that hit the endpoint — the C3 'send-as' auth context.

    C3 is not an authz swap: the leaked value is replayed *as* some identity. Per
    ADR-0050 the send-as identity is the **Principal** that reached the endpoint
    (CONTEXT.md: *reached* is defined as a Principal), and the AC is resolved from
    that Principal exactly as C2/C2b do — so a discovered cookie of a declared
    Principal yields the Principal's *declared* AC (the armable resolution handle),
    not the observed token snapshot.

    Two steps:
      1. Rank the **distinct Principals** whose AuthContexts were `OBSERVED_UNDER` a
         request that `HIT` the endpoint: declared > anonymous > discovered (mirrors
         `ARMABLE_ATTACKER_TIERS` at the Principal level), tie-break `p.label`.
         For the top Principal, also surface one observed `ac.token_kind` (the
         auth mechanism the traffic used).
      2. Resolve that Principal's armable AC via
         `_fetch_principal_auth(p.id, prefer_token_kind=<observed kind>)`.

    Returns the `_AuthView` (which may be `slot=None` when the top Principal is
    discovered/non-anon — `resolve_c3_draft` then rejects with `attacker_no_slot`)
    + the principal's display label, or `None` when nothing hit the endpoint.
    """

    frag = for_engagement(engagement_id, var="r")
    rows = client.execute_read(
        f"""
        MATCH (r:RequestObservation)-[:HIT]->(e:Endpoint {{id: $endpoint_id}}),
              (r)-[:OBSERVED_UNDER]->(ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        {frag.and_("r.status = 'active' AND e.status = 'active' AND ac.status = 'active' AND p.status = 'active'")}
        WITH p,
             CASE
               WHEN p.tier = 'declared' THEN 0
               WHEN coalesce(p.is_anonymous, false) THEN 1
               ELSE 2
             END AS p_rank,
             coalesce(p.label, p.identity_key) AS label,
             coalesce(p.is_anonymous, false) AS p_anon,
             collect(DISTINCT ac.token_kind)[0] AS observed_kind
        RETURN p.id AS principal_id, p_rank, p_anon, label, observed_kind
        ORDER BY p_rank ASC, label ASC
        LIMIT 1
        """,
        endpoint_id=endpoint_id,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    label = "anon" if bool(row["p_anon"]) else str(row["label"])
    observed_kind = (
        str(row["observed_kind"]) if row["observed_kind"] is not None else None
    )
    view = _fetch_principal_auth(
        client,
        engagement_id,
        str(row["principal_id"]),
        prefer_token_kind=observed_kind,
    )
    if view is None:
        # The Principal hit the endpoint, so it has ≥1 active AC; this is the
        # defensive empty-after-retraction case.
        return None
    return view, label


def assemble_c3_pack(
    client: Neo4jClient,
    *,
    gap: C3Result,
    code_version: str,
    now: datetime,
) -> ContextPack | None:
    """Build the `ContextPack` for one C3 leak-to-input pivot, or None if unproposable.

    The target is the **input Parameter** the leaked value is sent to (`T1`,
    `kind="parameter"`); scope is enforced on its endpoint by the Validator
    (ADR-0020). One auth context (`A1`) is the identity to replay the value as. The
    leaked value's `kind`/`preview`/source endpoints go in `candidate_reason` (never
    the raw secret, ADR-0015); `observed_value_hash` carries the propose-time-known
    payload the resolver fixes into `payload_spec = observed_value`. Returns None
    when the row names no parameter, the `Parameter` node can't be resolved, or no
    send-as identity resolves.
    """

    eid = gap.engagement_id
    if gap.parameter_name is None:
        return None  # no named input parameter → nothing to target.

    frag = for_engagement(eid, var="p")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint {{id: $endpoint_id}})-[:HAS_PARAMETER]->(p:Parameter {{name: $name}})
        {frag.and_("p.status = 'active' AND e.status = 'active'")}
        RETURN p.id AS id, p.location AS location
        ORDER BY p.location
        LIMIT 1
        """,
        endpoint_id=gap.target_endpoint_id,
        name=gap.parameter_name,
        **frag.parameters,
    )
    if not rows:
        log.warning(
            "planner.assemble.c3_parameter_unresolved",
            engagement_id=eid,
            endpoint_id=gap.target_endpoint_id,
            parameter_name=gap.parameter_name,
        )
        return None
    param_id = ParameterId(str(rows[0]["id"]))
    location = str(rows[0]["location"]) if rows[0]["location"] is not None else None

    send_as = _fetch_send_as_auth(client, eid, gap.target_endpoint_id)
    if send_as is None:
        log.warning(
            "planner.assemble.c3_no_send_as_auth",
            engagement_id=eid,
            endpoint_id=gap.target_endpoint_id,
        )
        return None
    auth, principal_label = send_as

    target = PackTarget(
        handle="T1",
        kind="parameter",
        method=gap.target_method,
        path_template=gap.target_path_template,
        param_name=gap.parameter_name,
        location=location,
        endpoint_id=gap.target_endpoint_id,
        parameter_id=param_id,
    )
    auth_ctx = PackAuthContext(
        handle="A1",
        principal_label=principal_label,
        tier=auth.tier,
        claims_summary=auth.claims_summary,
        is_attacker_candidate=False,
        auth_context_id=auth.auth_context_id,
        slot=auth.slot,
    )
    preview = f" (preview {gap.value_preview!r})" if gap.value_preview is not None else ""
    reason = (
        f"C3 leak-to-input: a {gap.kind} value{preview} leaked from "
        f"{', '.join(gap.source_endpoints)} is accepted as parameter "
        f"{gap.parameter_name!r} by in-scope {gap.target_method} "
        f"{gap.target_host}{gap.target_path_template}"
    )
    return ContextPack(
        engagement_id=eid,
        candidate_kind="C3",
        candidate_reason=reason,
        endpoint_method=gap.target_method,
        endpoint_path_template=gap.target_path_template,
        targets=(target,),
        auth_contexts=(auth_ctx,),
        observed_value_hash=Sha256Hex(gap.value_hash),
        code_version=code_version,
        generated_at=now,
    )


def assemble_sink_pack(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    parameter_id: str,
    sink_role: str,
    code_version: str,
    now: datetime,
) -> ContextPack | None:
    """Build the `ContextPack` for one sink `Parameter` (S6), or None if unproposable.

    The sink parameter is the target (`T1`, `kind="parameter"`, carrying its detected
    `sink_role` as `semantic`); scope is enforced on its endpoint by the Validator.
    One send-as identity (`A1`) is resolved from a request that hit the endpoint.
    Returns None when the parameter / endpoint or a send-as identity does not resolve.
    """

    frag = for_engagement(engagement_id, var="p")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter {{id: $pid}}),
              (e)-[:ON_HOST]->(:Host)
        {frag.and_("p.status = 'active' AND e.status = 'active'")}
        RETURN e.id AS eid, e.method AS method, e.path_template AS path,
               p.name AS name, p.location AS loc
        LIMIT 1
        """,
        pid=parameter_id,
        **frag.parameters,
    )
    if not rows:
        return None
    r = rows[0]
    send_as = _fetch_send_as_auth(client, engagement_id, str(r["eid"]))
    if send_as is None:
        return None
    auth, principal_label = send_as

    target = PackTarget(
        handle="T1",
        kind="parameter",
        method=str(r["method"]),
        path_template=str(r["path"]),
        param_name=str(r["name"]),
        location=str(r["loc"]) if r["loc"] is not None else None,
        semantic=sink_role,
        endpoint_id=str(r["eid"]),
        parameter_id=ParameterId(parameter_id),
    )
    auth_ctx = PackAuthContext(
        handle="A1",
        principal_label=principal_label,
        tier=auth.tier,
        claims_summary=auth.claims_summary,
        is_attacker_candidate=False,
        auth_context_id=auth.auth_context_id,
        slot=auth.slot,
    )
    reason = (
        f"Sink parameter: {r['method']} {r['path']} consumes a caller-controlled "
        f"{sink_role} via parameter {str(r['name'])!r} — test for the corresponding "
        f"sink vulnerability (SSRF / open-redirect / path-traversal)"
    )
    return ContextPack(
        engagement_id=engagement_id,
        candidate_kind="sink",
        candidate_reason=reason,
        endpoint_method=str(r["method"]),
        endpoint_path_template=str(r["path"]),
        targets=(target,),
        auth_contexts=(auth_ctx,),
        code_version=code_version,
        generated_at=now,
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
        slot=a_auth.slot,
    )
    b_ctx = PackAuthContext(
        handle="A2",
        principal_label=gap.principal_b_label,
        tier=b_auth.tier,
        claims_summary=b_auth.claims_summary,
        is_attacker_candidate=True,
        auth_context_id=b_auth.auth_context_id,
        slot=b_auth.slot,
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


def _outlier_holders(evidence: Sequence[PrincipalEvidence]) -> set[str]:
    """Principal ids holding an *outlier* body vs the baseline cluster (#112).

    The per-principal signature is the same tuple C2b's divergence test keys on —
    `(response_body_sha256, response_size_bytes)`, nulls included (mirrors
    `coverage.queries._group_diverges`) — so planner and coverage never disagree on
    what "differs." The **modal** signature is the one held by *strictly more*
    principals than any other; every principal NOT holding it is an outlier (it
    already holds a differentiated response, so replaying as it tests nothing).

    When there is no strict plurality — a tie for most-common, which includes the
    all-distinct case (every body unique) — there is no baseline to contrast
    against, so nobody is an outlier and the set is empty. The deterministic layer
    deliberately degrades to silence there and hands the LLM the full, un-steered
    set (ADR-0033: surface, don't adjudicate the ambiguous case).
    """

    if len(evidence) < 2:
        return set()
    sig = {
        ev.principal_id: (ev.response_body_sha256, ev.response_size_bytes)
        for ev in evidence
    }
    ranked = Counter(sig.values()).most_common()
    top_signature, top_count = ranked[0]
    if len(ranked) > 1 and ranked[1][1] == top_count:
        return set()  # tie for most-common → no baseline cluster → flag nobody
    return {pid for pid, s in sig.items() if s != top_signature}


# C2b A1/A2/... preference rank (#113/#131): declared before anonymous before
# anything else (discovered/None → 2). Coupled to `ARMABLE_ATTACKER_TIERS` —
# every armable tier MUST have a rank < 2 so a candidate never sorts behind a
# non-candidate.
_ATTACKER_TIER_RANK: dict[str, int] = {"declared": 0, "anonymous": 1}


def assemble_c2b_pack(
    client: Neo4jClient,
    *,
    gap: C2bResult,
    code_version: str,
    now: datetime,
) -> ContextPack | None:
    """Build the `ContextPack` for one C2b content-differential gap, or None.

    A C2b gap is an endpoint ≥2 active principals ALL reached with a 2xx but whose
    response bodies differ (the role-differentiated-200 BOLA/IDOR hotspot). Unlike
    C2 (one reached, one did not), here there is no privileged "victim vs attacker"
    split a priori: any reaching principal could be the attacker reading another's
    differentiated resource. So **every** reaching principal becomes a
    `PackAuthContext`, but only the **armable** ones (`ARMABLE_ATTACKER_TIERS` —
    declared- or anonymous-tier; credentials the tester controls or can omit —
    ADR-0010/0048/0049, #131) are marked `is_attacker_candidate=True`; discovered-
    tier contexts remain in the pack as evidence/victim context, never offered as the
    swap-in side. The endpoint is the single holdable target (`T1`).

    `gap.evidence` already carries every reaching principal (per ADR-0033). Each
    principal's AuthContext is resolved the same way `assemble_c2_pack` does
    (`_fetch_principal_auth`). Returns None when fewer than two principals have a
    resolvable AuthContext (nothing differential left to replay) **or** when none of
    the resolved contexts is an armable tier (no controlled credential to replay
    as) — the caller treats either as a skipped gap, not a model call.
    """

    eid = gap.engagement_id

    # The outlier set is computed over the FULL differential population (every
    # reaching principal), not just the resolvable ones — the baseline cluster is
    # defined by what was observed (#112).
    outlier_holders = _outlier_holders(gap.evidence)

    # Collect resolved (ev, auth) pairs in **evidence order** first; handles are
    # assigned in a separate pass below so they can be ordered by attacker
    # preference (#113) without disturbing exemplar selection.
    resolved: list[tuple[PrincipalEvidence, _AuthView]] = []
    exemplar_principal_id: str | None = None
    for ev in gap.evidence:
        auth = _fetch_principal_auth(client, eid, ev.principal_id)
        if auth is None:
            log.warning(
                "planner.assemble.c2b.principal_auth_unresolved",
                engagement_id=eid,
                endpoint_id=gap.endpoint_id,
                principal_label=ev.label,
            )
            continue
        resolved.append((ev, auth))
        if exemplar_principal_id is None:
            exemplar_principal_id = ev.principal_id

    # Assign A1, A2, ... in **preference order** (#113): a positionally-biased weak
    # model defaults to A1, so put the most-meaningful pick there. Stable sort over
    # evidence order by (tier rank, holds_outlier_body) ascending →
    #   1. declared  ∧ ¬outlier  — preferred attacker (meaningful, dispatchable)
    #   2. declared  ∧  outlier  — dispatchable but no-op (#112 soft signal)
    #   3. anonymous ∧ ¬outlier  — armable (no-auth sentinel, #131)
    #   4. anonymous ∧  outlier
    #   5. discovered/unknown    — evidence-only (#110: never an attacker candidate)
    # Same entries, same flag values; only handle numbering / list position move.
    resolved.sort(
        key=lambda ea: (
            _ATTACKER_TIER_RANK.get(ea[1].tier or "", 2),
            ea[0].principal_id in outlier_holders,
        )
    )
    auth_contexts: list[PackAuthContext] = [
        PackAuthContext(
            handle=f"A{n}",
            principal_label=ev.label,
            tier=auth.tier,
            claims_summary=auth.claims_summary,
            # Any reaching principal is a *potential* attacker for the content
            # differential (no a-priori victim/attacker split, ADR-0033) — but an
            # authz replay only swaps in a credential the tester controls or can
            # omit, so only **armable** contexts (declared/anonymous —
            # ADR-0010/0048/0049, #131) are offered as attacker candidates.
            # Discovered-tier contexts stay in the pack as evidence/victim context.
            is_attacker_candidate=(auth.tier in ARMABLE_ATTACKER_TIERS),
            # Advisory soft steer (#112): this principal already holds a body
            # that differs from the baseline group, so replaying as it is a
            # no-op. It stays a candidate; only the prompt is nudged. See
            # `PackAuthContext.holds_outlier_body` for why this is soft, not a
            # filter.
            holds_outlier_body=(ev.principal_id in outlier_holders),
            auth_context_id=auth.auth_context_id,
            slot=auth.slot,
        )
        for n, (ev, auth) in enumerate(resolved, start=1)
    ]

    if len(auth_contexts) < 2:
        log.warning(
            "planner.assemble.c2b.too_few_auth_contexts",
            engagement_id=eid,
            endpoint_id=gap.endpoint_id,
            resolved=len(auth_contexts),
        )
        return None
    if not any(a.is_attacker_candidate for a in auth_contexts):
        log.warning(
            "planner.assemble.c2b.no_armable_attacker",
            engagement_id=eid,
            endpoint_id=gap.endpoint_id,
            resolved=len(auth_contexts),
            tiers=sorted({a.tier for a in auth_contexts if a.tier is not None}),
        )
        return None

    target = PackTarget(
        handle="T1",
        kind="endpoint",
        method=gap.method,
        path_template=gap.path_template,
        endpoint_id=gap.endpoint_id,
    )
    labels = ", ".join(ev.label for ev in gap.evidence)
    exemplar = (
        _fetch_exemplar(
            client, eid, endpoint_id=gap.endpoint_id, principal_id=exemplar_principal_id
        )
        if exemplar_principal_id is not None
        else None
    )

    return ContextPack(
        engagement_id=eid,
        candidate_kind="C2b",
        candidate_reason=(
            f"C2b content-differential: {gap.method} {gap.host}{gap.path_template} "
            f"reached (2xx) by {len(gap.evidence)} principals ({labels}) whose "
            "response bodies differ — a role-differentiated 200 (BOLA/IDOR hotspot)"
        ),
        endpoint_method=gap.method,
        endpoint_path_template=gap.path_template,
        targets=(target,),
        auth_contexts=tuple(auth_contexts),
        exemplar=exemplar,
        code_version=code_version,
        generated_at=now,
    )


def _parse_value_candidates(raw: object) -> tuple[ValueCandidate, ...]:
    """Parse the node's stored `value_candidates` (a list of JSON strings) to models.

    `resolve.py` persists each `ValueCandidate` as a JSON string in a list property
    (Neo4j has no struct type). A malformed entry is skipped defensively rather than
    failing the whole detection.
    """

    if not isinstance(raw, list):
        return ()
    out: list[ValueCandidate] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        try:
            out.append(ValueCandidate.model_validate_json(item))
        except ValueError:
            continue
    return tuple(out)


def _boundary_evidence_endpoint(
    client: Neo4jClient, engagement_id: EngagementId, boundary_id: str
) -> tuple[str, str, str] | None:
    """The (endpoint_id, method, path_template) of a boundary's DERIVED_FROM evidence."""

    frag = for_engagement(engagement_id, var="tb")
    rows = client.execute_read(
        f"""
        MATCH (tb:TrustBoundary {{id: $tbid}})-[:DERIVED_FROM]->
              (r:RequestObservation)-[:HIT]->(e:Endpoint)
        {frag.and_("(tb.status IS NULL OR tb.status = 'active') AND e.status = 'active'")}
        RETURN e.id AS id, e.method AS method, e.path_template AS path_template
        ORDER BY e.id
        LIMIT 1
        """,
        tbid=boundary_id,
        **frag.parameters,
    )
    if not rows:
        return None
    r = rows[0]
    return str(r["id"]), str(r["method"]), str(r["path_template"])


def _parse_claims(raw: object) -> dict[str, object]:
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _capability_auth_contexts(
    client: Neo4jClient, engagement_id: EngagementId, boundary_id: str, cap_kind: str
) -> tuple[PackAuthContext, PackAuthContext] | None:
    """The (victim=stronger, attacker=weaker) auth contexts of a capability boundary."""

    if cap_kind not in ("scope", "mfa", "freshness"):
        return None
    frag = for_engagement(engagement_id, var="tb")
    rows = client.execute_read(
        f"""
        MATCH (tb:TrustBoundary {{id: $tbid}})-[:BETWEEN]->
              (ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        {frag.and_("(ac.status IS NULL OR ac.status = 'active')")}
        RETURN ac.id AS id, ac.identity_claims AS claims, ac.tier AS tier,
               p.label AS p_label,
               CASE ac.tier
                 WHEN 'declared' THEN coalesce(ac.slot, ac.token_kind)
                 WHEN 'anonymous' THEN 'anonymous'
               END AS slot
        ORDER BY ac.id
        """,
        tbid=boundary_id,
        **frag.parameters,
    )
    if len(rows) != 2:
        return None
    claims = [_parse_claims(r["claims"]) for r in rows]
    direction = stronger_capability_side(claims[0], claims[1], cast("CapabilityKind", cap_kind))
    if direction is None:
        return None
    strong_i, weak_i = (0, 1) if direction == "a" else (1, 0)

    def _ctx(i: int, *, attacker: bool, label: str) -> PackAuthContext:
        # ADR-0049: `principal_label` is the REAL `p.label` (the resolvable
        # `attacker_principal`); the synthetic tier description moves to
        # `display_label` (LLM-facing only).
        return PackAuthContext(
            handle="A2" if attacker else "A1",
            principal_label=str(rows[i]["p_label"]),
            tier=str(rows[i]["tier"]) if rows[i]["tier"] is not None else None,
            claims_summary=_summarise_claims(rows[i]["claims"]),
            is_attacker_candidate=attacker,
            auth_context_id=AuthContextId(str(rows[i]["id"])),
            slot=str(rows[i]["slot"]) if rows[i]["slot"] is not None else None,
            display_label=label,
        )

    return (
        _ctx(strong_i, attacker=False, label=f"{cap_kind}-stronger-tier"),
        _ctx(weak_i, attacker=True, label=f"{cap_kind}-weaker-tier"),
    )


def _tenant_auth_contexts(
    client: Neo4jClient, engagement_id: EngagementId, boundary_id: str
) -> tuple[PackAuthContext, PackAuthContext] | None:
    """The (victim=tenant-A, attacker=tenant-B) auth contexts of a tenant boundary.

    Per ADR-0050 the per-tenant identity is resolved **Principal-first**: rank the
    tenant's Principals (declared > anonymous > discovered, tie-break `p.label`),
    take the top one, and resolve its armable AC via `_fetch_principal_auth` — so
    a tenant whose only observed traffic is a discovered cookie of a declared
    Principal still yields that Principal's declared AC.
    """

    frag = for_engagement(engagement_id, var="tb")
    tenants = client.execute_read(
        f"""
        MATCH (tb:TrustBoundary {{id: $tbid}})-[:BETWEEN]->(t:Tenant)
        {frag.and_("(t.status IS NULL OR t.status = 'active')")}
        RETURN t.id AS id, t.normalized_value AS value
        ORDER BY t.id
        """,
        tbid=boundary_id,
        **frag.parameters,
    )
    if len(tenants) != 2:
        return None

    def _auth_for_tenant(tenant_id: str) -> tuple[_AuthView, str] | None:
        pfrag = for_engagement(engagement_id, var="p")
        rows = client.execute_read(
            f"""
            MATCH (t:Tenant {{id: $tid}})<-[:OF_TENANT]-(p:Principal)
            {pfrag.and_("(p.status IS NULL OR p.status = 'active')")}
            RETURN p.id AS principal_id,
                   coalesce(p.label, p.identity_key) AS label,
                   CASE
                     WHEN p.tier = 'declared' THEN 0
                     WHEN coalesce(p.is_anonymous, false) THEN 1
                     ELSE 2
                   END AS p_rank
            ORDER BY p_rank ASC, label ASC
            LIMIT 1
            """,
            tid=tenant_id,
            **pfrag.parameters,
        )
        if not rows:
            return None
        view = _fetch_principal_auth(
            client, engagement_id, str(rows[0]["principal_id"])
        )
        if view is None:
            return None
        return view, str(rows[0]["label"])

    a, b = _auth_for_tenant(str(tenants[0]["id"])), _auth_for_tenant(str(tenants[1]["id"]))
    if a is None or b is None:
        return None

    def _ctx(
        pair: tuple[_AuthView, str], tval: object, *, attacker: bool
    ) -> PackAuthContext:
        view, p_label = pair
        # ADR-0049: `principal_label` is the REAL `p.label`; the synthetic
        # `tenant:<value>` description moves to `display_label` (LLM-facing only).
        return PackAuthContext(
            handle="A2" if attacker else "A1",
            principal_label=p_label,
            tier=view.tier,
            claims_summary=view.claims_summary,
            is_attacker_candidate=attacker,
            auth_context_id=view.auth_context_id,
            slot=view.slot,
            display_label=f"tenant:{tval}",
        )

    return (
        _ctx(a, tenants[0]["value"], attacker=False),
        _ctx(b, tenants[1]["value"], attacker=True),
    )


def assemble_boundary_pack(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    boundary_id: str,
    boundary_kind: str,
    code_version: str,
    now: datetime,
) -> ContextPack | None:
    """Build the `ContextPack` for one capability/tenant `TrustBoundary`, or None.

    The boundary is the target (`T1`, `kind="boundary"`); its concrete endpoint is
    read from `DERIVED_FROM` evidence (ADR-0039 — no endpoint edge on the boundary).
    The two `BETWEEN` sides become the auth contexts with the attacker side marked:
    - **capability** (`boundary_kind ∈ {scope,mfa,freshness}`): two AuthContexts of one
      Principal, the **weaker** tier the attacker; None when the ordering is ambiguous.
    - **tenant** (`boundary_kind = "tenant"`): two Tenants, one AuthContext per tenant
      (via `OF_TENANT`/`OF_PRINCIPAL`), the second the attacker; None when either has
      no resolvable AuthContext.
    """

    evidence = _boundary_evidence_endpoint(client, engagement_id, boundary_id)
    if evidence is None:
        return None
    endpoint_id, method, path_template = evidence

    if boundary_kind == "tenant":
        sides = _tenant_auth_contexts(client, engagement_id, boundary_id)
        candidate_kind = "tenant"
        reason = (
            f"Tenant boundary: replay {method} {path_template} (held as tenant A's "
            f"resource) under tenant B's auth to test cross-tenant access"
        )
    else:
        sides = _capability_auth_contexts(client, engagement_id, boundary_id, boundary_kind)
        candidate_kind = "capability"
        reason = (
            f"Capability boundary ({boundary_kind}): replay {method} {path_template} "
            f"(reached by the stronger tier) under the weaker token to test privilege "
            f"escalation"
        )
    if sides is None:
        log.warning(
            "planner.assemble.boundary_unproposable",
            engagement_id=engagement_id,
            boundary_id=boundary_id,
            boundary_kind=boundary_kind,
        )
        return None

    target = PackTarget(
        handle="T1",
        kind="boundary",
        method=method,
        path_template=path_template,
        endpoint_id=endpoint_id,
        trust_boundary_id=TrustBoundaryId(boundary_id),
    )
    return ContextPack(
        engagement_id=engagement_id,
        candidate_kind=cast("Any", candidate_kind),
        candidate_reason=reason,
        endpoint_method=method,
        endpoint_path_template=path_template,
        targets=(target,),
        auth_contexts=sides,
        code_version=code_version,
        generated_at=now,
    )


def fetch_reaching_observation_hazards(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    endpoint_id: str,
) -> tuple[ReplayHazardRole, ...]:
    """Detect replay hazards from one reaching 2xx observation's request fields (ADR-0041).

    Replay-breakers (CSRF tokens / nonces / signatures / timestamps) are
    endpoint-level request features, so the detector runs once over a reaching 2xx
    observation rather than per auth context. Picks the most recently-seen reaching
    2xx observation deterministically and runs the **deterministic** detector over
    its parsed `value_candidates` — header-borne fields included (a CSRF token is
    commonly an `X-CSRF-Token` request header). No LLM (CLAUDE.md hard rule). Returns
    an empty tuple when there is no reaching observation or no detected hazard.
    """

    frag = for_engagement(engagement_id, var="r")
    rows = client.execute_read(
        f"""
        MATCH (r:RequestObservation)-[:HIT]->(e:Endpoint {{id: $endpoint_id}})
        {frag.and_("r.status = 'active' AND e.status = 'active'")}
          AND r.response_status >= 200 AND r.response_status <= 299
          AND r.value_candidates IS NOT NULL
        RETURN r.value_candidates AS value_candidates
        ORDER BY coalesce(r.last_seen, r.ingested_at) DESC, r.observation_id ASC
        LIMIT 1
        """,
        endpoint_id=endpoint_id,
        **frag.parameters,
    )
    if not rows:
        return ()
    candidates = _parse_value_candidates(rows[0]["value_candidates"])
    return hazards_for_value_candidates(candidates)


def fetch_reaching_observation_source_hints(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    endpoint_id: str,
) -> tuple[str, ...]:
    """`source_hint`s for the reaching observation's resolvable hazards (ADR-0041).

    Sibling of `fetch_reaching_observation_hazards`, over the same most-recent
    reaching 2xx observation: emits `"csrf_token=<referer>"` when the request
    carried a CSRF token + a `Referer` (the page that minted it), so slice-4 can
    fetch a fresh token under the test's auth. Empty when there is nothing to hint.
    """

    frag = for_engagement(engagement_id, var="r")
    rows = client.execute_read(
        f"""
        MATCH (r:RequestObservation)-[:HIT]->(e:Endpoint {{id: $endpoint_id}})
        {frag.and_("r.status = 'active' AND e.status = 'active'")}
          AND r.response_status >= 200 AND r.response_status <= 299
          AND r.value_candidates IS NOT NULL
        RETURN r.value_candidates AS value_candidates
        ORDER BY coalesce(r.last_seen, r.ingested_at) DESC, r.observation_id ASC
        LIMIT 1
        """,
        endpoint_id=endpoint_id,
        **frag.parameters,
    )
    if not rows:
        return ()
    candidates = _parse_value_candidates(rows[0]["value_candidates"])
    return source_hints_for_value_candidates(candidates)
