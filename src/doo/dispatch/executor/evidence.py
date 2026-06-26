"""Evidence resolution: `TestCase` → the `RequestObservation` to replay.

A constructor (ADR-0043) is a pure function of `(TestCase, evidence observation,
auth material)`. The evidence is the highest-confidence `RequestObservation` that
demonstrated the target was reachable by the **victim** side — read via the
target's structural edges, not a TestCase→observation edge:

- `TARGETS_BOUNDARY` → `TrustBoundary -[DERIVED_FROM]-> RequestObservation`
  (the boundary's evidence chain, ADR-0039).
- `TARGETS_ENDPOINT` → `RequestObservation -[HIT]-> Endpoint` (any observed hit
  on this endpoint, preferring one under a non-anonymous, non-attacker
  `AuthContext`).
- `TARGETS_PARAMETER` → via the owning Endpoint's `HIT`s.

Kept separate from the constructor module so constructors stay pure / IO-free
(unit-testable against a synthetic `EvidenceObservation`).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from doo.canonical.value_objects import HostRef
from doo.ids import (
    AuthContextId,
    EngagementId,
    ObservationId,
    TestCaseKeyHash,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    """The constructor-facing projection of an evidencing `RequestObservation`.

    Carries only what request construction needs: the concrete request shape
    (method, host, path, query/header/cookie name→value pairs) plus the
    Endpoint's current `path_template` (for `OpaInput`, ADR-0046) and the live AC
    to send `baseline_victim` under (S5+). Bodies stay as blob refs (ADR-0015);
    raw secret-shaped values are already scrubbed at L2.

    `baseline_victim_auth_context_id` (ADR-0052) is "the live AC to send
    `baseline_victim` under," which may differ from the AC the evidence was
    *observed* under: when the observed victim AC is discovered-tier (an expired
    HAR session with no slot), `load_evidence` walks the shared Principal's
    declared siblings and substitutes the live declared id whose `slot` matches
    the observed carrier. Observed provenance stays recoverable via
    `observation_id → OBSERVED_UNDER → AuthContext`.
    """

    observation_id: ObservationId
    method: str
    host: HostRef
    concrete_path: str
    path_template: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body_blob_key: str | None = None
    body_content_type: str | None = None
    baseline_victim_auth_context_id: AuthContextId | None = None
    confidence: float = 1.0
    # The engagement's `auth.session_cookie_names` (ADR-0026), carried here so the
    # request constructors send a `cookie`-kind credential under the configured
    # name and strip every configured session cookie inherited from the evidence
    # (#176/#177). Empty → the `_splice_auth` `"session"` fallback (un-configured
    # engagement).
    session_cookie_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DispatchTestCase:
    """A `TestCase` projection for the Executor (read from the graph).

    The constructor needs the full content-addressed identity plus the
    execution-fidelity annotations (`hold`, `replay_hazards`, ADR-0041) the
    planner persisted.
    """

    engagement_id: EngagementId
    key_hash: TestCaseKeyHash
    test_class: str
    payload_class: str
    auth_context_id: AuthContextId
    target_endpoint_id: str | None
    target_parameter_id: str | None
    target_trust_boundary_id: str | None
    hold: tuple[str, ...]
    replay_hazards: tuple[str, ...]
    # Resolvable-hazard `source_hint`s (`"<kind>=<url>"`, ADR-0041): where the
    # hazard resolver fetches a fresh token (csrf). Set by the planner; a
    # `doo dispatch review --set-hint` override takes precedence at run time.
    hazard_source_hints: tuple[str, ...] = ()
    expected_yield: float = 0.0
    generator: str | None = None
    confidence: float = 1.0
    # ADR-0049 attacker identity; `None` only on un-migrated pre-0049 TestCases.
    # The Interpreter pack surfaces this so the model knows who `primary` was.
    attacker_principal: str | None = None
    attacker_slot: str | None = None


def load_evidence(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    testcase: DispatchTestCase,
    session_cookie_names: tuple[str, ...] = (),
) -> EvidenceObservation | None:
    """Resolve the highest-confidence evidencing `RequestObservation` for a TestCase.

    Ordered by `confidence` desc, `last_seen` desc so a fresher, cleaner
    observation wins. Returns `None` when no evidence resolves — the run records
    `hazard_unresolved` (ADR-0043 surfacing) rather than guessing.
    """

    frag = for_engagement(engagement_id, var="t")
    # Three target shapes, one OPTIONAL-MATCH each, coalesced. The boundary path
    # uses its `DERIVED_FROM` evidence (ADR-0039); the endpoint/parameter paths
    # use `HIT`. The observation must be under a non-anonymous AuthContext (the
    # victim side of the replay) — an anonymous hit gives nothing to swap.
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        OPTIONAL MATCH (t)-[:TARGETS_BOUNDARY]->(tb:TrustBoundary)
                       -[:DERIVED_FROM]->(rb:RequestObservation)
                       -[:HIT]->(eb:Endpoint)-[:ON_HOST]->(hb:Host)
        OPTIONAL MATCH (t)-[:TARGETS_ENDPOINT]->(ee:Endpoint)
                       <-[:HIT]-(re:RequestObservation),
                       (ee)-[:ON_HOST]->(he:Host)
        OPTIONAL MATCH (t)-[:TARGETS_PARAMETER]->(pp:Parameter)
                       <-[:HAS_PARAMETER]-(ep:Endpoint)
                       <-[:HIT]-(rp:RequestObservation),
                       (ep)-[:ON_HOST]->(hp:Host)
        WITH t,
             coalesce(rb, re, rp) AS r,
             coalesce(eb, ee, ep) AS e,
             coalesce(hb, he, hp) AS h
        WHERE r IS NOT NULL AND e IS NOT NULL
        OPTIONAL MATCH (r)-[:OBSERVED_UNDER]->(ac:AuthContext)
        WITH t, r, e, h, ac
        ORDER BY (ac IS NOT NULL AND coalesce(ac.is_anonymous, false) = false) DESC,
                 coalesce(r.confidence, 1.0) DESC,
                 r.last_seen DESC
        LIMIT 1
        RETURN r.id AS observation_id,
               r.method AS method,
               r.concrete_path AS concrete_path,
               r.query AS query,
               r.headers AS headers,
               r.cookies AS cookies,
               r.request_body_blob_key AS body_blob_key,
               r.request_body_content_type AS body_content_type,
               coalesce(r.confidence, 1.0) AS confidence,
               e.path_template AS path_template,
               h.scheme AS scheme,
               h.canonical_hostname AS host,
               h.port AS port,
               h.is_ip_literal AS is_ip,
               ac.id AS victim_ac_id,
               ac.tier AS victim_ac_tier,
               ac.token_kind AS victim_ac_carrier
        """,
        key_hash=testcase.key_hash,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    observed_victim_ac = (
        AuthContextId(str(row["victim_ac_id"]))
        if row.get("victim_ac_id") is not None
        else None
    )
    # ADR-0052: when the observed victim AC is discovered-tier (an expired HAR
    # session with no slot, so `material_for` would miss), follow the shared
    # Principal's `OF_PRINCIPAL` edge to a live declared sibling whose `slot`
    # matches the observed carrier. Strictly additive: a declared observed AC, a
    # miss, or an ambiguous walk all leave the observed (discovered) id in place
    # → the existing un-armable path.
    baseline_victim_ac = observed_victim_ac
    if observed_victim_ac is not None and str(row.get("victim_ac_tier")) == "discovered":
        resolved = _walk_baseline_victim_sibling(
            client,
            engagement_id=engagement_id,
            key_hash=testcase.key_hash,
            observed_auth_context_id=observed_victim_ac,
            observed_carrier=(
                str(row["victim_ac_carrier"])
                if row.get("victim_ac_carrier") is not None
                else None
            ),
        )
        if resolved is not None:
            baseline_victim_ac = resolved
    return EvidenceObservation(
        observation_id=ObservationId(str(row["observation_id"])),
        method=str(row["method"]),
        host=HostRef(
            scheme=str(row["scheme"]),  # type: ignore[arg-type]
            canonical_hostname=str(row["host"]),
            port=row["port"],
            is_ip_literal=bool(row["is_ip"]),
        ),
        concrete_path=str(row["concrete_path"]),
        path_template=str(row["path_template"]),
        query=_kv(row.get("query")),
        headers=_kv(row.get("headers")),
        cookies=_kv(row.get("cookies")),
        body_blob_key=row.get("body_blob_key"),
        body_content_type=row.get("body_content_type"),
        baseline_victim_auth_context_id=baseline_victim_ac,
        confidence=float(row["confidence"]),
        session_cookie_names=session_cookie_names,
    )


@dataclass(frozen=True, slots=True)
class _DeclaredSibling:
    """A declared `AuthContext` sharing the observed victim's Principal (ADR-0052).

    `slot` is the ADR-0049 rotation-stable label (defaults to `token_kind`, but
    may be a custom name like `session` / `stepup`); `carrier` is the AC's
    `token_kind` (bearer / cookie / api_key), which is what we match the observed
    discovered session's carrier against. Two declared cookie credentials can
    share a carrier under *distinct* slots — that is the ambiguous shape.
    """

    principal_id: str
    id: AuthContextId
    slot: str | None
    carrier: str | None


def _walk_baseline_victim_sibling(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
    observed_auth_context_id: AuthContextId,
    observed_carrier: str | None,
) -> AuthContextId | None:
    """ADR-0052: resolve a live declared sibling for a discovered victim AC.

    Follows the `OF_PRINCIPAL` edge L3 already drew between the discovered HAR
    session and the declared Principal it converged onto (ADR-0048) — this is
    *not* a re-run of identity matching. The shared Principal's declared siblings
    are handed (with the observed carrier) to the pure selector; generation is
    left to `SlotResolvingSecretStore`'s rotation overlay.

    Returns the resolved declared id, or `None` when the selector declines
    (no carrier match / ambiguous / no sibling) — leaving the existing
    un-armable path untouched.
    """

    # The brief's verbatim walk, plus `decl.token_kind AS carrier`: a declared
    # cookie credential may carry a custom `slot` (session / stepup), so the
    # carrier match is on `token_kind` while ambiguity is judged on distinct
    # `slot`s (the ADR-0049 dedup key).
    rows = client.execute_read(
        """
        MATCH (ac:AuthContext {engagement_id: $eid, id: $victim_ac_id})
              -[:OF_PRINCIPAL]->(p:Principal)
        MATCH (p)<-[:OF_PRINCIPAL]-(decl:AuthContext {tier: 'declared'})
        RETURN p.id AS principal_id, decl.id AS id, decl.slot AS slot,
               decl.token_kind AS carrier
        """,
        eid=str(engagement_id),
        victim_ac_id=str(observed_auth_context_id),
    )
    siblings = [
        _DeclaredSibling(
            principal_id=str(r["principal_id"]),
            id=AuthContextId(str(r["id"])),
            slot=str(r["slot"]) if r.get("slot") is not None else None,
            carrier=str(r["carrier"]) if r.get("carrier") is not None else None,
        )
        for r in rows
    ]
    resolved = _resolve_baseline_victim_sibling(observed_carrier, siblings)
    if resolved is not None:
        match = next(s for s in siblings if s.id == resolved)
        log.info(
            "dispatch.evidence.baseline_victim_resolved_via_sibling",
            engagement_id=str(engagement_id),
            key_hash=key_hash,
            observed_auth_context_id=str(observed_auth_context_id),
            resolved_auth_context_id=str(resolved),
            principal_id=match.principal_id,
            carrier=observed_carrier,
            slot=match.slot,
        )
    else:
        # Only a genuine walk attempt (carrier present, siblings existed) is
        # worth surfacing; a no-sibling discovered AC is the common, expected
        # un-armable shape (#160) and stays quiet.
        if observed_carrier is not None and siblings:
            log.debug(
                "dispatch.evidence.baseline_victim_sibling_ambiguous",
                engagement_id=str(engagement_id),
                key_hash=key_hash,
                observed_auth_context_id=str(observed_auth_context_id),
                carrier=observed_carrier,
                candidate_count=len(siblings),
            )
    return resolved


def _resolve_baseline_victim_sibling(
    observed_carrier: str | None,
    siblings: list[_DeclaredSibling],
) -> AuthContextId | None:
    """Pure selector (ADR-0052): pick the live declared sibling to send under.

    The discovered observed AC has `slot=None`, so we match its carrier
    (`token_kind`: bearer / cookie / api_key) against each declared sibling's
    carrier (`token_kind`); ambiguity is judged on the sibling's `slot` (the
    ADR-0049 `(principal_label, slot)` dedup key). Strictly additive — never
    flips an existing outcome:

    - no carrier / no sibling → None (un-armable, unchanged);
    - siblings exist but none share the carrier → None (never replay over a
      different carrier — false-negative risk);
    - exactly one *distinct slot* among the carrier matches → resolve it;
      multiple generations of that one slot collapse via the dedup key, and
      `SlotResolvingSecretStore` picks the latest generation — so we return the
      first matching id and let the overlay choose;
    - ≥2 *distinct slots* share the carrier → None (ambiguous, don't guess).
    """

    if observed_carrier is None or not siblings:
        return None
    matches = [s for s in siblings if s.carrier == observed_carrier]
    if not matches:
        return None
    distinct_slots = {s.slot for s in matches}
    if len(distinct_slots) > 1:
        return None
    return matches[0].id


def _kv(raw: object) -> dict[str, str]:
    """Coerce a Neo4j list-of-`name=value` / map property into a `{name: value}` dict.

    `RequestObservation` persists params as a flat `["name=value", ...]` array
    (Neo4j has no nested-map property type — same JSON-string discipline as
    `graph_state.py`). Missing/null → `{}`.
    """

    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    out: dict[str, str] = {}
    if isinstance(raw, (list, tuple)):
        for item in raw:
            s = str(item)
            if "=" in s:
                name, _, value = s.partition("=")
                out[name] = value
    return out
