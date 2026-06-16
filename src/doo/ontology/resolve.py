"""Entity resolution (slice-1 T2, deep module D — minimal subset).

Deterministic resolvers that MERGE the observation- and inference-layer nodes a
single `RequestObservation` implies, all engagement-scoped per ADR-0017:

- `resolve_host` — Host identity `(engagement_id, scheme, canonical_hostname,
  port)`; engagement-scoped (two engagements observing the same hostname get two
  Host nodes).
- `resolve_auth_context` — anonymous singleton only: exactly one anonymous
  AuthContext + one anonymous Principal per engagement (CONTEXT.md / ADR-0010).
- `commit_request_observation` — the RequestObservation node plus its non-`HIT`
  structural edges (`OBSERVED_UNDER` to AuthContext, `ON_HOST` to Host), and its
  inline value candidates + diagnostics (ADR-0023). The revisable `HIT` -> Endpoint
  grouping is owned by `ontology/templating.py`; `ObservedValue` promotion is owned
  by the flush-time promotion pass (`ontology/promotion.py`).
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
from datetime import UTC, datetime

from doo.canonical.identity import (
    ANONYMOUS_TOKEN_KIND,
    anonymous_principal_identity_key,
    auth_context_id,
    compute_anonymous_auth_hash,
    compute_cue_auth_hash,
    discovered_principal_identity_key,
    host_id,
    principal_id,
)
from doo.canonical.value_objects import AuthContextCue, HostRef
from doo.events.l2 import ParseFailure, RequestObservation
from doo.ids import (
    AuthContextId,
    EngagementId,
    HostId,
    ObservationId,
    PrincipalId,
    Sha256Hex,
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
class ResolvedAuthContext:
    """The AuthContext + Principal a `RequestObservation` resolves to (ADR-0010).

    `tier` is the resolved AuthContext's tier (`anonymous` / `discovered`). The
    Principal it attaches to may be `declared` (reconciliation matched a declared
    Principal's known signal) or `discovered` (synthetic fallback). `unmerged` is
    True only for the synthetic-fallback discovered Principal.
    """

    auth_context_id: AuthContextId
    principal_id: PrincipalId
    tier: str
    principal_tier: str
    unmerged: bool


# Back-compat alias: T2 referred to the anonymous singleton as `AnonymousIdentity`.
AnonymousIdentity = ResolvedAuthContext


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
    cue: AuthContextCue | None = None,
    preferred_claim: str | None = None,
) -> ResolvedAuthContext:
    """Resolve the AuthContext + Principal a request's auth cue maps to (ADR-0010).

    Three paths:

    1. **Anonymous** (`cue is None` or `cue.is_anonymous`): MERGE the per-engagement
       anonymous singleton — exactly one anonymous AuthContext + one anonymous
       Principal. Invariant preserved from T2.
    2. **Known auth_hash**: if `(engagement_id, auth_hash)` already exists (declared
       at setup or seen earlier), attach to it; no new Principal.
    3. **Reconciliation** (ADR-0010 priority list): a fresh cue is matched against
       declared Principals' `known_signals`. On a match the discovered AuthContext
       attaches to the matched **declared** Principal (no phantom twin). On no
       match a discovered Principal is synthesised (`unmerged=true`).

    `preferred_claim` is the engagement-global `auth.identity_key` override
    (ADR-0032). When set, it is forwarded to `discovered_principal_identity_key`
    so step 5 keys on the declared claim rather than the heuristic priority.
    Anonymous, declared-match, and re-attach paths are unaffected.
    """

    if cue is None or cue.is_anonymous:
        return _resolve_anonymous(
            client, engagement_id=engagement_id, observed_at=observed_at, ingested_at=ingested_at
        )

    auth_hash = compute_cue_auth_hash(cue)
    ac_id = auth_context_id(engagement_id, auth_hash)

    # Path 2: this exact AuthContext is already known (declared or discovered).
    existing = _existing_auth_context(client, engagement_id=engagement_id, auth_hash=auth_hash)
    if existing is not None:
        # Re-attaching to a known AuthContext: bump last_seen, return its identity.
        _touch_auth_context(
            client, engagement_id=engagement_id, auth_hash=auth_hash, observed_at=observed_at
        )
        return ResolvedAuthContext(
            auth_context_id=ac_id,
            principal_id=PrincipalId(str(existing["principal_id"])),
            tier=str(existing["ac_tier"]),
            principal_tier=str(existing["principal_tier"]),
            unmerged=bool(existing.get("unmerged") or False),
        )

    # Path 3: reconcile a fresh discovered AuthContext against declared signals.
    matched = _match_declared_principal(
        client, engagement_id=engagement_id, cue=cue, preferred_claim=preferred_claim
    )
    token_kind = _cue_primary_kind(cue)

    if matched is not None:
        # Match → attach discovered AuthContext to the existing declared Principal.
        p_identity_key = str(matched["identity_key"])
        p_id = PrincipalId(str(matched["id"]))
        _write_discovered_auth_context(
            client,
            engagement_id=engagement_id,
            auth_hash=auth_hash,
            ac_id=ac_id,
            token_kind=token_kind,
            cue=cue,
            principal_identity_key=p_identity_key,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        return ResolvedAuthContext(
            auth_context_id=ac_id,
            principal_id=p_id,
            tier="discovered",
            principal_tier="declared",
            unmerged=False,
        )

    # No match → discovered Principal (step 5), low confidence, unmerged. Keyed on
    # the namespaced claim-priority list (sub → … → email) decoded from the cue's
    # credential, so a user's reissued tokens collapse to one Principal (ADR-0027);
    # else on the per-credential auth_hash.
    # ADR-0032: preferred_claim overrides the heuristic when set.
    p_key = discovered_principal_identity_key(
        auth_hash, identity_claims=cue.identity_claims, preferred_claim=preferred_claim
    )
    p_id = principal_id(engagement_id, p_key)
    _write_discovered_principal_and_auth_context(
        client,
        engagement_id=engagement_id,
        auth_hash=auth_hash,
        ac_id=ac_id,
        token_kind=token_kind,
        cue=cue,
        principal_identity_key=p_key,
        principal_id_value=p_id,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    return ResolvedAuthContext(
        auth_context_id=ac_id,
        principal_id=p_id,
        tier="discovered",
        principal_tier="discovered",
        unmerged=True,
    )


def _resolve_anonymous(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> ResolvedAuthContext:
    """MERGE the anonymous singleton (one AuthContext + one Principal per engagement)."""

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
                      p.unmerged = false, p += $p_props
        ON MATCH SET p.last_seen = $p_props.last_seen
        MERGE (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        ON CREATE SET ac.id = $auth_context_id, ac.token_kind = $token_kind,
                      ac.tier = 'anonymous', ac.is_anonymous = true, ac += $ac_props
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
    return ResolvedAuthContext(
        auth_context_id=ac_id,
        principal_id=p_id,
        tier="anonymous",
        principal_tier="anonymous",
        unmerged=False,
    )


def _cue_primary_kind(cue: AuthContextCue) -> str:
    """The token kind that names this cue's AuthContext (bearer > cookie > ...)."""

    if cue.bearer_token_hash is not None:
        return "bearer"
    if cue.cookie_session_hashes:
        return "cookie"
    if cue.api_key_headers:
        return "api_key"
    if cue.basic_auth_user_hash is not None:
        return "basic_auth"
    return "unknown"


def _existing_auth_context(
    client: Neo4jClient, *, engagement_id: EngagementId, auth_hash: Sha256Hex
) -> dict[str, object] | None:
    """Return the AuthContext + its Principal if `(engagement_id, auth_hash)` exists."""

    rows = client.execute_read(
        """
        MATCH (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        OPTIONAL MATCH (ac)-[:OF_PRINCIPAL]->(p:Principal)
        RETURN ac.tier AS ac_tier, p.id AS principal_id, p.tier AS principal_tier,
               p.unmerged AS unmerged
        LIMIT 1
        """,
        engagement_id=engagement_id,
        auth_hash=auth_hash,
    )
    if not rows or rows[0].get("principal_id") is None:
        return None
    return rows[0]


def _touch_auth_context(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    auth_hash: Sha256Hex,
    observed_at: datetime,
) -> None:
    client.execute_write(
        """
        MATCH (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        SET ac.last_seen = $observed_at
        """,
        engagement_id=engagement_id,
        auth_hash=auth_hash,
        observed_at=observed_at,
    )


def _match_declared_principal(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    cue: AuthContextCue,
    preferred_claim: str | None = None,
) -> dict[str, object] | None:
    """Walk ADR-0010's reconciliation priority list against declared Principals.

    **Priority 0 (ADR-0048):** the cue's decoded `identity_claims` are matched
    against each declared `AuthContext`'s own decoded `identity_claims` (loaded
    by the engagement loader / written by the auth-helper on rotation), via
    `match_identity_claims` — the same ADR-0030 walk-and-intersect the
    discovered-key resolver uses, with `preferred_claim` (`auth.identity_key`,
    ADR-0032) first. Expired declared ACs are included: a rotated-out token's
    claims remain valid identity evidence for its Principal. A per-AC
    `DISAGREE` (highest shared claim differs) skips that AC; `None` (no shared
    claim) leaves the AC undecided and falls through to the `known_signals`
    priorities — so an opaque declared token (empty claims) still reconciles
    via the tester-supplied fallback signals.

    Lower priorities (the slice-1 `known_signals` opaque-token fallback) are
    unchanged: (1) JWT `sub` → `known_signals.jwt_sub`, (2) identifying header →
    `known_signals.headers`, (3) email → `known_signals.email`. Step 4 (the
    `/me` observed-user-id match) is deferred — see the TODO below. Step 5
    (synthetic fallback) is handled by the caller when this returns None.

    Returns the matched declared Principal's `{id, identity_key}` or None.
    """

    import json

    from doo.canonical.identity import DISAGREE, match_identity_claims

    declared = client.execute_read(
        """
        MATCH (p:Principal {engagement_id: $engagement_id, tier: 'declared'})
        WHERE p.status = 'active'
        OPTIONAL MATCH (ac:AuthContext {tier: 'declared'})-[:OF_PRINCIPAL]->(p)
        WHERE ac.status IN ['active', 'expired']
        RETURN p.id AS id, p.identity_key AS identity_key,
               p.known_signals AS known_signals,
               collect(ac.identity_claims) AS ac_identity_claims
        """,
        engagement_id=engagement_id,
    )

    parsed: list[tuple[dict[str, object], dict[str, object]]] = []
    for row in declared:
        ks = row.get("known_signals") or {}
        if isinstance(ks, str):
            ks = json.loads(ks)
        parsed.append((row, ks))

    # Priority 0 (ADR-0048): cue claims vs each declared AuthContext's own
    # decoded claims, walk-and-intersect over the ADR-0030 list. A shared
    # agreeing claim is the strongest possible reconciliation signal — the
    # declared credential itself proves the actor.
    if cue.identity_claims:
        for row, _ks in parsed:
            ac_claims_raw = row.get("ac_identity_claims")
            if not isinstance(ac_claims_raw, list):
                continue
            for raw_claims in ac_claims_raw:
                if not raw_claims:
                    continue
                try:
                    decl_claims = json.loads(str(raw_claims))
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(decl_claims, dict) or not decl_claims:
                    continue
                outcome = match_identity_claims(
                    cue.identity_claims, decl_claims, preferred_claim=preferred_claim
                )
                if outcome is None or outcome == DISAGREE:
                    # No shared claim, or a both-present disagreement: this AC
                    # is not evidence either way → try the Principal's other
                    # ACs / other Principals; fall through to known_signals.
                    continue
                return {"id": row["id"], "identity_key": row["identity_key"]}

    # Priority 1: JWT `sub` claim from the cue's decoded identity_claims.
    cue_sub = cue.identity_claims.get("sub")
    if cue_sub is not None:
        for row, ks in parsed:
            if ks.get("jwt_sub") is not None and str(ks["jwt_sub"]) == str(cue_sub):
                return {"id": row["id"], "identity_key": row["identity_key"]}

    # Priority 2: identifying header. The cue exposes header *names* it carries as
    # api-key headers, but the matching values are hashed at L2 (ADR-0015). A
    # declared `known_signals.headers` value is a cleartext tester-side fact; to
    # match we compare the hash of the declared value against the cue's hash.
    if cue.api_key_headers:
        from doo.canonical.identity import compute_auth_hash

        cue_header_hashes = {name.lower(): h for name, h in cue.api_key_headers.items()}
        for row, ks in parsed:
            headers = ks.get("headers") or {}
            if not isinstance(headers, dict):
                continue
            for hname, hvalue in headers.items():
                expected = compute_auth_hash("api_key", str(hvalue))
                if cue_header_hashes.get(str(hname).lower()) == expected:
                    return {"id": row["id"], "identity_key": row["identity_key"]}

    # Priority 3: email tied to the AuthContext. Slice-1 only surfaces an email if
    # the decoded JWT carries an `email` claim (response-body emails arrive in T6).
    cue_email = cue.identity_claims.get("email")
    if cue_email is not None:
        for row, ks in parsed:
            if ks.get("email") is not None and str(ks["email"]) == str(cue_email):
                return {"id": row["id"], "identity_key": row["identity_key"]}

    # TODO(T6): Priority 4 — `/me` / `/whoami` observed user-id. Requires
    # response-body ResponseArtifact extraction (T6); the priority list above
    # already works without it for slice 1.

    return None


def _discovered_ac_props(
    cue: AuthContextCue,
    *,
    confidence: float,
) -> dict[str, object]:
    """Secret-free AuthContext properties derived from a cue (claims + windows)."""

    import json

    exp = cue.identity_claims.get("exp")
    validity_window = None
    if isinstance(exp, int | float):
        validity_window = json.dumps(
            {"exp": datetime.fromtimestamp(float(exp), tz=UTC).isoformat()}, sort_keys=True
        )
    return {
        # Source-agnostic cue claims persisted as `identity_claims` (ADR-0027/0048).
        "identity_claims": json.dumps(dict(cue.identity_claims), sort_keys=True),
        "validity_window": validity_window,
        "confidence": confidence,
    }


def _write_discovered_auth_context(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    auth_hash: Sha256Hex,
    ac_id: AuthContextId,
    token_kind: str,
    cue: AuthContextCue,
    principal_identity_key: str,
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """Create a discovered AuthContext attached to an existing (declared) Principal.

    No phantom twin: the `OF_PRINCIPAL` edge points at the already-resolved
    Principal; no new Principal node is created.
    """

    props = cross_cutting(
        source="har", source_id=None, observed_at=observed_at, ingested_at=ingested_at
    )
    derived = _discovered_ac_props(cue, confidence=1.0)
    client.execute_write(
        """
        MATCH (p:Principal {engagement_id: $engagement_id, identity_key: $identity_key})
        MERGE (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        ON CREATE SET ac.id = $auth_context_id, ac.token_kind = $token_kind,
                      ac.tier = 'discovered', ac.is_anonymous = false,
                      ac.identity_claims = $derived.identity_claims,
                      ac.validity_window = $derived.validity_window,
                      ac += $props
        ON MATCH SET ac.last_seen = $props.last_seen
        MERGE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        engagement_id=engagement_id,
        identity_key=principal_identity_key,
        auth_hash=auth_hash,
        auth_context_id=ac_id,
        token_kind=token_kind,
        derived=derived,
        props=props,
    )


def _write_discovered_principal_and_auth_context(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    auth_hash: Sha256Hex,
    ac_id: AuthContextId,
    token_kind: str,
    cue: AuthContextCue,
    principal_identity_key: str,
    principal_id_value: PrincipalId,
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """Synthetic fallback (ADR-0010 step 5): new discovered Principal + AuthContext.

    Low confidence, `unmerged=true`, deterministic id over the first AuthContext's
    `auth_hash` so replay converges.
    """

    p_props = cross_cutting(
        source="har",
        source_id=None,
        observed_at=observed_at,
        ingested_at=ingested_at,
        confidence=0.3,
    )
    ac_props = cross_cutting(
        source="har", source_id=None, observed_at=observed_at, ingested_at=ingested_at
    )
    derived = _discovered_ac_props(cue, confidence=1.0)
    client.execute_write(
        """
        MERGE (p:Principal {engagement_id: $engagement_id, identity_key: $identity_key})
        ON CREATE SET p.id = $principal_id, p.tier = 'discovered', p.is_anonymous = false,
                      p.unmerged = true, p += $p_props
        ON MATCH SET p.last_seen = $p_props.last_seen
        MERGE (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        ON CREATE SET ac.id = $auth_context_id, ac.token_kind = $token_kind,
                      ac.tier = 'discovered', ac.is_anonymous = false,
                      ac.identity_claims = $derived.identity_claims,
                      ac.validity_window = $derived.validity_window,
                      ac += $ac_props
        ON MATCH SET ac.last_seen = $ac_props.last_seen
        MERGE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        engagement_id=engagement_id,
        identity_key=principal_identity_key,
        principal_id=principal_id_value,
        auth_hash=auth_hash,
        auth_context_id=ac_id,
        token_kind=token_kind,
        derived=derived,
        p_props=p_props,
        ac_props=ac_props,
    )


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
    object store; path-position Parameters come from templating. Body-parameter
    names are stored the same way (`body_param_names`).

    Request/response body `BlobRef`s are persisted as JSON-serialised string
    properties (`request_body_ref` / `response_body_ref`) — Neo4j has no struct
    property type, so the small `BlobRef` serialises as a JSON string holding the
    hash + metadata + storage key (the raw body lives only in object storage;
    ADR-0015 / CLAUDE.md hard rule).

    Extracted value occurrences (ADR-0023) are stored inline as a list of
    JSON-serialised `ValueCandidate`s (`value_candidates`); the flush-time
    promotion pass aggregates them by `value_hash` into `ObservedValue`s. Secret
    candidates carry only hash + length + preview, never a raw value (ADR-0015).
    One-per-response diagnostics (`server_fingerprint`, `error_excerpt`) are inline
    scalar properties, not nodes.

    The claim-tagged observed identities this response asserted (ADR-0030) are
    stored as ONE serialized JSON list (`observed_identities`), each entry an
    `{claim, value}` object — replacing the prior single-value scalar pair. The
    flush-time reconciler reads this list to key/alias the request's Principal.
    """

    props = cross_cutting(
        source=obs.source,
        source_id=obs.source_id,
        observed_at=obs.observed_at,
        ingested_at=obs.ingested_at,
    )
    query_param_names = [p.name for p in obs.query_params]
    # De-duplicated body-param names, order-preserving, for L3 aggregation.
    body_param_names: list[str] = []
    for bp in obs.request_body_params:
        if bp.name not in body_param_names:
            body_param_names.append(bp.name)
    request_body_ref = (
        obs.request_body_ref.model_dump_json() if obs.request_body_ref is not None else None
    )
    response_body_ref = (
        obs.response_body_ref.model_dump_json() if obs.response_body_ref is not None else None
    )
    # ADR-0033 body-metadata promotion: lift the response body sha256 out of the
    # `response_body_ref` JSON string onto a top-level node property so the
    # coverage C2/C2b queries can compare it without JSON-extracting in Cypher,
    # and confirm `response_size_bytes` lands as a queryable scalar. Both are the
    # per-principal evidence the authz-coverage queries surface (null body sha256
    # when there was no response body).
    response_body_sha256 = (
        obs.response_body_ref.sha256 if obs.response_body_ref is not None else None
    )
    value_candidates = [vc.model_dump_json() for vc in obs.value_candidates]
    # ADR-0030: the claim-tagged observed identities are persisted as ONE serialized
    # JSON list (`observed_identities`) — replacing the prior single-value
    # `observed_identity_signal`/`observed_identity_value` scalar pair — so the flush
    # reconciler can build a claim->value map per AuthContext.
    observed_identities = [oi.model_dump_json() for oi in obs.observed_identities]
    # ADR-0031: SSO login binding — identities the login ISSUES, attached at flush
    # to the AuthContext of the issued credential (not this observation's own).
    issued_identities = [oi.model_dump_json() for oi in obs.issued_identities]
    client.execute_write(
        """
        MERGE (r:RequestObservation {engagement_id: $engagement_id,
                                     observation_id: $observation_id})
        ON CREATE SET r.id = $observation_id, r.method = $method,
                      r.concrete_path = $concrete_path, r.query_string = $query_string,
                      r.query_param_names = $query_param_names,
                      r.body_param_names = $body_param_names,
                      r.request_body_ref = $request_body_ref,
                      r.response_body_ref = $response_body_ref,
                      r.response_body_sha256 = $response_body_sha256,
                      r.response_size_bytes = $response_size_bytes,
                      r.response_status = $response_status,
                      r.value_candidates = $value_candidates,
                      r.server_fingerprint = $server_fingerprint,
                      r.error_excerpt = $error_excerpt,
                      r.observed_identities = $observed_identities,
                      r.issued_credential_auth_hash = $issued_credential_auth_hash,
                      r.issued_identities = $issued_identities,
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
        body_param_names=body_param_names,
        request_body_ref=request_body_ref,
        response_body_ref=response_body_ref,
        response_body_sha256=response_body_sha256,
        response_size_bytes=obs.response_size_bytes,
        response_status=obs.response_status,
        value_candidates=value_candidates,
        server_fingerprint=obs.server_fingerprint,
        error_excerpt=obs.error_excerpt,
        observed_identities=observed_identities,
        issued_credential_auth_hash=obs.issued_credential_auth_hash,
        issued_identities=issued_identities,
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
