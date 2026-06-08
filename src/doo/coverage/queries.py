"""The shared coverage query library (ADR-0034) — slice 2, C1 first.

Each `run_*` function is a thin consumer of the same discipline:

1. **Cypher does traversal only.** It fetches the active `Endpoint`s for one
   engagement (scoped via `for_engagement`, ADR-0017), each with its `Host`'s
   identity fields and whether it carries *any* `HIT` edge. It does **not**
   decide scope, decay confidence, or rank — those are Python.
2. **Python does the judgement.** `is_in_scope` (ADR-0020) decides scope on the
   same helper the dispatcher uses; `effective_confidence` (ADR-0005) decays;
   ranking/filtering happen here. This keeps the security-relevant predicates in
   one auditable place rather than re-expressed per query string.

C1 — *dead endpoints* — lists in-scope `Endpoint`s with no `HIT` edge of any
kind (ADR-0033: "hit" is asymmetric from C2's "reached" — any `HIT` regardless
of `response_status` or `source` proves the endpoint is not dead).

**Settle-point assumption (ADR-0022).** Coverage reads at a settle point and
assumes ingestion has drained and the deferred endpoint inference has flushed
(`CommitOrchestrator.flush`). Run after the L3 worker has drained; the CLI
documents this and may trigger a flush first. Coverage writes nothing back.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from doo.canonical.value_objects import Scheme
from doo.coverage.decay import effective_confidence
from doo.coverage.models import C1Result, C2bResult, C2Result, C3Result, PrincipalEvidence
from doo.coverage.reached import ReachedEvidence, reached_map
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.policy.scope import is_in_scope
from doo.setup.config import ScopeRules

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lightweight scope-evaluable adapters.
#
# `is_in_scope` accepts any object exposing the EndpointLike / HostLike
# attributes (structural Protocols, not the L3 node classes). These frozen
# dataclasses wrap the plain Cypher row so the pure helper can judge it without
# the ontology layer leaking into coverage.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _HostView:
    scheme: Scheme
    canonical_hostname: str
    port: int | None
    is_ip_literal: bool


@dataclass(frozen=True, slots=True)
class _EndpointView:
    method: str
    host: _HostView
    path_template: str


def _load_scope_rules(client: Neo4jClient, engagement_id: EngagementId) -> ScopeRules:
    """Reconstruct the engagement's `ScopeRules` from its `Scope` node.

    The loader stores the material scope view as a JSON string on `Scope.rules`
    (`graph_state._scope_create`). We read it back and validate it into the same
    `ScopeRules` model so `is_in_scope` runs against exactly the program's
    declared rules. Engagement-scoped via the `Engagement`->`Scope` edge, so no
    cross-engagement leak.
    """

    rows = client.execute_read(
        """
        MATCH (e:Engagement {id: $engagement_id})-[:UNDER_SCOPE]->(s:Scope)
        RETURN s.rules AS rules
        """,
        engagement_id=engagement_id,
    )
    if not rows or rows[0]["rules"] is None:
        raise ValueError(
            f"engagement {engagement_id!r} has no Scope.rules; cannot evaluate "
            "coverage (run `doo engagement start` first)"
        )
    raw = rows[0]["rules"]
    rules_dict = json.loads(raw) if isinstance(raw, str) else raw
    return ScopeRules.model_validate(rules_dict)


def _to_aware(value: Any, *, fallback: datetime) -> datetime:
    """Coerce a Neo4j temporal / python datetime to a tz-aware datetime.

    Neo4j returns `neo4j.time.DateTime`; `.to_native()` gives a python
    `datetime`. Naive values are assumed UTC. A missing `last_seen` decays from
    `fallback` (now), i.e. no decay.
    """

    if value is None:
        return fallback
    native = value.to_native() if hasattr(value, "to_native") else value
    if not isinstance(native, datetime):
        return fallback
    if native.tzinfo is None:
        return native.replace(tzinfo=UTC)
    return native


def _warn_if_scope_matches_nothing(
    *,
    engagement_id: EngagementId,
    query: str,
    total_endpoints: int,
    in_scope_endpoints: int,
) -> None:
    """Emit a likely-misconfigured-scope warning (ADR-0035, #55).

    When the graph holds active endpoints for the engagement but the Scope
    matched **zero** of them, the most likely cause is a bad scope pattern (e.g.
    a regex that slipped through, or a host/path that names nothing real). A
    silent empty coverage result reads as "doo found nothing"; this surfaces the
    far-more-likely "your scope matched nothing" instead. Shared by all four
    queries so the signal is uniform.
    """

    if total_endpoints > 0 and in_scope_endpoints == 0:
        log.warning(
            "coverage.scope_matched_nothing",
            engagement_id=engagement_id,
            query=query,
            total_active_endpoints=total_endpoints,
            in_scope_endpoints=0,
            hint=(
                "the engagement scope matched zero of the active endpoints in the "
                "graph — likely a misconfigured host_patterns/allowed_path_patterns "
                "(patterns are glob/segment, not regex; see ADR-0035)"
            ),
        )


def run_c1(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    min_confidence: float = 0.0,
    now: datetime | None = None,
) -> list[C1Result]:
    """C1 — in-scope active `Endpoint`s with no `HIT` edge of any kind.

    Cypher fetches every active endpoint for the engagement with its host
    identity and a `HIT`-existence flag (traversal only). Python then keeps the
    rows that are (a) in scope per `is_in_scope` and (b) have no `HIT`, decays
    confidence per ADR-0005, and drops rows below `min_confidence` (default 0 =
    keep everything; low-confidence leads are surfaced, never silently hidden).

    `now` is injectable for deterministic tests; defaults to the wall clock.
    """

    run_at = now or datetime.now(UTC)
    scope = _load_scope_rules(client, engagement_id)

    frag = for_engagement(engagement_id, var="e")
    cypher = f"""
        MATCH (e:Endpoint)-[:ON_HOST]->(h:Host)
        {frag.and_("e.status = 'active'")}
        RETURN e.id AS endpoint_id,
               e.method AS method,
               e.path_template AS path_template,
               e.confidence AS confidence,
               e.last_seen AS last_seen,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal,
               EXISTS {{ (:RequestObservation)-[:HIT]->(e) }} AS has_hit
        ORDER BY h.canonical_hostname, e.path_template, e.method
    """

    rows = client.execute_read(cypher, **frag.parameters)

    in_scope_count = 0
    results: list[C1Result] = []
    for row in rows:
        endpoint = _EndpointView(
            method=str(row["method"]),
            host=_HostView(
                scheme=row["scheme"],
                canonical_hostname=str(row["canonical_hostname"]),
                port=row["port"],
                is_ip_literal=bool(row["is_ip_literal"]),
            ),
            path_template=str(row["path_template"]),
        )
        if not is_in_scope(endpoint, scope):
            continue
        in_scope_count += 1

        if row["has_hit"]:
            # Any HIT — even a 401 — proves the endpoint is not dead (ADR-0033).
            continue

        stored = float(row["confidence"]) if row["confidence"] is not None else 1.0
        last_seen = _to_aware(row["last_seen"], fallback=run_at)
        eff = effective_confidence(stored, last_seen, now=run_at)
        if eff < min_confidence:
            continue

        host_label = endpoint.host.canonical_hostname
        if endpoint.host.port is not None:
            host_label = f"{host_label}:{endpoint.host.port}"

        results.append(
            C1Result(
                engagement_id=engagement_id,
                generated_at=run_at,
                endpoint_id=str(row["endpoint_id"]),
                method=endpoint.method,
                host=host_label,
                path_template=endpoint.path_template,
                effective_confidence=eff,
            )
        )

    _warn_if_scope_matches_nothing(
        engagement_id=engagement_id,
        query="c1",
        total_endpoints=len(rows),
        in_scope_endpoints=in_scope_count,
    )
    log.info(
        "coverage.c1.complete",
        engagement_id=engagement_id,
        dead_endpoints=len(results),
        min_confidence=min_confidence,
    )
    return results


# ---------------------------------------------------------------------------
# C2 — presence-differential authz coverage (ADR-0033).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PrincipalView:
    """One active Principal with its CLI/display label.

    `label` is the handle the `--as` / `--not-as` flags pin and the table prints:
    the anonymous singleton reads `anon`; a declared Principal uses its manual
    `label`; a discovered Principal falls back to its `identity_key`
    (`discovered:sub:…`). All three tiers participate in pairing (ADR-0033).
    """

    principal_id: str
    label: str


def _principal_label(*, is_anonymous: bool, label: object, identity_key: str) -> str:
    """Resolve a Principal's display / pin label across the three tiers."""

    if is_anonymous:
        return "anon"
    if label is not None and str(label) != "":
        return str(label)
    return identity_key


def _load_principals(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_PrincipalView]:
    """Fetch every active Principal for the engagement with a display label.

    Declared + discovered tiers + the anonymous singleton (ADR-0033). Scoped via
    `for_engagement` (ADR-0017) and filtered to `status = 'active'` so retracted
    Principals (e.g. collapsed synthetics, ADR-0029) never appear as a pairing
    side.
    """

    frag = for_engagement(engagement_id, var="p")
    rows = client.execute_read(
        f"""
        MATCH (p:Principal)
        {frag.and_("p.status = 'active'")}
        RETURN p.id AS principal_id,
               p.is_anonymous AS is_anonymous,
               p.label AS label,
               p.identity_key AS identity_key
        ORDER BY p.identity_key
        """,
        **frag.parameters,
    )
    return [
        _PrincipalView(
            principal_id=str(row["principal_id"]),
            label=_principal_label(
                is_anonymous=bool(row["is_anonymous"]),
                label=row["label"],
                identity_key=str(row["identity_key"]),
            ),
        )
        for row in rows
    ]


def _host_label(host: _HostView) -> str:
    label = host.canonical_hostname
    if host.port is not None:
        label = f"{label}:{host.port}"
    return label


def _load_in_scope_endpoints(
    client: Neo4jClient,
    engagement_id: EngagementId,
    scope: ScopeRules,
    *,
    run_at: datetime,
    query: str,
) -> dict[str, dict[str, Any]]:
    """Return `{endpoint_id: {method, host_label, path_template, eff_conf}}`.

    Active engagement endpoints (with host identity) filtered through the same
    `is_in_scope` helper the dispatcher uses (ADR-0020); confidence decayed per
    ADR-0005. Shared by C2 so the authz differential is computed only over the
    endpoints the policy layer would allow.
    """

    frag = for_engagement(engagement_id, var="e")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint)-[:ON_HOST]->(h:Host)
        {frag.and_("e.status = 'active'")}
        RETURN e.id AS endpoint_id,
               e.method AS method,
               e.path_template AS path_template,
               e.confidence AS confidence,
               e.last_seen AS last_seen,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal
        """,
        **frag.parameters,
    )

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        endpoint = _EndpointView(
            method=str(row["method"]),
            host=_HostView(
                scheme=row["scheme"],
                canonical_hostname=str(row["canonical_hostname"]),
                port=row["port"],
                is_ip_literal=bool(row["is_ip_literal"]),
            ),
            path_template=str(row["path_template"]),
        )
        if not is_in_scope(endpoint, scope):
            continue
        stored = float(row["confidence"]) if row["confidence"] is not None else 1.0
        last_seen = _to_aware(row["last_seen"], fallback=run_at)
        out[str(row["endpoint_id"])] = {
            "method": endpoint.method,
            "host": _host_label(endpoint.host),
            "path_template": endpoint.path_template,
            "effective_confidence": effective_confidence(stored, last_seen, now=run_at),
        }
    _warn_if_scope_matches_nothing(
        engagement_id=engagement_id,
        query=query,
        total_endpoints=len(rows),
        in_scope_endpoints=len(out),
    )
    return out


def _evidence(
    label: str, reached: ReachedEvidence | None
) -> PrincipalEvidence | None:
    if reached is None:
        return None
    return PrincipalEvidence(
        principal_id=reached.principal_id,
        label=label,
        status=reached.status,
        response_size_bytes=reached.response_size_bytes,
        response_body_sha256=reached.response_body_sha256,
    )


def run_c2(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    as_label: str | None = None,
    not_as_label: str | None = None,
    min_confidence: float = 0.0,
    now: datetime | None = None,
) -> list[C2Result]:
    """C2 — endpoints reached as principal A but not as B (ADR-0033).

    For each ordered active-principal pair `(A, B)`, `A != B`, emit the in-scope
    endpoints where `reached(e, A) ∧ ¬reached(e, B)`. `reached` is the 2xx-only
    predicate from `coverage.reached` — deliberately asymmetric from C1's any-
    `HIT` "hit": a 401/403/404/5xx (or no request) on the B side counts as *not*
    reached, so a possibly-bypassable boundary surfaces instead of being hidden.

    `as_label` / `not_as_label` pin A / B by their display label (`--as` /
    `--not-as`); unset means "all". Each row carries A's success evidence and B's
    evidence-or-null `(status, response_size_bytes, response_body_sha256)`.
    Engagement-scoped (ADR-0017), `status='active'` throughout, effective
    confidence decayed (ADR-0005) with opt-in `min_confidence`. No
    `dispatch_status` filter (slice 4). `now` is injectable for tests.
    """

    run_at = now or datetime.now(UTC)
    scope = _load_scope_rules(client, engagement_id)
    principals = _load_principals(client, engagement_id)
    endpoints = _load_in_scope_endpoints(
        client, engagement_id, scope, run_at=run_at, query="c2"
    )
    reached = reached_map(client, engagement_id)

    a_candidates = [p for p in principals if as_label is None or p.label == as_label]
    b_candidates = [p for p in principals if not_as_label is None or p.label == not_as_label]

    results: list[C2Result] = []
    for a in a_candidates:
        for b in b_candidates:
            if a.principal_id == b.principal_id:
                continue
            for endpoint_id, ep in endpoints.items():
                ev_a = reached.get((endpoint_id, a.principal_id))
                if ev_a is None:
                    continue  # A must have genuine 2xx access (ADR-0033 A side).
                ev_b = reached.get((endpoint_id, b.principal_id))
                if ev_b is not None:
                    continue  # B reached it too — not a differential.

                eff = ep["effective_confidence"]
                if eff < min_confidence:
                    continue

                evidence_a = _evidence(a.label, ev_a)
                assert evidence_a is not None  # ev_a is not None here.
                results.append(
                    C2Result(
                        engagement_id=engagement_id,
                        generated_at=run_at,
                        endpoint_id=endpoint_id,
                        method=str(ep["method"]),
                        host=str(ep["host"]),
                        path_template=str(ep["path_template"]),
                        principal_a_label=a.label,
                        principal_b_label=b.label,
                        evidence_a=evidence_a,
                        evidence_b=_evidence(b.label, ev_b),
                        effective_confidence=eff,
                    )
                )

    results.sort(
        key=lambda r: (
            r.principal_a_label,
            r.principal_b_label,
            r.host,
            r.path_template,
            r.method,
        )
    )
    log.info(
        "coverage.c2.complete",
        engagement_id=engagement_id,
        gaps=len(results),
        principals=len(principals),
        min_confidence=min_confidence,
    )
    return results


# ---------------------------------------------------------------------------
# C2b — content-differential authz coverage (ADR-0033).
# ---------------------------------------------------------------------------


def _diverges(group: list[ReachedEvidence]) -> bool:
    """True iff the reached evidence in this endpoint group is not all identical.

    Pure metadata comparison (ADR-0033): a group diverges when its principals do
    not all share the same `(response_body_sha256, response_size_bytes)`. A group
    where every principal returned the same hash AND size is *not* a divergence
    (the role-differentiated-200 signal is absent), and a group of <2 principals
    can never diverge. No body is parsed — only the promoted node properties.
    """

    if len(group) < 2:
        return False
    signatures = {(ev.response_body_sha256, ev.response_size_bytes) for ev in group}
    return len(signatures) > 1


def run_c2b(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    min_confidence: float = 0.0,
    now: datetime | None = None,
) -> list[C2bResult]:
    """C2b — endpoints reached (2xx) by ≥2 principals whose responses DIFFER (ADR-0033).

    The content-differential sibling of C2. Where C2 surfaces *presence* gaps
    (A reached, B did not), C2b surfaces *content* divergence among principals who
    ALL reached the endpoint with a 2xx — the role-differentiated-200 case C2 is
    blind to (both "reached"), and where BOLA/IDOR lives.

    Reuses the `reached_map` 2xx traversal (no re-derived predicate): it groups the
    reached pairs by endpoint, keeps the groups with ≥2 active principals, and
    emits one row per group whose per-principal `response_body_sha256` OR
    `response_size_bytes` differ. Groups where every principal returned the
    IDENTICAL hash AND size are dropped. The comparison is **pure metadata** — no
    body is parsed or fetched. Each row carries the full per-principal evidence
    list so the divergence is visible; coverage surfaces it, it does not adjudicate.

    Engagement-scoped (ADR-0017), `status='active'` throughout (via `reached_map` /
    `_load_principals` / `_load_in_scope_endpoints`), in-scope via `is_in_scope`
    (ADR-0020), effective confidence decayed (ADR-0005) with opt-in
    `min_confidence`. No `dispatch_status` filter (slice 4). `now` injectable.
    """

    run_at = now or datetime.now(UTC)
    scope = _load_scope_rules(client, engagement_id)
    principals = _load_principals(client, engagement_id)
    endpoints = _load_in_scope_endpoints(
        client, engagement_id, scope, run_at=run_at, query="c2b"
    )
    reached = reached_map(client, engagement_id)

    label_by_id = {p.principal_id: p.label for p in principals}

    # Group the reached evidence per endpoint, keeping only active principals.
    groups: dict[str, list[ReachedEvidence]] = {}
    for (endpoint_id, principal_id), ev in reached.items():
        if endpoint_id not in endpoints:
            continue  # out of scope / inactive endpoint (filtered upstream)
        if principal_id not in label_by_id:
            continue  # retracted / inactive principal
        groups.setdefault(endpoint_id, []).append(ev)

    results: list[C2bResult] = []
    for endpoint_id, group in groups.items():
        if not _diverges(group):
            continue

        ep = endpoints[endpoint_id]
        eff = ep["effective_confidence"]
        if eff < min_confidence:
            continue

        evidence = tuple(
            PrincipalEvidence(
                principal_id=ev.principal_id,
                label=label_by_id[ev.principal_id],
                status=ev.status,
                response_size_bytes=ev.response_size_bytes,
                response_body_sha256=ev.response_body_sha256,
            )
            for ev in sorted(group, key=lambda e: label_by_id[e.principal_id])
        )
        results.append(
            C2bResult(
                engagement_id=engagement_id,
                generated_at=run_at,
                endpoint_id=endpoint_id,
                method=str(ep["method"]),
                host=str(ep["host"]),
                path_template=str(ep["path_template"]),
                evidence=evidence,
                effective_confidence=eff,
            )
        )

    results.sort(key=lambda r: (r.host, r.path_template, r.method))
    log.info(
        "coverage.c2b.complete",
        engagement_id=engagement_id,
        divergent_endpoints=len(results),
        principals=len(principals),
        min_confidence=min_confidence,
    )
    return results


# ---------------------------------------------------------------------------
# C3 — leak-to-input pivot (issue #53). INDEPENDENT of C2/C2b: it does not use
# the `reached` predicate. A pivot is an ObservedValue that is BOTH a response
# output (YIELDED_VALUE) and a request input (SENT_VALUE), where the input
# endpoint is in scope (the source need not be, ADR-0020).
# ---------------------------------------------------------------------------

# Value-shape specificity buckets for ranking (issue #53). Lower sorts first:
# the more specific / globally-unique the shape, the higher the lead quality, so
# a UUID/email/JWT pivot ranks above an opaque_token, which ranks above a bare
# integer. The bucket is derived from the ObservedValue `kind` plus a light
# preview shape-check (the `identifier` kind covers UUIDs, emails-in-claims, and
# bare integers alike, so kind alone is not enough).
_SHAPE_RANK_SPECIFIC = 0  # UUID / email / JWT — globally unique, high-value lead
_SHAPE_RANK_OPAQUE = 1  # opaque_token / secret / token — high-entropy blob
_SHAPE_RANK_INTEGER = 2  # bare integer — low specificity (sequential id risk)
_SHAPE_RANK_OTHER = 3  # everything else (hostnames, urls, free-form identifiers)

_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_EMAIL_RE = re.compile(r"\A[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_JWT_RE = re.compile(r"\Aey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\Z")
_INT_RE = re.compile(r"\A-?\d+\Z")


def _shape_rank(kind: str, value: str | None, value_preview: str | None) -> int:
    """Rank a pivot value by shape specificity (issue #53; lower = sorts first).

    UUID / email / JWT shapes are the highest-value leads (globally unique, so a
    successful swap is unambiguous). `opaque_token` / `secret` / `token` are
    high-entropy but coarse. A bare integer is the weakest (sequential-id noise).
    Everything else (hostnames, URLs, free-form identifiers) sorts last.

    For secret-shaped kinds the raw value is absent (ADR-0015); we classify from
    the kind alone (always the opaque bucket) and never inspect a raw secret.
    """

    if kind in ("email",):
        return _SHAPE_RANK_SPECIFIC
    if kind in ("secret", "token", "opaque_token"):
        # JWTs are detected as `secret` upstream; the preview ("eyJ…") is safe to
        # peek at to lift a JWT above a generic opaque blob.
        if value_preview is not None and value_preview.startswith("ey"):
            return _SHAPE_RANK_SPECIFIC
        return _SHAPE_RANK_OPAQUE
    # Non-secret kinds carry the raw value; inspect its concrete shape.
    probe = value if value is not None else value_preview
    if probe is not None:
        if _UUID_RE.match(probe) or _EMAIL_RE.match(probe) or _JWT_RE.match(probe):
            return _SHAPE_RANK_SPECIFIC
        if _INT_RE.match(probe):
            return _SHAPE_RANK_INTEGER
    return _SHAPE_RANK_OTHER


def run_c3(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    include_same_endpoint: bool = False,
    min_confidence: float = 0.0,
    now: datetime | None = None,
) -> list[C3Result]:
    """C3 — leak-to-input pivots (issue #53). Independent of `reached`.

    A pivot is an `ObservedValue` that is BOTH `YIELDED_VALUE` from some
    observation (it surfaced in a *response* — the output side) AND `SENT_VALUE`
    from some observation (it was sent as a request *parameter* — the input side).
    The actionable lead: a concrete value the app handed out and that an endpoint
    consumes as input. Only **promoted** values are `ObservedValue` nodes, so junk
    is already excluded (ADR-0009).

    Cypher does traversal only: for the engagement's active `ObservedValue`s it
    fetches each value's output endpoints and input `(endpoint, parameter_name)`
    pairs (with host identity), plus the value's shape fields and confidence.
    Python then applies the security-relevant predicates:

    - The **target (input)** endpoint must pass `is_in_scope` (ADR-0020); the
      **source (output)** endpoint need NOT (a value leaked from an out-of-scope
      SSO host is still a valid lead).
    - **Cross-endpoint by default** (source ≠ target). `include_same_endpoint`
      also surfaces same-endpoint reuse (e.g. a pagination token echoed back).
    - Temporality ignored; `status='active'` throughout; engagement-scoped
      (ADR-0017); effective confidence decayed (ADR-0005) with opt-in
      `min_confidence`.

    One row per `(value, target_endpoint, parameter_name)` input, naming all
    distinct source endpoints. Secret-shaped values surface `value_hash` +
    `value_preview` only (ADR-0015) — never a raw secret. Ranked by value-shape
    specificity (UUID/email/JWT > opaque_token > bare integer) then descending
    confidence. `now` injectable for tests.
    """

    run_at = now or datetime.now(UTC)
    scope = _load_scope_rules(client, engagement_id)

    frag = for_engagement(engagement_id, var="v")
    cypher = f"""
        MATCH (v:ObservedValue)
        {frag.and_("v.status = 'active'")}
        MATCH (out:RequestObservation)-[:YIELDED_VALUE]->(v)
        MATCH (out)-[:HIT]->(oe:Endpoint)
        WHERE oe.status = 'active'
        MATCH (inp:RequestObservation)-[s:SENT_VALUE]->(v)
        MATCH (inp)-[:HIT]->(ie:Endpoint)-[:ON_HOST]->(ih:Host)
        WHERE ie.status = 'active'
        WITH v, ie, ih, s.parameter_name AS parameter_name,
             collect(DISTINCT {{
                 endpoint_id: oe.id, method: oe.method, path_template: oe.path_template
             }}) AS source_endpoints
        RETURN v.value_hash AS value_hash,
               v.kind AS kind,
               v.value AS value,
               v.value_preview AS value_preview,
               v.confidence AS confidence,
               v.last_seen AS last_seen,
               ie.id AS target_endpoint_id,
               ie.method AS target_method,
               ie.path_template AS target_path_template,
               ih.scheme AS scheme,
               ih.canonical_hostname AS canonical_hostname,
               ih.port AS port,
               ih.is_ip_literal AS is_ip_literal,
               parameter_name AS parameter_name,
               source_endpoints AS source_endpoints
    """

    rows = client.execute_read(cypher, **frag.parameters)

    # Track distinct target (input) endpoints for the zero-in-scope-match warning
    # (#55): C3's in-scope predicate applies to the TARGET endpoint only.
    seen_targets: set[str] = set()
    in_scope_targets: set[str] = set()

    results: list[C3Result] = []
    for row in rows:
        target = _EndpointView(
            method=str(row["target_method"]),
            host=_HostView(
                scheme=row["scheme"],
                canonical_hostname=str(row["canonical_hostname"]),
                port=row["port"],
                is_ip_literal=bool(row["is_ip_literal"]),
            ),
            path_template=str(row["target_path_template"]),
        )
        target_id = str(row["target_endpoint_id"])
        seen_targets.add(target_id)
        # The TARGET (input) endpoint must be in scope; the source need not be.
        if not is_in_scope(target, scope):
            continue
        in_scope_targets.add(target_id)

        # Cross-endpoint by default: drop the target from the source list, and
        # decide same-endpoint inclusion on whether any source is the target.
        sources = list(row["source_endpoints"])
        cross_sources = [
            src for src in sources if str(src["endpoint_id"]) != target_id
        ]
        is_same_endpoint = len(cross_sources) < len(sources)

        if cross_sources:
            kept_sources = cross_sources
            same_flag = False
        elif include_same_endpoint and is_same_endpoint:
            # Only same-endpoint reuse exists for this (value, target) — surface
            # it only behind the flag.
            kept_sources = sources
            same_flag = True
        else:
            continue

        stored = float(row["confidence"]) if row["confidence"] is not None else 1.0
        last_seen = _to_aware(row["last_seen"], fallback=run_at)
        eff = effective_confidence(stored, last_seen, now=run_at)
        if eff < min_confidence:
            continue

        source_labels = tuple(
            sorted(
                f"{src['method']} {src['path_template']}" for src in kept_sources
            )
        )

        kind = str(row["kind"])
        value = row["value"]
        preview = row["value_preview"]
        # Surface a human-readable preview WITHOUT ever exposing a raw secret
        # (ADR-0015). Secret-shaped kinds carry value=None and an 8-char preview
        # (or None for short secrets) — surface that. Non-secret kinds carry the
        # raw value (safe to surface) and no preview — surface the value.
        surfaced_preview: str | None
        if preview is not None:
            surfaced_preview = str(preview)
        elif value is not None:
            surfaced_preview = str(value)
        else:
            surfaced_preview = None
        results.append(
            C3Result(
                engagement_id=engagement_id,
                generated_at=run_at,
                value_hash=str(row["value_hash"]),
                kind=kind,
                value_preview=surfaced_preview,
                source_endpoints=source_labels,
                target_endpoint_id=target_id,
                target_method=target.method,
                target_host=_host_label(target.host),
                target_path_template=target.path_template,
                parameter_name=(
                    str(row["parameter_name"])
                    if row["parameter_name"] is not None
                    else None
                ),
                same_endpoint=same_flag,
                shape_rank=_shape_rank(
                    kind,
                    str(value) if value is not None else None,
                    str(preview) if preview is not None else None,
                ),
                effective_confidence=eff,
            )
        )

    results.sort(
        key=lambda r: (
            r.shape_rank,
            -r.effective_confidence,
            r.target_host,
            r.target_path_template,
            r.target_method,
            r.parameter_name or "",
            r.value_hash,
        )
    )
    _warn_if_scope_matches_nothing(
        engagement_id=engagement_id,
        query="c3",
        total_endpoints=len(seen_targets),
        in_scope_endpoints=len(in_scope_targets),
    )
    log.info(
        "coverage.c3.complete",
        engagement_id=engagement_id,
        pivots=len(results),
        include_same_endpoint=include_same_endpoint,
        min_confidence=min_confidence,
    )
    return results
