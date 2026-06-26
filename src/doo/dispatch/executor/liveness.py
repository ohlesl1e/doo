"""ADR-0044 liveness probe: disambiguate an authz `primary`'s 4xx.

When an authz-class `primary` returns 401/403/login-redirect, a 4xx is the
*expected* negative ("boundary held"), not "test didn't run". This module sends a
**liveness probe** — a known-allowed warm-up request under the *same*
`AuthContext` — so the classifier can tell a dead token (`auth_invalid` + reactive
refresh) from a genuine boundary (`ok`) from a stale replay (`replay_invalid`).

The probe is a real Dispatcher send (kill-switch → OPA → budget → wire), tagged
`request_role = "liveness"`, counted against the run budget. Its result is
**cached per `((principal_label, slot), window)`** (ADR-0049; default 60s) so a
run of N authz tests under one attacker credential — across any rotated
generation of it — costs ~1 probe per window, not N.

The probe endpoint is the Principal's declared `liveness_endpoint` (ADR-0012-legal
warm-up knowledge), falling back to the first observed self-endpoint
(`/me`/`/userinfo`/…) under that `AuthContext`. No endpoint resolvable → the probe
returns `unknown` and the run flags the engagement once ("authz negatives
unverified", ADR-0044).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from doo.dispatch.executor.classify import BodyMatchers, LivenessResult, is_auth_negative
from doo.dispatch.executor.constructors import _splice_auth
from doo.dispatch.executor.dispatcher import Dispatcher, DispatchResult
from doo.dispatch.executor.evidence import EvidenceObservation
from doo.dispatch.models import ConcreteRequest
from doo.dispatch.secrets import AuthMaterial
from doo.events.execution import PayloadClass, TestClass
from doo.ids import AuthContextId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.setup.config import EngagementConfig

log = get_logger(__name__)

# Path suffixes that read as a self/identity endpoint (ADR-0029/0031 self-endpoint
# heuristic). Used only as the *fallback* when no `liveness_endpoint` is declared.
_SELF_ENDPOINT_SUFFIXES: tuple[str, ...] = (
    "/me",
    "/userinfo",
    "/user",
    "/account",
    "/profile",
    "/whoami",
    "/session",
)

# The probe is a benign GET — no payload (ADR-0044 / ADR-0003 payload class).
_PROBE_PAYLOAD_CLASS: PayloadClass = "benign-probe"


@dataclass(frozen=True, slots=True)
class LivenessEndpointSpec:
    """A resolved probe target: a method + absolute path (host comes from evidence)."""

    method: str
    path: str


@dataclass(frozen=True, slots=True)
class LivenessPolicy:
    """Engagement-level liveness config, projected from `EngagementConfig` (ADR-0044).

    ADR-0049: `declared_by_slot` maps each rotation-stable `(principal_label,
    slot)` to its Principal's `liveness_endpoint`; `slot_for_id` translates a
    (possibly stale) `auth_context_id` to that key via the run-arm graph read.
    `matchers` are the compiled body-match overrides. Built once at run-arm time
    and injected into the run driver.
    """

    matchers: BodyMatchers
    declared_by_slot: dict[tuple[str, str], LivenessEndpointSpec]
    slot_for_id: dict[AuthContextId, tuple[str, str]]

    @classmethod
    def from_config(
        cls,
        config: EngagementConfig,
        *,
        graph_map: dict[AuthContextId, tuple[str, str]] | None = None,
    ) -> LivenessPolicy:
        declared: dict[tuple[str, str], LivenessEndpointSpec] = {}
        for principal in config.principals:
            if principal.liveness_endpoint is None:
                continue
            spec = LivenessEndpointSpec(
                method=principal.liveness_endpoint.method,
                path=principal.liveness_endpoint.path,
            )
            for decl in principal.auth_contexts:
                # T1 guarantees `slot` post-validation (defaults to `kind`).
                assert decl.slot is not None
                declared[(principal.label, decl.slot)] = spec

        d = config.dispatch
        matchers = BodyMatchers(
            auth_invalid=re.compile(d.auth_invalid_match)
            if d.auth_invalid_match
            else None,
            replay_invalid=re.compile(d.replay_invalid_match)
            if d.replay_invalid_match
            else None,
        )
        return cls(
            matchers=matchers,
            declared_by_slot=declared,
            slot_for_id=dict(graph_map) if graph_map is not None else {},
        )


def infer_self_endpoint(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    auth_context_id: AuthContextId,
) -> LivenessEndpointSpec | None:
    """First observed self-endpoint (`/me`/…) under this `AuthContext` (ADR-0044 fallback).

    A 2xx `RequestObservation` `OBSERVED_UNDER` the AuthContext whose concrete path
    ends with a known self-endpoint suffix, highest-confidence / freshest first.
    Returns `None` when none is observed — the run then falls back to `unknown`.
    """

    frag = for_engagement(engagement_id, var="r")
    rows = client.execute_read(
        f"""
        MATCH (r:RequestObservation)-[:OBSERVED_UNDER]->(ac:AuthContext {{id: $ac_id}})
        {frag.and_(
            "r.status = 'active' "
            "AND coalesce(r.response_status, 0) >= 200 "
            "AND coalesce(r.response_status, 0) < 300 "
            "AND any(s IN $suffixes WHERE toLower(r.concrete_path) ENDS WITH s)"
        )}
        RETURN r.method AS method, r.concrete_path AS path
        ORDER BY coalesce(r.confidence, 1.0) DESC, r.last_seen DESC
        LIMIT 1
        """,
        ac_id=str(auth_context_id),
        suffixes=list(_SELF_ENDPOINT_SUFFIXES),
        **frag.parameters,
    )
    if not rows:
        return None
    return LivenessEndpointSpec(
        method=str(rows[0]["method"]).upper(), path=str(rows[0]["path"])
    )


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """The result of one `LivenessProber.probe` call.

    `result` is what the classifier consumes. `sent` is True only when a *fresh*
    wire send happened this call (not a cache hit), so the run driver knows
    whether to commit a `liveness` `RequestObservation`. `endpoint_missing` drives
    the run's one-time "authz negatives unverified" flag (ADR-0044).
    """

    result: LivenessResult
    sent: bool
    endpoint_missing: bool = False
    dispatch_result: DispatchResult | None = None
    request: ConcreteRequest | None = None


@dataclass
class LivenessProber:
    """Sends + caches ADR-0044 liveness probes for one dispatch run.

    Holds the run's `Dispatcher` (so the probe passes the identical gate + counts
    against the same budget) and the graph client (for the self-endpoint
    fallback). `acs_without_endpoint` accumulates the AuthContexts that had no
    resolvable probe endpoint, surfaced once at run end.
    """

    dispatcher: Dispatcher
    neo4j: Neo4jClient
    policy: LivenessPolicy
    engagement_id: EngagementId
    window_s: float = 60.0
    clock: Callable[[], float] = time.monotonic
    # ADR-0049: cache keys on the slot key (or the raw id when no slot maps), so
    # one probe covers every generation of the same `(principal, slot)`.
    _cache: dict[tuple[str, str] | AuthContextId, tuple[LivenessResult, float]] = (
        field(default_factory=dict)
    )
    acs_without_endpoint: set[AuthContextId] = field(default_factory=set)

    def _resolve_endpoint(
        self, ac_id: AuthContextId, slot_key: tuple[str, str] | None
    ) -> LivenessEndpointSpec | None:
        if slot_key is not None:
            declared = self.policy.declared_by_slot.get(slot_key)
            if declared is not None:
                return declared
        return infer_self_endpoint(
            self.neo4j, engagement_id=self.engagement_id, auth_context_id=ac_id
        )

    def probe(
        self,
        *,
        auth_context_id: AuthContextId,
        material: AuthMaterial,
        evidence: EvidenceObservation,
        test_class: TestClass,
        now: object,
    ) -> ProbeOutcome:
        """Probe (or return cached) the AuthContext's liveness (ADR-0044)."""

        slot_key = self.policy.slot_for_id.get(auth_context_id)
        cache_key: tuple[str, str] | AuthContextId = (
            slot_key if slot_key is not None else auth_context_id
        )
        cached = self._cache.get(cache_key)
        if cached is not None and (self.clock() - cached[1]) < self.window_s:
            return ProbeOutcome(result=cached[0], sent=False)

        endpoint = self._resolve_endpoint(auth_context_id, slot_key)
        if endpoint is None:
            self.acs_without_endpoint.add(auth_context_id)
            self._cache[cache_key] = ("unknown", self.clock())
            log.warning(
                "dispatch.liveness.no_endpoint",
                engagement_id=self.engagement_id,
                auth_context_id=auth_context_id,
            )
            return ProbeOutcome(result="unknown", sent=False, endpoint_missing=True)

        request = self._build_probe_request(
            endpoint=endpoint,
            evidence=evidence,
            material=material,
            auth_context_id=auth_context_id,
        )
        dr = self.dispatcher.dispatch(
            request,
            test_class=test_class,
            payload_class=_PROBE_PAYLOAD_CLASS,
            role="liveness",
            principal_tier=material.tier,
            target_confidence=evidence.confidence,
            now=now,
        )
        result = self._interpret(dr)
        self._cache[cache_key] = (result, self.clock())
        log.info(
            "dispatch.liveness.probed",
            engagement_id=self.engagement_id,
            auth_context_id=auth_context_id,
            path=endpoint.path,
            sent=dr.sent,
            http_status=dr.response.status if dr.response is not None else None,
            result=result,
        )
        return ProbeOutcome(
            result=result, sent=dr.sent, dispatch_result=dr, request=request
        )

    @staticmethod
    def _interpret(dr: DispatchResult) -> LivenessResult:
        if not dr.sent or dr.response is None:
            # Gate-blocked or transport error: cannot verify the token.
            return "unknown"
        status = dr.response.status
        if 200 <= status < 300:
            return "live"
        if is_auth_negative(dr.response):
            return "dead"
        return "unknown"

    def _build_probe_request(
        self,
        *,
        endpoint: LivenessEndpointSpec,
        evidence: EvidenceObservation,
        material: AuthMaterial,
        auth_context_id: AuthContextId,
    ) -> ConcreteRequest:
        # A standalone request to the self-endpoint under the same auth — NOT a
        # replay of the target (no target query/headers ride along). Only the
        # auth-carrying header/cookie is set, via the shared splice helper.
        headers, cookies = _splice_auth(
            headers={},
            cookies={},
            material=material,
            session_cookie_names=evidence.session_cookie_names,
        )
        return ConcreteRequest(
            method=endpoint.method,
            host=evidence.host,
            path=endpoint.path,
            path_template=endpoint.path,
            query=(),
            headers=tuple(sorted(headers.items())),
            cookies=tuple(sorted(cookies.items())),
            body=None,
            auth_context_id=auth_context_id,
        )


__all__ = [
    "LivenessEndpointSpec",
    "LivenessPolicy",
    "LivenessProber",
    "ProbeOutcome",
    "infer_self_endpoint",
]
