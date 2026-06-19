"""ADR-0044 liveness prober + policy unit tests (issue #89).

The prober is exercised against a real `Dispatcher` (StubSender, always-alive
lease, allow-all OPA) and a tiny fake graph client — no testcontainers. Covers:
declared-endpoint probe → live/dead, per-(slot, window) caching, the
self-endpoint inference fallback, the no-endpoint `unknown` + flag, a
gate-blocked probe → `unknown`, and `LivenessPolicy.from_config` slot mapping.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from doo.canonical.value_objects import HostRef
from doo.dispatch.executor.dispatcher import (
    AlwaysAliveLease,
    BudgetTracker,
    Dispatcher,
    StubOpaClient,
)
from doo.dispatch.executor.evidence import EvidenceObservation
from doo.dispatch.executor.liveness import (
    LivenessEndpointSpec,
    LivenessPolicy,
    LivenessProber,
    infer_self_endpoint,
)
from doo.dispatch.executor.send import HttpResponse, StubSender
from doo.dispatch.models import DispatchRun, DispatchSelection, RunBudget
from doo.dispatch.secrets import AuthMaterial
from doo.ids import AuthContextId, DispatchRunId, EngagementId, TraceId
from doo.setup.config import EngagementConfig

ENG = EngagementId("eng-liveness")
AC = AuthContextId("ac-attacker")
HOST = HostRef(scheme="https", canonical_hostname="shop.example.com", port=None, is_ip_literal=False)


def _run() -> DispatchRun:
    return DispatchRun(
        engagement_id=ENG,
        run_id=DispatchRunId("run-test"),
        trace_id=TraceId("trace-test"),
        environment="staging",
        arming="auto",
        interpreter="confirm",
        selection=DispatchSelection(),
        budget=RunBudget(request_budget=100, wallclock_budget_s=600, max_tool_calls=6),
        actor="unit",
        armed_at=datetime.now(UTC),
    )


def _dispatcher(sender: StubSender, *, alive: bool = True) -> Dispatcher:
    run = _run()
    return Dispatcher(
        run=run,
        lease=AlwaysAliveLease(alive=alive),
        opa=StubOpaClient(allow=True),
        budget=BudgetTracker(run.budget),
        sender=sender,
    )


def _evidence() -> EvidenceObservation:
    return EvidenceObservation(
        observation_id="obs-x",  # type: ignore[arg-type]
        method="GET",
        host=HOST,
        concrete_path="/orders/123",
        path_template="/orders/{order_id}",
        confidence=0.9,
    )


def _material() -> AuthMaterial:
    return AuthMaterial(kind="bearer", raw="attacker-tok", principal_label="attacker-b")


class _FakeClient:
    """Duck-typed Neo4jClient: returns a scripted row list for execute_read."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self._rows = rows or []
        self.reads = 0

    def execute_read(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self.reads += 1
        return self._rows


_SLOT = ("attacker-b", "bearer")


def _policy(spec: LivenessEndpointSpec | None) -> LivenessPolicy:
    from doo.dispatch.executor.classify import BodyMatchers

    declared = {_SLOT: spec} if spec is not None else {}
    slot_for_id = {AC: _SLOT} if spec is not None else {}
    return LivenessPolicy(
        matchers=BodyMatchers(), declared_by_slot=declared, slot_for_id=slot_for_id
    )


def test_declared_endpoint_probe_live() -> None:
    sender = StubSender(response=HttpResponse(status=200, body=b'{"id":1}'))
    prober = LivenessProber(
        dispatcher=_dispatcher(sender),
        neo4j=_FakeClient(),  # type: ignore[arg-type]
        policy=_policy(LivenessEndpointSpec(method="GET", path="/me")),
        engagement_id=ENG,
    )
    out = prober.probe(
        auth_context_id=AC,
        material=_material(),
        evidence=_evidence(),
        test_class="idor",
        now=datetime.now(UTC),
    )
    assert out.result == "live"
    assert out.sent is True
    assert len(sender.sent) == 1
    probe_req = sender.sent[0]
    assert probe_req.path == "/me"
    assert dict(probe_req.headers).get("Authorization") == "Bearer attacker-tok"


def test_probe_dead_on_4xx() -> None:
    sender = StubSender(response=HttpResponse(status=401, body=b"nope"))
    prober = LivenessProber(
        dispatcher=_dispatcher(sender),
        neo4j=_FakeClient(),  # type: ignore[arg-type]
        policy=_policy(LivenessEndpointSpec(method="GET", path="/me")),
        engagement_id=ENG,
    )
    out = prober.probe(
        auth_context_id=AC, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    assert out.result == "dead"


def test_cached_per_window() -> None:
    sender = StubSender(response=HttpResponse(status=200))
    clock = {"t": 1000.0}
    prober = LivenessProber(
        dispatcher=_dispatcher(sender),
        neo4j=_FakeClient(),  # type: ignore[arg-type]
        policy=_policy(LivenessEndpointSpec(method="GET", path="/me")),
        engagement_id=ENG,
        window_s=60.0,
        clock=lambda: clock["t"],
    )
    kw = dict(
        auth_context_id=AC, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    first = prober.probe(**kw)  # type: ignore[arg-type]
    assert first.sent is True
    # Within the window: cached, no new wire send.
    second = prober.probe(**kw)  # type: ignore[arg-type]
    assert second.sent is False and second.result == "live"
    assert len(sender.sent) == 1
    # Past the window: a fresh probe.
    clock["t"] += 61.0
    third = prober.probe(**kw)  # type: ignore[arg-type]
    assert third.sent is True
    assert len(sender.sent) == 2


def test_no_endpoint_is_unknown_and_flags() -> None:
    sender = StubSender(response=HttpResponse(status=200))
    prober = LivenessProber(
        dispatcher=_dispatcher(sender),
        neo4j=_FakeClient(rows=[]),  # inference returns nothing  # type: ignore[arg-type]
        policy=_policy(None),  # nothing declared
        engagement_id=ENG,
    )
    out = prober.probe(
        auth_context_id=AC, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    assert out.result == "unknown"
    assert out.endpoint_missing is True
    assert out.sent is False
    assert len(sender.sent) == 0
    assert AC in prober.acs_without_endpoint


def test_self_endpoint_inference_fallback() -> None:
    sender = StubSender(response=HttpResponse(status=200))
    client = _FakeClient(rows=[{"method": "get", "path": "/userinfo"}])
    prober = LivenessProber(
        dispatcher=_dispatcher(sender),
        neo4j=client,  # type: ignore[arg-type]
        policy=_policy(None),  # undeclared → infer
        engagement_id=ENG,
    )
    out = prober.probe(
        auth_context_id=AC, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    assert out.result == "live"
    assert out.sent is True
    assert sender.sent[0].path == "/userinfo"


def test_infer_self_endpoint_none_when_no_rows() -> None:
    client = _FakeClient(rows=[])
    assert (
        infer_self_endpoint(client, engagement_id=ENG, auth_context_id=AC)  # type: ignore[arg-type]
        is None
    )


def test_gate_blocked_probe_is_unknown() -> None:
    sender = StubSender(response=HttpResponse(status=200))
    prober = LivenessProber(
        dispatcher=_dispatcher(sender, alive=False),  # dead lease → blocked
        neo4j=_FakeClient(),  # type: ignore[arg-type]
        policy=_policy(LivenessEndpointSpec(method="GET", path="/me")),
        engagement_id=ENG,
    )
    out = prober.probe(
        auth_context_id=AC, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    assert out.result == "unknown"
    assert len(sender.sent) == 0  # no bytes left the process


def test_policy_from_config_maps_slot_and_matchers() -> None:
    config = EngagementConfig.model_validate(
        {
            "engagement": {"id": "eng-cfg", "name": "cfg"},
            "environment": "staging",
            "scope": {
                "host_patterns": ["shop.example.com"],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "dispatch": {
                "auth_invalid_match": r"token (expired|revoked)",
                "replay_invalid_match": r"csrf",
            },
            "principals": [
                {
                    "label": "attacker-b",
                    "auth_contexts": [{"kind": "bearer", "token": "${TOK}"}],
                    "liveness_endpoint": {"method": "get", "path": "/me"},
                }
            ],
        }
    )
    stale = AuthContextId("ac-stale-gen")
    policy = LivenessPolicy.from_config(
        config, graph_map={stale: ("attacker-b", "bearer")}
    )

    # ADR-0049: keyed on (label, slot) — `slot` defaulted to `kind` (T1).
    assert ("attacker-b", "bearer") in policy.declared_by_slot
    spec = policy.declared_by_slot[("attacker-b", "bearer")]
    assert spec.method == "GET" and spec.path == "/me"  # method normalised upper
    # The graph map is copied through so the prober can translate stale ids.
    assert policy.slot_for_id[stale] == ("attacker-b", "bearer")
    assert policy.matchers.auth_invalid is not None
    assert policy.matchers.auth_invalid.search("token revoked")
    assert policy.matchers.replay_invalid is not None


def test_stale_id_resolves_declared_endpoint_via_slot() -> None:
    """ADR-0049 / #117: a probe under a *stale* (rotated-out) `auth_context_id`
    still hits the declared `liveness_endpoint` — and shares the cache window
    with the fresh id of the same `(principal, slot)`."""

    from doo.dispatch.executor.classify import BodyMatchers

    stale = AuthContextId("ac-stale")
    fresh = AuthContextId("ac-fresh")
    spec = LivenessEndpointSpec(method="GET", path="/me")
    policy = LivenessPolicy(
        matchers=BodyMatchers(),
        declared_by_slot={("alice", "cookie"): spec},
        slot_for_id={stale: ("alice", "cookie"), fresh: ("alice", "cookie")},
    )
    sender = StubSender(response=HttpResponse(status=200))
    prober = LivenessProber(
        dispatcher=_dispatcher(sender),
        neo4j=_FakeClient(),  # type: ignore[arg-type]
        policy=policy,
        engagement_id=ENG,
    )
    out = prober.probe(
        auth_context_id=stale, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    assert out.result == "live" and out.sent is True
    assert sender.sent[0].path == "/me"
    # Same slot, different id → cache hit, no second wire send.
    out2 = prober.probe(
        auth_context_id=fresh, material=_material(), evidence=_evidence(),
        test_class="idor", now=datetime.now(UTC),
    )
    assert out2.result == "live" and out2.sent is False
    assert len(sender.sent) == 1
