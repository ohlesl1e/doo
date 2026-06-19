"""Dispatch-layer Pydantic types (ADR-0042/0043/0046).

The Executor + Dispatcher contracts are typed and bounded, the same discipline as
the planner (ADR-0037): a `DispatchRun` is the authorization unit; a
`DispatchSelection` is the predicate over `approved` `TestCase`s it drains; a
`ConcreteRequest` is the deterministic constructor's output (the LLM never
touches it); an `OpaInput` is the ADR-0046 snapshot the Dispatcher hands to
policy; a `RunOutcome` is the per-`TestCase` ledger record.

Pydantic v2, `extra="forbid"` so a stray field is a loud error and the JSON form
round-trips exactly (mirrors `planner.models` / `coverage.models`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.canonical.value_objects import HostRef
from doo.events.execution import DispatchStatus, PayloadClass, TestClass
from doo.ids import (
    AuthContextId,
    DispatchRunId,
    EngagementId,
    ObservationId,
    TestCaseKeyHash,
    TraceId,
)
from doo.setup.config import ArmingMode, Environment, InterpreterMode

# ---------------------------------------------------------------------------
# Request roles (ADR-0043).
# ---------------------------------------------------------------------------

# A request role is a closed enum keyed by `test_class` (ADR-0043). The
# Interpreter's only authority over what goes on the wire is which role to send
# next. Executor-internal roles (`hazard_warmup`, `liveness`) pass the same
# Dispatcher gate (ADR-0046) but are NEVER Interpreter-selectable — they are
# emitted by the `primary` constructor (ADR-0043) and the classifier (ADR-0044)
# respectively.
RequestRole = Literal[
    "primary",
    "baseline_victim",
    "baseline_negative",
    "hazard_warmup",
    "liveness",
]
REQUEST_ROLES: tuple[RequestRole, ...] = (
    "primary",
    "baseline_victim",
    "baseline_negative",
    "hazard_warmup",
    "liveness",
)

# Authz `test_class`es (the slice-4 MVP execution surface): the per-`test_class`
# Interpreter-selectable role set (ADR-0043). Sink classes (`ssrf` /
# `open-redirect` / `path-traversal` / `leak_replay`) are post-MVP.
ROLES_BY_TEST_CLASS: dict[TestClass, tuple[RequestRole, ...]] = {
    "idor": ("primary", "baseline_victim", "baseline_negative"),
    "bola": ("primary", "baseline_victim", "baseline_negative"),
    "auth-bypass": ("primary", "baseline_victim"),
    "privilege-escalation": ("primary", "baseline_victim"),
    "boundary-violation": ("primary", "baseline_victim"),
}


# ---------------------------------------------------------------------------
# Selection + budget + run (ADR-0042).
# ---------------------------------------------------------------------------


class DispatchSelection(BaseModel):
    """The predicate over `approved` `TestCase`s a run drains (ADR-0042).

    Filter by `generator` and/or `test_class`; order by `expected_yield` desc;
    cap at `limit`. The run-level gate keeps the human decision count
    proportional to *intent* ("the C2 set, top-50"), not test count.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    generators: tuple[str, ...] = ()
    test_classes: tuple[TestClass, ...] = ()
    limit: int | None = Field(default=None, ge=1)

    def describe(self) -> str:
        """Human-readable summary for the arm prompt + ledger."""

        parts: list[str] = []
        if self.generators:
            parts.append(f"generator∈{{{','.join(self.generators)}}}")
        if self.test_classes:
            parts.append(f"test_class∈{{{','.join(self.test_classes)}}}")
        if not parts:
            parts.append("all approved")
        if self.limit is not None:
            parts.append(f"top-{self.limit} by expected_yield")
        return ", ".join(parts)


class RunBudget(BaseModel):
    """Per-run hard caps (ADR-0042: budget-bounded).

    `request_budget` counts EVERY wire send through the Dispatcher gate —
    `primary`, baselines, hazard-warmup, liveness probes (ADR-0043/0044) — so a
    runaway target cannot turn one run into an unbounded crawl.
    `wallclock_budget_s` is checked before each send (a cheap monotonic compare,
    not a watchdog thread; the kill switch is the hard stop).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_budget: int = Field(ge=1)
    wallclock_budget_s: int = Field(ge=1)
    max_tool_calls: int = Field(ge=1)


class DispatchRun(BaseModel):
    """A human-armed, budget-bounded dispatch run — the authorization unit (ADR-0042).

    One arming decision → one run. Carries its own `trace_id`, the selection
    predicate, the budget, and the resolved `(arming, interpreter)` mode. NOT a
    graph node (ADR-0042/0040: tester identity stays out of the target model) —
    persisted only as a dispatch-ledger row keyed by `(engagement_id, run_id)`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    run_id: DispatchRunId
    trace_id: TraceId
    environment: Environment
    arming: ArmingMode
    interpreter: InterpreterMode
    selection: DispatchSelection
    budget: RunBudget
    actor: str = Field(min_length=1)
    armed_at: datetime

    @model_validator(mode="after")
    def _environment_gates_modes(self) -> DispatchRun:
        """Re-assert the ADR-0042 matrix at run construction.

        `EngagementConfig` already rejects illegal combos at LOAD time; this is
        defence-in-depth against a CLI override (`--arming auto`) bypassing the
        loaded default on a production engagement.
        """

        if self.environment == "production" and (
            self.arming != "review" or self.interpreter != "confirm"
        ):
            raise ValueError(
                f"environment=production permits only arming=review + "
                f"interpreter=confirm (got {self.arming!r} + {self.interpreter!r}); "
                "ADR-0042: human-in-the-loop on production targets"
            )
        return self


# ---------------------------------------------------------------------------
# ConcreteRequest — the constructor's output (ADR-0043).
# ---------------------------------------------------------------------------


class ConcreteRequest(BaseModel):
    """A fully-resolved HTTP request, ready for the wire.

    Produced **only** by a deterministic per-`(test_class, role)` constructor
    (ADR-0043); the LLM never composes one. Carries the auth-carrying header /
    cookie material as **already-spliced** name→value pairs (the constructor read
    the live token from the `SecretStore`; raw tokens never reach the graph,
    ADR-0015 — they live only here, in-process, until the wire send).

    `path_template` rides along (not sent on the wire) so the Dispatcher can
    build `OpaInput` with both the concrete `path` AND the inference (ADR-0046).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str
    host: HostRef
    path: str = Field(min_length=1)
    path_template: str = Field(min_length=1)
    query: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None
    body_content_type: str | None = None
    # The `AuthContext` this request is sent under (the attacker side for an
    # authz `primary`); recorded onto the resulting `RequestObservation` so the
    # graph attributes the agent send correctly.
    auth_context_id: AuthContextId

    @model_validator(mode="after")
    def _path_absolute(self) -> ConcreteRequest:
        if not self.path.startswith("/"):
            raise ValueError("path must be absolute (start with /)")
        return self

    def url(self) -> str:
        """The absolute URL (no query — `query` is sent as params)."""

        port = f":{self.host.port}" if self.host.port is not None else ""
        return f"{self.host.scheme}://{self.host.canonical_hostname}{port}{self.path}"


# ---------------------------------------------------------------------------
# OPA input (ADR-0046).
# ---------------------------------------------------------------------------


class OpaInput(BaseModel):
    """The `input` document the Dispatcher's Rego rules evaluate (ADR-0046).

    A snapshot from the constructed request + `TestCase` + run — no graph read
    inside policy (ADR-0003). **Both** `path` (concrete) and `path_template` (the
    Endpoint's current inference) are present: scope-glob rules match `path`;
    tester-authored deny rules can name an Endpoint via `path_template` without
    enumerating ids. `request_role` lets policy treat controls differently
    (e.g. always allow `liveness`; never allow `baseline_negative` with a
    destructive `payload_class`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    environment: Environment
    run_id: DispatchRunId
    request: dict[str, str | None]
    test_class: TestClass
    payload_class: PayloadClass
    request_role: RequestRole
    auth_context_id: AuthContextId
    principal_tier: Literal["declared", "discovered"]
    target_confidence: float = Field(ge=0.0, le=1.0)
    now: datetime

    @classmethod
    def from_send(
        cls,
        *,
        run: DispatchRun,
        request: ConcreteRequest,
        test_class: TestClass,
        payload_class: PayloadClass,
        role: RequestRole,
        principal_tier: Literal["declared", "discovered"],
        target_confidence: float,
        now: datetime,
    ) -> OpaInput:
        """Build the ADR-0046 `input` snapshot for one Dispatcher send."""

        return cls(
            engagement_id=run.engagement_id,
            environment=run.environment,
            run_id=run.run_id,
            request={
                "scheme": request.host.scheme,
                "method": request.method,
                "host": request.host.canonical_hostname,
                "path": request.path,
                "path_template": request.path_template,
            },
            test_class=test_class,
            payload_class=payload_class,
            request_role=role,
            auth_context_id=request.auth_context_id,
            principal_tier=principal_tier,
            target_confidence=target_confidence,
            now=now,
        )


# ---------------------------------------------------------------------------
# Per-TestCase run outcome (ADR-0043 consequence).
# ---------------------------------------------------------------------------

# A dispatch run's per-TestCase outcome (ADR-0043). `executed` ⇒ ≥1 `EXECUTED_AS`
# edge created (the Interpreter ran in S5+); `hazard_unresolved` ⇒ the Executor
# refused the `primary` send upfront; `dispatcher_blocked` ⇒ OPA / lease / budget
# refused before any send. `constructor_missing` (S1-transient) ⇒ no constructor
# registered for this `test_class` yet — surfaces in `doo dispatch review` rather
# than silently skipping.
RunOutcomeKind = Literal[
    "executed",
    "hazard_unresolved",
    "dispatcher_blocked",
    "constructor_missing",
]


class HazardInfo(BaseModel):
    """Structured `hazard_unresolved` detail for `doo dispatch review` (ADR-0041)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    param: str
    reason: str


class RunOutcome(BaseModel):
    """The per-`TestCase` record one dispatch run leaves in the dispatch ledger.

    Keyed by `(engagement_id, run_id, key_hash)`. The full per-send detail lives
    on the `EXECUTED_AS` edge(s); this is the run-level summary `doo dispatch
    review` renders (incl. `hazard_unresolved` reasons, ADR-0043).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    run_id: DispatchRunId
    key_hash: TestCaseKeyHash
    test_class: TestClass
    outcome: RunOutcomeKind
    reason: str | None = None
    # On `hazard_unresolved`: the structured `{kind, param, reason}` (ADR-0041) so
    # `doo dispatch review` can offer a targeted `--set-hint` / `--ignore-hazard`.
    hazard: HazardInfo | None = None
    # On `executed`: the `(role, dispatch_status, observation_id)` per send.
    sends: tuple[tuple[RequestRole, DispatchStatus, ObservationId | None], ...] = ()
    # #125: `(finding_key, prior_status)` when this TestCase's `vulnerable`
    # verdict landed on an already-decided Finding (`finding_status` ≠
    # `proposed`). Surfaced in the run summary so the tester re-reviews.
    finding_reasserted: tuple[str, str] | None = None
    at: datetime


# ---------------------------------------------------------------------------
# Dispatch ledger event (ADR-0042: sibling of the review ledger).
# ---------------------------------------------------------------------------


class DispatchLedgerEvent(BaseModel):
    """One provenanced append-only dispatch-run record (ADR-0042).

    Keyed by `(engagement_id, run_id)`. Tester identity (`actor`) lives here,
    never as a graph node (ADR-0040). One `armed` event per run, plus zero or
    more `outcome` events per `TestCase` — same JSON-array shape as
    `JsonFileReviewLedger`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["armed", "outcome", "override"]
    engagement_id: EngagementId
    run_id: DispatchRunId
    timestamp: datetime
    # `armed` only:
    actor: str | None = None
    selection: DispatchSelection | None = None
    budget: RunBudget | None = None
    arming: ArmingMode | None = None
    interpreter: InterpreterMode | None = None
    environment: Environment | None = None
    # `outcome` only:
    outcome: RunOutcome | None = None
    # `override` only (S5 `doo dispatch review`): a tester-supplied hazard fix the
    # NEXT run reads. `set_hint` supplies a `source_hint`; `ignore_hazard` sends
    # anyway (accept `replay_invalid` risk). Not run-scoped — `run_id` is a sentinel.
    key_hash: TestCaseKeyHash | None = None
    override_action: Literal["set_hint", "ignore_hazard"] | None = None
    hazard_kind: str | None = None
    hint: str | None = None

    @model_validator(mode="after")
    def _kind_shape(self) -> DispatchLedgerEvent:
        if self.kind == "armed":
            if self.actor is None or self.selection is None or self.budget is None:
                raise ValueError("armed event requires actor + selection + budget")
            if self.outcome is not None:
                raise ValueError("armed event carries no outcome")
        elif self.kind == "outcome":
            if self.outcome is None:
                raise ValueError("outcome event requires an outcome")
        else:  # override
            if (
                self.key_hash is None
                or self.override_action is None
                or self.hazard_kind is None
            ):
                raise ValueError(
                    "override event requires key_hash + override_action + hazard_kind"
                )
            if self.override_action == "set_hint" and not self.hint:
                raise ValueError("set_hint override requires a hint")
        return self
