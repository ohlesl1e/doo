"""Planner I/O and review-lifecycle Pydantic models (ADRs 0036/0037/0040).

The planner's contracts are **typed and bounded** (ADR-0037): a deterministic
generator emits a `Candidate`; a `PlannerProposal` (deterministic for C1, LLM for
later generators) names a closed-enum `test_class`, a target reference, an
`AuthContext` reference, a closed-enum `payload_class`, a resolvable `payload_spec`
(never bytes), and an `expected_yield` priority hunch *separate* from `confidence`
(validity). The Validator resolves a proposal into a content-addressed `TestCase`.

The review lifecycle (ADR-0040) adds the `review_status` axis (orthogonal to
`status` and `dispatch_status`), a rejection `disposition`, and a provenanced
append-only audit-ledger event. Tester identity is recorded only on the ledger
event and as denormalised fields on the node — never as a graph node (ADR-0012).

Pydantic v2, `extra="forbid"` so a stray field is a loud error and the JSON form
round-trips exactly (mirrors `coverage.models`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.events.slice4 import PayloadClass, TestClass
from doo.ids import (
    AuthContextId,
    EngagementId,
    ParameterId,
    Sha256Hex,
    TestCaseKeyHash,
    TrustBoundaryId,
)

# ---------------------------------------------------------------------------
# Candidate (generator output, ADR-0036).
# ---------------------------------------------------------------------------

# The deterministic generator that produced a candidate. Each value doubles as
# the `source` provenance tag on a committed deterministic TestCase
# (`deterministic-c1`, ADR-0036). LLM-proposing generators (slice-3 tracers,
# slice 4) commit `source = "llm-planner"` instead.
# `interpreter` is the slice-4 follow-up *source* (ADR-0045/S8): the confirm loop
# surfaces a genuinely-new test, committed via this same Validator path. It is a
# valid `generator` provenance value but NOT a runnable planner generator, so it is
# deliberately absent from `GENERATOR_IDS` (the config default + planner registry).
GeneratorId = Literal["c1", "c2", "c2b", "c3", "c4", "tenant", "sink", "interpreter"]
GENERATOR_IDS: tuple[GeneratorId, ...] = ("c1", "c2", "c2b", "c3", "c4", "tenant", "sink")

# A replay-breaking request-field role (ADR-0041). A field bound to the original
# session whose verbatim replay under a swapped identity would fail for a *non-authz*
# reason (and thus false-negative a boundary as "enforced"). Detected
# **deterministically** by name + shape/entropy/short-lived heuristics
# (`replay_hazards.py`) — never by the LLM. Slice 3 only *flags* these; the actual
# refresh + the `replay_invalid` dispatch_status land in slice 4.
ReplayHazardRole = Literal["csrf_token", "nonce", "signature", "timestamp"]
REPLAY_HAZARD_ROLES: tuple[ReplayHazardRole, ...] = (
    "csrf_token",
    "nonce",
    "signature",
    "timestamp",
)

# How a generator turns a selected target into a proposal (ADR-0036).
ProposalMode = Literal["deterministic", "llm"]


class Candidate(BaseModel):
    """One deterministically-selected target plus its naming reason (ADR-0036).

    A generator reads the shared coverage library (or other deterministic signal)
    and emits one `Candidate` per selected target. Each candidate carries the
    `generator` that produced it and a `reason` string (the gap evidence) so every
    downstream proposal traces back to *why* it was proposed — the provenance story
    that matters for disclosure.

    The target reference is the same three-way handle a `PlannerProposal` carries;
    for C1 it is always an `endpoint_id` (a route-level dead-endpoint probe).
    `criticality` is the generator/gap-class weight the prioritiser multiplies in
    (ADR-0036: tenant > capability > C2b > C2 > C1); C1 is the lowest tier.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    generator: GeneratorId
    reason: str = Field(min_length=1)
    criticality: float = Field(gt=0.0)
    # Effective (decayed) confidence of the target inference (ADR-0005), carried
    # so the prioritiser can discount a test against a shaky target.
    target_confidence: float = Field(ge=0.0, le=1.0)

    # Target handle: exactly one is set (the ADR-0007 three-way XOR). For C1 it is
    # always `target_endpoint_id`.
    target_endpoint_id: str | None = None
    target_parameter_id: ParameterId | None = None
    target_trust_boundary_id: TrustBoundaryId | None = None

    @model_validator(mode="after")
    def _target_is_xor(self) -> Candidate:
        present = [
            self.target_endpoint_id is not None,
            self.target_parameter_id is not None,
            self.target_trust_boundary_id is not None,
        ]
        if sum(present) != 1:
            raise ValueError(
                "Candidate target is exactly one of target_endpoint_id / "
                "target_parameter_id / target_trust_boundary_id (ADR-0007 XOR)"
            )
        return self


# ---------------------------------------------------------------------------
# PlannerProposal (the typed output, ADR-0037).
# ---------------------------------------------------------------------------

# payload_spec is NEVER bytes (ADR-0037). The Validator resolves it to concrete
# bytes -> payload_hash. Slice 3 needs only `none` (authz replays / forced
# browsing -> sentinel `sha256("")`); `observed_value` (C3) and `configured`
# (sink_params) land in later tracers. The kind is a closed discriminator.
PayloadSpecKind = Literal["none", "observed_value", "configured"]


class PayloadSpec(BaseModel):
    """A resolvable, propose-time-known payload reference (ADR-0037) — never bytes.

    `none` carries no reference (forced browsing / authz replays -> sentinel
    `sha256("")`). `observed_value` carries the `value_hash` of an already-observed
    `ObservedValue` (C3). `configured` carries an engagement-config key (the
    tester-configured callback URL for `sink_params`). Only `none` is exercised in
    the S1 tracer; the other resolvers land with their generators.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: PayloadSpecKind = "none"
    value_hash: Sha256Hex | None = None
    config_key: str | None = None

    @model_validator(mode="after")
    def _reference_matches_kind(self) -> PayloadSpec:
        if self.kind == "none" and (self.value_hash or self.config_key):
            raise ValueError("payload_spec kind 'none' carries no reference")
        if self.kind == "observed_value" and self.value_hash is None:
            raise ValueError("payload_spec kind 'observed_value' requires value_hash")
        if self.kind == "configured" and self.config_key is None:
            raise ValueError("payload_spec kind 'configured' requires config_key")
        return self


class PlannerProposal(BaseModel):
    """A typed test proposal (ADR-0037): enums + references, never request bytes.

    For C1 this is produced deterministically (no LLM): `test_class =
    forced_browsing`, `payload_class = no-payload`, `payload_spec = none`,
    `auth_context_id` = the anonymous singleton (a benign GET as nobody). The
    target is the ADR-0007 three-way XOR, echoed from the `Candidate`.

    `expected_yield` is the priority hunch — *distinct* from the validator-set
    `confidence` (validity). `confidence_method` records how `expected_yield` was
    derived (`heuristic` for deterministic generators, `llm-self-reported` for the
    LLM). `justification` cites the candidate gap; `expected_outcome` says what
    would confirm the lead (for the slice-4 Interpreter).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    generator: GeneratorId
    mode: ProposalMode

    test_class: TestClass
    payload_class: PayloadClass
    payload_spec: PayloadSpec = Field(default_factory=PayloadSpec)
    auth_context_id: AuthContextId
    # ADR-0049: the rotation-stable attacker identity that keys the TestCase
    # `key_hash`. Required (no default) so every proposer — deterministic, LLM
    # resolver, interpreter follow-up — must set them explicitly.
    attacker_principal: str
    attacker_slot: str

    # Target XOR (echoed from the candidate; the validator re-checks it).
    target_endpoint_id: str | None = None
    target_parameter_id: ParameterId | None = None
    target_trust_boundary_id: TrustBoundaryId | None = None

    expected_yield: float = Field(ge=0.0, le=1.0)
    confidence_method: Literal["heuristic", "llm-self-reported"] = "heuristic"
    justification: str = Field(min_length=1)
    expected_outcome: str = Field(min_length=1)

    # Authz-replay intent (ADR-0041): references held verbatim from the evidence
    # observation when this test is an authz replay (e.g. principal A's object id,
    # kept while the attacker AuthContext is swapped in). Resolved from pack handles
    # to stable labels by the resolver; empty for non-replay proposals (e.g. C1).
    # NOT part of the ADR-0007 key_hash — a derivable execution strategy, not
    # identity.
    hold: tuple[str, ...] = ()

    # Replay-fidelity annotation (ADR-0041): the replay-breaking field roles
    # (`csrf_token` / `nonce` / `signature` / `timestamp`) the deterministic
    # detector (`replay_hazards.py`) found in the evidencing observation. Set by
    # CODE after the LLM returns — the model selects handles + classifies, it never
    # touches this. Like `hold`, a **derivable execution-fidelity** annotation, so it
    # is **NOT part of the ADR-0007 key_hash** (adding it would needlessly fracture
    # content-addressed identity). Empty when no hazard was detected. Slice 3 only
    # *flags* a naive-replay false-negative risk; the refresh + the `replay_invalid`
    # dispatch_status land in slice 4.
    replay_hazards: tuple[str, ...] = ()

    # Resolvable-hazard `source_hint`s (`"<kind>=<url>"`, ADR-0041): for a
    # `csrf_token`, the page the token was minted on (the observed `Referer`), so
    # the slice-4 resolver can fetch a fresh token under the test's auth. Set by
    # CODE alongside `replay_hazards`; like it, NOT part of the key_hash. Empty when
    # no hint applies (nonce/timestamp need none; no observed Referer).
    hazard_source_hints: tuple[str, ...] = ()

    # Object-storage key of the verbatim LLM request/response that produced this
    # proposal (ADR-0037 replayability). Set only for `mode == "llm"` proposals —
    # the service persists the audit, stamps the key here, and commits it onto the
    # node as provenance (CLAUDE.md: provenance on every node). `None` for
    # deterministic generators (no LLM call to replay).
    llm_audit_key: str | None = None


# ---------------------------------------------------------------------------
# Context pack + LLM draft (ADR-0037, S2a) — the typed planner I/O for the LLM.
# ---------------------------------------------------------------------------

# What the LLM may classify a C2 authz test as — a constrained subset of TestClass
# (the authz-relevant classes), so the model cannot wander outside authz.
C2TestClass = Literal["idor", "bola", "auth-bypass", "privilege-escalation"]

# What the LLM may classify a C3 leak-replay test as — the vuln classes a
# leaked-then-consumed value enables. `leak_replay` is the generic default; the
# model specialises to `ssrf`/`open-redirect` for URL-shaped values or `idor` for
# id-shaped ones. Constrained so the model can't wander outside the leak-to-input
# frame.
C3TestClass = Literal["leak_replay", "ssrf", "idor", "open-redirect"]

# What the LLM may classify a boundary (capability / tenant) replay test as
# (ADR-0039). `boundary-violation` is the generic cross-boundary access; the model
# specialises to `privilege-escalation` (capability tier) or `idor`/`bola` (tenant
# object/ownership) when the evidence supports it.
BoundaryTestClass = Literal["boundary-violation", "privilege-escalation", "idor", "bola"]

# Sink-parameter roles (ADR-0036, S6) — a request parameter that consumes a
# caller-controlled address. Deterministically detected (`sink_params.py`), never
# LLM. Ordered by detection precedence (redirect > url > file).
SinkRole = Literal["redirect_target", "url_sink", "file_path"]
SINK_ROLES: tuple[SinkRole, ...] = ("redirect_target", "url_sink", "file_path")

# What the LLM may classify a sink-parameter test as — the dangerous-sink classes
# (`lfi` maps to the `path-traversal` TestClass). Constrained to the sink frame.
SinkTestClass = Literal["ssrf", "open-redirect", "path-traversal"]


class PackTarget(BaseModel):
    """One holdable/targetable node in a context pack, addressed by `handle`.

    The LLM sees the `handle` (`"T1"`) and the descriptive fields; it never sees a
    Neo4j id. The resolver reads `endpoint_id` / `parameter_id` off this object to
    build the concrete-id `PlannerProposal`. `to_llm_dict()` is the id-free
    projection serialised into the prompt.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    handle: str = Field(min_length=1)
    kind: Literal["endpoint", "parameter", "boundary"]
    method: str
    path_template: str
    param_name: str | None = None
    location: str | None = None
    semantic: str | None = None
    # Real ids — for the resolver only; excluded from the LLM-facing projection.
    # For a `boundary` target the `method`/`path_template` describe the evidence
    # endpoint (so `hold` reads naturally); `endpoint_id` is that evidence endpoint
    # and `trust_boundary_id` is the actual target id.
    endpoint_id: str
    parameter_id: ParameterId | None = None
    trust_boundary_id: TrustBoundaryId | None = None

    def to_llm_dict(self) -> dict[str, object]:
        """Id-free projection for the prompt (never leaks raw node ids)."""

        d: dict[str, object] = {
            "handle": self.handle,
            "kind": self.kind,
            "method": self.method,
            "path_template": self.path_template,
        }
        if self.param_name is not None:
            d["param_name"] = self.param_name
        if self.location is not None:
            d["location"] = self.location
        if self.semantic is not None:
            d["semantic"] = self.semantic
        return d


class PackAuthContext(BaseModel):
    """One AuthContext the LLM may pick as the attacker side, by `handle`.

    Carries the real `auth_context_id` for the resolver; `to_llm_dict()` excludes
    it. `is_attacker_candidate` marks the B side (the principal that did *not*
    reach the endpoint) for a C2 replay.

    `holds_outlier_body` is an **advisory** signal for the C2b content-differential
    case (#112): the principal already holds a response body that differs from the
    baseline group, so replaying *as* it tests nothing (it reads its own resource —
    no boundary crossed). It is a soft steer, NOT a filter — the principal stays an
    `is_attacker_candidate` and the deterministic resolver never rejects an
    outlier pick. Soft, not hard, on purpose: #110's discovered-tier exclusion is a
    *dispatchability* constraint (the AC is physically un-armable), whereas the
    outlier is a *meaningfulness* judgment, which ADR-0033 reserves for the LLM/human
    ("assembly surfaces evidence, it does not adjudicate"). A wrong hard-exclude
    would suppress a real attacker (missed vuln); a soft flag a weak model ignores
    yields only a harmless, reviewable no-op proposal. `False` for every non-C2b
    generator (C2 / boundary / tenant), which never set it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    handle: str = Field(min_length=1)
    principal_label: str
    tier: str | None = None
    claims_summary: str | None = None
    is_attacker_candidate: bool = False
    holds_outlier_body: bool = False
    auth_context_id: AuthContextId
    # ADR-0049: the credential slot — the rotation-stable half of the attacker
    # identity `(principal_label, slot)`. Resolver-side only; NEVER serialised to
    # the LLM. `None` for a discovered-tier or pre-ADR-0049 AuthContext (the
    # resolver rejects an attacker pick whose slot is None).
    slot: str | None = None
    # Optional human-readable label for the prompt (e.g. `"scope-weaker-tier"`,
    # `"tenant:42"`) when the real `principal_label` would be opaque or repetitive.
    # `to_llm_dict()` prefers it over `principal_label`; the resolver always reads
    # the real `principal_label` for `attacker_principal`.
    display_label: str | None = None

    def to_llm_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "handle": self.handle,
            "principal_label": self.display_label or self.principal_label,
            "is_attacker_candidate": self.is_attacker_candidate,
        }
        if self.tier is not None:
            d["tier"] = self.tier
        if self.claims_summary is not None:
            d["claims_summary"] = self.claims_summary
        if self.holds_outlier_body:
            d["holds_outlier_body"] = True
        return d


class PackExemplar(BaseModel):
    """A real observed request under the A side, the LLM reasons about replaying.

    Carries only safe, non-secret request shape (concrete path + observed
    non-secret param names→values). Bodies/tokens never appear (ADR-0015/0037).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    concrete_path: str
    observed_params: dict[str, str] = Field(default_factory=dict)


class ContextPack(BaseModel):
    """The typed, bounded projection a candidate hands the LLM (ADR-0037).

    Deterministically assembled (`code_version`-stamped); response bodies are out
    (hashes/metadata only); targets and auth contexts are addressed by pack-local
    handles, never raw node ids. `to_llm_payload()` is the id-free dict serialised
    into the prompt; the resolver uses the typed objects directly to resolve
    handles back to concrete ids and reject any handle the LLM invents.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    candidate_kind: Literal["C2", "C2b", "C3", "capability", "tenant", "sink"]
    candidate_reason: str
    endpoint_method: str
    endpoint_path_template: str
    targets: tuple[PackTarget, ...] = Field(min_length=1)
    auth_contexts: tuple[PackAuthContext, ...] = Field(min_length=1)
    exemplar: PackExemplar | None = None
    # C3 only: the leaked `ObservedValue`'s hash — the propose-time-known payload the
    # resolver fixes into `payload_spec = observed_value(value_hash)`. Resolver-side
    # id (never serialised into the prompt); the value's shape/preview is conveyed in
    # `candidate_reason` instead (raw secret never carried, ADR-0015).
    observed_value_hash: Sha256Hex | None = None
    code_version: str
    generated_at: datetime

    def to_llm_payload(self) -> dict[str, object]:
        """The id-free structure serialised into the user prompt."""

        payload: dict[str, object] = {
            "candidate_kind": self.candidate_kind,
            "candidate_reason": self.candidate_reason,
            "endpoint": {
                "method": self.endpoint_method,
                "path_template": self.endpoint_path_template,
            },
            "targets": [t.to_llm_dict() for t in self.targets],
            "auth_contexts": [a.to_llm_dict() for a in self.auth_contexts],
        }
        if self.exemplar is not None:
            payload["exemplar"] = {
                "concrete_path": self.exemplar.concrete_path,
                "observed_params": self.exemplar.observed_params,
            }
        return payload

    def target_handles(self) -> set[str]:
        return {t.handle for t in self.targets}

    def auth_handles(self) -> set[str]:
        return {a.handle for a in self.auth_contexts}


class LLMProposalDraft(BaseModel):
    """The LLM's structured output (ADR-0037): handles + enums, never bytes.

    Produced by a forced tool call whose schema mirrors this model, so parsing is
    deterministic. The resolver maps `target_ref` / `auth_context_ref` / `hold`
    handles to concrete ids (rejecting any handle absent from the pack) and builds
    a `PlannerProposal`. `payload_class` is fixed by the resolver
    (`auth-token-swap`, `payload_spec = none`) — not the LLM's to choose.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Either an authz class (C2/C2b) or a leak-replay class (C3); the per-candidate
    # tool schema constrains which set the model actually sees.
    test_class: C2TestClass | C3TestClass | BoundaryTestClass | SinkTestClass
    target_ref: str = Field(min_length=1)
    auth_context_ref: str = Field(min_length=1)
    hold: tuple[str, ...] = ()
    justification: str = Field(min_length=1)
    expected_outcome: str = Field(min_length=1)
    expected_yield: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Review lifecycle (ADR-0040).
# ---------------------------------------------------------------------------

ReviewStatus = Literal["proposed", "approved", "rejected"]
REVIEW_STATUSES: tuple[ReviewStatus, ...] = ("proposed", "approved", "rejected")

ReviewDecision = Literal["approve", "reject"]

# Rejection durability (ADR-0040). `defer` is the default safe choice (do not
# permanently blind yourself); `permanent` is a deliberate human "never again".
Disposition = Literal["permanent", "defer"]
DISPOSITIONS: tuple[Disposition, ...] = ("permanent", "defer")


class ReviewLedgerEvent(BaseModel):
    """One provenanced append-only review-decision event (ADR-0040).

    Keyed by `(engagement_id, key_hash)`; the full history (including
    approve-then-rescind) is the ordered ledger. Tester identity lives here, never
    in the target graph (ADR-0012). `disposition` is meaningful only for a
    `reject` (`None` for `approve`). `prior_status -> new_status` records the
    transition. `evidence_*` snapshot the target's state at decision time so the
    re-surface predicate can later detect a material change (ADR-0040).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    key_hash: TestCaseKeyHash
    actor: str = Field(min_length=1)
    timestamp: datetime
    decision: ReviewDecision
    reason: str | None = None
    disposition: Disposition | None = None
    prior_status: ReviewStatus
    new_status: ReviewStatus
    # Evidence snapshot at decision time (ADR-0040 re-surface predicate).
    evidence_confidence: float = Field(ge=0.0, le=1.0)
    evidence_derived_from_count: int = Field(ge=0, default=0)

    @model_validator(mode="after")
    def _disposition_only_on_reject(self) -> ReviewLedgerEvent:
        if self.decision == "reject" and self.disposition is None:
            raise ValueError("a reject decision requires a disposition")
        if self.decision == "approve" and self.disposition is not None:
            raise ValueError("an approve decision carries no disposition")
        return self


# ---------------------------------------------------------------------------
# Review queue (prioritiser output, ADR-0036).
# ---------------------------------------------------------------------------


class ProposedTestCaseView(BaseModel):
    """A committed `proposed` `TestCase` projected for review (ADR-0040 surface).

    The read model the prioritiser orders and the CLI renders: the node's identity
    and target, the justification / gap / expected-outcome the reviewer needs, plus
    `priority_score` (the deterministic ordering key) and the re-surface flag for a
    previously-`defer`-rejected test whose evidence materially changed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    key_hash: TestCaseKeyHash
    test_class: TestClass
    generator: GeneratorId
    source: str
    target_endpoint_id: str | None = None
    target_parameter_id: ParameterId | None = None
    target_trust_boundary_id: TrustBoundaryId | None = None
    method: str | None = None
    host: str | None = None
    path_template: str | None = None
    payload_class: PayloadClass
    expected_yield: float
    confidence: float
    effective_target_confidence: float
    criticality: float
    justification: str
    expected_outcome: str
    priority_score: float
    # Replay-fidelity annotation (ADR-0041): the detected replay-breaker roles on the
    # committed node. Surfaced so the reviewer sees a naive replay would
    # false-negative; set by code, never by the LLM, and not part of `key_hash`.
    replay_hazards: tuple[str, ...] = ()
    review_status: ReviewStatus = "proposed"
    # Re-surface annotation for a previously-`defer`-rejected test (ADR-0040).
    resurfaced: bool = False
    resurfaced_reason: str | None = None
