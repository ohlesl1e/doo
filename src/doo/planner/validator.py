"""The deterministic Validator — the planner's correctness core (ADRs 0037/0038/0040).

Every `PlannerProposal` (deterministic or LLM) passes through here before anything
commits. No LLM (CLAUDE.md hard rule): the Validator is pure deterministic code
that turns a proposal into either a `ValidatedTestCase` (ready to commit) or a
**discard** (logged in the planner-run audit, never committed — ADR-0040).

Checks, in order:

1. **Target resolution** — the proposal's target handle must resolve to exactly one
   active graph node (an `Endpoint` for C1). An unresolvable / hallucinated handle
   is discarded (ADR-0037 "kills hallucinated targets").
2. **Three-way XOR** — exactly one of the three targets is set (ADR-0007). A
   malformed proposal is discarded, never committed.
3. **Scope** — the resolved target must pass the shared `is_in_scope` helper
   (ADR-0038: the planner is a query-time consumer, like coverage — **not** OPA).
4. **Payload resolution** — `payload_spec` is resolved to concrete bytes and a
   `payload_hash` (ADR-0037). Slice 3 ships the `none` resolver (sentinel
   `sha256("")`); `observed_value` / `configured` land with their generators.
5. **Identity** — the ADR-0007 `key_hash` is computed from the resolved content.

Content-address **dedup** (a no-op re-commit) is a property of the commit MERGE
(ADR-0007), not a pre-pass — the validator simply produces the same `key_hash` for
the same content, and the commit converges. The **re-surface predicate** (ADR-0040)
is the read here that decides whether a previously-`defer`-rejected test should be
shown again.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from doo.coverage.queries import _EndpointView, _HostView, _load_scope_rules
from doo.events.execution import compute_testcase_key_hash
from doo.ids import EngagementId, Sha256Hex
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.commit import ValidatedTestCase, source_for
from doo.planner.models import PayloadSpec, PlannerProposal
from doo.policy.scope import is_in_scope

log = get_logger(__name__)

# The empty-payload sentinel (ADR-0007): a no-payload test hashes the empty string
# rather than carrying a SQL null.
_EMPTY_PAYLOAD_HASH = Sha256Hex(hashlib.sha256(b"").hexdigest())


@dataclass(frozen=True, slots=True)
class DiscardedProposal:
    """A proposal the Validator rejected — logged, never committed (ADR-0040).

    `reason` is the audit string; `code` is a stable discriminator for tests /
    metrics (`unresolvable_target`, `target_xor`, `out_of_scope`,
    `payload_unresolvable`).
    """

    code: str
    reason: str
    proposal: PlannerProposal


@dataclass(frozen=True, slots=True)
class _EndpointResolution:
    endpoint_id: str
    view: _EndpointView


def _resolve_endpoint(
    client: Neo4jClient, engagement_id: EngagementId, endpoint_id: str
) -> _EndpointResolution | None:
    """Resolve an `endpoint_id` handle to its active node + host (scope input).

    Returns None when the handle names no active in-engagement `Endpoint` — a
    hallucinated or stale target the Validator discards (ADR-0037).
    """

    frag = for_engagement(engagement_id, var="e")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint {{id: $endpoint_id}})-[:ON_HOST]->(h:Host)
        {frag.and_("e.status = 'active'")}
        RETURN e.method AS method,
               e.path_template AS path_template,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal
        """,
        endpoint_id=endpoint_id,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    view = _EndpointView(
        method=str(row["method"]),
        host=_HostView(
            scheme=row["scheme"],
            canonical_hostname=str(row["canonical_hostname"]),
            port=row["port"],
            is_ip_literal=bool(row["is_ip_literal"]),
        ),
        path_template=str(row["path_template"]),
    )
    return _EndpointResolution(endpoint_id=endpoint_id, view=view)


def _resolve_parameter(
    client: Neo4jClient, engagement_id: EngagementId, parameter_id: str
) -> _EndpointResolution | None:
    """Resolve a `parameter_id` target to its owning Endpoint + host (scope input).

    A C3 leak-replay targets a `Parameter` (the input the leaked value is sent to);
    scope is enforced on that Parameter's **owning Endpoint** (the input endpoint,
    ADR-0020). Returns None when the handle names no active in-engagement
    `Parameter` (hallucinated / stale). The returned `_EndpointResolution` carries
    the owning endpoint's view so the same `is_in_scope` check applies.
    """

    frag = for_engagement(engagement_id, var="p")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter {{id: $parameter_id}}),
              (e)-[:ON_HOST]->(h:Host)
        {frag.and_("p.status = 'active' AND e.status = 'active'")}
        RETURN e.id AS endpoint_id,
               e.method AS method,
               e.path_template AS path_template,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal
        """,
        parameter_id=parameter_id,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    view = _EndpointView(
        method=str(row["method"]),
        host=_HostView(
            scheme=row["scheme"],
            canonical_hostname=str(row["canonical_hostname"]),
            port=row["port"],
            is_ip_literal=bool(row["is_ip_literal"]),
        ),
        path_template=str(row["path_template"]),
    )
    return _EndpointResolution(endpoint_id=str(row["endpoint_id"]), view=view)


def _resolve_boundary(
    client: Neo4jClient, engagement_id: EngagementId, trust_boundary_id: str
) -> _EndpointResolution | None:
    """Resolve a `TrustBoundary` target to the endpoint of its `DERIVED_FROM` evidence.

    A boundary test is an authz replay of the boundary's evidence (ADR-0039): the
    concrete endpoint is read from a `DERIVED_FROM` observation's `HIT` endpoint —
    the boundary itself carries NO endpoint edge (the ADR-0007 XOR is preserved by
    `TARGETS_BOUNDARY`). Scope is enforced on that evidence endpoint. Returns None
    when the boundary, or an active evidence endpoint, does not resolve.
    """

    frag = for_engagement(engagement_id, var="tb")
    rows = client.execute_read(
        f"""
        MATCH (tb:TrustBoundary {{id: $tbid}})-[:DERIVED_FROM]->
              (r:RequestObservation)-[:HIT]->(e:Endpoint)-[:ON_HOST]->(h:Host)
        {frag.and_("(tb.status IS NULL OR tb.status = 'active') AND e.status = 'active'")}
        RETURN e.id AS endpoint_id,
               e.method AS method,
               e.path_template AS path_template,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal
        ORDER BY e.id
        LIMIT 1
        """,
        tbid=str(trust_boundary_id),
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    view = _EndpointView(
        method=str(row["method"]),
        host=_HostView(
            scheme=row["scheme"],
            canonical_hostname=str(row["canonical_hostname"]),
            port=row["port"],
            is_ip_literal=bool(row["is_ip_literal"]),
        ),
        path_template=str(row["path_template"]),
    )
    return _EndpointResolution(endpoint_id=str(row["endpoint_id"]), view=view)


def _resolve_payload_hash(
    client: Neo4jClient, engagement_id: EngagementId, spec: PayloadSpec
) -> Sha256Hex | None:
    """Resolve a `payload_spec` to a concrete `payload_hash` (ADR-0037).

    Two slice-3 resolvers ship:
    - `none` — empty sentinel `sha256("")` (authz replays / forced browsing).
    - `observed_value` — the C3 leak-replay payload: verify an active
      `ObservedValue` with this `value_hash` exists in the engagement, and use its
      `value_hash` directly as the `payload_hash`. The `ObservedValue` identity IS
      `sha256(value)` (`canonical/values.py`), so this is exactly the ADR-0007
      payload hash — and for secret-shaped kinds it resolves by hash alone, never
      reading the raw secret (ADR-0015).

    The `configured` resolver (sink_params) lands with its generator; until then it
    returns None and the validator discards the proposal as unresolvable rather than
    committing a placeholder hash (ADR-0007).
    """

    if spec.kind == "none":
        return _EMPTY_PAYLOAD_HASH
    if spec.kind == "observed_value":
        if spec.value_hash is None:
            return None  # guarded by the PayloadSpec model_validator, defensive here.
        frag = for_engagement(engagement_id, var="v")
        rows = client.execute_read(
            f"""
            MATCH (v:ObservedValue {{value_hash: $value_hash}})
            {frag.and_("v.status = 'active'")}
            RETURN v.value_hash AS value_hash
            """,
            value_hash=str(spec.value_hash),
            **frag.parameters,
        )
        if not rows:
            return None
        return Sha256Hex(str(rows[0]["value_hash"]))
    if spec.kind == "configured":
        if spec.config_key is None:
            return None  # guarded by the PayloadSpec model_validator, defensive here.
        # The `sink_params` payload is a SINGLE canonical probe known at propose time
        # (ADR-0037) — the tester-configured callback/marker for this key. Slice 3
        # dispatches nothing, so the resolver returns a deterministic content address
        # for the probe (stable per key); the slice-4 dispatcher substitutes the real
        # configured callback (ADR-0012) at execution under its OPA check (ADR-0038).
        canonical = f"configured-probe:{spec.config_key}"
        return Sha256Hex(hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    return None


def validate(
    client: Neo4jClient,
    proposal: PlannerProposal,
) -> ValidatedTestCase | DiscardedProposal:
    """Validate one proposal: produce a `ValidatedTestCase` or a `DiscardedProposal`.

    Deterministic and side-effecting only via reads. The order is target
    resolution -> XOR -> scope -> payload -> identity (see module docstring). The
    first failed check short-circuits to a discard with a stable `code` and an
    audit `reason`; a discard is never committed (ADR-0040).
    """

    eid = proposal.engagement_id

    # --- (2) three-way XOR (ADR-0007). A malformed proposal is discarded. ---
    targets = [
        proposal.target_endpoint_id is not None,
        proposal.target_parameter_id is not None,
        proposal.target_trust_boundary_id is not None,
    ]
    if sum(targets) != 1:
        return _discard(
            "target_xor",
            "proposal target is not exactly one of endpoint/parameter/boundary "
            "(ADR-0007 three-way XOR)",
            proposal,
        )

    # --- (1) target resolution + (3) scope. Endpoint (C1/C2/C2b) or Parameter
    # (C3 leak-replay); scope is enforced on the (owning) endpoint either way. ---
    if proposal.target_endpoint_id is not None:
        resolution = _resolve_endpoint(client, eid, proposal.target_endpoint_id)
        if resolution is None:
            return _discard(
                "unresolvable_target",
                f"target_endpoint_id {proposal.target_endpoint_id!r} resolves to no "
                "active in-engagement Endpoint (hallucinated or stale handle)",
                proposal,
            )
    elif proposal.target_parameter_id is not None:
        resolution = _resolve_parameter(client, eid, proposal.target_parameter_id)
        if resolution is None:
            return _discard(
                "unresolvable_target",
                f"target_parameter_id {proposal.target_parameter_id!r} resolves to no "
                "active in-engagement Parameter (hallucinated or stale handle)",
                proposal,
            )
    elif proposal.target_trust_boundary_id is not None:
        resolution = _resolve_boundary(client, eid, proposal.target_trust_boundary_id)
        if resolution is None:
            return _discard(
                "unresolvable_target",
                f"target_trust_boundary_id {proposal.target_trust_boundary_id!r} "
                "resolves to no active boundary with a DERIVED_FROM evidence endpoint",
                proposal,
            )
    else:  # pragma: no cover - the XOR check above guarantees one branch.
        return _discard("target_xor", "no target set after XOR check", proposal)

    scope = _load_scope_rules(client, eid)
    if not is_in_scope(resolution.view, scope):
        return _discard(
            "out_of_scope",
            f"target endpoint {resolution.view.method} "
            f"{resolution.view.host.canonical_hostname}"
            f"{resolution.view.path_template} is out of scope (is_in_scope, "
            "ADR-0038)",
            proposal,
        )

    # --- (4) payload resolution (ADR-0037). ---
    payload_hash = _resolve_payload_hash(client, eid, proposal.payload_spec)
    if payload_hash is None:
        return _discard(
            "payload_unresolvable",
            f"payload_spec kind {proposal.payload_spec.kind!r} has no resolver in "
            "the S1 planner spine",
            proposal,
        )

    # --- (5) identity (ADR-0007 + ADR-0049). ---
    key_hash = compute_testcase_key_hash(
        engagement_id=eid,
        test_class=proposal.test_class,
        target_endpoint_id=proposal.target_endpoint_id,
        target_parameter_id=proposal.target_parameter_id,
        target_trust_boundary_id=proposal.target_trust_boundary_id,
        payload_class=proposal.payload_class,
        payload_hash=payload_hash,
        attacker_principal=proposal.attacker_principal,
        attacker_slot=proposal.attacker_slot,
    )
    return ValidatedTestCase(
        engagement_id=eid,
        key_hash=key_hash,
        test_class=proposal.test_class,
        target_endpoint_id=proposal.target_endpoint_id,
        target_parameter_id=proposal.target_parameter_id,
        target_trust_boundary_id=proposal.target_trust_boundary_id,
        payload_class=proposal.payload_class,
        payload_hash=payload_hash,
        auth_context_id=proposal.auth_context_id,
        attacker_principal=proposal.attacker_principal,
        attacker_slot=proposal.attacker_slot,
        source=source_for(proposal.generator, proposal.mode),
        generator=proposal.generator,
        expected_yield=proposal.expected_yield,
        expected_yield_method=proposal.confidence_method,
        justification=proposal.justification,
        expected_outcome=proposal.expected_outcome,
        # Authz-replay execution intent + replay-fidelity annotation (ADR-0041):
        # code-set on the proposal, carried through verbatim. NOT identity inputs
        # (absent from `key_hash` above).
        hold=proposal.hold,
        replay_hazards=proposal.replay_hazards,
        hazard_source_hints=proposal.hazard_source_hints,
        llm_audit_key=proposal.llm_audit_key,
    )


def _discard(code: str, reason: str, proposal: PlannerProposal) -> DiscardedProposal:
    """Build + log a discard (ADR-0040: discarded proposals live only in the audit)."""

    log.warning(
        "planner.validator.discarded",
        engagement_id=proposal.engagement_id,
        generator=proposal.generator,
        code=code,
        reason=reason,
        test_class=proposal.test_class,
        target_endpoint_id=proposal.target_endpoint_id,
    )
    return DiscardedProposal(code=code, reason=reason, proposal=proposal)


# ---------------------------------------------------------------------------
# Re-surface predicate (ADR-0040). A read over the ledger + current graph; no
# graph mutation. Lives here because it is the validator-family decision "should
# this previously-rejected content be shown again?".
# ---------------------------------------------------------------------------

# Effective confidence must rise by at least this absolute amount above the
# rejection snapshot to count as a *material* increase (ADR-0040). Tunable; kept
# conservative so noise-level decay/refresh wobble does not re-surface a reject.
_MATERIAL_CONFIDENCE_DELTA = 0.05


@dataclass(frozen=True, slots=True)
class ResurfaceVerdict:
    """Whether a previously-rejected `TestCase` should be re-surfaced (ADR-0040)."""

    resurface: bool
    reason: str | None = None


def should_resurface(
    *,
    disposition: str,
    snapshot_confidence: float,
    snapshot_derived_from_count: int,
    current_confidence: float,
    current_derived_from_count: int,
) -> ResurfaceVerdict:
    """The ADR-0040 re-surface predicate (a predicate, not a presence check).

    `permanent` rejections stay suppressed forever. A `defer` rejection re-surfaces
    only if effective confidence has risen materially above the snapshot *or* new
    `DERIVED_FROM` evidence has appeared since the rejection — flagged with what
    changed so the human sees the delta, not a blind re-ask.
    """

    if disposition == "permanent":
        return ResurfaceVerdict(resurface=False)

    confidence_up = (
        current_confidence - snapshot_confidence
    ) >= _MATERIAL_CONFIDENCE_DELTA
    new_evidence = current_derived_from_count > snapshot_derived_from_count

    if confidence_up and new_evidence:
        return ResurfaceVerdict(
            resurface=True,
            reason=(
                f"effective confidence rose {snapshot_confidence:.3f}->"
                f"{current_confidence:.3f} and new DERIVED_FROM evidence appeared "
                f"({snapshot_derived_from_count}->{current_derived_from_count})"
            ),
        )
    if confidence_up:
        return ResurfaceVerdict(
            resurface=True,
            reason=(
                f"effective confidence rose materially {snapshot_confidence:.3f}->"
                f"{current_confidence:.3f} since rejection"
            ),
        )
    if new_evidence:
        return ResurfaceVerdict(
            resurface=True,
            reason=(
                f"new DERIVED_FROM evidence appeared "
                f"({snapshot_derived_from_count}->{current_derived_from_count}) "
                "since rejection"
            ),
        )
    return ResurfaceVerdict(resurface=False)
