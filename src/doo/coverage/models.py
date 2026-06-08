"""Coverage result models (ADR-0034 — per-query typed models over a base).

The coverage analyzer is a *pull / ephemeral* shared library (ADR-0034): every
query function returns typed Pydantic results, and both the `doo coverage` CLI
and the slice-3 planner consume the same models. There is deliberately no
generic `CoverageGap` envelope — the four slice-2 queries return structurally
different shapes (C1 yields Endpoints, C2/C2b carry per-principal evidence
tuples, C3 yields pivots), so a shared envelope would be lossy.

`CoverageResult` is the small shared base every per-query model extends:
`engagement_id`, the `query_id` discriminator, and the `generated_at` stamp of
the query run (event time of the *analysis*, not of the underlying facts). Each
row also carries the **effective (decayed) confidence** computed at query time
per ADR-0005 — confidence is never re-written in storage, only decayed by
consumers on read.

Pydantic v2, strict-ish (`extra="forbid"`) so a stray field is a loud error and
the `--json` form round-trips exactly.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from doo.ids import EngagementId


class CoverageResult(BaseModel):
    """Base for every coverage-query result row (ADR-0034).

    `query_id` is the stable query discriminator (`"C1"`, `"C2"`, …) so a
    heterogeneous `--json` stream stays self-describing. `generated_at` is the
    wall-clock time the analysis ran — the settle-point read, not the age of the
    facts (those drive the decayed `effective_confidence` on each row).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    query_id: str
    generated_at: datetime


class PrincipalEvidence(BaseModel):
    """Per-principal response evidence on a C2 row (ADR-0033).

    Coverage *surfaces evidence, it does not adjudicate* the soft-200 case, so a
    C2 row carries the concrete observation that backs (or fails to back) each
    side rather than a bare boolean. The **A** side always has a real 2xx
    (`status` 200..299, `reached`); the **B** side is `None` when B never reached
    the endpoint (either never tried or was blocked — both bypass candidates).

    `response_body_sha256` is null until the body-metadata promotion has data and
    for empty-body responses; consumers tolerate null.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str
    label: str
    status: int
    response_size_bytes: int | None = None
    response_body_sha256: str | None = None


class C2Result(CoverageResult):
    """One endpoint reached as principal A but not as principal B (ADR-0033).

    The presence-differential authz signal: A got a 2xx, B did not (B never
    tried, or B was blocked with 401/403/404/5xx). Both are IDOR / privilege-
    escalation candidates, so the boundary is surfaced rather than suppressed.

    The row names the ordered pair by `(principal_a_label, principal_b_label)`
    and the endpoint's `(method, host, path_template)` identity, and carries A's
    real success evidence plus B's evidence-or-null per ADR-0033. `reached` is
    deliberately asymmetric from C1's any-`HIT` "hit".
    """

    query_id: str = Field(default="C2", frozen=True)

    endpoint_id: str
    method: str
    host: str
    path_template: str
    principal_a_label: str
    principal_b_label: str
    evidence_a: PrincipalEvidence
    evidence_b: PrincipalEvidence | None = None
    effective_confidence: float


class C2bResult(CoverageResult):
    """One endpoint reached (2xx) by ≥2 principals whose responses DIFFER (ADR-0033).

    The content-differential sibling of C2's presence query. C2 is blind to
    *role-differentiated 200s* — apps where every principal gets a 200 but the
    body is rendered per role/account (both principals "reached", so C2 finds no
    gap). C2b surfaces exactly those: the endpoint was reached by two or more
    active principals, but their per-principal `response_body_sha256` OR
    `response_size_bytes` differ. That divergence is the deterministic black-box
    handle on where BOLA/IDOR lives.

    The comparison is **pure metadata** (ADR-0033) — no body is parsed or fetched.
    Endpoints reached by ≥2 principals with IDENTICAL body hash AND size are not a
    divergence and do not appear. The row names the endpoint's
    `(method, host, path_template)` identity and carries the full per-principal
    evidence list `(principal, status, response_size_bytes, response_body_sha256)`
    so the differential is visible; coverage surfaces it, it does not adjudicate
    whether the difference is a vulnerability (the human's / slice-3 call).
    """

    query_id: str = Field(default="C2b", frozen=True)

    endpoint_id: str
    method: str
    host: str
    path_template: str
    evidence: tuple[PrincipalEvidence, ...]
    effective_confidence: float


class C3Result(CoverageResult):
    """One leak-to-input pivot: a value leaked in a response AND sent as input (issue #53).

    An `ObservedValue` that is BOTH `YIELDED_VALUE` from some observation (it
    appeared in a *response*, the output side) AND `SENT_VALUE` from some
    observation (it was sent as a request *parameter*, the input side). The
    actionable "what to test next" lead: a concrete value the app handed out and
    that some endpoint consumes as a parameter.

    The **target** (input) endpoint must pass `is_in_scope`; the **source**
    (output) endpoint need not (ADR-0020 — a value leaked from an out-of-scope SSO
    host is still a valid lead). Cross-endpoint by default (source ≠ target);
    same-endpoint reuse is opt-in.

    `value_preview` is the human-readable handle. For secret-shaped kinds
    (`kind ∈ {secret, token, opaque_token}`, ADR-0015) it is the stored 8-char
    preview (or None for short secrets) — the raw secret is NEVER carried. For
    non-secret kinds it is the (safe) raw value, which the upstream extractor keeps
    on the node. `value_hash` is always present (the `ObservedValue` identity).
    `source_endpoints` lists every distinct output
    endpoint that yielded the value (identity-tuple strings `method host path`);
    the row names exactly one `(target_*, parameter_name)` input.

    `shape_rank` is the value-shape specificity bucket (lower sorts first):
    UUID/email/JWT-shaped > opaque_token > bare integer (issue #53 ranking). Rows
    sort by `(shape_rank, -effective_confidence, …)`.
    """

    query_id: str = Field(default="C3", frozen=True)

    value_hash: str
    kind: str
    value_preview: str | None = None
    source_endpoints: tuple[str, ...]
    target_endpoint_id: str
    target_method: str
    target_host: str
    target_path_template: str
    parameter_name: str | None = None
    same_endpoint: bool = False
    shape_rank: int
    effective_confidence: float


class C1Result(CoverageResult):
    """One in-scope `Endpoint` with no `HIT` edge of any kind (a dead endpoint).

    "Dead" per ADR-0033 is asymmetric from C2's "reached": C1 counts *any* `HIT`
    edge regardless of `response_status` or `source`, so a 401-touched endpoint
    is *not* dead. Each row names the endpoint's `(method, host, path_template)`
    identity tuple plus its `endpoint_id`, and carries the effective (decayed)
    confidence of the underlying inference.
    """

    query_id: str = Field(default="C1", frozen=True)

    endpoint_id: str
    method: str
    host: str
    path_template: str
    effective_confidence: float
