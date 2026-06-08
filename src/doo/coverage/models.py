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
