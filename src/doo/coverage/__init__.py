"""Coverage analyzer (slice 2) — the shared, pull/ephemeral query library.

ADR-0034: a library of deterministic read-only queries over the engagement
graph, consumed by the `doo coverage` CLI now and the slice-3 planner later.
Writes nothing back — gaps are derived at query time (ADR-0020/0005 discipline).
ADR-0033 fixes the C-query success semantics.

Public surface:

- `run_c1` — C1 dead-endpoint query.
- `run_c2` — C2 presence-differential authz-coverage query (ADR-0033).
- `reached` / `reached_map` — the shared 2xx `reached` predicate (ADR-0033).
- `CoverageResult` / `C1Result` / `C2Result` — the result-model base and the
  per-query typed models (C2 carries per-principal evidence).
- `effective_confidence` — the shared query-time decay (ADR-0005).
- `coverage_app` — the Typer sub-app mounted at `doo coverage`.
"""

from __future__ import annotations

from doo.coverage.cli import coverage_app
from doo.coverage.decay import effective_confidence
from doo.coverage.models import C1Result, C2Result, CoverageResult, PrincipalEvidence
from doo.coverage.queries import run_c1, run_c2
from doo.coverage.reached import reached, reached_map

__all__ = [
    "C1Result",
    "C2Result",
    "CoverageResult",
    "PrincipalEvidence",
    "coverage_app",
    "effective_confidence",
    "reached",
    "reached_map",
    "run_c1",
    "run_c2",
]
