"""The deterministic review-queue prioritiser (ADR-0036).

Gap-driven breadth can yield hundreds of candidates and the human approves all of
them, so review is the throughput wall. The defence is **deterministic**
prioritisation, always on: order the queue by

    priority_score = expected_yield  ×  criticality  ×  effective_target_confidence

i.e. `expected_yield × gap/boundary criticality × decay`, **discounted by the
target inference's effective (decayed) confidence** so a test against a shaky
inferred target does not outrank one against a solid target (ADR-0036). The decay
is already folded into `effective_target_confidence` (ADR-0005). Shown top-N per
session. Ordering is stable and deterministic (ties broken by a fixed key) so the
same graph state yields the same queue order.
"""

from __future__ import annotations

from doo.planner.models import ProposedTestCaseView


def priority_score(
    *, expected_yield: float, criticality: float, effective_target_confidence: float
) -> float:
    """`expected_yield × criticality × effective_target_confidence` (ADR-0036)."""

    return expected_yield * criticality * effective_target_confidence


def prioritize(
    views: list[ProposedTestCaseView], *, top_n: int | None = None
) -> list[ProposedTestCaseView]:
    """Order `views` by descending `priority_score`, truncate to `top_n` (ADR-0036).

    Stable, deterministic order: primary key is `-priority_score`; ties break by a
    fixed lexical key `(test_class, host, path_template, method, key_hash)` so the
    same set always sorts identically. `top_n=None` returns the full ordered queue;
    a positive `top_n` truncates to the highest-priority N (the per-session view).
    """

    ordered = sorted(
        views,
        key=lambda v: (
            -v.priority_score,
            v.test_class,
            v.host or "",
            v.path_template or "",
            v.method or "",
            v.key_hash,
        ),
    )
    if top_n is not None and top_n >= 0:
        return ordered[:top_n]
    return ordered
