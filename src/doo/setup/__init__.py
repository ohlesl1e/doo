"""Engagement setup (the only declarative seam).

Per ADR-0012 the loader is the only code that lays down tester-side facts:
`Engagement` + `Scope` + declared `Principal`s (in T4). Slice 1 / T1 covers
Engagement + Scope only — no `principals:` block.

Per ADR-0019 the loader is idempotent: re-running `doo engagement start`
against the same YAML and same engagement_id is a no-op when nothing changed,
and prints a unified diff + asks for confirmation when material changes are
detected.
"""

from doo.setup.config import (
    EngagementConfig,
    EngagementMeta,
    KillSwitchConfig,
    RateLimit,
    ScopeRules,
    TimeWindow,
    compute_scope_content_hash,
)
from doo.setup.loader import (
    EngagementLoadResult,
    EngagementMismatchError,
    EngagementSetupError,
    ScopeChangeRequiresConfirmation,
    load_engagement,
)

__all__ = [
    "EngagementConfig",
    "EngagementLoadResult",
    "EngagementMeta",
    "EngagementMismatchError",
    "EngagementSetupError",
    "KillSwitchConfig",
    "RateLimit",
    "ScopeChangeRequiresConfirmation",
    "ScopeRules",
    "TimeWindow",
    "compute_scope_content_hash",
    "load_engagement",
]
