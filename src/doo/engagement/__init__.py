"""Engagement-lifecycle pieces that don't fit L1/L2/L3 cleanly (T7).

Slice 1 ships the kill-switch keepalive process (ADR-0014 sibling-process trust
split). The keepalive is started explicitly by the tester after engagement
setup — never auto-spawned by the loader (ARCHITECTURE.md L5).
"""

from doo.engagement.keepalive import (
    KeepaliveConfig,
    LeaseConfigReader,
    run_keepalive,
)

__all__ = [
    "KeepaliveConfig",
    "LeaseConfigReader",
    "run_keepalive",
]
