"""Reactive token-refresh events (ADR-0014): the Executor → auth-helper signal.

When the ADR-0044 liveness probe shows an attacker token is **dead** (an authz
`primary` 4xx + probe 4xx), the Executor emits a reactive-refresh event onto a
Redis stream. The auth-helper sibling process (S6, ADR-0014) consumes it and
rotates the declared material out-of-band; the agent process itself only ever
*reads* refreshed material (the same trust split as the kill-switch lease).

This module owns only the **emit** side and the stream-name shape. The consumer
is S6. The emitter is a Protocol so the run driver injects a real
`StreamReactiveEmitter` in production and a `FakeReactiveEmitter` in tests
(asserting the event fired exactly when the classifier said `auth_invalid`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from doo.ids import AuthContextId, DispatchRunId, EngagementId, TestCaseKeyHash
from doo.infra.streams import StreamClient
from doo.observability.logging import get_logger

log = get_logger(__name__)

# The stream the auth-helper (S6) consumes. One per deployment; the payload
# carries the engagement id so a shared helper can fan out.
AUTH_REACTIVE_STREAM = "auth-reactive"

# Event kind on the stream (room for proactive/expiry kinds the helper also
# emits in S6).
REACTIVE_AUTH_INVALID = "auth_invalid"


class ReactiveEmitter(Protocol):
    """Emit a reactive token-refresh signal (ADR-0014)."""

    def emit_auth_invalid(
        self,
        *,
        engagement_id: EngagementId,
        run_id: DispatchRunId,
        auth_context_id: AuthContextId,
        principal_label: str,
        key_hash: TestCaseKeyHash,
    ) -> str | None: ...


def _payload(
    *,
    engagement_id: EngagementId,
    run_id: DispatchRunId,
    auth_context_id: AuthContextId,
    principal_label: str,
    key_hash: TestCaseKeyHash,
    at: datetime,
) -> dict[str, str]:
    return {
        "kind": REACTIVE_AUTH_INVALID,
        "engagement_id": str(engagement_id),
        "run_id": str(run_id),
        "auth_context_id": str(auth_context_id),
        "principal_label": principal_label,
        "key_hash": str(key_hash),
        "detected_at": at.isoformat(),
    }


@dataclass(frozen=True, slots=True)
class StreamReactiveEmitter:
    """`ReactiveEmitter` backed by the shared Redis `StreamClient` (XADD)."""

    streams: StreamClient
    stream: str = AUTH_REACTIVE_STREAM

    def emit_auth_invalid(
        self,
        *,
        engagement_id: EngagementId,
        run_id: DispatchRunId,
        auth_context_id: AuthContextId,
        principal_label: str,
        key_hash: TestCaseKeyHash,
    ) -> str | None:
        msg_id = self.streams.publish(
            self.stream,
            _payload(
                engagement_id=engagement_id,
                run_id=run_id,
                auth_context_id=auth_context_id,
                principal_label=principal_label,
                key_hash=key_hash,
                at=datetime.now(UTC),
            ),
        )
        log.info(
            "dispatch.reactive.auth_invalid",
            engagement_id=engagement_id,
            run_id=run_id,
            auth_context_id=auth_context_id,
            principal_label=principal_label,
            stream=self.stream,
            message_id=msg_id,
        )
        return msg_id


@dataclass
class FakeReactiveEmitter:
    """Records emitted events instead of touching Redis (tests / no-redis runs)."""

    events: list[dict[str, str]] = field(default_factory=list)

    def emit_auth_invalid(
        self,
        *,
        engagement_id: EngagementId,
        run_id: DispatchRunId,
        auth_context_id: AuthContextId,
        principal_label: str,
        key_hash: TestCaseKeyHash,
    ) -> str | None:
        self.events.append(
            _payload(
                engagement_id=engagement_id,
                run_id=run_id,
                auth_context_id=auth_context_id,
                principal_label=principal_label,
                key_hash=key_hash,
                at=datetime.now(UTC),
            )
        )
        return f"fake-{len(self.events)}"


__all__ = [
    "AUTH_REACTIVE_STREAM",
    "REACTIVE_AUTH_INVALID",
    "ReactiveEmitter",
    "StreamReactiveEmitter",
    "FakeReactiveEmitter",
]
