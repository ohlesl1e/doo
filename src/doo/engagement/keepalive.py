"""Kill-switch keepalive process (ADR-0014, ARCHITECTURE.md L5).

A thin, sibling process the tester starts *explicitly* after engagement setup
(`doo engagement keepalive <engagement_id>`). It is the only party allowed to
refresh the kill-switch lease; the agent process has read-only access (the
trust split that keeps kill authority outside the agent — ADR-0014).

Behaviour:

- Reads `Engagement.kill_switch_config` from the graph (TTL + refresh interval);
  defaults to ADR-0014's 60s TTL / 30s refresh when the YAML omitted them
  (the loader already applies those defaults, so a well-formed Engagement node
  always carries concrete values; the defaults here are belt-and-braces).
- Writes `engagement:{id}:lease = "active"` with the TTL immediately on start.
- Refreshes the lease every `refresh_interval_seconds`.
- On **SIGTERM**: releases the lease (`DEL`) and exits cleanly with code 0.
- On **SIGKILL** / process death: nothing runs; the lease expires naturally
  within the TTL (no refresh arrives). This is the fail-safe — the agent cannot
  keep itself alive past a hard kill.

Deliberately no business logic beyond the loop. No graph writes (the keepalive
only reads the Engagement config; the lease lives in Redis). No LLM. Pure
deterministic control.
"""

from __future__ import annotations

import signal
import threading
from dataclasses import dataclass
from types import FrameType
from typing import Protocol

from doo.ids import EngagementId
from doo.infra.redis_lease import RedisLease
from doo.observability.logging import get_logger
from doo.setup.config import KillSwitchConfig

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class KeepaliveConfig:
    """Resolved keepalive parameters for one engagement."""

    engagement_id: EngagementId
    lease_ttl_seconds: int
    refresh_interval_seconds: int

    @classmethod
    def from_kill_switch(
        cls, engagement_id: EngagementId, kill_switch: KillSwitchConfig
    ) -> KeepaliveConfig:
        return cls(
            engagement_id=engagement_id,
            lease_ttl_seconds=kill_switch.lease_ttl_seconds,
            refresh_interval_seconds=kill_switch.refresh_interval_seconds,
        )


class LeaseConfigReader(Protocol):
    """Reads an Engagement's kill-switch lease config from the graph.

    A real Neo4j-backed implementation reads the `kill_switch` property the
    loader wrote onto the `Engagement` node (ADR-0019). Tests inject a fake.
    Returns `None` when the engagement does not exist — the keepalive must not
    start for an unknown engagement (it would write a lease the dispatcher would
    then trust).
    """

    def read_kill_switch_config(
        self, engagement_id: EngagementId
    ) -> KillSwitchConfig | None: ...


class EngagementNotFoundError(Exception):
    """The engagement has no node in the graph; refuse to start the keepalive."""


def resolve_keepalive_config(
    engagement_id: EngagementId, reader: LeaseConfigReader
) -> KeepaliveConfig:
    """Read TTL + refresh interval from the graph, applying ADR-0014 defaults.

    The loader (T1) already persisted concrete values (defaulting 60/30 when the
    YAML omitted `kill_switch`), so in practice `read_kill_switch_config` returns
    a fully-populated `KillSwitchConfig`. If it returns `None` the engagement is
    unknown and we refuse to mint a lease.
    """

    ks = reader.read_kill_switch_config(engagement_id)
    if ks is None:
        raise EngagementNotFoundError(
            f"engagement {engagement_id!r} not found in graph; refusing to start "
            "keepalive (would write a lease the dispatcher then trusts)."
        )
    return KeepaliveConfig.from_kill_switch(engagement_id, ks)


def run_keepalive(
    config: KeepaliveConfig,
    lease: RedisLease,
    *,
    stop_event: threading.Event | None = None,
    install_signal_handlers: bool = True,
) -> int:
    """Run the keepalive loop until SIGTERM (or `stop_event`); return exit code.

    Writes the lease immediately, then refreshes every
    `refresh_interval_seconds`. SIGTERM sets the stop event; on loop exit the
    lease is released (`DEL`) and 0 is returned. The caller (`cli.py`) maps the
    return value to the process exit code.

    `stop_event` is injectable so integration tests can drive shutdown without a
    real signal; `install_signal_handlers=False` lets tests run the loop on a
    non-main thread (where `signal.signal` is illegal).
    """

    stop = stop_event if stop_event is not None else threading.Event()

    if install_signal_handlers:

        def _handle_sigterm(signum: int, _frame: FrameType | None) -> None:
            log.info(
                "keepalive.sigterm",
                engagement_id=config.engagement_id,
                signal=signum,
                action="release_lease_and_exit",
            )
            stop.set()

        # SIGTERM is the tester's clean-kill signal (ARCHITECTURE.md L5).
        signal.signal(signal.SIGTERM, _handle_sigterm)
        # SIGINT (Ctrl-C) gets the same clean release for interactive use.
        signal.signal(signal.SIGINT, _handle_sigterm)

    # Immediate first write so the lease is present the moment the dispatcher
    # might look.
    lease.set_active(config.lease_ttl_seconds)
    log.info(
        "keepalive.started",
        engagement_id=config.engagement_id,
        lease_key=lease.key,
        lease_ttl_seconds=config.lease_ttl_seconds,
        refresh_interval_seconds=config.refresh_interval_seconds,
    )

    try:
        # Wait up to the refresh interval; `Event.wait` returns True if the
        # event was set (shutdown) and False on timeout (time to refresh). This
        # gives prompt SIGTERM response without a busy loop.
        while not stop.wait(timeout=config.refresh_interval_seconds):
            lease.refresh(config.lease_ttl_seconds)
            log.debug(
                "keepalive.refreshed",
                engagement_id=config.engagement_id,
                lease_key=lease.key,
            )
    finally:
        # Clean-shutdown path: release the lease instantly. On SIGKILL this code
        # never runs and the lease expires within the TTL instead.
        lease.release()
        log.info(
            "keepalive.stopped",
            engagement_id=config.engagement_id,
            lease_key=lease.key,
            lease_released=True,
        )

    return 0
