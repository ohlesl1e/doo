"""Child auth-helper supervisor for `keepalive --with-auth-helper` (ADR-0054, #182).

The keepalive parent holds the kill-switch lease (the system's load-bearing safety
primitive). ADR-0054 lets it *co-launch* the auth-helper as an **isolated child
subprocess** so a dispatch needs two terminals instead of three — without giving
the agent either authority and without letting the helper's refresh work touch the
heartbeat.

`HelperSupervisor` wraps a `subprocess.Popen` and is driven by the keepalive loop:

* ``start()`` once, before the loop;
* ``poll()`` every keepalive tick — a clean ``exit 0`` is left alone, a crash is
  restarted with a **bounded** budget (≤ ``max_restarts`` within ``window_s``, with
  exponential backoff), and past the cap it stops respawning, logs loudly, and
  leaves the lease alone;
* ``stop()`` in the loop's ``finally`` — terminate (then kill) the child on the
  parent's own shutdown, marking it so the exit is not miscounted as a crash.

`poll()` never blocks: a backoff is scheduled (``_restart_not_before``) and the
respawn happens on a later tick, so the lease refresh in the same loop is never
delayed by a flapping child. The supervisor performs **no** lease writes — helper
death must never touch the kill-switch (ADR-0054).
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from doo.observability.logging import get_logger

log = get_logger(__name__)


class _ChildProcess(Protocol):
    """The subset of `subprocess.Popen` the supervisor uses.

    A `Protocol` so a real `Popen` satisfies it structurally and tests can inject a
    fake process without spawning anything.
    """

    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


SpawnFn = Callable[[Sequence[str]], _ChildProcess]


@dataclass(frozen=True, slots=True)
class RestartPolicy:
    """Bounded-restart budget for a crashing child (ADR-0054)."""

    max_restarts: int = 3
    window_s: float = 600.0  # 10 minutes
    backoff_base_s: float = 1.0

    def backoff_for(self, attempt: int) -> float:
        """Exponential backoff for the ``attempt``-th restart in the window (0-based)."""

        return float(self.backoff_base_s * (2**attempt))


def default_spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    """Spawn the child, inheriting the parent's env (so refresh creds reach it)."""

    return subprocess.Popen(list(argv))  # noqa: S603 - argv is built, not shell


@dataclass
class HelperSupervisor:
    """Supervise the co-launched auth-helper child (ADR-0054, #182).

    `argv` is the full command (typically ``python -m doo.cli auth-helper run …``).
    `spawn` / `clock` are injectable so tests drive the lifecycle deterministically
    without a real subprocess or wall-clock.
    """

    argv: Sequence[str]
    policy: RestartPolicy = field(default_factory=RestartPolicy)
    spawn: SpawnFn = default_spawn
    clock: Callable[[], float] = time.monotonic

    _proc: _ChildProcess | None = field(default=None, init=False)
    # Crash timestamps still inside the policy window (for the bounded count).
    _restarts: list[float] = field(default_factory=list, init=False)
    # Monotonic time before which a respawn must not happen (backoff).
    _restart_not_before: float = field(default=0.0, init=False)
    # Set by `stop()`: a child exit during our own shutdown is not a crash.
    _shutting_down: bool = field(default=False, init=False)
    # Set once the restart budget is spent or the child exited cleanly: no respawn.
    _stopped_respawning: bool = field(default=False, init=False)

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Spawn the child once, before the keepalive loop."""

        self._spawn_proc()

    def poll(self) -> None:
        """Check the child once (per keepalive tick); restart a crash within budget.

        Non-blocking: a backoff defers the respawn to a later tick so the lease
        refresh in the same loop is never delayed by a flapping child.
        """

        if self._shutting_down or self._stopped_respawning:
            return
        now = self.clock()

        # A previous crash scheduled a backed-off respawn; do it once due.
        if self._proc is None:
            if now >= self._restart_not_before:
                self._spawn_proc()
            return

        rc = self._proc.poll()
        if rc is None:
            return  # still running — the common case.

        self._proc = None
        if rc == 0:
            # Clean exit: nothing left to rotate (or the tester stopped it). Not a
            # crash — do not respawn, and do not touch the lease.
            log.info("auth_helper_child.exited_clean", returncode=rc)
            self._stopped_respawning = True
            return

        self._handle_crash(rc, now)

    def stop(self, timeout: float = 5.0) -> None:
        """Terminate the child on the parent's own shutdown (loop ``finally``).

        SIGTERM-then-wait, escalating to kill on timeout. Marks shutdown first so a
        child exit during this teardown is not miscounted as a crash by a racing
        `poll`. Never raises — shutdown must complete so the lease is released.
        """

        self._shutting_down = True
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is not None:
                return  # already gone.
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                log.warning("auth_helper_child.terminate_timeout", timeout_s=timeout)
                proc.kill()
                proc.wait(timeout=timeout)
            log.info("auth_helper_child.stopped")
        except Exception as exc:  # noqa: BLE001 - teardown must not break release
            log.warning("auth_helper_child.stop_error", error=f"{type(exc).__name__}: {exc}")
        finally:
            self._proc = None

    # --- internals ---------------------------------------------------------

    def _spawn_proc(self) -> None:
        self._proc = self.spawn(self.argv)
        log.info(
            "auth_helper_child.started",
            pid=getattr(self._proc, "pid", None),
            restarts=len(self._restarts),
        )

    def _handle_crash(self, rc: int, now: float) -> None:
        # Drop crash timestamps that have aged out of the window, then decide.
        self._restarts = [t for t in self._restarts if now - t < self.policy.window_s]
        if len(self._restarts) >= self.policy.max_restarts:
            self._stopped_respawning = True
            msg = (
                f"auth-helper child crashed {len(self._restarts)} times within "
                f"{int(self.policy.window_s)}s (last exit {rc}); giving up restarting "
                "it. The kill-switch lease is STILL held — dispatch is unaffected, but "
                "credentials will no longer rotate. Check the refresh config / env and "
                "restart `doo auth-helper run` (or the keepalive) manually."
            )
            log.warning(
                "auth_helper_child.restart_exhausted",
                returncode=rc,
                restarts=len(self._restarts),
                window_s=self.policy.window_s,
            )
            print(f"WARNING: {msg}", file=sys.stderr, flush=True)
            return

        backoff = self.policy.backoff_for(len(self._restarts))
        self._restarts.append(now)
        self._restart_not_before = now + backoff
        log.warning(
            "auth_helper_child.crashed",
            returncode=rc,
            restart=len(self._restarts),
            backoff_s=backoff,
        )


def build_auth_helper_argv(engagement_id: str, config_path: str) -> list[str]:
    """The argv for the co-launched auth-helper child (`doo.cli` has a __main__ guard)."""

    return [
        sys.executable,
        "-m",
        "doo.cli",
        "auth-helper",
        "run",
        "-e",
        engagement_id,
        "-c",
        config_path,
    ]
