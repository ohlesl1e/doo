"""Kill-switch keepalive tests (T7, ADR-0014, ARCHITECTURE.md L5).

Two tiers:

- **Unit** (no container): a fake Redis client + fake config reader exercise the
  lease writes, refresh, release-on-stop, the config-default resolution, and the
  unknown-engagement refusal.
- **Integration** (Redis testcontainer, real subprocess): asserts the lease key
  is present after startup, removed after SIGTERM with exit 0, and absent after
  `ttl + 5s` when the process is SIGKILLed (lease expires naturally).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import typer

from doo.engagement.cli_keepalive import _Neo4jLeaseConfigReader
from doo.engagement.keepalive import (
    EngagementNotFoundError,
    KeepaliveConfig,
    resolve_keepalive_config,
    run_keepalive,
)
from doo.ids import EngagementId
from doo.infra.redis_lease import LEASE_VALUE_ACTIVE, RedisLease, lease_key
from doo.setup.config import KillSwitchConfig

# --- _Neo4jLeaseConfigReader unit -------------------------------------------
# Regression for the `TypeError: string indices must be integers` on
# `doo engagement keepalive`: the loader JSON-encodes `kill_switch` (Neo4j
# cannot store a nested map as a node property — `graph_state.py:253`); the
# reader must decode it.


class _FakeSession:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def run(self, cypher: str, **params: object) -> list[dict[str, object]]:
        return list(self._rows)


def test_neo4j_reader_decodes_json_kill_switch() -> None:
    """`e.kill_switch` is stored as a JSON string; the reader decodes it."""
    session = _FakeSession(
        [{"kill_switch": '{"lease_ttl_seconds": 45, "refresh_interval_seconds": 20}'}]
    )
    cfg = _Neo4jLeaseConfigReader(session).read_kill_switch_config(EngagementId("e"))
    assert cfg == KillSwitchConfig(lease_ttl_seconds=45, refresh_interval_seconds=20)


def test_neo4j_reader_unknown_engagement_returns_none() -> None:
    cfg = _Neo4jLeaseConfigReader(_FakeSession([])).read_kill_switch_config(
        EngagementId("missing")
    )
    assert cfg is None


def test_neo4j_reader_null_kill_switch_falls_back_to_defaults() -> None:
    cfg = _Neo4jLeaseConfigReader(
        _FakeSession([{"kill_switch": None}])
    ).read_kill_switch_config(EngagementId("e"))
    assert cfg == KillSwitchConfig()

# --- Fakes -------------------------------------------------------------------


class FakeRedis:
    """In-memory stand-in for the lease operations (no TTL expiry simulation)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.set_calls: int = 0

    def set(self, name: str, value: str, *, ex: int | None = None) -> object:
        self.store[name] = value
        if ex is not None:
            self.ttls[name] = ex
        self.set_calls += 1
        return True

    def delete(self, *names: str) -> int:
        n = 0
        for name in names:
            if name in self.store:
                del self.store[name]
                self.ttls.pop(name, None)
                n += 1
        return n

    def get(self, name: str) -> object:
        return self.store.get(name)


class FakeReader:
    def __init__(self, ks: KillSwitchConfig | None) -> None:
        self._ks = ks

    def read_kill_switch_config(self, engagement_id: EngagementId) -> KillSwitchConfig | None:
        return self._ks


# --- Config resolution -------------------------------------------------------


def test_resolve_uses_graph_values() -> None:
    reader = FakeReader(KillSwitchConfig(lease_ttl_seconds=30, refresh_interval_seconds=15))
    cfg = resolve_keepalive_config(EngagementId("eng-1"), reader)
    assert cfg == KeepaliveConfig(EngagementId("eng-1"), 30, 15)


def test_resolve_defaults_to_60_30_when_yaml_omitted() -> None:
    # The loader persists defaults; KillSwitchConfig() is the 60/30 default.
    reader = FakeReader(KillSwitchConfig())
    cfg = resolve_keepalive_config(EngagementId("eng-1"), reader)
    assert cfg.lease_ttl_seconds == 60
    assert cfg.refresh_interval_seconds == 30


def test_resolve_refuses_unknown_engagement() -> None:
    reader = FakeReader(None)
    with pytest.raises(EngagementNotFoundError):
        resolve_keepalive_config(EngagementId("nope"), reader)


# --- Neo4j reader (json-string property) -------------------------------------
# Regression: `e.kill_switch` is persisted as a JSON *string* (Neo4j cannot
# store nested maps as node properties — see `ontology/graph_state.py` writer),
# not a property map. The reader must decode it. Previously it subscripted the
# raw string and raised `TypeError: string indices must be integers`.


class _FakeSession:
    """Minimal stand-in for a neo4j Session: `.run()` returns dict-records."""

    def __init__(self, records: list[dict[str, object]]) -> None:
        self._records = records

    def run(self, *_a: object, **_k: object) -> list[dict[str, object]]:
        return self._records


def _neo4j_reader(records: list[dict[str, object]]):  # type: ignore[no-untyped-def]
    from doo.engagement.cli_keepalive import _Neo4jLeaseConfigReader

    return _Neo4jLeaseConfigReader(_FakeSession(records))


def test_neo4j_reader_decodes_json_string_property() -> None:
    import json

    stored = json.dumps(
        {"backend": "redis", "lease_ttl_seconds": 45, "refresh_interval_seconds": 20},
        sort_keys=True,
    )
    ks = _neo4j_reader([{"kill_switch": stored}]).read_kill_switch_config(
        EngagementId("eng-1")
    )
    assert ks == KillSwitchConfig(lease_ttl_seconds=45, refresh_interval_seconds=20)


def test_neo4j_reader_missing_engagement_returns_none() -> None:
    assert _neo4j_reader([]).read_kill_switch_config(EngagementId("nope")) is None


def test_neo4j_reader_null_property_falls_back_to_defaults() -> None:
    ks = _neo4j_reader([{"kill_switch": None}]).read_kill_switch_config(
        EngagementId("eng-1")
    )
    assert ks == KillSwitchConfig()


# --- Lease key shape ---------------------------------------------------------


def test_lease_key_shape() -> None:
    assert lease_key(EngagementId("abc")) == "engagement:abc:lease"


# --- Run loop (unit, driven by stop_event) -----------------------------------


def test_run_writes_lease_immediately_and_releases_on_stop() -> None:
    fake = FakeRedis()
    lease = RedisLease(fake, EngagementId("eng-1"))
    cfg = KeepaliveConfig(EngagementId("eng-1"), lease_ttl_seconds=60, refresh_interval_seconds=30)
    stop = threading.Event()

    key = lease_key(EngagementId("eng-1"))

    # Run on a thread so we can observe the lease then stop it.
    result: list[int] = []

    def _run() -> None:
        result.append(
            run_keepalive(cfg, lease, stop_event=stop, install_signal_handlers=False)
        )

    t = threading.Thread(target=_run)
    t.start()
    # The first write happens before the loop's first wait; poll briefly.
    deadline = time.time() + 2.0
    while time.time() < deadline and key not in fake.store:
        time.sleep(0.01)
    assert fake.store.get(key) == LEASE_VALUE_ACTIVE
    assert fake.ttls.get(key) == 60

    stop.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert result == [0]
    # Released on clean stop.
    assert key not in fake.store


def test_run_refreshes_on_interval() -> None:
    fake = FakeRedis()
    lease = RedisLease(fake, EngagementId("eng-1"))
    # Tiny refresh interval so we see multiple refreshes quickly.
    cfg = KeepaliveConfig(EngagementId("eng-1"), lease_ttl_seconds=5, refresh_interval_seconds=1)
    stop = threading.Event()

    def _run() -> None:
        run_keepalive(cfg, lease, stop_event=stop, install_signal_handlers=False)

    t = threading.Thread(target=_run)
    t.start()
    time.sleep(2.5)  # ~1 initial set + ~2 refreshes
    stop.set()
    t.join(timeout=5)
    # Initial set + at least two refreshes.
    assert fake.set_calls >= 3


# --- Integration: real Redis + real subprocess (signals) ---------------------


def _spawn_keepalive(redis_url: str, *, ttl: int, refresh: int, engagement_id: str) -> subprocess.Popen[bytes]:
    env = dict(os.environ)
    env.update(
        {
            "DOO_KEEPALIVE_ENGAGEMENT_ID": engagement_id,
            "DOO_REDIS_URL": redis_url,
            "DOO_KEEPALIVE_TTL_SECONDS": str(ttl),
            "DOO_KEEPALIVE_REFRESH_SECONDS": str(refresh),
        }
    )
    return subprocess.Popen(
        [sys.executable, "-m", "doo.engagement._keepalive_runner"],
        env=env,
    )


def _redis_client(redis_url: str):
    import redis

    return redis.Redis.from_url(redis_url)


def _wait_for_key(client, key: str, *, present: bool, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        exists = client.exists(key) == 1
        if exists == present:
            return True
        time.sleep(0.1)
    return client.exists(key) == 1 if present else client.exists(key) == 0


def test_lease_present_after_startup(redis_url: str) -> None:
    eng = "eng-startup"
    key = lease_key(EngagementId(eng))
    client = _redis_client(redis_url)
    proc = _spawn_keepalive(redis_url, ttl=60, refresh=30, engagement_id=eng)
    try:
        assert _wait_for_key(client, key, present=True, timeout=10), "lease not written"
        assert client.get(key) == LEASE_VALUE_ACTIVE.encode()
    finally:
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)


def test_sigterm_releases_lease_and_exits_zero(redis_url: str) -> None:
    eng = "eng-sigterm"
    key = lease_key(EngagementId(eng))
    client = _redis_client(redis_url)
    proc = _spawn_keepalive(redis_url, ttl=60, refresh=30, engagement_id=eng)
    try:
        assert _wait_for_key(client, key, present=True, timeout=10)
        proc.send_signal(signal.SIGTERM)
        code = proc.wait(timeout=10)
        assert code == 0, f"expected clean exit 0 on SIGTERM, got {code}"
        # Lease removed promptly (DEL), well before TTL.
        assert _wait_for_key(client, key, present=False, timeout=5), "lease not released on SIGTERM"
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=10)


def test_sigkill_lets_lease_expire_within_ttl(redis_url: str) -> None:
    eng = "eng-sigkill"
    ttl = 5  # short TTL so the test is quick; refresh below TTL
    key = lease_key(EngagementId(eng))
    client = _redis_client(redis_url)
    proc = _spawn_keepalive(redis_url, ttl=ttl, refresh=2, engagement_id=eng)
    try:
        assert _wait_for_key(client, key, present=True, timeout=10)
        # Hard kill: no SIGTERM handler runs, so no DEL. The lease must expire
        # on its own within the TTL (no refresh arrives).
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
        # After ttl + 5s the key must be gone.
        assert _wait_for_key(client, key, present=False, timeout=ttl + 5), (
            "lease did not expire within ttl+5s after SIGKILL"
        )
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=10)


# --- #182: co-launched auth-helper child (ADR-0054) --------------------------


class _FakeProc:
    """Duck-typed `subprocess.Popen` for `HelperSupervisor` unit tests."""

    def __init__(self, pid: int = 1000) -> None:
        self.pid = pid
        self._rc: int | None = None  # None == alive
        self.terminated = False
        self.killed = False

    def set_exit(self, rc: int) -> None:
        self._rc = rc

    def poll(self) -> int | None:
        return self._rc

    def terminate(self) -> None:
        self.terminated = True
        if self._rc is None:
            self._rc = 0  # clean exit on SIGTERM

    def kill(self) -> None:
        self.killed = True
        self._rc = -9

    def wait(self, timeout: float | None = None) -> int:
        return self._rc if self._rc is not None else 0


class _StubbornProc(_FakeProc):
    """Ignores `terminate`; only `kill` stops it (drives the stop() escalation)."""

    def terminate(self) -> None:
        self.terminated = True  # but does not exit

    def wait(self, timeout: float | None = None) -> int:
        if not self.killed:
            raise subprocess.TimeoutExpired(cmd="auth-helper", timeout=timeout or 0)
        return -9


class _FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _spawner(procs: list[_FakeProc]):
    """Return `(spawn_fn, spawned_list)` handing out `procs` in order."""
    it = iter(procs)
    spawned: list[_FakeProc] = []

    def spawn(argv: object) -> _FakeProc:
        p = next(it)
        spawned.append(p)
        return p

    return spawn, spawned


def test_build_auth_helper_argv_shape() -> None:
    from doo.engagement.auth_helper_child import build_auth_helper_argv

    argv = build_auth_helper_argv("eng-x", "/tmp/e.yaml")
    assert argv[:1] == [sys.executable]
    assert argv[1:] == ["-m", "doo.cli", "auth-helper", "run", "-e", "eng-x", "-c", "/tmp/e.yaml"]


def test_supervisor_clean_exit_is_not_restarted() -> None:
    from doo.engagement.auth_helper_child import HelperSupervisor

    p0 = _FakeProc()
    spawn, spawned = _spawner([p0])
    sup = HelperSupervisor(argv=["x"], spawn=spawn, clock=_FakeClock())
    sup.start()
    assert len(spawned) == 1

    p0.set_exit(0)
    sup.poll()
    # A clean exit is left alone — no respawn, ever.
    sup.poll()
    assert len(spawned) == 1


def test_supervisor_crash_restarts_within_budget_then_gives_up() -> None:
    from doo.engagement.auth_helper_child import HelperSupervisor, RestartPolicy

    procs = [_FakeProc(pid=i) for i in range(6)]
    spawn, spawned = _spawner(procs)
    clock = _FakeClock()
    sup = HelperSupervisor(
        argv=["x"],
        spawn=spawn,
        clock=clock,
        policy=RestartPolicy(max_restarts=3, window_s=600.0, backoff_base_s=1.0),
    )
    sup.start()  # spawn procs[0]
    assert len(spawned) == 1

    # Three crashes → three backed-off restarts (1s, 2s, 4s).
    for i, backoff in enumerate((1.0, 2.0, 4.0)):
        procs[i].set_exit(1)
        sup.poll()  # records the crash + schedules the respawn
        assert len(spawned) == i + 1, "respawn must wait for the backoff"
        clock.advance(backoff)
        sup.poll()  # backoff elapsed → respawn
        assert len(spawned) == i + 2

    # The 4th crash exceeds the budget: stop respawning, keep quiet about the lease.
    procs[3].set_exit(1)
    sup.poll()
    sup.poll()
    assert len(spawned) == 4  # 1 initial + 3 restarts, no more


def test_supervisor_stop_terminates_child() -> None:
    from doo.engagement.auth_helper_child import HelperSupervisor

    p0 = _FakeProc()
    spawn, spawned = _spawner([p0])
    sup = HelperSupervisor(argv=["x"], spawn=spawn, clock=_FakeClock())
    sup.start()
    sup.stop(timeout=1.0)
    assert p0.terminated is True
    # A child exit during our own shutdown is not counted as a crash → no respawn.
    sup.poll()
    assert len(spawned) == 1


def test_supervisor_stop_escalates_to_kill_on_timeout() -> None:
    from doo.engagement.auth_helper_child import HelperSupervisor

    p0 = _StubbornProc()
    spawn, _ = _spawner([p0])
    sup = HelperSupervisor(argv=["x"], spawn=spawn, clock=_FakeClock())
    sup.start()
    sup.stop(timeout=0.01)
    assert p0.terminated is True and p0.killed is True


def _make_config(*, with_refresh: bool, eid: str = "eng-x"):
    from doo.setup.config import EngagementConfig

    ac: dict[str, object] = {"kind": "bearer", "token": "${TOK}"}
    if with_refresh:
        ac["refresh"] = {"mechanism": "command", "command": "echo tok"}
    return EngagementConfig.model_validate(
        {
            "engagement": {"id": eid, "name": eid},
            "environment": "staging",
            "scope": {
                "host_patterns": ["h.example.com"],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "principals": [{"label": "attacker", "auth_contexts": [ac]}],
        }
    )


def test_has_managed_slots() -> None:
    from doo.engagement.cli_keepalive import _has_managed_slots

    assert _has_managed_slots(_make_config(with_refresh=True)) is True
    assert _has_managed_slots(_make_config(with_refresh=False)) is False


def test_resolve_child_spawns_when_flag_and_managed(monkeypatch: pytest.MonkeyPatch) -> None:
    from doo.engagement import cli_keepalive
    from doo.engagement.auth_helper_child import HelperSupervisor

    monkeypatch.setattr(
        cli_keepalive, "_load_config", lambda _p: _make_config(with_refresh=True)
    )
    child = cli_keepalive._resolve_child(
        "eng-x", with_auth_helper=True, config_path=Path("e.yaml")
    )
    assert isinstance(child, HelperSupervisor)
    assert child.argv[-4:] == ["-e", "eng-x", "-c", "e.yaml"]


def test_resolve_child_lease_only_when_flag_but_no_managed(monkeypatch: pytest.MonkeyPatch) -> None:
    from doo.engagement import cli_keepalive

    monkeypatch.setattr(
        cli_keepalive, "_load_config", lambda _p: _make_config(with_refresh=False)
    )
    child = cli_keepalive._resolve_child(
        "eng-x", with_auth_helper=True, config_path=Path("e.yaml")
    )
    assert child is None


def test_resolve_child_requires_config_with_flag() -> None:
    from doo.engagement import cli_keepalive

    with pytest.raises(typer.Exit):
        cli_keepalive._resolve_child("eng-x", with_auth_helper=True, config_path=None)


def test_resolve_child_rejects_mismatched_engagement(monkeypatch: pytest.MonkeyPatch) -> None:
    from doo.engagement import cli_keepalive

    monkeypatch.setattr(
        cli_keepalive,
        "_load_config",
        lambda _p: _make_config(with_refresh=True, eid="other"),
    )
    with pytest.raises(typer.Exit):
        cli_keepalive._resolve_child(
            "eng-x", with_auth_helper=True, config_path=Path("e.yaml")
        )


def test_resolve_child_none_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    from doo.engagement import cli_keepalive

    # No flag, no config → plain lease-only, no child.
    assert (
        cli_keepalive._resolve_child("eng-x", with_auth_helper=False, config_path=None)
        is None
    )
    # No flag but a config with managed slots → still None (a hint is printed).
    monkeypatch.setattr(
        cli_keepalive, "_load_config", lambda _p: _make_config(with_refresh=True)
    )
    assert (
        cli_keepalive._resolve_child(
            "eng-x", with_auth_helper=False, config_path=Path("e.yaml")
        )
        is None
    )


def test_run_keepalive_starts_and_stops_child_and_releases_lease() -> None:
    from doo.engagement.auth_helper_child import HelperSupervisor

    fake = FakeRedis()
    lease = RedisLease(fake, EngagementId("eng-child"))
    cfg = KeepaliveConfig(
        EngagementId("eng-child"), lease_ttl_seconds=5, refresh_interval_seconds=1
    )
    p0 = _FakeProc()
    spawn, spawned = _spawner([p0])
    sup = HelperSupervisor(argv=["x"], spawn=spawn, clock=_FakeClock())
    stop = threading.Event()
    key = lease_key(EngagementId("eng-child"))

    def _run() -> None:
        run_keepalive(
            cfg, lease, stop_event=stop, install_signal_handlers=False, child=sup
        )

    t = threading.Thread(target=_run)
    t.start()
    # Child spawned at startup; lease present.
    deadline = time.time() + 2.0
    while time.time() < deadline and not spawned:
        time.sleep(0.01)
    assert len(spawned) == 1
    assert fake.store.get(key) == LEASE_VALUE_ACTIVE

    stop.set()
    t.join(timeout=5)
    assert not t.is_alive()
    # Child stopped on shutdown; lease released after.
    assert p0.terminated is True
    assert key not in fake.store
