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

import pytest

from doo.engagement.keepalive import (
    EngagementNotFoundError,
    KeepaliveConfig,
    resolve_keepalive_config,
    run_keepalive,
)
from doo.ids import EngagementId
from doo.infra.redis_lease import LEASE_VALUE_ACTIVE, RedisLease, lease_key
from doo.setup.config import KillSwitchConfig

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
