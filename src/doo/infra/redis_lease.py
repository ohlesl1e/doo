"""Thin Redis lease client for the kill-switch keepalive (ARCHITECTURE.md L5).

A minimal wrapper around `redis.Redis` exposing exactly the three operations
the keepalive needs against the lease key `engagement:{id}:lease`:

- `set_active(ttl_seconds)` — write `value = "active"` with a TTL (the loader
  does the very first write; the keepalive re-writes on each refresh).
- `refresh(ttl_seconds)` — re-assert `"active"` and reset the TTL.
- `release()` — `DEL` the key (SIGTERM path; instant kill).

Kept deliberately small. The dispatcher's *read-only* lease check (ADR-0014
trust split: the agent may only read the lease) lives in the dispatcher (T-later)
and is not part of this module. T2 may add its own broader Redis client under
`infra/`; merge reconciles — this wrapper owns only the lease key shape.

The class takes an injected client so unit/integration tests can pass a
testcontainer-backed `redis.Redis` or a fake.
"""

from __future__ import annotations

from typing import Protocol

from doo.ids import EngagementId

LEASE_VALUE_ACTIVE = "active"


def lease_key(engagement_id: EngagementId) -> str:
    """The canonical lease key for an engagement: `engagement:{id}:lease`."""

    return f"engagement:{engagement_id}:lease"


class RedisLike(Protocol):
    """Minimal duck-type for the redis client surface the lease needs."""

    def set(self, name: str, value: str, *, ex: int | None = ...) -> object: ...

    def delete(self, *names: str) -> int: ...

    def get(self, name: str) -> object: ...


class RedisLease:
    """Read/write access to one engagement's kill-switch lease key.

    Only the keepalive process constructs this with write intent. In deployed
    setups Redis ACLs enforce that the agent process holds a read-only client
    (ADR-0014); here the split is honour-system, and the dispatcher simply never
    calls the mutating methods.
    """

    def __init__(self, client: RedisLike, engagement_id: EngagementId) -> None:
        self._client = client
        self._engagement_id = engagement_id
        self._key = lease_key(engagement_id)

    @property
    def key(self) -> str:
        return self._key

    def set_active(self, ttl_seconds: int) -> None:
        """Write `value = "active"` with the given TTL (seconds)."""

        self._client.set(self._key, LEASE_VALUE_ACTIVE, ex=ttl_seconds)

    def refresh(self, ttl_seconds: int) -> None:
        """Re-assert `"active"` and reset the TTL. Identical to `set_active`.

        Kept as a named operation so call sites read intentionally and so a
        future refresh-only optimisation (e.g. `EXPIRE`) can change here without
        touching the keepalive loop.
        """

        self._client.set(self._key, LEASE_VALUE_ACTIVE, ex=ttl_seconds)

    def release(self) -> None:
        """`DEL` the lease key — the instant-kill / clean-shutdown path."""

        self._client.delete(self._key)

    def read(self) -> str | None:
        """Read the current lease value (read-only; the agent's only capability)."""

        raw = self._client.get(self._key)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return str(raw)
