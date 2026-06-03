"""Redis Streams helper (slice-1 T2, L1<->L2<->L3 transport).

A thin, typed wrapper over `redis.Redis` for the consumer-group pattern the
pipeline uses on the `ingest`, `l2-events`, and `l3-events` streams:

- `publish(stream, payload)` — `XADD` one JSON message; returns the message id.
- `ensure_group(stream, group)` — `XGROUP CREATE ... MKSTREAM` so the stream and
  group auto-create on first use; idempotent (swallows BUSYGROUP).
- `read_group(stream, group, consumer)` — consumer-group `XREADGROUP` with a
  block timeout; yields `(message_id, payload)` pairs.
- `ack(stream, group, message_id)` — explicit `XACK`.

Messages are a single JSON document under the field key `data`. The Pydantic
model on each side owns the schema; this module only moves opaque JSON.

ARCHITECTURE.md keeps the L1<->L2 interface "event with payload reference" and
the transport swappable (Redis Streams now, Kafka only if shown insufficient).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, Protocol

# Stream names (ARCHITECTURE.md "Layer contracts").
INGEST_STREAM = "ingest"
L2_EVENTS_STREAM = "l2-events"
L3_EVENTS_STREAM = "l3-events"

# The single JSON field every message carries.
_FIELD = "data"


class RedisStreamLike(Protocol):
    """Minimal duck-type for the redis-py stream surface this wrapper needs."""

    def xadd(self, name: str, fields: dict[str, str]) -> Any: ...

    def xgroup_create(
        self, name: str, groupname: str, id: str = ..., mkstream: bool = ...
    ) -> Any: ...

    def xreadgroup(
        self,
        groupname: str,
        consumername: str,
        streams: dict[str, str],
        count: int | None = ...,
        block: int | None = ...,
    ) -> Any: ...

    def xack(self, name: str, groupname: str, *ids: str) -> Any: ...


def _as_str(value: Any) -> str:
    """Decode a redis field value (bytes or str) to str."""

    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


class StreamClient:
    """Consumer-group helper around one injected redis client.

    The client is injected so tests can pass a testcontainer-backed
    `redis.Redis` (or a fake). Construct with `decode_responses` either way — the
    helper normalises both.
    """

    def __init__(self, client: RedisStreamLike) -> None:
        self._client = client

    def publish(self, stream: str, payload: dict[str, Any]) -> str:
        """`XADD` one JSON message onto `stream`; return its message id."""

        message_id = self._client.xadd(stream, {_FIELD: json.dumps(payload)})
        return _as_str(message_id)

    def ensure_group(self, stream: str, group: str) -> None:
        """`XGROUP CREATE ... MKSTREAM`; idempotent (swallows BUSYGROUP)."""

        try:
            self._client.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception as exc:  # noqa: BLE001 - redis raises ResponseError
            # The group already exists — that's the steady state, not an error.
            if "BUSYGROUP" in str(exc):
                return
            raise

    def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 16,
        block_ms: int = 1000,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """`XREADGROUP` new messages; yield `(message_id, payload)` pairs.

        Reads only never-delivered messages (`>`). Blocks up to `block_ms` for at
        least one message, then returns whatever arrived (possibly nothing).
        """

        resp = self._client.xreadgroup(
            group,
            consumer,
            {stream: ">"},
            count=count,
            block=block_ms,
        )
        if not resp:
            return
        for _stream_name, entries in resp:
            for message_id, fields in entries:
                raw = fields.get(_FIELD) if isinstance(fields, dict) else None
                if raw is None:
                    # Field keys may be bytes when decode_responses is off.
                    raw = fields.get(_FIELD.encode()) if isinstance(fields, dict) else None
                payload = json.loads(_as_str(raw)) if raw is not None else {}
                yield _as_str(message_id), payload

    def ack(self, stream: str, group: str, message_id: str) -> None:
        """`XACK` one processed message."""

        self._client.xack(stream, group, message_id)
