"""W3C trace-context id generators.

`trace_id` is 16 random bytes / 32 lowercase hex chars; `span_id` is 8 random
bytes / 16 lowercase hex chars. Per ADR-0018 we use the W3C format from day 1
so when the OTel SDK lands it reads our ids without translation.
"""

from __future__ import annotations

import secrets

from doo.ids import SpanId, TraceId


def new_trace_id() -> TraceId:
    """Generate a fresh W3C trace-id (16 bytes / 32 hex chars)."""
    return TraceId(secrets.token_hex(16))


def new_span_id() -> SpanId:
    """Generate a fresh W3C span-id (8 bytes / 16 hex chars)."""
    return SpanId(secrets.token_hex(8))
