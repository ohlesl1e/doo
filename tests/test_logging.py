"""structlog emits JSON with bound trace_id/span_id/engagement_id (ADR-0018)."""

from __future__ import annotations

import io
import json

import structlog

from doo.observability import (
    bind_correlation,
    clear_correlation,
    configure_logging,
    new_span_id,
    new_trace_id,
)


def test_logging_emits_json_with_bound_correlation(capsys) -> None:
    clear_correlation()
    configure_logging(level="DEBUG")

    trace = new_trace_id()
    span = new_span_id()
    bind_correlation(trace_id=trace, span_id=span, engagement_id="acme-2026")

    log = structlog.get_logger("test")
    log.info("hello.world", custom_field=42)

    captured = capsys.readouterr().out.strip().splitlines()
    assert captured, "no log line emitted"
    record = json.loads(captured[-1])
    assert record["event"] == "hello.world"
    assert record["trace_id"] == trace
    assert record["span_id"] == span
    assert record["engagement_id"] == "acme-2026"
    assert record["custom_field"] == 42
    # OTel-shaped fields per ADR-0018.
    assert record["otel.trace_id"] == trace
    assert record["otel.span_id"] == span


def test_clear_correlation_drops_bound_fields(capsys) -> None:
    configure_logging(level="DEBUG")
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())
    clear_correlation()

    log = structlog.get_logger("test")
    log.info("after.clear")
    captured = capsys.readouterr().out.strip().splitlines()
    record = json.loads(captured[-1])
    assert "trace_id" not in record
    assert "span_id" not in record


def test_trace_id_and_span_id_are_w3c_shaped() -> None:
    """16 bytes (32 hex chars) and 8 bytes (16 hex chars) per ADR-0018."""
    for _ in range(20):
        t = new_trace_id()
        s = new_span_id()
        assert len(t) == 32 and all(c in "0123456789abcdef" for c in t)
        assert len(s) == 16 and all(c in "0123456789abcdef" for c in s)
