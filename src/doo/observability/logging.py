"""structlog configuration.

JSON output. `trace_id`, `span_id`, `engagement_id` ride in `contextvars` so
they propagate across async boundaries without manual plumbing. The OTel-stub
processor adds OTel-shaped fields on every log record but does not export
spans — flipping that switch later is a configuration change (ADR-0018).
"""

from __future__ import annotations

from typing import Any

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
from structlog.typing import EventDict, WrappedLogger

from doo.ids import EngagementId, SpanId, TraceId


def _otel_stub_processor(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Emit OTel-shaped trace_id / span_id fields without the SDK.

    Real OTel uses the same field names. When the SDK lands (ADR-0018), this
    processor is replaced by `structlog.contextvars.merge_contextvars` plus the
    real OTel-logs integration; the wire shape of structured logs is unchanged.
    """

    # If the contextvars merger already set trace_id / span_id, surface them
    # under the OTel-canonical key names too. Idempotent if already present.
    trace_id = event_dict.get("trace_id")
    span_id = event_dict.get("span_id")
    if trace_id is not None:
        event_dict.setdefault("otel.trace_id", trace_id)
    if span_id is not None:
        event_dict.setdefault("otel.span_id", span_id)
    return event_dict


def configure_logging(*, level: str = "INFO") -> None:
    """Configure structlog with JSON output and OTel-shaped correlation fields.

    Safe to call multiple times; structlog handles re-configuration.
    """

    structlog.configure(
        processors=[
            merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _otel_stub_processor,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(_level_to_int(level)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _level_to_int(level: str) -> int:
    import logging

    return logging.getLevelNamesMapping().get(level.upper(), logging.INFO)


def bind_correlation(
    *,
    trace_id: TraceId | None = None,
    span_id: SpanId | None = None,
    engagement_id: EngagementId | None = None,
    **extra: Any,
) -> None:
    """Bind correlation IDs to the current contextvars.

    Subsequent log lines from any logger include these fields automatically.
    Per ADR-0018, these are the three required correlation fields.
    """

    fields: dict[str, Any] = {}
    if trace_id is not None:
        fields["trace_id"] = trace_id
    if span_id is not None:
        fields["span_id"] = span_id
    if engagement_id is not None:
        fields["engagement_id"] = engagement_id
    fields.update(extra)
    bind_contextvars(**fields)


def clear_correlation() -> None:
    """Clear all bound contextvars. Useful between request handlers / tests."""
    clear_contextvars()


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structlog bound logger."""
    return structlog.get_logger(name) if name is not None else structlog.get_logger()
