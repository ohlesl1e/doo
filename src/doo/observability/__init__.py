"""Cross-cutting observability.

Slice 1 ships:
- structlog JSON config with `trace_id` / `span_id` / `engagement_id` context vars.
- An OTel-friendly processor in stub mode per ADR-0018 — emit OTel-shaped
  `trace_id`/`span_id` log fields without the SDK. Enabling the SDK later is a
  configuration change.
- W3C trace-context id generators.
"""

from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import (
    bind_correlation,
    clear_correlation,
    configure_logging,
    get_logger,
)

__all__ = [
    "bind_correlation",
    "clear_correlation",
    "configure_logging",
    "get_logger",
    "new_span_id",
    "new_trace_id",
]
