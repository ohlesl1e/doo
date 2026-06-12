"""Unit tests for `doo worker run` — the drain loop + command registration.

The L2/L3 worker functions themselves are covered against real containers in
`tests/test_pipeline_e2e.py`; here we test only the new orchestration: the
`_drain_once` loop (pure, with injected runners) and that the command is wired
onto the root CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from typer.testing import CliRunner

from doo.cli import app
from doo.cli_worker import _drain_once, _report_parse_failures, _truncate
from doo.events.l2 import ParseFailure
from doo.ids import EngagementId, L2EventId, ObservationId, SourceId


def _parse_failure(kind: str, msg: str, where: str | None = "log") -> ParseFailure:
    return ParseFailure(
        event_id=L2EventId("e" * 32),
        trace_id="a" * 32,  # type: ignore[arg-type]
        span_id="b" * 16,  # type: ignore[arg-type]
        engagement_id=EngagementId("eng-x"),
        envelope_event_id=uuid4(),
        source="har",
        source_id=SourceId("0|t"),
        ingested_at=datetime.now(UTC),
        observed_at=datetime.now(UTC),
        confidence=1.0,
        observation_id=ObservationId("eng-x:har:pf:0|t"),
        error_kind=kind,  # type: ignore[arg-type]
        error_message=msg,
        location_hint=where,
    )


def test_drain_once_continues_until_both_passes_are_idle() -> None:
    # pass 1: L2=3, L3=0 (more to do); pass 2: L2=0, L3=2 (L3 caught up);
    # pass 3: L2=0, L3=0 -> stop. Totals sum across passes.
    l2 = iter([3, 0, 0])
    l3 = iter([0, 2, 0])
    extracted, committed = _drain_once(run_l2=lambda: next(l2), run_l3=lambda: next(l3))
    assert extracted == 3
    assert committed == 2


def test_drain_once_stops_immediately_when_streams_empty() -> None:
    extracted, committed = _drain_once(run_l2=lambda: 0, run_l3=lambda: 0)
    assert (extracted, committed) == (0, 0)


def test_worker_run_command_is_registered() -> None:
    result = CliRunner().invoke(app, ["worker", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output


def test_worker_run_has_json_flag() -> None:
    result = CliRunner().invoke(app, ["worker", "run", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.output


def test_worker_progress_disabled_yields_working_noop_callbacks() -> None:
    # When disabled (non-TTY / --json) the context manager yields no-op callbacks
    # so the drain code path is identical without a terminal.
    from doo.cli_worker import _worker_progress

    with _worker_progress(enabled=False) as (on_extracted, on_committed):
        on_extracted(3)
        on_committed()  # no terminal, no error, no output


def test_truncate_collapses_whitespace_and_limits_length() -> None:
    assert _truncate("a   b\nc", 100) == "a b c"
    out = _truncate("x" * 300, 50)
    assert len(out) == 50
    assert out.endswith("...")


def test_report_parse_failures_groups_by_kind(capsys) -> None:
    _report_parse_failures(
        [
            _parse_failure("decode_error", "HAR blob is not valid JSON at char 100"),
            _parse_failure("missing_required_field", "entry missing startedDateTime", "log.entries[9]"),
            _parse_failure("missing_required_field", "entry missing startedDateTime", "log.entries[12]"),
        ]
    )
    out = capsys.readouterr().out
    assert "3 parse failure(s)" in out
    assert "decode_error x1" in out
    assert "missing_required_field x2" in out


def test_report_parse_failures_empty_prints_nothing(capsys) -> None:
    _report_parse_failures([])
    assert capsys.readouterr().out == ""
