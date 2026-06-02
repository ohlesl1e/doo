"""Unit tests for `doo worker run` — the drain loop + command registration.

The L2/L3 worker functions themselves are covered against real containers in
`tests/test_pipeline_e2e.py`; here we test only the new orchestration: the
`_drain_once` loop (pure, with injected runners) and that the command is wired
onto the root CLI.
"""

from __future__ import annotations

from typer.testing import CliRunner

from doo.cli import app
from doo.cli_worker import _drain_once


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
