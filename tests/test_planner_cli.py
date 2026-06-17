"""Planner CLI option tests — no containers (issue #111).

Asserts `doo planner propose -g/--generator` is a Typer choice backed by the
canonical `GENERATOR_IDS` tuple: `--help` enumerates the valid ids, an unknown
id is rejected cleanly by Click (no Pydantic traceback), and the chosen ids
reach `PlannerConfig.candidate_generators` as plain strings. The Neo4j client
and `propose` service are stubbed so the test exercises only the CLI layer.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import doo.planner.cli as cli_mod
from doo.planner.cli import GeneratorOpt
from doo.planner.generators import PlannerConfig
from doo.planner.models import GENERATOR_IDS
from doo.planner.service import ProposeResult


class _StubClient:
    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _invoke(*args: str):  # type: ignore[no-untyped-def]
    from doo.cli import app

    return CliRunner().invoke(app, ["planner", "propose", *args])


def test_generator_opt_tracks_canonical_ids() -> None:
    """Drift guard: the CLI choice enum is generated from `GENERATOR_IDS`."""
    assert {m.value for m in GeneratorOpt} == set(GENERATOR_IDS)
    # `interpreter` is a valid `GeneratorId` provenance value but NOT a runnable
    # planner generator (ADR-0045/S8) — it must not leak into the CLI choices.
    assert "interpreter" not in {m.value for m in GeneratorOpt}


def test_propose_help_enumerates_generator_ids() -> None:
    result = _invoke("--help")
    assert result.exit_code == 0, result.output
    for gid in GENERATOR_IDS:
        assert gid in result.output, f"{gid!r} missing from --help: {result.output}"
    assert "S1" not in result.output
    assert "interpreter" not in result.output
    # Rich word-wraps the help column, so match the cross-ref loosely.
    assert "doo coverage" in result.output


def test_propose_rejects_unknown_generator_cleanly() -> None:
    result = _invoke("--engagement", "eng-1", "-g", "bogus")
    assert result.exit_code != 0
    combined = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Invalid value" in combined
    # The clean Click error lists the valid ids; no Pydantic / Python traceback.
    for gid in GENERATOR_IDS:
        assert gid in combined
    assert "Traceback" not in combined
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_propose_passes_generator_choices_to_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def _fake_propose(*a: object, **k: object) -> ProposeResult:
        captured["config"] = k["config"]
        return ProposeResult()

    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    # Short-circuit the LLM-dep builder: c2b/sink are LLM generators, but the
    # service is stubbed so no caller is needed.
    monkeypatch.setattr(cli_mod, "requested_llm_generator_ids", lambda config: ())
    monkeypatch.setattr(cli_mod, "propose", _fake_propose)

    result = _invoke("--engagement", "eng-1", "-g", "c2b", "-g", "sink")
    assert result.exit_code == 0, result.output
    config = captured["config"]
    assert isinstance(config, PlannerConfig)
    assert config.candidate_generators == ("c2b", "sink")
    # Coerced enum -> str: members are plain `str`, not the CLI-local enum.
    assert all(type(g) is str for g in config.candidate_generators)
