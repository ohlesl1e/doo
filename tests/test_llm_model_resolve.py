"""ADR-0051 per-role model resolver precedence — pure unit tests (#142).

Covers `_resolve_planner_model` / `_resolve_interpreter_model` across the full
precedence chain (CLI > env > graph > default), and that `--model` is documented
on both commands' `--help`. No Neo4j, no network.
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from doo.dispatch.cli import _resolve_interpreter_model
from doo.planner.cli import _resolve_planner_model

DEFAULT = "anthropic/claude-opus-4-8"

# Rich force-enables colour under GITHUB_ACTIONS and renders option flags as
# two styled spans (``\x1b[1;36m-\x1b[0m\x1b[1;36m-model\x1b[0m``), so a literal
# ``"--model"`` substring check fails in CI. Strip ANSI before asserting.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(s: str) -> str:
    return _ANSI.sub("", s)


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep model-selection env from the host shell out of these tests."""
    monkeypatch.delenv("DOO_PLANNER_MODEL", raising=False)
    monkeypatch.delenv("DOO_INTERPRETER_MODEL", raising=False)


# ---------------------------------------------------------------------------
# Planner: --model > DOO_PLANNER_MODEL > Engagement.llm_model > default
# ---------------------------------------------------------------------------


def test_planner_default_when_nothing_set() -> None:
    assert _resolve_planner_model(None) == DEFAULT


def test_planner_env_beats_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-sonnet-4-6")
    assert _resolve_planner_model(None) == "anthropic/claude-sonnet-4-6"


def test_planner_cli_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-sonnet-4-6")
    assert _resolve_planner_model("openai/qwen3") == "openai/qwen3"


def test_planner_graph_beats_default_loses_to_env_and_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # graph beats default
    assert _resolve_planner_model(None, graph_model="openai/qwen3") == "openai/qwen3"
    # env beats graph
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-sonnet-4-6")
    assert (
        _resolve_planner_model(None, graph_model="openai/qwen3")
        == "anthropic/claude-sonnet-4-6"
    )
    # cli beats both
    assert (
        _resolve_planner_model("anthropic/claude-opus-4-8", graph_model="openai/qwen3")
        == "anthropic/claude-opus-4-8"
    )


# ---------------------------------------------------------------------------
# Interpreter: --model > DOO_INTERPRETER_MODEL > DOO_PLANNER_MODEL
#   > Engagement.llm_interpreter_model > Engagement.llm_model > default
# ---------------------------------------------------------------------------


def test_interpreter_default_when_nothing_set() -> None:
    assert _resolve_interpreter_model(None) == DEFAULT


def test_interpreter_falls_back_to_planner_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Back-compat: only DOO_PLANNER_MODEL set ⇒ interpreter still picks it up."""
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-sonnet-4-6")
    assert _resolve_interpreter_model(None) == "anthropic/claude-sonnet-4-6"


def test_interpreter_env_beats_planner_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-opus-4-8")
    monkeypatch.setenv("DOO_INTERPRETER_MODEL", "anthropic/claude-sonnet-4-6")
    assert _resolve_interpreter_model(None) == "anthropic/claude-sonnet-4-6"


def test_interpreter_cli_beats_both_envs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-sonnet-4-6")
    monkeypatch.setenv("DOO_INTERPRETER_MODEL", "anthropic/claude-sonnet-4-6")
    assert _resolve_interpreter_model("openai/qwen3") == "openai/qwen3"


def test_interpreter_graph_interpreter_beats_graph_model_beats_default() -> None:
    assert (
        _resolve_interpreter_model(None, graph_model="openai/qwen3") == "openai/qwen3"
    )
    assert (
        _resolve_interpreter_model(
            None,
            graph_interpreter_model="anthropic/claude-sonnet-4-6",
            graph_model="openai/qwen3",
        )
        == "anthropic/claude-sonnet-4-6"
    )


def test_interpreter_env_beats_both_graph_kwargs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOO_PLANNER_MODEL", "anthropic/claude-opus-4-8")
    assert (
        _resolve_interpreter_model(
            None,
            graph_interpreter_model="anthropic/claude-sonnet-4-6",
            graph_model="openai/qwen3",
        )
        == "anthropic/claude-opus-4-8"
    )
    monkeypatch.setenv("DOO_INTERPRETER_MODEL", "openai/qwen3")
    assert (
        _resolve_interpreter_model(
            None,
            graph_interpreter_model="anthropic/claude-sonnet-4-6",
            graph_model="anthropic/claude-sonnet-4-6",
        )
        == "openai/qwen3"
    )


# ---------------------------------------------------------------------------
# `--help` documents the flag on both commands.
# ---------------------------------------------------------------------------


def test_planner_propose_help_mentions_model_flag() -> None:
    from doo.cli import app

    result = CliRunner().invoke(
        app, ["planner", "propose", "--help"], env={"COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    out = _plain(result.output)
    assert "--model" in out
    assert "DOO_PLANNER_MODEL" in out


def test_dispatch_run_help_mentions_model_flag() -> None:
    from doo.cli import app

    result = CliRunner().invoke(
        app, ["dispatch", "run", "--help"], env={"COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    out = _plain(result.output)
    assert "--model" in out
    assert "DOO_INTERPRETER_MODEL" in out
