"""ADR-0051 full precedence table — graph tier wired (#145).

`tests/test_llm_model_resolve.py` (wave 1, #142) covers each tier pairwise;
this file restates the **complete** ADR-0051 resolution table as parametrised
rows so the documented precedence is checked end-to-end in one place. Pure
unit tests on the resolver functions — the graph tier is exercised by passing
literals for the `graph_*` kwargs (no Neo4j fixture).
"""

from __future__ import annotations

import pytest

from doo.dispatch.cli import _resolve_interpreter_model
from doo.planner.cli import _resolve_planner_model

DEFAULT = "anthropic/claude-opus-4-8"


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep model-selection env from the host shell out of these tests."""
    monkeypatch.delenv("DOO_PLANNER_MODEL", raising=False)
    monkeypatch.delenv("DOO_INTERPRETER_MODEL", raising=False)


# ---------------------------------------------------------------------------
# Planner: --model > DOO_PLANNER_MODEL > Engagement.llm_model > default
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cli", "env_planner", "graph", "expected"),
    [
        # row 1: --model wins over everything
        ("openai/qwen3", "anthropic/claude-sonnet-4-6", "anthropic/claude-opus-4-8", "openai/qwen3"),
        # row 2: DOO_PLANNER_MODEL wins over graph
        (None, "anthropic/claude-sonnet-4-6", "openai/qwen3", "anthropic/claude-sonnet-4-6"),
        # row 4: Engagement.llm_model wins over default
        (None, None, "openai/qwen3", "openai/qwen3"),
        # row 6: hardcoded default
        (None, None, None, DEFAULT),
    ],
)
def test_planner_chain_full_table(
    monkeypatch: pytest.MonkeyPatch,
    cli: str | None,
    env_planner: str | None,
    graph: str | None,
    expected: str,
) -> None:
    if env_planner is not None:
        monkeypatch.setenv("DOO_PLANNER_MODEL", env_planner)
    assert _resolve_planner_model(cli, graph_model=graph) == expected


# ---------------------------------------------------------------------------
# Interpreter: --model > DOO_INTERPRETER_MODEL > DOO_PLANNER_MODEL
#   > Engagement.llm_interpreter_model > Engagement.llm_model > default
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cli", "env_interp", "env_planner", "graph_interp", "graph", "expected"),
    [
        # row 1: --model wins over everything
        (
            "openai/qwen3",
            "anthropic/claude-sonnet-4-6",
            "anthropic/claude-sonnet-4-6",
            "anthropic/claude-opus-4-8",
            "anthropic/claude-opus-4-8",
            "openai/qwen3",
        ),
        # row 2: DOO_INTERPRETER_MODEL wins over DOO_PLANNER_MODEL + graph
        (
            None,
            "anthropic/claude-sonnet-4-6",
            "openai/qwen3",
            "anthropic/claude-opus-4-8",
            "anthropic/claude-opus-4-8",
            "anthropic/claude-sonnet-4-6",
        ),
        # row 3: DOO_PLANNER_MODEL (back-compat shared var) wins over graph
        (
            None,
            None,
            "anthropic/claude-sonnet-4-6",
            "openai/qwen3",
            "anthropic/claude-opus-4-8",
            "anthropic/claude-sonnet-4-6",
        ),
        # row 4: Engagement.llm_interpreter_model wins over llm_model
        (None, None, None, "anthropic/claude-sonnet-4-6", "openai/qwen3", "anthropic/claude-sonnet-4-6"),
        # row 5: Engagement.llm_model wins over default
        (None, None, None, None, "openai/qwen3", "openai/qwen3"),
        # row 6: hardcoded default
        (None, None, None, None, None, DEFAULT),
    ],
)
def test_interpreter_chain_full_table(
    monkeypatch: pytest.MonkeyPatch,
    cli: str | None,
    env_interp: str | None,
    env_planner: str | None,
    graph_interp: str | None,
    graph: str | None,
    expected: str,
) -> None:
    if env_interp is not None:
        monkeypatch.setenv("DOO_INTERPRETER_MODEL", env_interp)
    if env_planner is not None:
        monkeypatch.setenv("DOO_PLANNER_MODEL", env_planner)
    assert (
        _resolve_interpreter_model(
            cli, graph_interpreter_model=graph_interp, graph_model=graph
        )
        == expected
    )


def test_planner_graph_absent_falls_through() -> None:
    """Pre-#144 engagement (node properties unset) ⇒ clean fall-through, no error."""
    assert _resolve_planner_model(None, graph_model=None) == DEFAULT


def test_interpreter_graph_model_used_when_interpreter_model_absent() -> None:
    """`llm_interpreter_model` unset ⇒ interpreter falls back to `llm_model`."""
    assert (
        _resolve_interpreter_model(None, graph_interpreter_model=None, graph_model="x")
        == "x"
    )
