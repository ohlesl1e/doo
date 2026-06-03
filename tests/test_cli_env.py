"""Tests for the `.env` loader (precedence + parsing)."""

from __future__ import annotations

import os

import pytest

from doo.cli_env import load_dotenv


def test_load_dotenv_sets_missing_keys(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOO_TEST_DOTENV_A", raising=False)
    monkeypatch.delenv("DOO_TEST_DOTENV_QUOTED", raising=False)
    env = tmp_path / ".env"
    env.write_text(
        '# a comment\nDOO_TEST_DOTENV_A=bar\n\nDOO_TEST_DOTENV_QUOTED="baz"\nno_equals_here\n'
    )
    n = load_dotenv(env)
    assert os.environ["DOO_TEST_DOTENV_A"] == "bar"
    assert os.environ["DOO_TEST_DOTENV_QUOTED"] == "baz"  # quotes stripped
    assert n == 2  # the comment, blank, and malformed lines are ignored


def test_load_dotenv_does_not_override_existing_env(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOO_TEST_DOTENV_B", "from-real-env")
    env = tmp_path / ".env"
    env.write_text("DOO_TEST_DOTENV_B=from-file\n")
    load_dotenv(env)
    assert os.environ["DOO_TEST_DOTENV_B"] == "from-real-env"  # export wins


def test_load_dotenv_absent_file_is_noop(tmp_path) -> None:
    assert load_dotenv(tmp_path / "does-not-exist.env") == 0
