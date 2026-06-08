"""Coverage CLI rendering tests — no containers.

Asserts `doo coverage c1` renders a human table by default and the typed result
models under `--json` (round-trippable). The Neo4j client and `run_c1` are
stubbed so the test exercises only the rendering / serialization path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import doo.coverage.cli as cli_mod
from doo.coverage.models import C1Result

_ROWS = [
    C1Result(
        engagement_id="eng-1",  # type: ignore[arg-type]
        generated_at=datetime(2026, 6, 1, tzinfo=UTC),
        endpoint_id="ep-admin",
        method="GET",
        host="shop.example.com",
        path_template="/admin/dashboard",
        effective_confidence=0.875,
    )
]


class _StubClient:
    def close(self) -> None:  # pragma: no cover - trivial
        pass


@pytest.fixture(autouse=True)
def _stub_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c1", lambda *a, **k: list(_ROWS))


def _invoke(*args: str):  # type: ignore[no-untyped-def]
    from doo.cli import app

    return CliRunner().invoke(app, ["coverage", "c1", *args])


def test_c1_table_rendering() -> None:
    result = _invoke("--engagement", "eng-1")
    assert result.exit_code == 0, result.output
    assert "dead endpoints" in result.output
    assert "GET" in result.output
    assert "shop.example.com" in result.output
    assert "/admin/dashboard" in result.output
    assert "0.875" in result.output


def test_c1_json_rendering_round_trips() -> None:
    result = _invoke("--engagement", "eng-1", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list) and len(payload) == 1
    restored = C1Result.model_validate(payload[0])
    assert restored == _ROWS[0]
    assert restored.query_id == "C1"


def test_c1_empty_table_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "run_c1", lambda *a, **k: [])
    result = _invoke("--engagement", "eng-1")
    assert result.exit_code == 0, result.output
    assert "no in-scope endpoints are dead" in result.output
