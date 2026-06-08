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
from doo.coverage.models import C1Result, C2bResult, C2Result, PrincipalEvidence

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


# --- C2 rendering ---------------------------------------------------------

_C2_ROWS = [
    C2Result(
        engagement_id="eng-1",  # type: ignore[arg-type]
        generated_at=datetime(2026, 6, 1, tzinfo=UTC),
        endpoint_id="ep-admin",
        method="GET",
        host="shop.example.com",
        path_template="/admin/dashboard",
        principal_a_label="admin",
        principal_b_label="user",
        evidence_a=PrincipalEvidence(
            principal_id="pAdmin", label="admin", status=200, response_size_bytes=512
        ),
        evidence_b=None,
        effective_confidence=0.875,
    )
]


def _invoke_c2(*args: str):  # type: ignore[no-untyped-def]
    from doo.cli import app

    return CliRunner().invoke(app, ["coverage", "c2", *args])


def test_c2_table_rendering(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2", lambda *a, **k: list(_C2_ROWS))
    result = _invoke_c2("--engagement", "eng-1")
    assert result.exit_code == 0, result.output
    assert "authz-coverage gaps" in result.output
    assert "admin" in result.output
    assert "user" in result.output
    assert "/admin/dashboard" in result.output
    assert "200/512b" in result.output  # A evidence
    assert "0.875" in result.output


def test_c2_json_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2", lambda *a, **k: list(_C2_ROWS))
    result = _invoke_c2("--engagement", "eng-1", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list) and len(payload) == 1
    restored = C2Result.model_validate(payload[0])
    assert restored == _C2_ROWS[0]
    assert restored.query_id == "C2"


def test_c2_passes_pins_through(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _capture(*a: object, **k: object):  # type: ignore[no-untyped-def]
        captured.update(k)
        return []

    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2", _capture)
    result = _invoke_c2("--engagement", "eng-1", "--as", "admin", "--not-as", "user")
    assert result.exit_code == 0, result.output
    assert captured["as_label"] == "admin"
    assert captured["not_as_label"] == "user"


def test_c2_empty_table_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2", lambda *a, **k: [])
    result = _invoke_c2("--engagement", "eng-1")
    assert result.exit_code == 0, result.output
    assert "no presence-differential authz gaps" in result.output


# --- C2b rendering --------------------------------------------------------

_C2B_ROWS = [
    C2bResult(
        engagement_id="eng-1",  # type: ignore[arg-type]
        generated_at=datetime(2026, 6, 1, tzinfo=UTC),
        endpoint_id="ep-orders",
        method="GET",
        host="shop.example.com",
        path_template="/orders/{id}",
        evidence=(
            PrincipalEvidence(
                principal_id="pAdmin",
                label="admin",
                status=200,
                response_size_bytes=512,
                response_body_sha256="aaa",
            ),
            PrincipalEvidence(
                principal_id="pUser",
                label="user",
                status=200,
                response_size_bytes=128,
                response_body_sha256="bbb",
            ),
        ),
        effective_confidence=0.875,
    )
]


def _invoke_c2b(*args: str):  # type: ignore[no-untyped-def]
    from doo.cli import app

    return CliRunner().invoke(app, ["coverage", "c2b", *args])


def test_c2b_table_rendering(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2b", lambda *a, **k: list(_C2B_ROWS))
    result = _invoke_c2b("--engagement", "eng-1")
    assert result.exit_code == 0, result.output
    assert "DIFFERING responses" in result.output
    assert "/orders/{id}" in result.output
    assert "admin: 200/512b" in result.output
    assert "user: 200/128b" in result.output
    assert "0.875" in result.output


def test_c2b_json_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2b", lambda *a, **k: list(_C2B_ROWS))
    result = _invoke_c2b("--engagement", "eng-1", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list) and len(payload) == 1
    restored = C2bResult.model_validate(payload[0])
    assert restored == _C2B_ROWS[0]
    assert restored.query_id == "C2b"


def test_c2b_empty_table_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "_build_client", lambda: _StubClient())
    monkeypatch.setattr(cli_mod, "run_c2b", lambda *a, **k: [])
    result = _invoke_c2b("--engagement", "eng-1")
    assert result.exit_code == 0, result.output
    assert "no content-differential authz divergence" in result.output
