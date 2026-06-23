"""Unit tests for the ADR-0051 per-role ``api_base`` / ``api_key`` env chain.

``DOO_<ROLE>_*`` → ``DOO_LLM_*`` → ``None``. ``None`` is the normal state
(litellm prefix-routes); setting any var force-pins that role to one endpoint.
"""

from __future__ import annotations

import pytest

from doo.cli_env import resolve_llm_api_base, resolve_llm_api_key

_ALL_VARS = (
    "DOO_PLANNER_API_BASE",
    "DOO_INTERPRETER_API_BASE",
    "DOO_LLM_API_BASE",
    "DOO_PLANNER_API_KEY",
    "DOO_INTERPRETER_API_KEY",
    "DOO_LLM_API_KEY",
)


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermetic: scrub every var the resolvers read so ambient shell state
    cannot leak into the precedence assertions."""
    for var in _ALL_VARS:
        monkeypatch.delenv(var, raising=False)


# (resolver, role-specific var template, shared var)
_CASES = [
    pytest.param(resolve_llm_api_base, "DOO_{}_API_BASE", "DOO_LLM_API_BASE", id="api_base"),
    pytest.param(resolve_llm_api_key, "DOO_{}_API_KEY", "DOO_LLM_API_KEY", id="api_key"),
]
_ROLES = ["planner", "interpreter"]


@pytest.mark.parametrize(("resolve", "role_tmpl", "shared"), _CASES)
@pytest.mark.parametrize("role", _ROLES)
def test_unset_is_none(resolve, role_tmpl, shared, role) -> None:
    """Nothing set → ``None`` (the normal state: litellm prefix-routes)."""
    assert resolve(role) is None


@pytest.mark.parametrize(("resolve", "role_tmpl", "shared"), _CASES)
@pytest.mark.parametrize("role", _ROLES)
def test_shared_only_applies_to_both_roles(
    resolve, role_tmpl, shared, role, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only ``DOO_LLM_*`` set → both roles resolve to it."""
    monkeypatch.setenv(shared, "http://shared.example")
    assert resolve(role) == "http://shared.example"


@pytest.mark.parametrize(("resolve", "role_tmpl", "shared"), _CASES)
@pytest.mark.parametrize("role", _ROLES)
def test_role_specific_only_applies_to_that_role(
    resolve, role_tmpl, shared, role, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the role-specific var set → that role gets it; the other role
    stays ``None`` (no shared fallback)."""
    other = "interpreter" if role == "planner" else "planner"
    monkeypatch.setenv(role_tmpl.format(role.upper()), "http://role.example")
    assert resolve(role) == "http://role.example"
    assert resolve(other) is None


@pytest.mark.parametrize(("resolve", "role_tmpl", "shared"), _CASES)
@pytest.mark.parametrize("role", _ROLES)
def test_role_specific_beats_shared(
    resolve, role_tmpl, shared, role, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both set → role-specific wins over ``DOO_LLM_*``."""
    monkeypatch.setenv(role_tmpl.format(role.upper()), "http://role.example")
    monkeypatch.setenv(shared, "http://shared.example")
    assert resolve(role) == "http://role.example"


@pytest.mark.parametrize(("resolve", "role_tmpl", "shared"), _CASES)
@pytest.mark.parametrize("role", _ROLES)
def test_empty_role_specific_falls_through_to_shared(
    resolve, role_tmpl, shared, role, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty-string role-specific var is falsy under ``or`` and falls
    through to the shared var (matches the pre-existing ``or None`` semantics
    in the callers this helper replaces)."""
    monkeypatch.setenv(role_tmpl.format(role.upper()), "")
    monkeypatch.setenv(shared, "http://shared.example")
    assert resolve(role) == "http://shared.example"
