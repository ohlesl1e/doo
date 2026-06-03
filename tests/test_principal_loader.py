"""Declared-Principal loader tests (T4: ADR-0010 / ADR-0012 / ADR-0019).

Covers, without Neo4j (against the in-memory `FakeGraphState`):
- env-var token resolution + secret-free `auth_hash` computation,
- JWT/known_signals `sub` cross-check (loud failure on mismatch),
- `validity_window.exp` derivation from the JWT `exp` claim,
- declared Principal + AuthContext mutations with the right tier/provenance,
- diff-and-confirm for principal add/remove/modify (ADR-0019),
- raw tokens never appear in any emitted mutation property.
"""

from __future__ import annotations

import io
import json

import jwt
import pytest

from doo.canonical.identity import compute_auth_hash
from doo.setup import (
    EngagementConfig,
    JwtSubjectMismatchError,
    MissingTokenEnvVarError,
    ScopeChangeRequiresConfirmation,
    load_engagement,
)
from tests.test_loader import FakeGraphState, _base_config_dict

# A real-shaped (but unsigned-irrelevant) token. We never verify the signature.
RAW_TOKEN_A = jwt.encode(
    {"sub": "uuid-aaa", "email": "a@example.com", "exp": 4102444800},  # 2100-01-01
    "irrelevant-signing-key-at-least-32-bytes-long!",
    algorithm="HS256",
)


def _config_with_principal(**signals: str) -> EngagementConfig:
    d = _base_config_dict()
    d["principals"] = [
        {
            "label": "test-user-a",
            "description": "tester account A",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-aaa", **signals},
        }
    ]
    return EngagementConfig.model_validate(d)


def test_declared_principal_creates_principal_and_auth_context() -> None:
    state = FakeGraphState()
    config = _config_with_principal()
    result = load_engagement(config, state, env={"TOK_A": RAW_TOKEN_A})
    assert result.created

    pdecl = [m for m in result.mutations if m.kind == "principal_declare"]
    acdecl = [m for m in result.mutations if m.kind == "auth_context_declare"]
    assert len(pdecl) == 1
    assert len(acdecl) == 1
    assert pdecl[0].properties["tier"] == "declared"
    assert pdecl[0].properties["source"] == "manual"
    assert pdecl[0].properties["confidence"] == 1.0
    assert pdecl[0].properties["confidence_method"] == "manual"
    assert acdecl[0].properties["tier"] == "declared"
    # AuthContext auth_hash == sha256("bearer:" + token).
    assert acdecl[0].properties["auth_hash"] == compute_auth_hash("bearer", RAW_TOKEN_A)


def test_validity_window_exp_derived_from_jwt() -> None:
    state = FakeGraphState()
    result = load_engagement(_config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A})
    ac = next(m for m in result.mutations if m.kind == "auth_context_declare")
    vw = ac.properties["validity_window"]
    assert vw is not None
    assert vw["exp"].startswith("2100-01-01")


def test_jwt_sub_mismatch_fails_loudly_naming_both() -> None:
    d = _base_config_dict()
    d["principals"] = [
        {
            "label": "test-user-a",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-WRONG"},
        }
    ]
    config = EngagementConfig.model_validate(d)
    with pytest.raises(JwtSubjectMismatchError) as exc:
        load_engagement(config, FakeGraphState(), env={"TOK_A": RAW_TOKEN_A})
    msg = str(exc.value)
    assert "uuid-aaa" in msg  # token's sub
    assert "uuid-WRONG" in msg  # declared signal


def test_missing_env_var_fails_loudly() -> None:
    with pytest.raises(MissingTokenEnvVarError) as exc:
        load_engagement(_config_with_principal(), FakeGraphState(), env={})
    assert "TOK_A" in str(exc.value)


def test_raw_token_never_in_any_mutation_property() -> None:
    state = FakeGraphState()
    result = load_engagement(_config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A})
    blob = json.dumps(
        [m.properties for m in result.mutations], default=str
    )
    assert RAW_TOKEN_A not in blob


def test_principal_add_is_material_and_confirmed() -> None:
    state = FakeGraphState()
    base = _base_config_dict()
    load_engagement(EngagementConfig.model_validate(base), state, env={})

    # Add a principal; must require confirmation.
    with pytest.raises(ScopeChangeRequiresConfirmation):
        load_engagement(
            _config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A}, stdin=None, stdout=io.StringIO()
        )

    stdout = io.StringIO()
    result = load_engagement(
        _config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A}, apply=True, stdout=stdout
    )
    assert result.material_changes_applied
    assert "test-user-a" in stdout.getvalue()


def test_principal_reload_is_noop() -> None:
    state = FakeGraphState()
    load_engagement(_config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A})
    result = load_engagement(_config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A})
    assert result.noop
    assert result.mutations == ()


def test_principal_known_signals_change_is_material() -> None:
    state = FakeGraphState()
    load_engagement(_config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A})
    # Add an email signal -> material diff.
    result = load_engagement(
        _config_with_principal(email="a2@example.com"),
        state,
        env={"TOK_A": RAW_TOKEN_A},
        apply=True,
        stdout=io.StringIO(),
    )
    assert result.material_changes_applied
    assert any(m.kind == "principal_declare" for m in result.mutations)


def test_principal_removal_retracts() -> None:
    state = FakeGraphState()
    load_engagement(_config_with_principal(), state, env={"TOK_A": RAW_TOKEN_A})
    # Drop the principal entirely.
    result = load_engagement(
        EngagementConfig.model_validate(_base_config_dict()),
        state,
        env={},
        apply=True,
        stdout=io.StringIO(),
    )
    assert result.material_changes_applied
    assert any(m.kind == "principal_retract" for m in result.mutations)


def test_unrelated_principal_unchanged_on_other_principal_edit() -> None:
    """Editing one principal does not re-emit mutations for an unrelated one."""

    d = _base_config_dict()
    d["principals"] = [
        {"label": "user-a", "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
         "known_signals": {"jwt_sub": "uuid-aaa"}},
        {"label": "user-b", "auth_contexts": [{"kind": "api_key", "token": "${TOK_B}"}]},
    ]
    config = EngagementConfig.model_validate(d)
    state = FakeGraphState()
    env = {"TOK_A": RAW_TOKEN_A, "TOK_B": "key-b-value"}
    load_engagement(config, state, env=env)

    # Change only user-b's token reference value (different env value -> different hash).
    result = load_engagement(
        config, state, env={"TOK_A": RAW_TOKEN_A, "TOK_B": "key-b-CHANGED"}, apply=True,
        stdout=io.StringIO(),
    )
    declared_labels = {
        m.properties["label"] for m in result.mutations if m.kind == "principal_declare"
    }
    # Only user-b is re-declared; user-a untouched.
    assert declared_labels == {"user-b"}
