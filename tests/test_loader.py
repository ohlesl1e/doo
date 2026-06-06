"""Engagement loader tests (ADR-0019).

Covers:
- create on first load
- no-op on identical re-load
- cosmetic change applies silently
- material Scope change requires confirmation; --apply bypasses
- engagement.id mismatch raises EngagementMismatchError
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml

from doo.ids import EngagementId
from doo.setup import (
    EngagementConfig,
    EngagementMismatchError,
    ScopeChangeRequiresConfirmation,
    compute_scope_content_hash,
    load_engagement,
)
from doo.setup.loader import (
    CurrentEngagementState,
    JsonFileLedger,
    PlannedMutation,
    load_engagement_from_yaml,
)


@dataclass
class FakeGraphState:
    """In-memory `GraphState` for loader tests."""

    by_id: dict[EngagementId, CurrentEngagementState] = field(default_factory=dict)
    applied: list[PlannedMutation] = field(default_factory=list)
    # engagement_id -> {label -> _principal_view-shaped dict}
    principals: dict[EngagementId, dict[str, dict]] = field(default_factory=dict)

    def fetch_engagement_state(
        self, engagement_id: EngagementId
    ) -> CurrentEngagementState | None:
        base = self.by_id.get(engagement_id)
        if base is None:
            return None
        # Re-emit with the current principal views attached (loader diffs these).
        return CurrentEngagementState(
            engagement_id=base.engagement_id,
            engagement_name=base.engagement_name,
            engagement_description=base.engagement_description,
            scope_content_hash=base.scope_content_hash,
            kill_switch_ttl_seconds=base.kill_switch_ttl_seconds,
            kill_switch_refresh_seconds=base.kill_switch_refresh_seconds,
            session_cookie_names=base.session_cookie_names,
            identity_key=base.identity_key,
            declared_principals=dict(self.principals.get(engagement_id, {})),
        )

    def _apply_principal_mutation(self, m: PlannedMutation) -> None:
        eid = m.properties["engagement_id"]
        bucket = self.principals.setdefault(eid, {})
        if m.kind == "principal_declare":
            label = m.properties["label"]
            ks = m.properties["known_signals"]
            view = bucket.setdefault(
                label,
                {"label": label, "description": None, "auth_contexts": [], "known_signals": ks},
            )
            view["description"] = m.properties["description"]
            view["known_signals"] = ks
            view["auth_contexts"] = []  # rebuilt by following auth_context_declare
        elif m.kind == "auth_context_declare":
            # Attach to the most recently declared principal (label via identity_key).
            ik = m.properties["principal_identity_key"]
            label = ik.removeprefix("declared:")
            view = bucket.setdefault(
                label,
                {"label": label, "description": None, "auth_contexts": [], "known_signals": {}},
            )
            view["auth_contexts"].append(
                {
                    "kind": m.properties["token_kind"],
                    "auth_hash": m.properties["auth_hash"],
                    "validity_window": m.properties["validity_window"],
                }
            )
            view["auth_contexts"].sort(key=lambda a: str(a["auth_hash"]))
        elif m.kind == "principal_retract":
            label = m.properties["identity_key"].removeprefix("declared:")
            bucket.pop(label, None)

    def apply_mutations(self, mutations: tuple[PlannedMutation, ...]) -> None:
        self.applied.extend(mutations)
        # Record what the state would look like after applying — so subsequent
        # `fetch_engagement_state` calls in the same test see the new world.
        for m in mutations:
            if m.kind in ("principal_declare", "auth_context_declare", "principal_retract"):
                self._apply_principal_mutation(m)
            if m.kind == "engagement_create":
                # Find the matching scope mutation we just recorded.
                scope_hash = None
                for prev in mutations:
                    if prev.kind == "scope_create":
                        scope_hash = prev.properties["content_hash"]
                        break
                assert scope_hash is not None
                self.by_id[m.properties["id"]] = CurrentEngagementState(
                    engagement_id=m.properties["id"],
                    engagement_name=m.properties["name"],
                    engagement_description=m.properties["description"],
                    scope_content_hash=scope_hash,
                    kill_switch_ttl_seconds=m.properties["kill_switch"]["lease_ttl_seconds"],
                    kill_switch_refresh_seconds=m.properties["kill_switch"][
                        "refresh_interval_seconds"
                    ],
                    session_cookie_names=tuple(m.properties.get("session_cookie_names") or ()),
                    identity_key=m.properties.get("identity_key"),
                )
            elif m.kind == "engagement_rebind_scope":
                eid = m.properties["engagement_id"]
                prev = self.by_id[eid]
                self.by_id[eid] = CurrentEngagementState(
                    engagement_id=prev.engagement_id,
                    engagement_name=prev.engagement_name,
                    engagement_description=prev.engagement_description,
                    scope_content_hash=m.properties["new_scope_content_hash"],
                    kill_switch_ttl_seconds=prev.kill_switch_ttl_seconds,
                    kill_switch_refresh_seconds=prev.kill_switch_refresh_seconds,
                    session_cookie_names=prev.session_cookie_names,
                    identity_key=prev.identity_key,
                )
            elif m.kind == "engagement_update":
                eid = m.properties["id"]
                prev = self.by_id[eid]
                ks = m.properties.get("kill_switch", {})
                self.by_id[eid] = CurrentEngagementState(
                    engagement_id=prev.engagement_id,
                    engagement_name=m.properties["name"],
                    engagement_description=m.properties["description"],
                    scope_content_hash=prev.scope_content_hash,
                    kill_switch_ttl_seconds=ks.get("lease_ttl_seconds", prev.kill_switch_ttl_seconds),
                    kill_switch_refresh_seconds=ks.get(
                        "refresh_interval_seconds", prev.kill_switch_refresh_seconds
                    ),
                    session_cookie_names=tuple(
                        m.properties.get("session_cookie_names")
                        if m.properties.get("session_cookie_names") is not None
                        else prev.session_cookie_names
                    ),
                    identity_key=(
                        m.properties.get("identity_key")
                        if "identity_key" in m.properties
                        else prev.identity_key
                    ),
                )


def _base_config_dict() -> dict:
    return {
        "engagement": {
            "id": "acme-2026",
            "name": "Acme spring engagement",
            "description": "Bug bounty research against Acme",
        },
        "scope": {
            "host_patterns": ["^api\\.acme\\.example$"],
            "allowed_methods": ["GET", "POST"],
            "allowed_path_patterns": ["^/api/v[0-9]+/.*$"],
            "payload_class_denylist": ["destructive-sql"],
        },
        "kill_switch": {
            "lease_ttl_seconds": 60,
            "refresh_interval_seconds": 30,
        },
    }


def _build_config(d: dict | None = None) -> EngagementConfig:
    return EngagementConfig.model_validate(d if d is not None else _base_config_dict())


def test_loader_creates_on_first_load() -> None:
    state = FakeGraphState()
    config = _build_config()
    result = load_engagement(config, state)
    assert result.created
    assert not result.noop
    assert any(m.kind == "engagement_create" for m in result.mutations)
    assert any(m.kind == "scope_create" for m in result.mutations)
    assert any(m.kind == "engagement_under_scope" for m in result.mutations)


def test_loader_is_noop_on_identical_reload() -> None:
    state = FakeGraphState()
    config = _build_config()
    load_engagement(config, state)
    result = load_engagement(config, state)
    assert result.noop
    assert not result.created
    assert result.mutations == ()


def test_config_accepts_session_cookie_names_and_defaults_empty() -> None:
    # Default: no auth block → empty allowlist.
    assert _build_config().auth.session_cookie_names == ()
    # Explicit list parses (and a YAML list coerces to a tuple).
    d = _base_config_dict()
    d["auth"] = {"session_cookie_names": ["token", "sid"]}
    assert _build_config(d).auth.session_cookie_names == ("token", "sid")


def test_loader_session_cookie_names_round_trips_and_reload_is_noop() -> None:
    state = FakeGraphState()
    d = _base_config_dict()
    d["auth"] = {"session_cookie_names": ["token"]}
    config = _build_config(d)
    load_engagement(config, state)
    # The value was stored on the engagement_create mutation…
    create = next(m for m in state.applied if m.kind == "engagement_create")
    assert create.properties["session_cookie_names"] == ["token"]
    # …and an identical reload is a noop (the field round-trips through the diff).
    result = load_engagement(config, state)
    assert result.noop
    assert result.mutations == ()


def test_loader_session_cookie_names_change_is_material() -> None:
    state = FakeGraphState()
    load_engagement(_build_config(), state)  # starts with empty allowlist
    d2 = _base_config_dict()
    d2["auth"] = {"session_cookie_names": ["token"]}
    result = load_engagement(_build_config(d2), state, apply=True)
    assert not result.noop
    update = next(m for m in result.mutations if m.kind == "engagement_update")
    assert update.properties["session_cookie_names"] == ["token"]


def test_loader_applies_cosmetic_change_silently() -> None:
    state = FakeGraphState()
    config1 = _build_config()
    load_engagement(config1, state)

    d2 = _base_config_dict()
    d2["engagement"]["description"] = "Updated description (typo fix)"
    config2 = _build_config(d2)
    result = load_engagement(config2, state)
    assert result.cosmetic_only
    assert not result.noop
    assert not result.material_changes_applied


def test_loader_requires_confirmation_on_scope_change() -> None:
    state = FakeGraphState()
    config1 = _build_config()
    load_engagement(config1, state)

    d2 = _base_config_dict()
    d2["scope"]["host_patterns"] = ["^api\\.acme\\.example$", "^admin\\.acme\\.example$"]
    config2 = _build_config(d2)

    # Without --apply and no stdin → refuses.
    with pytest.raises(ScopeChangeRequiresConfirmation):
        load_engagement(config2, state, apply=False, stdin=None, stdout=io.StringIO())


def test_loader_applies_scope_change_with_apply_flag() -> None:
    state = FakeGraphState()
    config1 = _build_config()
    load_engagement(config1, state)
    h1 = compute_scope_content_hash(config1.scope)

    d2 = _base_config_dict()
    d2["scope"]["host_patterns"] = ["^api\\.acme\\.example$", "^admin\\.acme\\.example$"]
    config2 = _build_config(d2)
    h2 = compute_scope_content_hash(config2.scope)
    assert h1 != h2

    stdout = io.StringIO()
    result = load_engagement(config2, state, apply=True, stdout=stdout)
    # Diff was printed.
    assert "current" in stdout.getvalue() and "proposed" in stdout.getvalue()
    assert result.material_changes_applied
    assert any(m.kind == "engagement_rebind_scope" for m in result.mutations)


def test_loader_applies_scope_change_with_interactive_yes() -> None:
    state = FakeGraphState()
    load_engagement(_build_config(), state)

    d2 = _base_config_dict()
    d2["scope"]["allowed_methods"] = ["GET", "POST", "PUT"]
    config2 = _build_config(d2)

    stdout = io.StringIO()
    stdin = io.StringIO("y\n")
    result = load_engagement(config2, state, apply=False, stdin=stdin, stdout=stdout)
    assert result.material_changes_applied


def test_loader_refuses_when_user_says_no() -> None:
    state = FakeGraphState()
    load_engagement(_build_config(), state)

    d2 = _base_config_dict()
    d2["scope"]["allowed_methods"] = ["GET", "POST", "PUT"]
    config2 = _build_config(d2)

    stdout = io.StringIO()
    stdin = io.StringIO("n\n")
    with pytest.raises(ScopeChangeRequiresConfirmation):
        load_engagement(config2, state, apply=False, stdin=stdin, stdout=stdout)


def test_scope_content_hash_canonical_ignores_notes() -> None:
    d1 = _base_config_dict()
    d2 = _base_config_dict()
    d2["scope"]["notes"] = "cosmetic"
    h1 = compute_scope_content_hash(_build_config(d1).scope)
    h2 = compute_scope_content_hash(_build_config(d2).scope)
    assert h1 == h2


def test_loader_fails_on_engagement_id_mismatch(tmp_path: Path) -> None:
    yaml_path = tmp_path / "engagement.yaml"
    d1 = _base_config_dict()
    yaml_path.write_text(yaml.safe_dump(d1))
    ledger = JsonFileLedger(tmp_path / "ledger.json")
    state = FakeGraphState()
    load_engagement_from_yaml(yaml_path, state, ledger)

    # Same path, different engagement.id → must refuse.
    d2 = _base_config_dict()
    d2["engagement"]["id"] = "acme-2027"
    yaml_path.write_text(yaml.safe_dump(d2))
    with pytest.raises(EngagementMismatchError):
        load_engagement_from_yaml(yaml_path, state, ledger)


def test_loader_strict_extra_forbid_rejects_unknown_yaml_keys() -> None:
    from pydantic import ValidationError

    d = _base_config_dict()
    d["unexpected_top_level"] = "nope"
    with pytest.raises(ValidationError):
        _build_config(d)


def test_loader_accepts_well_formed_principals_block() -> None:
    """T4: the `principals[]` block is now a valid part of the schema."""

    d = _base_config_dict()
    d["principals"] = [
        {
            "label": "test-user-a",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-aaa"},
        }
    ]
    config = _build_config(d)
    assert config.principals[0].label == "test-user-a"
    assert config.principals[0].auth_contexts[0].env_var_name == "TOK_A"


def test_loader_rejects_inline_token_and_non_kebab_label() -> None:
    """T4: tokens must be env-var refs (ADR-0012); labels must be kebab-case."""
    from pydantic import ValidationError

    d = _base_config_dict()
    d["principals"] = [
        {"label": "test-user-a", "auth_contexts": [{"kind": "bearer", "token": "raw-secret"}]}
    ]
    with pytest.raises(ValidationError):
        _build_config(d)

    d2 = _base_config_dict()
    d2["principals"] = [{"label": "Test_User_A"}]
    with pytest.raises(ValidationError):
        _build_config(d2)


# ---------------------------------------------------------------------------
# auth.identity_key tests (ADR-0032)
# ---------------------------------------------------------------------------


def test_config_accepts_identity_key_and_defaults_none() -> None:
    """Default: no auth block → identity_key is None."""
    assert _build_config().auth.identity_key is None

    # Explicit value parses correctly.
    d = _base_config_dict()
    d["auth"] = {"identity_key": "_id"}
    assert _build_config(d).auth.identity_key == "_id"

    # Source-qualified prefix is accepted as-is (stripping is in the resolver).
    d2 = _base_config_dict()
    d2["auth"] = {"identity_key": "claim:_id"}
    assert _build_config(d2).auth.identity_key == "claim:_id"


def test_loader_identity_key_round_trips_on_create() -> None:
    """identity_key is stored on the engagement_create mutation and round-trips."""
    state = FakeGraphState()
    d = _base_config_dict()
    d["auth"] = {"identity_key": "_id"}
    config = _build_config(d)
    load_engagement(config, state)

    create = next(m for m in state.applied if m.kind == "engagement_create")
    assert create.properties["identity_key"] == "_id"
    # Identical reload is a noop (the field round-trips through the diff).
    result = load_engagement(config, state)
    assert result.noop
    assert result.mutations == ()


def test_loader_identity_key_change_is_material() -> None:
    """Changing identity_key is a material change that requires confirmation."""
    state = FakeGraphState()
    load_engagement(_build_config(), state)  # starts with None

    d2 = _base_config_dict()
    d2["auth"] = {"identity_key": "_id"}
    result = load_engagement(_build_config(d2), state, apply=True)
    assert not result.noop
    assert result.material_changes_applied
    update = next(m for m in result.mutations if m.kind == "engagement_update")
    assert update.properties["identity_key"] == "_id"


def test_loader_identity_key_none_to_none_is_noop() -> None:
    """Re-loading with identity_key=None when current is None is a no-op."""
    state = FakeGraphState()
    config = _build_config()
    load_engagement(config, state)
    result = load_engagement(config, state)
    assert result.noop


def test_loader_identity_key_with_session_cookie_names_coexist() -> None:
    """Both auth fields can be set simultaneously."""
    state = FakeGraphState()
    d = _base_config_dict()
    d["auth"] = {"session_cookie_names": ["sid"], "identity_key": "username"}
    config = _build_config(d)
    load_engagement(config, state)
    create = next(m for m in state.applied if m.kind == "engagement_create")
    assert create.properties["session_cookie_names"] == ["sid"]
    assert create.properties["identity_key"] == "username"
