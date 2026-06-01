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
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from doo.ids import EngagementId, ScopeContentHash
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

    def fetch_engagement_state(
        self, engagement_id: EngagementId
    ) -> CurrentEngagementState | None:
        return self.by_id.get(engagement_id)

    def apply_mutations(self, mutations: tuple[PlannedMutation, ...]) -> None:
        self.applied.extend(mutations)
        # Record what the state would look like after applying — so subsequent
        # `fetch_engagement_state` calls in the same test see the new world.
        for m in mutations:
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


def test_loader_t1_does_not_accept_principals_block() -> None:
    """Principals block lands in T4; T1 schema must not silently accept it."""
    from pydantic import ValidationError

    d = _base_config_dict()
    d["principals"] = [{"label": "test_user_a"}]
    with pytest.raises(ValidationError):
        _build_config(d)
