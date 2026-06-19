"""ADR-0049 / #117: SlotResolvingSecretStore — the symptom regression."""

from __future__ import annotations

import pytest

from doo.canonical.identity import (
    auth_context_id,
    compute_anonymous_auth_hash,
    compute_auth_hash,
)
from doo.dispatch.secrets import (
    AuthMaterial,
    EnvSecretStore,
    SlotMaterialMissing,
    SlotResolvingSecretStore,
)
from doo.ids import AuthContextId, EngagementId

ENG = EngagementId("eng-slot")
ANON = auth_context_id(ENG, compute_anonymous_auth_hash())


def _env_store(
    by_id: dict[AuthContextId, AuthMaterial],
    by_slot: dict[tuple[str, str], AuthMaterial],
) -> EnvSecretStore:
    # Construct directly; from_config exercised elsewhere.
    return EnvSecretStore(by_id=by_id, by_slot=by_slot)


def test_stale_id_resolves_via_slot_the_regression() -> None:
    """The G5 symptom: TC carries an engagement-start id; env re-hashed at
    run-arm to a different id. Same (label, slot) → material resolves."""
    fresh = auth_context_id(ENG, compute_auth_hash("cookie", "sid=NEW"))
    stale = auth_context_id(ENG, compute_auth_hash("cookie", "sid=OLD"))
    mat = AuthMaterial(kind="cookie", raw="sid=NEW", principal_label="alice")
    store = SlotResolvingSecretStore(
        graph_map={stale: ("alice", "cookie"), fresh: ("alice", "cookie")},
        env=_env_store({fresh: mat}, {("alice", "cookie"): mat}),
        anon_id=ANON,
    )
    assert store.material_for(stale) is mat
    assert store.material_for(fresh) is mat  # fast path


def test_anonymous_short_circuits() -> None:
    store = SlotResolvingSecretStore(
        graph_map={}, env=_env_store({}, {}), anon_id=ANON
    )
    out = store.material_for(ANON)
    assert out is not None and out.principal_label == "anonymous" and out.raw == ""


def test_unknown_id_returns_none() -> None:
    store = SlotResolvingSecretStore(
        graph_map={}, env=_env_store({}, {}), anon_id=ANON
    )
    assert store.material_for(AuthContextId("ac-discovered")) is None


def test_slot_mapped_but_no_material_raises() -> None:
    stale = AuthContextId("ac-stale")
    store = SlotResolvingSecretStore(
        graph_map={stale: ("alice", "cookie")},
        env=_env_store({}, {}),
        anon_id=ANON,
    )
    with pytest.raises(SlotMaterialMissing) as exc:
        store.material_for(stale)
    assert exc.value.principal_label == "alice" and exc.value.slot == "cookie"


def test_env_store_from_config_builds_by_slot() -> None:
    from doo.setup.config import EngagementConfig

    cfg = EngagementConfig.model_validate(
        {
            "engagement": {"id": "e", "name": "n"},
            "environment": "staging",
            "scope": {
                "host_patterns": ["x"],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "principals": [
                {
                    "label": "alice",
                    "auth_contexts": [{"kind": "cookie", "token": "${T}"}],
                }
            ],
        }
    )
    store = EnvSecretStore.from_config(cfg, env={"T": "sid=x"})
    assert ("alice", "cookie") in store.by_slot
    assert store.by_slot[("alice", "cookie")].raw == "sid=x"
