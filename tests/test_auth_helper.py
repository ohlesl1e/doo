"""Auth-helper unit tests (S6/#91, ADR-0014).

Rate-limit guard, proactive scheduling at `exp − margin`, reactive rotation on a
stubbed stream event (respecting the rate limit), the rotation-file write, the
`RotatableSecretStore` overlay, and `RefreshConfig` shape validation. The graph
write is exercised by the integration e2e; here Neo4j is a no-op fake.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.dispatch.auth_helper import AuthHelper, ManagedAuthContext, RateLimiter
from doo.dispatch.reactive import AUTH_REACTIVE_STREAM, REACTIVE_AUTH_INVALID
from doo.dispatch.secrets import (
    AuthMaterial,
    EnvSecretStore,
    RotatableSecretStore,
    write_rotation_entry,
)
from doo.ids import AuthContextId, EngagementId
from doo.setup.config import RefreshConfig

ENG = EngagementId("eng-helper")
AC = AuthContextId("ac-1")


class _FakeNeo4j:
    def __init__(self) -> None:
        self.writes: list[dict[str, Any]] = []

    def execute_write(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self.writes.append(params)
        return []


def _refresh(**kw: Any) -> RefreshConfig:
    base: dict[str, Any] = dict(mechanism="command", command="true")
    base.update(kw)
    return RefreshConfig(**base)


def _helper(tmp_path: Path, *, clock_box: dict[str, float], **rc_kw: Any) -> AuthHelper:
    rc = _refresh(**rc_kw)
    helper = AuthHelper(
        engagement_id=ENG,
        neo4j=_FakeNeo4j(),  # type: ignore[arg-type]
        rotation_path=tmp_path / "rotation.json",
        managed={AC: ManagedAuthContext(AC, "bearer", "attacker-b", rc)},
        env={},
        clock=lambda: clock_box["t"],
        mechanisms={"command": lambda rc, env: "NEW-TOKEN"},
    )
    helper._schedule_all()
    return helper


# --- RateLimiter -----------------------------------------------------------


def test_rate_limiter_allows_up_to_max_then_blocks() -> None:
    box = {"t": 0.0}
    rl = RateLimiter(clock=lambda: box["t"])
    for _ in range(3):
        assert rl.allow("k", max_per_window=3)
        rl.record("k")
    assert not rl.allow("k", max_per_window=3)
    # After the window slides past, the old events expire.
    box["t"] = 3601.0
    assert rl.allow("k", max_per_window=3)


# --- proactive scheduling --------------------------------------------------


def test_due_proactively_fires_at_exp_minus_margin(tmp_path: Path) -> None:
    box = {"t": 1000.0}
    helper = _helper(tmp_path, clock_box=box, validity_window_s=100, margin_s=10)
    # scheduled at 1000 + 100 - 10 = 1090.
    box["t"] = 1089.0
    assert helper.due_proactively() == []
    box["t"] = 1090.0
    assert helper.due_proactively() == [AC]


# --- rotate ----------------------------------------------------------------


def test_rotate_writes_rotation_file_and_graph(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box, validity_window_s=100, max_refreshes_per_hour=2)
    assert helper.rotate(AC, reason="reactive") is True

    import json

    data = json.loads((tmp_path / "rotation.json").read_text())
    # New material written under BOTH the old id and the freshly-computed new id.
    new_id = auth_context_id(ENG, compute_auth_hash("bearer", "NEW-TOKEN"))
    assert data[str(AC)]["raw"] == "NEW-TOKEN"
    assert data[str(new_id)]["raw"] == "NEW-TOKEN"
    # Graph write happened (old expired + new node + OF_PRINCIPAL).
    assert helper.neo4j.writes  # type: ignore[attr-defined]
    assert helper.neo4j.writes[0]["old_id"] == str(AC)  # type: ignore[attr-defined]
    # The new id is now also managed (a later reactive event on it works).
    assert new_id in helper.managed


def test_rotate_quoted_cookie_hashes_canonical_writes_wire_raw(tmp_path: Path) -> None:
    """A `kind: cookie` rotation whose mechanism emits a DQUOTE-wrapped value (#103).

    The new `AuthContext` id is computed over the *canonical* (DQUOTE-stripped)
    value so it matches the loader/L2; but the rotation file's `raw` is the
    untouched wire-form value the Executor must send.
    """

    box = {"t": 0.0}
    rc = _refresh()
    ac_cookie = AuthContextId("ac-cookie")
    bare = "deadbeefdeadbeef"
    wire = f'"{bare}"'
    helper = AuthHelper(
        engagement_id=ENG,
        neo4j=_FakeNeo4j(),  # type: ignore[arg-type]
        rotation_path=tmp_path / "rotation.json",
        managed={ac_cookie: ManagedAuthContext(ac_cookie, "cookie", "user-c", rc)},
        env={},
        clock=lambda: box["t"],
        mechanisms={"command": lambda rc, env: wire},
    )
    helper._schedule_all()
    assert helper.rotate(ac_cookie, reason="reactive") is True

    import json

    data = json.loads((tmp_path / "rotation.json").read_text())
    new_id = auth_context_id(ENG, compute_auth_hash("cookie", bare))
    # Hashed on the canonical (bare) form → same id the loader/L2 would compute.
    assert str(new_id) in data
    # Wire-form raw survives un-stripped, under both old and new ids.
    assert data[str(new_id)]["raw"] == wire
    assert data[str(ac_cookie)]["raw"] == wire


def test_rotate_respects_rate_limit(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box, max_refreshes_per_hour=2)
    assert helper.rotate(AC, reason="reactive") is True
    assert helper.rotate(AC, reason="reactive") is True
    assert helper.rotate(AC, reason="reactive") is False  # 3rd within the hour blocked


def test_rotate_failed_mechanism_returns_false(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)

    def boom(rc: RefreshConfig, env: dict[str, str]) -> str:
        raise RuntimeError("idp down")

    helper.mechanisms["command"] = boom
    assert helper.rotate(AC, reason="proactive") is False
    assert not (tmp_path / "rotation.json").exists()  # nothing written on failure


# --- reactive --------------------------------------------------------------


class _FakeStream:
    def __init__(self, messages: list[tuple[str, dict[str, str]]]) -> None:
        self._messages = messages
        self.acked: list[str] = []
        self.groups: list[str] = []

    def ensure_group(self, stream: str, group: str) -> None:
        self.groups.append(group)

    def read_group(self, stream: str, group: str, consumer: str, **kw: Any):
        msgs, self._messages = self._messages, []
        yield from msgs

    def ack(self, stream: str, group: str, message_id: str) -> None:
        self.acked.append(message_id)


def test_poll_reactive_rotates_on_event(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)
    helper.streams = _FakeStream(  # type: ignore[assignment]
        [
            (
                "1-0",
                {
                    "kind": REACTIVE_AUTH_INVALID,
                    "engagement_id": str(ENG),
                    "auth_context_id": str(AC),
                },
            )
        ]
    )
    assert helper.poll_reactive(block_ms=0) == 1
    assert helper.streams.acked == ["1-0"]  # type: ignore[attr-defined]
    assert (tmp_path / "rotation.json").exists()


def test_poll_reactive_ignores_other_engagement(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)
    helper.streams = _FakeStream(  # type: ignore[assignment]
        [("1-0", {"kind": REACTIVE_AUTH_INVALID, "engagement_id": "other", "auth_context_id": str(AC)})]
    )
    assert helper.poll_reactive(block_ms=0) == 0


# --- RotatableSecretStore --------------------------------------------------


class _BaseStore:
    def material_for(self, ac: AuthContextId) -> AuthMaterial | None:
        if ac == AC:
            return AuthMaterial(kind="bearer", raw="OLD", principal_label="attacker-b")
        return None


def test_rotatable_overlay_wins(tmp_path: Path) -> None:
    path = tmp_path / "rot.json"
    store = RotatableSecretStore(base=_BaseStore(), rotation_path=path)
    # No file yet → base material.
    assert store.material_for(AC).raw == "OLD"  # type: ignore[union-attr]
    write_rotation_entry(path, auth_context_id=AC, raw="ROTATED", kind="bearer", principal_label="attacker-b")
    mat = store.material_for(AC)
    assert mat is not None and mat.raw == "ROTATED" and mat.kind == "bearer"


def test_env_secret_store_quoted_cookie_keys_canonical_keeps_wire_raw() -> None:
    """`EnvSecretStore` indexes a quoted cookie token on the canonical hash (#103)
    while `AuthMaterial.raw` stays the wire-form value for `_splice_auth`."""

    from doo.setup.config import EngagementConfig
    from tests.test_loader import _base_config_dict

    bare = "deadbeefdeadbeef"
    wire = f'"{bare}"'
    d = _base_config_dict()
    d["principals"] = [
        {"label": "user-c", "auth_contexts": [{"kind": "cookie", "token": "${C}"}]}
    ]
    config = EngagementConfig.model_validate(d)
    store = EnvSecretStore.from_config(config, env={"C": wire})

    ac_id = auth_context_id(
        EngagementId(d["engagement"]["id"]), compute_auth_hash("cookie", bare)
    )
    mat = store.material_for(ac_id)
    assert mat is not None
    assert mat.kind == "cookie"
    assert mat.raw == wire  # un-stripped: this is what the Executor sends.


def test_rotatable_falls_back_when_no_entry(tmp_path: Path) -> None:
    store = RotatableSecretStore(base=_BaseStore(), rotation_path=tmp_path / "absent.json")
    assert store.material_for(AC).raw == "OLD"  # type: ignore[union-attr]
    assert store.material_for(AuthContextId("unknown")) is None


# --- RefreshConfig validation ----------------------------------------------


def test_refresh_command_requires_command() -> None:
    with pytest.raises(ValidationError):
        RefreshConfig(mechanism="command")


def test_refresh_oauth_requires_token_url_and_refresh_env() -> None:
    with pytest.raises(ValidationError):
        RefreshConfig(mechanism="oauth_refresh", token_url="https://idp/token")
    RefreshConfig(mechanism="oauth_refresh", token_url="https://idp/token", refresh_token_env="RT")


def test_refresh_http_requires_url() -> None:
    with pytest.raises(ValidationError):
        RefreshConfig(mechanism="http")
    RefreshConfig(mechanism="http", http_url="https://idp/refresh")


def test_unused_stream_constant_importable() -> None:
    assert AUTH_REACTIVE_STREAM == "auth-reactive"
