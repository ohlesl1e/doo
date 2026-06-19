"""Auth-helper unit tests (S6/#91, ADR-0014; ADR-0049 slot re-key).

Rate-limit guard, proactive scheduling at `exp − margin`, reactive rotation on a
stubbed stream event (respecting the rate limit), the rotation-file write, and
`RefreshConfig` shape validation. The graph write is exercised by the
integration e2e; here Neo4j is a no-op fake.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.dispatch.auth_helper import AuthHelper, ManagedAuthContext, RateLimiter
from doo.dispatch.reactive import AUTH_REACTIVE_STREAM, REACTIVE_AUTH_INVALID
from doo.dispatch.secrets import AuthMaterial, EnvSecretStore
from doo.ids import AuthContextId, EngagementId
from doo.setup.config import RefreshConfig

ENG = EngagementId("eng-helper")
AC = AuthContextId("ac-1")
SLOT = ("attacker-b", "bearer")


class _FakeNeo4j:
    def __init__(self, read_rows: list[dict[str, Any]] | None = None) -> None:
        self.writes: list[dict[str, Any]] = []
        self._read_rows = read_rows or []

    def execute_write(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self.writes.append({"_query": query, **params})
        return []

    def execute_read(self, query: str, **params: Any) -> list[dict[str, Any]]:
        return list(self._read_rows)


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
        managed={
            SLOT: ManagedAuthContext(
                principal_label="attacker-b", slot="bearer", kind="bearer", refresh=rc
            )
        },
        id_to_slot={AC: SLOT},
        env={},
        clock=lambda: clock_box["t"],
        mechanisms={"command": lambda rc, env, verify: "NEW-TOKEN"},
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
    assert helper.due_proactively() == [SLOT]


# --- rotate ----------------------------------------------------------------


def test_rotate_writes_rotation_file_and_graph(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box, validity_window_s=100, max_refreshes_per_hour=2)
    assert helper.rotate(SLOT, reason="reactive") is True

    import json

    data = json.loads((tmp_path / "rotation.json").read_text())
    new_id = auth_context_id(ENG, compute_auth_hash("bearer", "NEW-TOKEN"))
    # ADR-0049: one rotation-stable key per slot, overwritten each rotation.
    assert data == {"attacker-b:bearer": {"raw": "NEW-TOKEN", "kind": "bearer"}}
    # No per-id keys (the dual-write under the old/new auth_context_id is gone).
    assert str(AC) not in data and str(new_id) not in data
    # Graph write: matches on (label, slot), not the old content-addressed id;
    # the new node's slot is written from the parameter.
    write = helper.neo4j.writes[0]  # type: ignore[attr-defined]
    assert write["label"] == "attacker-b"
    assert write["slot"] == "bearer"
    assert "old_id" not in write
    assert "new.slot = $slot" in write["_query"]
    # The new content-addressed id now maps back to the slot for later
    # reactive events on the rotated token.
    assert helper.id_to_slot[new_id] == SLOT


def test_rotate_writes_identity_claims_and_validity_window(tmp_path: Path) -> None:
    """A rotated bearer JWT's claims + `exp` are decoded and written on the new
    `AuthContext` node (ADR-0048), so priority-0 reconciliation sees the
    rotated token's identity. Opaque tokens degrade to `{}` / `None`."""

    import jwt as pyjwt

    box = {"t": 0.0}
    rotated = pyjwt.encode(
        {"_id": "u-rot", "exp": 4102444800}, "k" * 32, algorithm="HS256"
    )
    helper = _helper(tmp_path, clock_box=box)
    helper.mechanisms["command"] = lambda rc, env, verify: rotated
    assert helper.rotate(SLOT, reason="proactive") is True

    write = helper.neo4j.writes[0]  # type: ignore[attr-defined]
    import json as _json

    claims = _json.loads(write["identity_claims"])
    assert claims["_id"] == "u-rot"
    vw = _json.loads(write["validity_window"])
    assert vw["exp"].startswith("2100-01-01")

    # Opaque (non-JWT) credential → empty claims, no window; non-fatal.
    helper2 = _helper(tmp_path, clock_box=box)
    helper2.mechanisms["command"] = lambda rc, env, verify: "opaque-not-a-jwt"
    assert helper2.rotate(SLOT, reason="proactive") is True
    write2 = helper2.neo4j.writes[0]  # type: ignore[attr-defined]
    assert _json.loads(write2["identity_claims"]) == {}
    assert write2["validity_window"] is None


def test_rotate_quoted_cookie_hashes_canonical_writes_wire_raw(tmp_path: Path) -> None:
    """A `kind: cookie` rotation whose mechanism emits a DQUOTE-wrapped value (#103).

    The new `AuthContext` id is computed over the *canonical* (DQUOTE-stripped)
    value so it matches the loader/L2; but the rotation file's `raw` is the
    untouched wire-form value the Executor must send.
    """

    box = {"t": 0.0}
    rc = _refresh()
    cookie_slot = ("user-c", "cookie")
    bare = "deadbeefdeadbeef"
    wire = f'"{bare}"'
    helper = AuthHelper(
        engagement_id=ENG,
        neo4j=_FakeNeo4j(),  # type: ignore[arg-type]
        rotation_path=tmp_path / "rotation.json",
        managed={
            cookie_slot: ManagedAuthContext(
                principal_label="user-c", slot="cookie", kind="cookie", refresh=rc
            )
        },
        env={},
        clock=lambda: box["t"],
        mechanisms={"command": lambda rc, env, verify: wire},
    )
    helper._schedule_all()
    assert helper.rotate(cookie_slot, reason="reactive") is True

    import json

    data = json.loads((tmp_path / "rotation.json").read_text())
    new_id = auth_context_id(ENG, compute_auth_hash("cookie", bare))
    # Hashed on the canonical (bare) form → same id the loader/L2 would compute.
    assert helper.id_to_slot[new_id] == cookie_slot
    # Wire-form raw survives un-stripped under the slot key.
    assert data["user-c:cookie"]["raw"] == wire


def test_rotate_threads_tls_verify_to_mechanism(tmp_path: Path) -> None:
    """`dispatch.tls_verify` reaches the refresh mechanism (oauth/http honour it)."""
    seen: list[bool | str] = []

    def _mech(rc: RefreshConfig, env: dict[str, str], verify: bool | str) -> str:
        seen.append(verify)
        return "TOK"

    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)
    helper.tls_verify = False
    helper.mechanisms["command"] = _mech
    assert helper.rotate(SLOT, reason="reactive") is True
    assert seen == [False]


def test_rotate_respects_rate_limit(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box, max_refreshes_per_hour=2)
    assert helper.rotate(SLOT, reason="reactive") is True
    assert helper.rotate(SLOT, reason="reactive") is True
    assert helper.rotate(SLOT, reason="reactive") is False  # 3rd within the hour blocked


def test_rotate_failed_mechanism_returns_false(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)

    def boom(rc: RefreshConfig, env: dict[str, str]) -> str:
        raise RuntimeError("idp down")

    helper.mechanisms["command"] = boom
    assert helper.rotate(SLOT, reason="proactive") is False
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
    """Reactive event carries the content-addressed id; the helper translates
    via `id_to_slot` to the rotation-stable slot key and rotates that."""
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


def test_poll_reactive_unmapped_id_is_acked_not_rotated(tmp_path: Path) -> None:
    """An `auth_invalid` for an id absent from `id_to_slot` (discovered-tier
    or another engagement's helper) is acked and dropped — never rotated."""
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)
    helper.streams = _FakeStream(  # type: ignore[assignment]
        [
            (
                "1-0",
                {
                    "kind": REACTIVE_AUTH_INVALID,
                    "engagement_id": str(ENG),
                    "auth_context_id": "ac-unmapped",
                },
            )
        ]
    )
    assert helper.poll_reactive(block_ms=0) == 0
    assert helper.streams.acked == ["1-0"]  # type: ignore[attr-defined]
    assert not (tmp_path / "rotation.json").exists()
    assert helper.neo4j.writes == []  # type: ignore[attr-defined]


def test_poll_reactive_ignores_other_engagement(tmp_path: Path) -> None:
    box = {"t": 0.0}
    helper = _helper(tmp_path, clock_box=box)
    helper.streams = _FakeStream(  # type: ignore[assignment]
        [("1-0", {"kind": REACTIVE_AUTH_INVALID, "engagement_id": "other", "auth_context_id": str(AC)})]
    )
    assert helper.poll_reactive(block_ms=0) == 0


# --- from_config -----------------------------------------------------------


def test_from_config_seeds_managed_by_slot_and_id_to_slot_from_graph(
    tmp_path: Path,
) -> None:
    """ADR-0049 / #119: `managed` keys on the declared `(principal_label, slot)`
    (one entry per refreshable slot, regardless of how many AuthContext
    generations exist); `id_to_slot` is seeded from the graph so a reactive
    event on ANY historical generation maps to the same slot."""

    from doo.setup.config import EngagementConfig
    from tests.test_loader import _base_config_dict

    d = _base_config_dict()
    d["engagement"]["id"] = str(ENG)
    d["principals"] = [
        {
            "label": "attacker-b",
            "auth_contexts": [
                {
                    "kind": "bearer",
                    "token": "${T}",
                    "refresh": {"mechanism": "command", "command": "true"},
                }
            ],
        }
    ]
    config = EngagementConfig.model_validate(d)
    fake = _FakeNeo4j(
        read_rows=[
            {"id": "ac-gen1", "label": "attacker-b", "slot": "bearer"},
            {"id": "ac-gen2", "label": "attacker-b", "slot": "bearer"},
        ]
    )
    helper = AuthHelper.from_config(
        config, neo4j=fake, rotation_path=tmp_path / "r.json", env={"T": "tok"}  # type: ignore[arg-type]
    )
    assert set(helper.managed) == {("attacker-b", "bearer")}
    assert helper.managed[("attacker-b", "bearer")].kind == "bearer"
    assert helper.id_to_slot[AuthContextId("ac-gen1")] == ("attacker-b", "bearer")
    assert helper.id_to_slot[AuthContextId("ac-gen2")] == ("attacker-b", "bearer")


# --- EnvSecretStore --------------------------------------------------------


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


def test_auth_material_importable() -> None:
    assert AuthMaterial(kind="bearer", raw="x", principal_label="p").tier == "declared"
