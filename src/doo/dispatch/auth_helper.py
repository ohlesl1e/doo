"""Auth-helper sibling process: rotates declared `AuthContext`s (ADR-0014, #91).

A separate process the tester starts (`doo auth-helper run --engagement …`),
**never** the agent. It holds the refresh credentials (in its OWN env) and is the
only party that mints new token material — the same trust split as the kill-switch
keepalive (the agent only ever *reads* refreshed material via the rotation file).

Two triggers:

- **Proactive**: per declared AuthContext with a `validity_window_s`, refresh at
  `now + validity_window_s − margin_s` (ahead of expiry).
- **Reactive**: consume the `auth_invalid` events the S4 classifier emits onto the
  `auth-reactive` Redis stream; refresh the named AuthContext.

Both are **rate-limited** per AuthContext (default ≤3/hour) so a dead-token storm
cannot hammer the IdP. On a successful rotation the helper: runs the mechanism
(`command` / `oauth_refresh` / `http`, credentials from the helper's env) → writes
a new `AuthContext` node (`OF_PRINCIPAL` → the same Principal as the old one), marks
the old `status="expired"`, and writes the new raw material to the rotation file
the Executor's `RotatableSecretStore` reads. No LLM, deterministic control.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType

from doo.canonical.cookies import canonical_credential_value
from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.dispatch.reactive import AUTH_REACTIVE_STREAM, REACTIVE_AUTH_INVALID
from doo.dispatch.secrets import write_rotation_entry
from doo.ids import AuthContextId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import StreamClient
from doo.observability.logging import get_logger
from doo.setup.config import AuthContextKind, EngagementConfig, RefreshConfig

log = get_logger(__name__)

# Rate-limit window: rotations-per-AuthContext are counted over this span.
_RATE_WINDOW_S = 3600.0


class RefreshError(Exception):
    """A refresh mechanism failed to produce new token material."""


# ---------------------------------------------------------------------------
# Refresh mechanisms — `(refresh_config, env) → new raw token`. Credentials are
# read from the helper's env; never inline, never the dispatcher's env.
# ---------------------------------------------------------------------------

RefreshMechanismFn = Callable[[RefreshConfig, dict[str, str]], str]


def _refresh_command(rc: RefreshConfig, env: dict[str, str]) -> str:
    """Shell out to the tester's script; the fresh token is its stdout."""

    assert rc.command is not None
    proc = subprocess.run(  # noqa: S602 - tester-authored command, helper-host only
        rc.command,
        shell=True,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RefreshError(
            f"refresh command exited {proc.returncode}: {proc.stderr.strip()[:200]}"
        )
    token = proc.stdout.strip()
    if not token:
        raise RefreshError("refresh command produced no token on stdout")
    return token


def _refresh_oauth(rc: RefreshConfig, env: dict[str, str]) -> str:
    """OAuth2 refresh-grant POST; reads the refresh token + client creds from env."""

    import httpx

    assert rc.token_url is not None and rc.refresh_token_env is not None
    refresh_token = env.get(rc.refresh_token_env)
    if not refresh_token:
        raise RefreshError(f"oauth_refresh: env ${{{rc.refresh_token_env}}} is unset")
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if rc.client_id_env and env.get(rc.client_id_env):
        data["client_id"] = env[rc.client_id_env]
    if rc.client_secret_env and env.get(rc.client_secret_env):
        data["client_secret"] = env[rc.client_secret_env]
    resp = httpx.post(rc.token_url, data=data, timeout=30.0)
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise RefreshError("oauth_refresh: response carried no access_token")
    return str(token)


def _refresh_http(rc: RefreshConfig, env: dict[str, str]) -> str:
    """A templated HTTP request; `${VAR}` in the body is substituted from env."""

    import re

    import httpx

    assert rc.http_url is not None
    body = rc.http_body or ""
    body = re.sub(r"\$\{(\w+)\}", lambda m: env.get(m.group(1), ""), body)
    resp = httpx.request(
        rc.http_method, rc.http_url, headers=rc.http_headers, content=body, timeout=30.0
    )
    resp.raise_for_status()
    token = resp.text.strip()
    if not token:
        raise RefreshError("http refresh: response body was empty")
    return token


_MECHANISMS: dict[str, RefreshMechanismFn] = {
    "command": _refresh_command,
    "oauth_refresh": _refresh_oauth,
    "http": _refresh_http,
}


def _decode_credential_claims(
    kind: str, canonical: str
) -> tuple[dict[str, object], dict[str, str] | None]:
    """Best-effort decode of a rotated credential's identity claims (ADR-0048).

    `canonical` is the already-normalised credential value (#103). For
    `kind ∈ {bearer, cookie}` attempts an unverified JWT decode; an opaque /
    non-JWT credential is non-fatal and yields `({}, None)`. Mirrors the
    loader's `_resolve_auth_context`: scalar claims only, `validity_window`
    derived from `exp`. The raw token never escapes this function.
    """

    if kind not in ("bearer", "cookie"):
        return {}, None
    try:
        import jwt

        decoded = jwt.decode(
            canonical, options={"verify_signature": False, "verify_exp": False}
        )
    except Exception:  # noqa: BLE001 - any decode failure is opaque-token
        return {}, None
    if not isinstance(decoded, dict):
        return {}, None
    claims: dict[str, object] = {
        str(k): v
        for k, v in decoded.items()
        if isinstance(v, str | int | float | bool) or v is None
    }
    validity_window: dict[str, str] | None = None
    exp = decoded.get("exp")
    if isinstance(exp, int | float):
        validity_window = {
            "exp": datetime.fromtimestamp(float(exp), tz=UTC).isoformat()
        }
    return claims, validity_window


# ---------------------------------------------------------------------------
# Managed AuthContext + rate limiter.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ManagedAuthContext:
    """One declared AuthContext the helper rotates."""

    auth_context_id: AuthContextId
    kind: AuthContextKind
    principal_label: str
    refresh: RefreshConfig


@dataclass
class RateLimiter:
    """Per-AuthContext rotation rate limiter (ADR-0014)."""

    clock: Callable[[], float] = time.monotonic
    _events: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, key: str, *, max_per_window: int) -> bool:
        now = self.clock()
        recent = [t for t in self._events.get(key, []) if now - t < _RATE_WINDOW_S]
        self._events[key] = recent
        return len(recent) < max_per_window

    def record(self, key: str) -> None:
        self._events.setdefault(key, []).append(self.clock())


# ---------------------------------------------------------------------------
# The helper.
# ---------------------------------------------------------------------------


@dataclass
class AuthHelper:
    """Rotates declared AuthContexts for one engagement (ADR-0014, #91)."""

    engagement_id: EngagementId
    neo4j: Neo4jClient
    rotation_path: Path
    managed: dict[AuthContextId, ManagedAuthContext]
    streams: StreamClient | None = None
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    clock: Callable[[], float] = time.monotonic
    mechanisms: dict[str, RefreshMechanismFn] = field(
        default_factory=lambda: dict(_MECHANISMS)
    )
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    consumer_group: str = "auth-helper"
    _next_refresh_at: dict[AuthContextId, float] = field(default_factory=dict)

    @classmethod
    def from_config(
        cls,
        config: EngagementConfig,
        *,
        neo4j: Neo4jClient,
        rotation_path: Path,
        streams: StreamClient | None = None,
        env: dict[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> AuthHelper:
        e = env if env is not None else dict(os.environ)
        eid = config.engagement.id
        managed: dict[AuthContextId, ManagedAuthContext] = {}
        for principal in config.principals:
            for decl in principal.auth_contexts:
                if decl.refresh is None:
                    continue
                raw = e.get(decl.env_var_name)
                if not raw:
                    continue  # no current material → nothing to track yet
                ac_id = auth_context_id(
                    eid,
                    compute_auth_hash(
                        decl.kind, canonical_credential_value(decl.kind, raw)
                    ),
                )
                managed[ac_id] = ManagedAuthContext(
                    auth_context_id=ac_id,
                    kind=decl.kind,
                    principal_label=principal.label,
                    refresh=decl.refresh,
                )
        helper = cls(
            engagement_id=eid,
            neo4j=neo4j,
            rotation_path=rotation_path,
            managed=managed,
            streams=streams,
            env=e,
            clock=clock,
        )
        helper._schedule_all()
        return helper

    def _schedule_all(self) -> None:
        now = self.clock()
        for ac_id, m in self.managed.items():
            if m.refresh.validity_window_s is not None:
                self._next_refresh_at[ac_id] = (
                    now + m.refresh.validity_window_s - m.refresh.margin_s
                )

    def due_proactively(self, now: float | None = None) -> list[AuthContextId]:
        """AuthContexts whose proactive refresh time has arrived (ADR-0014)."""

        t = now if now is not None else self.clock()
        return [
            ac_id for ac_id, at in self._next_refresh_at.items() if at <= t
        ]

    def rotate(self, ac_id: AuthContextId, *, reason: str) -> bool:
        """Rotate one AuthContext: mechanism → new node + rotation-file material.

        Returns True on success, False if rate-limited or the mechanism failed.
        Reschedules the proactive timer on success.
        """

        m = self.managed.get(ac_id)
        if m is None:
            log.warning(
                "auth_helper.unmanaged", engagement_id=self.engagement_id, auth_context_id=ac_id
            )
            return False
        if not self.rate_limiter.allow(
            str(ac_id), max_per_window=m.refresh.max_refreshes_per_hour
        ):
            log.warning(
                "auth_helper.rate_limited",
                engagement_id=self.engagement_id,
                auth_context_id=ac_id,
                reason=reason,
                max_per_hour=m.refresh.max_refreshes_per_hour,
            )
            return False

        mechanism = self.mechanisms[m.refresh.mechanism]
        try:
            new_raw = mechanism(m.refresh, self.env)
        except Exception as exc:  # noqa: BLE001 - any mechanism failure is non-fatal
            log.warning(
                "auth_helper.refresh_failed",
                engagement_id=self.engagement_id,
                auth_context_id=ac_id,
                mechanism=m.refresh.mechanism,
                error=str(exc),
            )
            return False

        self.rate_limiter.record(str(ac_id))
        # Hash the canonical credential form (#103); `new_raw` itself stays the
        # wire-form value written to the rotation file for the Executor to send.
        canonical = canonical_credential_value(m.kind, new_raw)
        new_hash = compute_auth_hash(m.kind, canonical)
        new_id = auth_context_id(self.engagement_id, new_hash)
        # Decode the rotated credential's identity claims (ADR-0048): the new
        # declared AuthContext carries `identity_claims` + `validity_window`
        # exactly like a loader-written one, so priority-0 reconciliation and
        # the retroactive sweep see the rotated token's identity. Non-fatal on
        # an opaque (non-JWT) credential — empty claims, no window.
        identity_claims, validity_window = _decode_credential_claims(m.kind, canonical)
        self._rotate_graph(
            old_id=ac_id,
            new_id=new_id,
            new_hash=new_hash,
            kind=m.kind,
            identity_claims=identity_claims,
            validity_window=validity_window,
        )
        write_rotation_entry(
            self.rotation_path,
            auth_context_id=new_id,
            raw=new_raw,
            kind=m.kind,
            principal_label=m.principal_label,
        )
        # The selection/TestCases still reference the OLD id; also write the new
        # material under the OLD id so in-flight TestCases pick it up immediately.
        write_rotation_entry(
            self.rotation_path,
            auth_context_id=ac_id,
            raw=new_raw,
            kind=m.kind,
            principal_label=m.principal_label,
        )
        # Track the new id as managed (so a subsequent reactive event on it works)
        # and reschedule the proactive timer.
        self.managed[new_id] = ManagedAuthContext(
            auth_context_id=new_id, kind=m.kind,
            principal_label=m.principal_label, refresh=m.refresh,
        )
        if m.refresh.validity_window_s is not None:
            self._next_refresh_at[ac_id] = (
                self.clock() + m.refresh.validity_window_s - m.refresh.margin_s
            )
        log.info(
            "auth_helper.rotated",
            engagement_id=self.engagement_id,
            old_auth_context_id=ac_id,
            new_auth_context_id=new_id,
            principal_label=m.principal_label,
            mechanism=m.refresh.mechanism,
            reason=reason,
        )
        return True

    def _rotate_graph(
        self,
        *,
        old_id: AuthContextId,
        new_id: AuthContextId,
        new_hash: str,
        kind: AuthContextKind,
        identity_claims: dict[str, object],
        validity_window: dict[str, str] | None,
    ) -> None:
        now = datetime.now(UTC)
        self.neo4j.execute_write(
            """
            MATCH (old:AuthContext {engagement_id: $eid, id: $old_id})
                  -[:OF_PRINCIPAL]->(p:Principal)
            SET old.status = 'expired', old.last_seen = $now
            MERGE (new:AuthContext {engagement_id: $eid, auth_hash: $new_hash})
            ON CREATE SET new.id = $new_id, new.token_kind = $kind, new.tier = 'declared',
                          new.slot = coalesce(old.slot, old.token_kind),
                          new.is_anonymous = false, new.source = 'auth-helper',
                          new.confidence = 1.0, new.confidence_method = 'heuristic',
                          new.first_seen = $now, new.ingested_at = $now
            SET new.last_seen = $now, new.status = 'active',
                new.identity_claims = $identity_claims,
                new.validity_window = $validity_window
            MERGE (new)-[:OF_PRINCIPAL]->(p)
            """,
            eid=self.engagement_id,
            old_id=str(old_id),
            new_id=str(new_id),
            new_hash=new_hash,
            kind=kind,
            now=now,
            identity_claims=json.dumps(identity_claims, sort_keys=True),
            validity_window=(
                json.dumps(validity_window, sort_keys=True)
                if validity_window is not None
                else None
            ),
        )

    def poll_reactive(self, *, block_ms: int = 1000) -> int:
        """Drain pending `auth_invalid` events; rotate the named AuthContexts.

        Returns the number of rotations performed (rate-limited ones excluded).
        Idempotent w.r.t. stream acks; safe to call in a loop.
        """

        if self.streams is None:
            return 0
        self.streams.ensure_group(AUTH_REACTIVE_STREAM, self.consumer_group)
        rotations = 0
        for msg_id, payload in self.streams.read_group(
            AUTH_REACTIVE_STREAM, self.consumer_group, "helper", block_ms=block_ms
        ):
            if (
                payload.get("kind") == REACTIVE_AUTH_INVALID
                and payload.get("engagement_id") == str(self.engagement_id)
            ):
                ac_id = AuthContextId(str(payload.get("auth_context_id", "")))
                if ac_id in self.managed and self.rotate(ac_id, reason="reactive"):
                    rotations += 1
            self.streams.ack(AUTH_REACTIVE_STREAM, self.consumer_group, msg_id)
        return rotations

    def run(
        self,
        *,
        stop_event: threading.Event | None = None,
        install_signal_handlers: bool = True,
        tick_s: float = 1.0,
    ) -> int:
        """Run proactive + reactive rotation until SIGTERM / `stop_event` (ADR-0014)."""

        stop = stop_event if stop_event is not None else threading.Event()
        if install_signal_handlers:
            def _handle(signum: int, _frame: FrameType | None) -> None:
                log.info("auth_helper.sigterm", engagement_id=self.engagement_id, signal=signum)
                stop.set()

            signal.signal(signal.SIGTERM, _handle)
            signal.signal(signal.SIGINT, _handle)

        log.info(
            "auth_helper.started",
            engagement_id=self.engagement_id,
            managed=len(self.managed),
            rotation_path=str(self.rotation_path),
        )
        while not stop.is_set():
            for ac_id in self.due_proactively():
                self.rotate(ac_id, reason="proactive")
            self.poll_reactive(block_ms=int(tick_s * 1000))
            stop.wait(timeout=tick_s)
        log.info("auth_helper.stopped", engagement_id=self.engagement_id)
        return 0


__all__ = [
    "AuthHelper",
    "ManagedAuthContext",
    "RateLimiter",
    "RefreshError",
    "RefreshMechanismFn",
]
