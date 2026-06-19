"""`SecretStore` — live `AuthContext` material at dispatch time (ADR-0012/0015).

The graph carries only `auth_hash` (the secrets boundary, ADR-0015): raw tokens
are hashed at load and discarded. The Executor needs the **raw** token to splice
into the auth-carrying header/cookie. This module re-resolves the engagement's
declared `${ENV_VAR}` references at run-arm time, recomputes each
`auth_context_id`, and builds an in-process `{auth_context_id: (kind, raw)}` map.

Raw material lives only here, in-process, for the lifetime of a dispatch run. It
is never written to the graph, the ledger, blobs, or logs (the same discipline as
`setup.loader._resolve_auth_context`).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from doo.canonical.cookies import canonical_credential_value
from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.ids import AuthContextId, EngagementId
from doo.setup.config import AuthContextKind, EngagementConfig

if TYPE_CHECKING:
    from doo.infra.neo4j_driver import Neo4jClient


@dataclass(frozen=True, slots=True)
class AuthMaterial:
    """One `AuthContext`'s live token material.

    `kind` says where to splice it (`bearer` → `Authorization: Bearer <raw>`;
    `cookie` → the `session_cookie_names[0]` cookie; `api_key` → the declared
    header; `basic_auth` → `Authorization: Basic <raw>`). `principal_label` and
    `tier` ride along for the OPA `principal_tier` field (ADR-0046).
    """

    kind: AuthContextKind
    raw: str
    principal_label: str
    tier: str = "declared"


class SecretStore(Protocol):
    """Maps an `auth_context_id` to its live token material at dispatch time."""

    def material_for(self, auth_context_id: AuthContextId) -> AuthMaterial | None: ...


class UnknownAuthContextError(Exception):
    """The TestCase's `auth_context_id` has no resolvable live material.

    A discovered (non-declared) `AuthContext` has no `${VAR}` reference; for now
    the Executor refuses such tests with `hazard_unresolved` (ADR-0043 surfacing
    path) rather than guessing. The slice-4 auth-helper sibling process
    (ADR-0014) is where rotated declared material lands.
    """


class SlotMaterialMissing(UnknownAuthContextError):
    """A declared `(principal_label, slot)` exists in the graph but has no live
    material (env var unset AND no rotation entry). ADR-0049 distinguishes this
    from a discovered-tier id (`material_for` → `None`): the former is an
    operator/config error, the latter is an un-armable TestCase by design.
    """

    def __init__(self, *, principal_label: str, slot: str) -> None:
        self.principal_label = principal_label
        self.slot = slot
        super().__init__(
            f"declared principal {principal_label!r} slot {slot!r} has no live "
            "material (env unset and no rotation entry)"
        )


@dataclass(frozen=True, slots=True)
class EnvSecretStore:
    """Env-var-backed `SecretStore` built from a loaded `EngagementConfig`.

    Re-resolves each declared `auth_contexts[].token` (`${VAR}`) from `env` at
    construction, recomputes the deterministic `auth_context_id`, and indexes
    `(kind, raw)` by it. Same discipline as `setup.loader`: a missing env var is
    a loud, named error at run-arm time, not a silent skip.
    """

    by_id: dict[AuthContextId, AuthMaterial]
    by_slot: dict[tuple[str, str], AuthMaterial]

    @classmethod
    def from_config(
        cls, config: EngagementConfig, *, env: dict[str, str] | None = None
    ) -> EnvSecretStore:
        e = env if env is not None else dict(os.environ)
        eid: EngagementId = config.engagement.id
        by_id: dict[AuthContextId, AuthMaterial] = {}
        by_slot: dict[tuple[str, str], AuthMaterial] = {}
        for principal in config.principals:
            for decl in principal.auth_contexts:
                raw = e.get(decl.env_var_name)
                if raw is None or raw == "":
                    raise UnknownAuthContextError(
                        f"declared principal {principal.label!r}: token env-var "
                        f"${{{decl.env_var_name}}} is unset at dispatch time "
                        "(ADR-0012: tokens come from the environment)"
                    )
                # Hash the canonical credential form so the id matches the
                # loader's (and L2's) `AuthContext` (#103); `raw` stays the
                # wire-form value the Executor splices into the request.
                ah = compute_auth_hash(
                    decl.kind, canonical_credential_value(decl.kind, raw)
                )
                ac_id = auth_context_id(eid, ah)
                mat = AuthMaterial(
                    kind=decl.kind, raw=raw, principal_label=principal.label
                )
                by_id[ac_id] = mat
                # ADR-0049: the rotation-stable key. T1 guarantees `slot` is
                # always populated post-validation (defaults to `kind`).
                assert decl.slot is not None
                by_slot[(principal.label, decl.slot)] = mat
        return cls(by_id=by_id, by_slot=by_slot)

    def material_for(self, auth_context_id: AuthContextId) -> AuthMaterial | None:
        return self.by_id.get(auth_context_id)


def build_declared_slot_map(
    neo4j: Neo4jClient, engagement_id: EngagementId
) -> dict[AuthContextId, tuple[str, str]]:
    """One Cypher at run-arm: every declared AC id (all generations) → (principal_label, slot).

    ADR-0049: a TestCase carries the `auth_context_id` of the AuthContext
    generation it was *planned* against, which may have since rotated. This map
    lets the Executor translate any historical declared id to its rotation-stable
    `(principal_label, slot)` key, and from there to live material.
    """

    rows = neo4j.execute_read(
        """
        MATCH (ac:AuthContext {engagement_id: $eid})-[:OF_PRINCIPAL]->(p:Principal)
        WHERE ac.tier = 'declared'
        RETURN ac.id AS id, p.label AS label, coalesce(ac.slot, ac.token_kind) AS slot
        """,
        eid=str(engagement_id),
    )
    return {
        AuthContextId(str(r["id"])): (str(r["label"]), str(r["slot"])) for r in rows
    }


@dataclass(frozen=True, slots=True)
class SlotResolvingSecretStore:
    """ADR-0049: secrets lookup keys on the rotation-stable `(principal_label, slot)`,
    not the content-addressed `auth_context_id`.

    The G5 symptom this fixes: a TestCase planned at engagement-start carries an
    `auth_context_id` derived from the *then*-current token; by run-arm the env
    var holds a fresh token, so `EnvSecretStore.by_id` misses and the run refuses
    every authz test as `hazard_unresolved`. The slot indirection makes "alice's
    session cookie" the lookup key, which is stable across rotations.

    Resolution order (first hit wins):

    1. anonymous → placeholder material;
    2. `graph_map` translates the (possibly stale) id → `(principal_label, slot)`;
    3. rotation overlay on that slot — re-read on each call, so a mid-run
       helper write is picked up without a dispatch restart, and beats a
       stale env-held token;
    4. `env.by_id` — env-derived id matches (no rotation since plan; also the
       fallback when `graph_map` is incomplete);
    5. `graph_map` miss AND `by_id` miss → `None` (discovered-tier / genuinely
       unknown, un-armable by design);
    6. `env.by_slot` — the engagement-start declared material;
    7. `SlotMaterialMissing` — declared slot with neither overlay nor env.
    """

    graph_map: dict[AuthContextId, tuple[str, str]]
    env: EnvSecretStore
    anon_id: AuthContextId
    rotation_path: Path | None = None

    def _overlay(self) -> dict[str, dict[str, str]]:
        if self.rotation_path is None or not self.rotation_path.exists():
            return {}
        try:
            data: dict[str, dict[str, str]] = json.loads(self.rotation_path.read_text())
            return data
        except (json.JSONDecodeError, OSError):
            return {}

    def material_for(self, auth_context_id: AuthContextId) -> AuthMaterial | None:
        if auth_context_id == self.anon_id:
            # The anon constructors ignore `auth`; placeholder satisfies the
            # `AuthMaterial` Literal type and the OPA `principal_tier` field.
            return AuthMaterial(kind="bearer", raw="", principal_label="anonymous")
        slot_key = self.graph_map.get(auth_context_id)
        if slot_key is not None:
            entry = self._overlay().get(f"{slot_key[0]}:{slot_key[1]}")
            if entry is not None and entry.get("raw"):
                return AuthMaterial(
                    kind=entry["kind"],  # type: ignore[arg-type]
                    raw=entry["raw"],
                    principal_label=slot_key[0],
                )
        # Env-derived id matches (no rotation since plan-time); also covers a
        # declared id the graph_map missed (loader not yet run).
        hit = self.env.material_for(auth_context_id)
        if hit is not None:
            return hit
        if slot_key is None:
            # Genuinely unknown / discovered-tier — un-armable by design.
            return None
        mat = self.env.by_slot.get(slot_key)
        if mat is None:
            raise SlotMaterialMissing(principal_label=slot_key[0], slot=slot_key[1])
        return mat


def write_rotation_entry(
    rotation_path: Path,
    *,
    principal_label: str,
    slot: str,
    raw: str,
    kind: str,
) -> None:
    """Write/overwrite one rotated credential slot's material into the rotation file.

    ADR-0049: keyed on the rotation-stable `"{principal_label}:{slot}"`, not the
    content-addressed `auth_context_id` — one entry per slot, overwritten on each
    rotation. Called by the auth-helper after a successful refresh; the Executor's
    `SlotResolvingSecretStore` re-reads it on the next `material_for`. The file
    holds raw tokens — it lives on the helper/agent host only, never the graph
    (ADR-0015).
    """

    data: dict[str, dict[str, str]] = {}
    if rotation_path.exists():
        try:
            data = json.loads(rotation_path.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    data[f"{principal_label}:{slot}"] = {"raw": raw, "kind": kind}
    rotation_path.parent.mkdir(parents=True, exist_ok=True)
    rotation_path.write_text(json.dumps(data, indent=2))
