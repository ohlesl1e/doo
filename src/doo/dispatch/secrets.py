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

import os
from dataclasses import dataclass
from typing import Protocol

from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.ids import AuthContextId, EngagementId
from doo.setup.config import AuthContextKind, EngagementConfig


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


@dataclass(frozen=True, slots=True)
class EnvSecretStore:
    """Env-var-backed `SecretStore` built from a loaded `EngagementConfig`.

    Re-resolves each declared `auth_contexts[].token` (`${VAR}`) from `env` at
    construction, recomputes the deterministic `auth_context_id`, and indexes
    `(kind, raw)` by it. Same discipline as `setup.loader`: a missing env var is
    a loud, named error at run-arm time, not a silent skip.
    """

    by_id: dict[AuthContextId, AuthMaterial]

    @classmethod
    def from_config(
        cls, config: EngagementConfig, *, env: dict[str, str] | None = None
    ) -> EnvSecretStore:
        e = env if env is not None else dict(os.environ)
        eid: EngagementId = config.engagement.id
        by_id: dict[AuthContextId, AuthMaterial] = {}
        for principal in config.principals:
            for decl in principal.auth_contexts:
                raw = e.get(decl.env_var_name)
                if raw is None or raw == "":
                    raise UnknownAuthContextError(
                        f"declared principal {principal.label!r}: token env-var "
                        f"${{{decl.env_var_name}}} is unset at dispatch time "
                        "(ADR-0012: tokens come from the environment)"
                    )
                ah = compute_auth_hash(decl.kind, raw)
                ac_id = auth_context_id(eid, ah)
                by_id[ac_id] = AuthMaterial(
                    kind=decl.kind, raw=raw, principal_label=principal.label
                )
        return cls(by_id=by_id)

    def material_for(self, auth_context_id: AuthContextId) -> AuthMaterial | None:
        return self.by_id.get(auth_context_id)
