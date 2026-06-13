"""Per-`(test_class, role)` request constructors (ADR-0043).

A constructor is a **pure function** of `(DispatchTestCase, EvidenceObservation,
AuthMaterial)` → `ConcreteRequest`. The Interpreter's only authority over what
goes on the wire is which `RequestRole` to send next; **deterministic code**
constructs the request. No graph reads, no network, no LLM — unit-testable
table-driven against fixture inputs.

S1 ships `(idor, primary)` end-to-end. The registry is the seam every later
authz constructor (`baseline_victim` / `baseline_negative`, the other authz
classes) plugs into: a new confirmation strategy is "new enum value + new
constructor," not a prompt change (ADR-0043).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from doo.dispatch.executor.evidence import DispatchTestCase, EvidenceObservation
from doo.dispatch.models import ConcreteRequest, RequestRole
from doo.dispatch.secrets import AuthMaterial
from doo.events.slice4 import TestClass

# A constructor: pure `(testcase, evidence, auth material)` → `ConcreteRequest`.
# `auth` is the **attacker** material for `primary` (the TestCase's
# `auth_context_id`); `baseline_victim` constructors receive the victim's
# material instead. The constructor never sees a `Sender` or a graph client.
Constructor = Callable[
    [DispatchTestCase, EvidenceObservation, AuthMaterial], ConcreteRequest
]


class ConstructorMissingError(Exception):
    """No constructor registered for this `(test_class, role)`.

    Surfaces as `RunOutcome.outcome = constructor_missing` (ADR-0043 surfacing
    path: a test the Executor knows it cannot run is a question for the human,
    not a quiet gap).
    """


# Auth-carrying header/cookie names by `kind` (ADR-0012). The constructor swaps
# **only** these and strips any other auth-shaped headers from the evidence
# (replaying the victim's auth alongside the attacker's would defeat the test).
_AUTH_HEADERS = frozenset({"authorization", "x-api-key", "x-auth-token"})


def _splice_auth(
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    material: AuthMaterial,
    session_cookie_name: str | None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Swap the auth-carrying header/cookie to `material`; strip other auth.

    `bearer` / `basic_auth` / `api_key` → an `Authorization` (or kind-specific)
    header. `cookie` → the engagement's `session_cookie_names[0]`. Any *other*
    auth-shaped header from the evidence is dropped so the victim's credential
    cannot ride along (which would mask an authz hole).
    """

    # Strip every auth-carrying header from the evidence first.
    h = {k: v for k, v in headers.items() if k.lower() not in _AUTH_HEADERS}
    c = dict(cookies)
    if session_cookie_name is not None:
        c.pop(session_cookie_name, None)

    if material.kind == "bearer":
        h["Authorization"] = f"Bearer {material.raw}"
    elif material.kind == "basic_auth":
        h["Authorization"] = f"Basic {material.raw}"
    elif material.kind == "api_key":
        h["X-API-Key"] = material.raw
    elif material.kind == "cookie":
        name = session_cookie_name or "session"
        c[name] = material.raw
    return h, c


def _apply_hold(
    *, evidence: EvidenceObservation, hold: tuple[str, ...]
) -> tuple[str, dict[str, str]]:
    """Carry the held params verbatim from the evidence (ADR-0041 `hold`).

    `hold` names the params kept from the victim's observed request (e.g.
    principal A's `order_id`) while auth is swapped. For an authz `primary`,
    "apply hold" means the **entire concrete request shape** is replayed verbatim
    — path + query — and `hold` is the explicit subset the planner asserted is
    identity-bearing (recorded for the Interpreter's diff in S5+). An empty
    `hold` (e.g. a path-only IDOR) still replays the full evidence path.
    """

    return evidence.concrete_path, dict(evidence.query)


# ---------------------------------------------------------------------------
# (idor, primary): replay the victim's evidence under the attacker's auth.
# ---------------------------------------------------------------------------


def idor_primary(
    testcase: DispatchTestCase,
    evidence: EvidenceObservation,
    auth: AuthMaterial,
) -> ConcreteRequest:
    """The IDOR `primary`: the victim's request, attacker's `AuthContext` (ADR-0043).

    Picks the evidencing observation, applies `hold` (held params verbatim),
    swaps the auth-carrying header/cookie to the TestCase's `auth_context_id`
    material. Hazard resolution (S3) runs **inside** this constructor before the
    return; S1 carries no resolver — `replay_hazards` is surfaced upstream as
    `hazard_unresolved` instead.
    """

    path, query = _apply_hold(evidence=evidence, hold=testcase.hold)
    headers, cookies = _splice_auth(
        headers=evidence.headers,
        cookies=evidence.cookies,
        material=auth,
        # The session-cookie name is engagement-level; the run driver passes it
        # via the evidence headers/cookies it loaded. For S1 the bearer path is
        # the proven one; cookie-auth engagements get the right name in S3 when
        # the resolver registry takes the `EngagementConfig`.
        session_cookie_name=None,
    )
    return ConcreteRequest(
        method=evidence.method,
        host=evidence.host,
        path=path,
        path_template=evidence.path_template,
        query=tuple(sorted(query.items())),
        headers=tuple(sorted(headers.items())),
        cookies=tuple(sorted(cookies.items())),
        # Body replay (POST/PUT IDOR) lands with the hazard-resolver tracer (S3):
        # it needs the blob read + content-type-aware splice. S1 proves GET-shape
        # IDOR end-to-end.
        body=None,
        body_content_type=evidence.body_content_type,
        auth_context_id=testcase.auth_context_id,
    )


# ---------------------------------------------------------------------------
# Registry.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Key:
    test_class: TestClass
    role: RequestRole


_REGISTRY: dict[_Key, Constructor] = {
    _Key("idor", "primary"): idor_primary,
}


def constructor_for(test_class: str, role: RequestRole) -> Constructor:
    """Look up the registered constructor; raise `ConstructorMissingError` if absent."""

    fn = _REGISTRY.get(_Key(test_class, role))  # type: ignore[arg-type]
    if fn is None:
        raise ConstructorMissingError(
            f"no constructor registered for ({test_class!r}, {role!r}); "
            "this test_class/role is not yet executable (surfaces as "
            "RunOutcome.constructor_missing)"
        )
    return fn


def has_constructor(test_class: str, role: RequestRole) -> bool:
    return _Key(test_class, role) in _REGISTRY  # type: ignore[arg-type]
