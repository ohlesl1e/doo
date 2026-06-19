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
from doo.events.execution import TestClass

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
# (idor, baseline_victim): the same held object under the OWNER'S auth.
# ---------------------------------------------------------------------------


def idor_baseline_victim(
    testcase: DispatchTestCase,
    evidence: EvidenceObservation,
    auth: AuthMaterial,
) -> ConcreteRequest:
    """The IDOR `baseline_victim`: the victim's request under the **victim's** auth.

    The control the Interpreter diffs the `primary` against (ADR-0043): a
    generic-200 that returns the same body for everyone is NOT an IDOR. `auth`
    here is the **victim's** material (the evidence's `victim_auth_context_id`,
    not the TestCase's attacker `auth_context_id`); the run driver looks it up
    and passes it. This send is *not* a new TestCase (a control, not a
    hypothesis) but it IS a real send through the Dispatcher under the victim's
    auth — so `AuthContext` rotation (ADR-0014) and rate limits apply.
    """

    path, query = _apply_hold(evidence=evidence, hold=testcase.hold)
    headers, cookies = _splice_auth(
        headers=evidence.headers,
        cookies=evidence.cookies,
        material=auth,
        session_cookie_name=None,
    )
    # The send is OBSERVED_UNDER the victim's AuthContext, not the TestCase's.
    victim_ac = evidence.victim_auth_context_id or testcase.auth_context_id
    return ConcreteRequest(
        method=evidence.method,
        host=evidence.host,
        path=path,
        path_template=evidence.path_template,
        query=tuple(sorted(query.items())),
        headers=tuple(sorted(headers.items())),
        cookies=tuple(sorted(cookies.items())),
        body=None,
        body_content_type=evidence.body_content_type,
        auth_context_id=victim_ac,
    )


# ---------------------------------------------------------------------------
# (idor, baseline_negative): held identifier swapped to a known-nonexistent value.
# ---------------------------------------------------------------------------

# A reserved, structurally-valid identifier that no real target should have
# minted (cuid-shaped, kebab-prefixed). The Interpreter compares the `primary`
# against this to rule out "any id 200s" — if even a nonexistent id returns the
# same body, the `primary`'s 200 proves nothing.
_NONEXISTENT_SENTINEL = "doo-nonexistent-000000000000"


def idor_baseline_negative(
    testcase: DispatchTestCase,
    evidence: EvidenceObservation,
    auth: AuthMaterial,
) -> ConcreteRequest:
    """The IDOR `baseline_negative`: held id → known-nonexistent, attacker's auth.

    Rules out "any id 200s" (ADR-0043). The held identifier in the path / query
    is swapped to a sentinel no real target should have; everything else
    (including the attacker auth, since we're testing the *attacker's* view of a
    nonexistent resource) matches the `primary`.
    """

    # Swap each held param: in the path, replace the segment that matches the
    # evidence's concrete value at the `{param}` position; in the query, replace
    # the named key. `hold` carries human-readable labels (slice-3); for S3 we
    # swap the **first variable path segment** (the `{…}` template position) and
    # any query key whose name appears in `hold`.
    path = _swap_path_variable(
        evidence.concrete_path, evidence.path_template, _NONEXISTENT_SENTINEL
    )
    query = {
        k: (_NONEXISTENT_SENTINEL if k in set(testcase.hold) else v)
        for k, v in evidence.query.items()
    }
    headers, cookies = _splice_auth(
        headers=evidence.headers,
        cookies=evidence.cookies,
        material=auth,
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
        body=None,
        body_content_type=evidence.body_content_type,
        auth_context_id=testcase.auth_context_id,
    )


# ---------------------------------------------------------------------------
# (auth-bypass, primary): the victim's request with NO credential at all.
# ---------------------------------------------------------------------------


def authbypass_primary(
    testcase: DispatchTestCase,
    evidence: EvidenceObservation,
    auth: AuthMaterial,
) -> ConcreteRequest:
    """The auth-bypass `primary`: replay the victim's request ANONYMOUSLY (ADR-0043).

    Tests whether the endpoint is reachable with no authentication at all: every
    auth-carrying header is stripped and NO material is spliced (the `auth`
    argument is ignored on purpose); cookies — which carry the session — are
    dropped wholesale. The send is still attributed to the TestCase's
    `auth_context_id` for the `EXECUTED_AS` edge (provenance), even though the wire
    request carries no credential.
    """

    path, query = _apply_hold(evidence=evidence, hold=testcase.hold)
    headers = {k: v for k, v in evidence.headers.items() if k.lower() not in _AUTH_HEADERS}
    return ConcreteRequest(
        method=evidence.method,
        host=evidence.host,
        path=path,
        path_template=evidence.path_template,
        query=tuple(sorted(query.items())),
        headers=tuple(sorted(headers.items())),
        cookies=(),  # drop the session cookie(s) — anonymous send.
        body=None,
        body_content_type=evidence.body_content_type,
        auth_context_id=testcase.auth_context_id,
    )


def _swap_path_variable(concrete: str, template: str, replacement: str) -> str:
    """Replace each `{…}`-template segment's concrete value with `replacement`.

    `/orders/{order_id}` × `/orders/123` → `/orders/<replacement>`. Segments
    where the template is literal stay verbatim. When the template has no
    `{…}` segment, the concrete path is returned unchanged (a query-param IDOR
    handles the swap via `query` instead).
    """

    c_segs = [s for s in concrete.split("/") if s != ""]
    t_segs = [s for s in template.split("/") if s != ""]
    out: list[str] = []
    for i, cs in enumerate(c_segs):
        ts = t_segs[i] if i < len(t_segs) else cs
        out.append(replacement if ts.startswith("{") and ts.endswith("}") else cs)
    return "/" + "/".join(out)


# ---------------------------------------------------------------------------
# Registry.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Key:
    test_class: TestClass
    role: RequestRole


# The authz classes are all evidence-replays under a swapped identity (ADR-0043):
# `primary` replays under the attacker's auth, `baseline_victim` under the
# victim's, `baseline_negative` swaps the held id to a nonexistent sentinel. They
# share the idor constructors; only `auth-bypass primary` differs (strips all
# auth). `boundary-violation` resolves its evidence via the TrustBoundary's
# `DERIVED_FROM` chain — handled upstream by `load_evidence`, so the constructor is
# identical (ADR-0039).
_REGISTRY: dict[_Key, Constructor] = {
    _Key("idor", "primary"): idor_primary,
    _Key("idor", "baseline_victim"): idor_baseline_victim,
    _Key("idor", "baseline_negative"): idor_baseline_negative,
    _Key("bola", "primary"): idor_primary,
    _Key("bola", "baseline_victim"): idor_baseline_victim,
    _Key("bola", "baseline_negative"): idor_baseline_negative,
    _Key("privilege-escalation", "primary"): idor_primary,
    _Key("privilege-escalation", "baseline_victim"): idor_baseline_victim,
    _Key("boundary-violation", "primary"): idor_primary,
    _Key("boundary-violation", "baseline_victim"): idor_baseline_victim,
    _Key("auth-bypass", "primary"): authbypass_primary,
    _Key("auth-bypass", "baseline_victim"): idor_baseline_victim,
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
