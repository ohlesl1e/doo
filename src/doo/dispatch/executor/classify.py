"""Deterministic `dispatch_status` classifier (ADR-0013, S1-minimal).

S1 ships the minimal status-based rule: any HTTP status the target returned is
`ok` (the bytes reached the test path; the Interpreter judges what they mean,
ADR-0045); a transport-layer failure is `transport_error`; a Dispatcher-gate
deny is `dispatcher_blocked` / `rate_limited`. The authz-4xx disambiguation
(liveness probe → `auth_invalid` vs `replay_invalid` vs genuine `ok`, ADR-0044)
is S4 — the seam is the `test_class` parameter this function already takes.

The classifier is **deterministic** (CLAUDE.md hard rule): it never asks the
Interpreter, and it is the only code that sets `dispatch_status`.
"""

from __future__ import annotations

from doo.dispatch.executor.send import HttpResponse
from doo.dispatch.models import RequestRole
from doo.events.slice4 import DispatchStatus, TestClass

# Authz `test_class`es whose 4xx-on-`primary` is *not* immediately `auth_invalid`
# (ADR-0044 amendment). S1 treats them as `ok` (the least-bad default, ADR-0044
# fallback); S4's liveness probe disambiguates.
_AUTHZ_CLASSES: frozenset[str] = frozenset(
    {"idor", "bola", "auth-bypass", "privilege-escalation", "boundary-violation"}
)


def classify(
    *,
    response: HttpResponse | None,
    test_class: TestClass,
    role: RequestRole,
    transport_error: Exception | None = None,
) -> DispatchStatus:
    """Map a wire result to a `DispatchStatus` (ADR-0013, S1-minimal).

    Exactly one of `response` / `transport_error` is set. A Dispatcher-gate deny
    never reaches here (it short-circuits to `dispatcher_blocked` upstream and no
    send happens).
    """

    if transport_error is not None:
        return "transport_error"
    assert response is not None

    # S1-minimal: any status the target returned is `ok` — the test reached the
    # target. The ADR-0013 401/403 → `auth_invalid` rule applied to *non-authz*
    # classes would be wrong here (ADR-0044), and S1 only ships authz `idor`.
    # The full per-class rule + liveness-probe disambiguation is S4; the seam is
    # `test_class` + `role`, already threaded.
    _ = (test_class, role)
    return "ok"


def is_authz_class(test_class: str) -> bool:
    """True if `test_class` is in the ADR-0044 authz set (4xx ≠ `auth_invalid`)."""

    return test_class in _AUTHZ_CLASSES
