"""Deterministic `dispatch_status` classifier (ADR-0013 + ADR-0044).

The classifier is **deterministic** (CLAUDE.md hard rule): it never asks the
Interpreter, and it is the only code that sets `dispatch_status`. It is also
**pure** — `(response, test_class, role, replay_hazards, liveness_result,
matchers) → dispatch_status` — so the whole authz-disambiguation matrix is
exhaustively unit-testable without a wire send (the liveness probe itself is the
run driver's job; its *outcome* arrives here as `liveness_result`).

ADR-0013's rule (`401/403/login-redirect under a non-anonymous AuthContext →
auth_invalid`) is **amended** for authz-class `primary` sends (ADR-0044): a 4xx
there is the *expected negative* ("boundary held"), not "test didn't run". A
per-`AuthContext` liveness probe disambiguates:

- probe **dead** (4xx) → the token is dead → `auth_invalid` (+ reactive refresh).
- probe **live** (2xx) → the test 4xx is genuine → `replay_invalid` if the
  TestCase carried unverified `replay_hazards`, else `ok` (boundary held).
- probe **unknown** (no liveness endpoint, or the probe was itself blocked) →
  `ok` — the ADR-0044 least-bad fallback (over-report "boundary held" rather than
  spuriously trigger refresh storms); the run flags the engagement once.

An optional per-engagement body-match override (`auth_invalid_match` /
`replay_invalid_match`, ADR-0044) runs **before** the probe and short-circuits
it. The non-authz rule (ADR-0013) is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from doo.dispatch.executor.send import HttpResponse
from doo.dispatch.models import RequestRole
from doo.events.execution import DispatchStatus, TestClass

# Authz `test_class`es whose 4xx-on-`primary` is *not* immediately `auth_invalid`
# (ADR-0044 amendment): the liveness probe disambiguates.
_AUTHZ_CLASSES: frozenset[str] = frozenset(
    {"idor", "bola", "auth-bypass", "privilege-escalation", "boundary-violation"}
)

# HTTP statuses that read as an authz negative on the wire (ADR-0013).
_AUTH_NEGATIVE_STATUSES: frozenset[int] = frozenset({401, 403})

# The outcome of an ADR-0044 liveness probe (the run driver computes it from the
# probe's wire status; the classifier consumes it). `unknown` = no probe could
# run (no liveness endpoint, or the probe was itself gate-blocked).
LivenessResult = Literal["live", "dead", "unknown"]


@dataclass(frozen=True, slots=True)
class BodyMatchers:
    """Compiled per-engagement body-match overrides (ADR-0044).

    Both optional. `auth_invalid` matching the 4xx body ⇒ the token is dead;
    `replay_invalid` matching ⇒ the replay (not the token) is stale. Run BEFORE
    the probe and short-circuit it (cheaper when the target's bodies are
    distinguishable; the probe remains the fallback).
    """

    auth_invalid: re.Pattern[str] | None = None
    replay_invalid: re.Pattern[str] | None = None

    @property
    def empty(self) -> bool:
        return self.auth_invalid is None and self.replay_invalid is None


def is_authz_class(test_class: str) -> bool:
    """True if `test_class` is in the ADR-0044 authz set (4xx ≠ `auth_invalid`)."""

    return test_class in _AUTHZ_CLASSES


def is_auth_negative(response: HttpResponse) -> bool:
    """True if the response reads as an authz negative (ADR-0013): 401/403/login-redirect.

    A 3xx is a login redirect only when its `Location` points at a login/sign-in
    path — a redirect to a resource is not an auth failure.
    """

    if response.status in _AUTH_NEGATIVE_STATUSES:
        return True
    if 300 <= response.status < 400:
        location = next(
            (v for k, v in response.headers if k.lower() == "location"), ""
        ).lower()
        return any(tok in location for tok in ("login", "signin", "sign-in", "/auth"))
    return False


def classify(
    *,
    response: HttpResponse | None,
    test_class: TestClass,
    role: RequestRole,
    replay_hazards: tuple[str, ...] = (),
    liveness_result: LivenessResult = "unknown",
    matchers: BodyMatchers | None = None,
    transport_error: Exception | None = None,
) -> DispatchStatus:
    """Map a wire result to a `DispatchStatus` (ADR-0013 + ADR-0044).

    Exactly one of `response` / `transport_error` is set. A Dispatcher-gate deny
    never reaches here (it short-circuits to `dispatcher_blocked` upstream). For a
    non-`primary` role (baselines, `liveness`, `hazard_warmup`) the status is
    always `ok` when bytes returned — those sends are read raw by the prober /
    Interpreter, not by `dispatch_status`. The authz disambiguation applies only
    to the `primary`; `liveness_result` / `matchers` are ignored otherwise.
    """

    if transport_error is not None:
        return "transport_error"
    assert response is not None

    # Non-`primary` sends: reaching the wire is the only fact `dispatch_status`
    # carries; the prober / Interpreter judge the raw response.
    if role != "primary":
        return "ok"

    if not is_authz_class(test_class):
        # ADR-0013 (unamended) for non-authz primaries: a 4xx under the test's
        # own auth means it did not reach the test path.
        return "auth_invalid" if is_auth_negative(response) else "ok"

    # --- authz `primary` (ADR-0044). ---
    if not is_auth_negative(response):
        # 2xx / 404 / 5xx etc.: the boundary was exercised — the Interpreter
        # judges what the bytes mean.
        return "ok"

    # 4xx authz negative: disambiguate. Body-match overrides win first (ADR-0044).
    if matchers is not None and not matchers.empty:
        body = response.body.decode("utf-8", errors="replace")
        if matchers.auth_invalid is not None and matchers.auth_invalid.search(body):
            return "auth_invalid"
        if matchers.replay_invalid is not None and matchers.replay_invalid.search(body):
            return "replay_invalid"

    if liveness_result == "dead":
        return "auth_invalid"
    if liveness_result == "live":
        # Token live ⇒ the 4xx is genuine. Unverified replay hazards make it a
        # stale replay, not a held boundary (ADR-0041/0044).
        return "replay_invalid" if replay_hazards else "ok"
    # `unknown`: no probe could run — the least-bad fallback (ADR-0044).
    return "ok"
