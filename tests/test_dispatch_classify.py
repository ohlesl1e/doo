"""ADR-0044 classifier matrix: authz `primary` 4xx disambiguation (issue #89).

`classify` is pure, so the whole 4xx × probe-result × hazard-presence ×
matcher-hit matrix is a table-driven unit test with no wire send. Also covers the
non-authz (ADR-0013 unamended) rule and the non-`primary` roles.
"""

from __future__ import annotations

import re

import pytest

from doo.dispatch.executor.classify import (
    BodyMatchers,
    classify,
    is_auth_negative,
    is_authz_class,
)
from doo.dispatch.executor.send import HttpResponse


def _resp(status: int, *, body: bytes = b"", location: str | None = None) -> HttpResponse:
    headers = (("Location", location),) if location is not None else ()
    return HttpResponse(status=status, headers=headers, body=body)


# --- is_authz_class / is_auth_negative primitives. ---


def test_authz_class_membership() -> None:
    assert is_authz_class("idor")
    assert is_authz_class("boundary-violation")
    assert not is_authz_class("ssrf")
    assert not is_authz_class("forced_browsing")


@pytest.mark.parametrize(
    "resp,expected",
    [
        (_resp(401), True),
        (_resp(403), True),
        (_resp(200), False),
        (_resp(404), False),
        (_resp(302, location="https://x/login"), True),
        (_resp(302, location="https://x/orders/9"), False),
        (_resp(303, location="/auth/start"), True),
    ],
)
def test_is_auth_negative(resp: HttpResponse, expected: bool) -> None:
    assert is_auth_negative(resp) is expected


# --- transport error / non-primary roles. ---


def test_transport_error_wins() -> None:
    assert (
        classify(
            response=None,
            test_class="idor",
            role="primary",
            transport_error=RuntimeError("dns"),
        )
        == "transport_error"
    )


@pytest.mark.parametrize("role", ["baseline_victim", "baseline_negative", "liveness"])
def test_non_primary_roles_are_ok_on_any_status(role: str) -> None:
    # A 403 on a baseline / liveness send is read raw by the prober/Interpreter;
    # `dispatch_status` only records that bytes returned.
    assert (
        classify(response=_resp(403), test_class="idor", role=role)  # type: ignore[arg-type]
        == "ok"
    )


# --- non-authz primary keeps ADR-0013 (unamended). ---


@pytest.mark.parametrize(
    "status,expected",
    [(200, "ok"), (403, "auth_invalid"), (401, "auth_invalid"), (500, "ok")],
)
def test_non_authz_primary_adr0013(status: int, expected: str) -> None:
    assert (
        classify(response=_resp(status), test_class="ssrf", role="primary") == expected
    )


# --- authz primary, non-negative statuses → ok (boundary exercised). ---


@pytest.mark.parametrize("status", [200, 201, 404, 500])
def test_authz_primary_non_negative_is_ok(status: int) -> None:
    assert classify(response=_resp(status), test_class="idor", role="primary") == "ok"


# --- the ADR-0044 4xx disambiguation matrix. ---


@pytest.mark.parametrize(
    "liveness_result,hazards,expected",
    [
        ("dead", (), "auth_invalid"),
        ("dead", ("csrf_token",), "auth_invalid"),  # dead token wins over hazards
        ("live", (), "ok"),  # boundary genuinely held
        ("live", ("csrf_token",), "replay_invalid"),  # live token, stale replay
        ("unknown", (), "ok"),  # no probe → least-bad fallback
        ("unknown", ("csrf_token",), "ok"),  # fallback ignores hazards (can't verify)
    ],
)
def test_authz_primary_4xx_by_liveness(
    liveness_result: str, hazards: tuple[str, ...], expected: str
) -> None:
    assert (
        classify(
            response=_resp(403),
            test_class="idor",
            role="primary",
            replay_hazards=hazards,
            liveness_result=liveness_result,  # type: ignore[arg-type]
        )
        == expected
    )


# --- body-match overrides win over the probe outcome. ---


def test_auth_invalid_matcher_overrides_live_probe() -> None:
    matchers = BodyMatchers(auth_invalid=re.compile(r"token expired"))
    # Even with a LIVE probe, a matched auth_invalid body says the token is dead.
    assert (
        classify(
            response=_resp(403, body=b'{"error":"token expired"}'),
            test_class="idor",
            role="primary",
            liveness_result="live",
            matchers=matchers,
        )
        == "auth_invalid"
    )


def test_replay_invalid_matcher_overrides() -> None:
    matchers = BodyMatchers(replay_invalid=re.compile(r"csrf"))
    assert (
        classify(
            response=_resp(403, body=b'{"error":"bad csrf token"}'),
            test_class="bola",
            role="primary",
            liveness_result="live",
            matchers=matchers,
        )
        == "replay_invalid"
    )


def test_matcher_miss_falls_through_to_liveness() -> None:
    matchers = BodyMatchers(auth_invalid=re.compile(r"never matches this"))
    assert (
        classify(
            response=_resp(403, body=b"forbidden"),
            test_class="idor",
            role="primary",
            liveness_result="dead",
            matchers=matchers,
        )
        == "auth_invalid"
    )
