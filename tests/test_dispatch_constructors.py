"""`executor.constructors` table-driven unit tests (ADR-0043).

A constructor is a **pure function** of `(DispatchTestCase, EvidenceObservation,
AuthMaterial)` → `ConcreteRequest`. These tests assert externally-observable
behaviour at the module boundary: given a fixture TestCase + evidence + material,
the constructor emits *these* bytes. No graph, no network, no LLM.
"""

from __future__ import annotations

import pytest

from doo.canonical.value_objects import HostRef
from doo.dispatch.executor.constructors import (
    ConstructorMissingError,
    _splice_auth,
    authbypass_primary,
    constructor_for,
    has_constructor,
    idor_baseline_victim,
    idor_primary,
)
from doo.dispatch.executor.evidence import DispatchTestCase, EvidenceObservation
from doo.dispatch.secrets import AuthMaterial
from doo.ids import AuthContextId, EngagementId, ObservationId, TestCaseKeyHash


def _testcase(**over: object) -> DispatchTestCase:
    return DispatchTestCase(
        engagement_id=EngagementId("eng-x"),
        key_hash=TestCaseKeyHash("k" * 64),
        test_class=over.get("test_class", "idor"),  # type: ignore[arg-type]
        payload_class="auth-token-swap",
        auth_context_id=AuthContextId("ac-attacker"),
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        hold=tuple(over.get("hold", ("order_id",))),  # type: ignore[arg-type]
        replay_hazards=(),
        expected_yield=0.9,
        generator="c2",
        confidence=0.99,
    )


def _evidence(**over: object) -> EvidenceObservation:
    return EvidenceObservation(
        observation_id=ObservationId("obs-victim-1"),
        method=str(over.get("method", "GET")),
        host=HostRef(scheme="https", canonical_hostname="api.example.com"),
        concrete_path=str(over.get("concrete_path", "/orders/123")),
        path_template=str(over.get("path_template", "/orders/{order_id}")),
        query=dict(over.get("query", {})),  # type: ignore[arg-type]
        headers=dict(
            over.get(
                "headers",
                {
                    "Authorization": "Bearer victim-token",
                    "Accept": "application/json",
                    "X-Request-Id": "abc",
                },
            )
        ),  # type: ignore[arg-type]
        cookies=dict(over.get("cookies", {})),  # type: ignore[arg-type]
        baseline_victim_auth_context_id=AuthContextId("ac-victim"),
        session_cookie_names=tuple(over.get("session_cookie_names", ())),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("kind", "expect_header", "expect_value"),
    [
        ("bearer", "Authorization", "Bearer ATTACKER-TOKEN"),
        ("basic_auth", "Authorization", "Basic ATTACKER-TOKEN"),
        ("api_key", "X-API-Key", "ATTACKER-TOKEN"),
    ],
)
def test_idor_primary_swaps_auth_and_strips_victim_credential(
    kind: str, expect_header: str, expect_value: str
) -> None:
    """`(idor, primary)`: victim's request shape verbatim; attacker's auth swapped in.

    The victim's `Authorization` header MUST be stripped (replaying it alongside
    the attacker's would mask the authz hole — the test would pass for the wrong
    reason).
    """
    material = AuthMaterial(kind=kind, raw="ATTACKER-TOKEN", principal_label="user-b")  # type: ignore[arg-type]
    req = idor_primary(_testcase(), _evidence(), material)

    assert req.method == "GET"
    assert req.host.canonical_hostname == "api.example.com"
    # Hold applied: the victim's concrete path (their `order_id=123`) is replayed.
    assert req.path == "/orders/123"
    assert req.path_template == "/orders/{order_id}"
    # The TestCase's auth_context_id (attacker), not the evidence's (victim).
    assert req.auth_context_id == "ac-attacker"

    headers = dict(req.headers)
    # Victim's auth gone:
    assert headers.get("Authorization") != "Bearer victim-token"
    # Attacker's auth present:
    assert headers.get(expect_header) == expect_value
    # Non-auth headers preserved verbatim from evidence:
    assert headers.get("Accept") == "application/json"
    assert headers.get("X-Request-Id") == "abc"


def test_idor_primary_preserves_query_hold() -> None:
    """A query-param IDOR: the held query param is carried verbatim from evidence."""
    ev = _evidence(
        concrete_path="/orders",
        path_template="/orders",
        query={"order_id": "123", "format": "json"},
    )
    req = idor_primary(
        _testcase(hold=("order_id",)),
        ev,
        AuthMaterial(kind="bearer", raw="ATK", principal_label="user-b"),
    )
    assert dict(req.query) == {"order_id": "123", "format": "json"}


def test_registry_lookup_hits_and_misses() -> None:
    assert has_constructor("idor", "primary")
    fn = constructor_for("idor", "primary")
    assert fn is idor_primary

    assert not has_constructor("ssrf", "primary")
    with pytest.raises(ConstructorMissingError, match="no constructor registered"):
        constructor_for("ssrf", "primary")


def test_constructor_is_pure() -> None:
    """Same inputs → identical `ConcreteRequest` (constructors are reproducible)."""
    tc, ev = _testcase(), _evidence()
    mat = AuthMaterial(kind="bearer", raw="ATK", principal_label="user-b")
    a = idor_primary(tc, ev, mat)
    b = idor_primary(tc, ev, mat)
    assert a == b


# --- S7: all MVP authz classes registered (ADR-0043). ---


@pytest.mark.parametrize(
    ("test_class", "roles"),
    [
        ("bola", ("primary", "baseline_victim", "baseline_negative")),
        ("auth-bypass", ("primary", "baseline_victim")),
        ("privilege-escalation", ("primary", "baseline_victim")),
        ("boundary-violation", ("primary", "baseline_victim")),
    ],
)
def test_authz_classes_have_constructors(test_class: str, roles: tuple[str, ...]) -> None:
    for role in roles:
        assert has_constructor(test_class, role), f"{test_class}/{role}"
        assert constructor_for(test_class, role) is not None


def test_authbypass_primary_strips_all_credentials() -> None:
    """`(auth-bypass, primary)`: anonymous replay — no auth header, no cookies."""
    material = AuthMaterial(kind="bearer", raw="ATTACKER", principal_label="user-b")
    ev = _evidence(
        headers={"Authorization": "Bearer victim-token", "Accept": "application/json"},
        cookies={"session": "victim-sess"},
    )
    req = authbypass_primary(_testcase(test_class="auth-bypass"), ev, material)
    headers = dict(req.headers)
    assert "Authorization" not in headers  # no credential at all
    assert "ATTACKER" not in str(req.headers)  # attacker material NOT spliced
    assert req.cookies == ()  # session cookie dropped
    assert headers.get("Accept") == "application/json"  # non-auth header kept
    assert req.auth_context_id == "ac-attacker"  # provenance still the TC's context


# ---------------------------------------------------------------------------
# #135 — `_splice_auth` anonymous arm: "send as anon" = strip auth, add nothing.
# ---------------------------------------------------------------------------


def test_splice_auth_anonymous_strips_and_adds_nothing() -> None:
    """`kind='anonymous'`: every evidence auth carrier is dropped and no carrier
    is added back. The session cookie is dropped too (when named).
    """
    h, c = _splice_auth(
        headers={"Authorization": "Bearer victim-tok", "Accept": "*/*"},
        cookies={"sid": "victim-sess", "ui_theme": "dark"},
        material=AuthMaterial(
            kind="anonymous", raw="", principal_label="anonymous"
        ),
        session_cookie_names=("sid",),
    )
    assert "Authorization" not in h
    assert "X-API-Key" not in h
    assert h.get("Accept") == "*/*"  # non-auth headers preserved
    assert "sid" not in c
    assert c.get("ui_theme") == "dark"  # non-session cookies preserved


def test_idor_baseline_victim_with_anonymous_material_is_no_auth_send() -> None:
    """#135 repro: `('auth-bypass', 'baseline_victim')` → `idor_baseline_victim`.
    When the victim is the anonymous AC, the baseline send must carry NO auth
    header — not the degenerate `Authorization: Bearer ` the placeholder
    `kind='bearer', raw=''` previously produced.
    """
    anon = AuthMaterial(kind="anonymous", raw="", principal_label="anonymous")
    ev = _evidence(
        headers={"Authorization": "Bearer victim-tok", "Accept": "application/json"},
        cookies={"session": "victim-sess"},
    )
    req = idor_baseline_victim(_testcase(test_class="auth-bypass"), ev, anon)

    headers = dict(req.headers)
    assert "Authorization" not in headers
    assert "X-API-Key" not in headers
    assert headers.get("Accept") == "application/json"
    # `OBSERVED_UNDER` the victim's (anon) AC, not the TestCase's attacker AC.
    assert req.auth_context_id == "ac-victim"


@pytest.mark.parametrize(
    "kind", ["bearer", "basic_auth", "api_key", "cookie", "anonymous"]
)
def test_splice_auth_never_emits_empty_carrier(kind: str) -> None:
    """Guard against the #135 shape recurring under any kind: a non-anonymous
    `raw` is non-empty by construction (env-derived), and `anonymous` adds no
    carrier at all — so no header value ends in a bare scheme + space, and no
    cookie value is the empty string.
    """
    raw = "" if kind == "anonymous" else "TOKEN"
    h, c = _splice_auth(
        headers={"Authorization": "Bearer evidence-tok"},
        cookies={"sid": "evidence-sess"},
        material=AuthMaterial(kind=kind, raw=raw, principal_label="p"),  # type: ignore[arg-type]
        session_cookie_names=("sid",),
    )
    for v in h.values():
        assert not v.endswith(" "), f"{kind}: header value {v!r} has trailing space"
    for v in c.values():
        assert v != "", f"{kind}: empty cookie value"


# ---------------------------------------------------------------------------
# #176/#177 — cookie credential goes under the engagement's configured name,
# and every configured session cookie inherited from evidence is stripped.
# ---------------------------------------------------------------------------


def test_splice_auth_cookie_uses_configured_name() -> None:
    """A `cookie` credential is attached under `session_cookie_names[0]` (#176).

    Regression for the auth_unverified storm: the credential was previously
    written under the hardcoded `"session"`, so a target authenticating via a
    `token` cookie never saw it.
    """
    _, c = _splice_auth(
        headers={},
        cookies={},
        material=AuthMaterial(kind="cookie", raw="ATK-JWT", principal_label="p"),
        session_cookie_names=("token",),
    )
    assert c == {"token": "ATK-JWT"}
    assert "session" not in c


def test_splice_auth_cookie_falls_back_to_session_when_unconfigured() -> None:
    """Empty `session_cookie_names` → the legacy `"session"` fallback is retained."""
    _, c = _splice_auth(
        headers={},
        cookies={},
        material=AuthMaterial(kind="cookie", raw="ATK-JWT", principal_label="p"),
        session_cookie_names=(),
    )
    assert c == {"session": "ATK-JWT"}


def test_splice_auth_strips_every_configured_session_cookie() -> None:
    """All configured names are stripped from inherited evidence; credential lands
    under the first (#177 hardening — no victim session rides along, even with
    multiple configured names)."""
    _, c = _splice_auth(
        headers={},
        cookies={"token": "VICTIM-JWT", "sid": "VICTIM-SID", "ui_theme": "dark"},
        material=AuthMaterial(kind="cookie", raw="ATK-JWT", principal_label="p"),
        session_cookie_names=("token", "sid"),
    )
    assert c["token"] == "ATK-JWT"  # credential under the first configured name
    assert "VICTIM-JWT" not in c.values()
    assert "sid" not in c  # the other configured session cookie is stripped too
    assert c.get("ui_theme") == "dark"  # non-session cookies preserved


def test_idor_primary_sends_cookie_credential_under_configured_name() -> None:
    """End-to-end through `idor_primary`: the evidence's configured cookie name
    flows from `EvidenceObservation.session_cookie_names` to the wire cookie."""
    ev = _evidence(session_cookie_names=("token",))
    req = idor_primary(
        _testcase(),
        ev,
        AuthMaterial(kind="cookie", raw="ATK-JWT", principal_label="user-b"),
    )
    assert dict(req.cookies) == {"token": "ATK-JWT"}
