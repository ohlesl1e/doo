"""Pure unit tests for `doo.policy.scope.is_in_scope` (ADR-0020).

No containers, no I/O — `is_in_scope` is a pure function of (node, ScopeRules).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from doo.canonical.value_objects import Scheme
from doo.events.slice4 import PayloadClass
from doo.policy.scope import is_in_scope
from doo.setup.config import ScopeRules

# --- Fixture node shapes (structural; match the Protocols in scope.py) -------


@dataclass(frozen=True)
class FakeHost:
    scheme: Scheme
    canonical_hostname: str
    port: int | None = None
    is_ip_literal: bool = False


@dataclass(frozen=True)
class FakeEndpoint:
    method: str
    host: FakeHost
    path_template: str


@dataclass(frozen=True)
class FakeProposedRequest:
    method: str
    host: FakeHost
    path_template: str
    payload_class: PayloadClass


def _scope(
    *,
    host_patterns: tuple[str, ...] = ("api.example.com",),
    allowed_methods: tuple[str, ...] = ("GET",),
    allowed_path_patterns: tuple[str, ...] = ("/**",),
    payload_class_denylist: tuple[PayloadClass, ...] = (),
) -> ScopeRules:
    return ScopeRules(
        host_patterns=host_patterns,
        allowed_methods=allowed_methods,
        allowed_path_patterns=allowed_path_patterns,
        payload_class_denylist=payload_class_denylist,
    )


# --- Host matching -----------------------------------------------------------


def test_explicit_host_in_scope() -> None:
    scope = _scope(host_patterns=("api.example.com",))
    host = FakeHost(scheme="https", canonical_hostname="api.example.com")
    assert is_in_scope(host, scope) is True


def test_host_missing_from_allowlist_is_out_of_scope() -> None:
    scope = _scope(host_patterns=("api.example.com",))
    host = FakeHost(scheme="https", canonical_hostname="evil.example.org")
    assert is_in_scope(host, scope) is False


def test_glob_host_matches_subdomain() -> None:
    scope = _scope(host_patterns=("*.example.com",))
    assert is_in_scope(FakeHost("https", "a.example.com"), scope) is True
    assert is_in_scope(FakeHost("https", "a.b.example.com"), scope) is True


def test_glob_host_does_not_match_apex() -> None:
    scope = _scope(host_patterns=("*.example.com",))
    # `*.example.com` matches subdomains, not the apex.
    assert is_in_scope(FakeHost("https", "example.com"), scope) is False


def test_glob_host_does_not_match_unrelated_suffix() -> None:
    scope = _scope(host_patterns=("*.example.com",))
    assert is_in_scope(FakeHost("https", "notexample.com"), scope) is False
    assert is_in_scope(FakeHost("https", "a.example.com.evil.net"), scope) is False


def test_ip_literal_matches_explicit_pattern_only() -> None:
    scope = _scope(host_patterns=("10.0.0.5",))
    assert is_in_scope(FakeHost("http", "10.0.0.5", is_ip_literal=True), scope) is True


def test_ip_literal_never_matches_glob() -> None:
    scope = _scope(host_patterns=("*.0.0.5",))
    assert is_in_scope(FakeHost("http", "10.0.0.5", is_ip_literal=True), scope) is False


def test_scheme_pinned_pattern() -> None:
    scope = _scope(host_patterns=("https://api.example.com",))
    assert is_in_scope(FakeHost("https", "api.example.com"), scope) is True
    assert is_in_scope(FakeHost("http", "api.example.com"), scope) is False


def test_port_pinned_pattern_matches_nondefault_port() -> None:
    scope = _scope(host_patterns=("api.example.com:8443",))
    assert is_in_scope(FakeHost("https", "api.example.com", port=8443), scope) is True
    # Default port (None == 443) does not match the :8443 pin.
    assert is_in_scope(FakeHost("https", "api.example.com", port=None), scope) is False


def test_bare_pattern_matches_default_port_node() -> None:
    scope = _scope(host_patterns=("api.example.com",))
    # No port pin -> matches regardless of the node's (default) port.
    assert is_in_scope(FakeHost("https", "api.example.com", port=None), scope) is True


def test_host_match_is_case_insensitive() -> None:
    scope = _scope(host_patterns=("API.Example.com",))
    assert is_in_scope(FakeHost("https", "api.example.com"), scope) is True


# --- Method matching (Endpoint) ----------------------------------------------


def test_endpoint_method_must_be_allowed() -> None:
    scope = _scope(allowed_methods=("GET",), allowed_path_patterns=("/**",))
    ep = FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/users/{user_id}")
    assert is_in_scope(ep, scope) is True
    ep_post = FakeEndpoint("POST", FakeHost("https", "api.example.com"), "/users/{user_id}")
    assert is_in_scope(ep_post, scope) is False


def test_endpoint_post_allowed_when_listed() -> None:
    scope = _scope(allowed_methods=("GET", "POST"), allowed_path_patterns=("/**",))
    ep = FakeEndpoint("POST", FakeHost("https", "api.example.com"), "/orders")
    assert is_in_scope(ep, scope) is True


def test_wildcard_method_allows_any() -> None:
    scope = _scope(allowed_methods=("*",), allowed_path_patterns=("/**",))
    ep = FakeEndpoint("DELETE", FakeHost("https", "api.example.com"), "/orders/1")
    assert is_in_scope(ep, scope) is True


def test_method_match_case_insensitive() -> None:
    scope = _scope(allowed_methods=("get",), allowed_path_patterns=("/**",))
    ep = FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/x")
    assert is_in_scope(ep, scope) is True


# --- Path template matching --------------------------------------------------


def test_path_star_matches_template_placeholder() -> None:
    scope = _scope(allowed_path_patterns=("/users/*",))
    ep = FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/users/{user_id}")
    assert is_in_scope(ep, scope) is True


def test_path_star_is_single_segment() -> None:
    scope = _scope(allowed_path_patterns=("/users/*",))
    # `/users/*` is one segment after users; deeper template doesn't match.
    ep = FakeEndpoint(
        "GET", FakeHost("https", "api.example.com"), "/users/{user_id}/posts"
    )
    assert is_in_scope(ep, scope) is False


def test_path_globstar_matches_remaining_segments() -> None:
    scope = _scope(allowed_path_patterns=("/users/**",))
    ep = FakeEndpoint(
        "GET", FakeHost("https", "api.example.com"), "/users/{user_id}/posts/{post_id}"
    )
    assert is_in_scope(ep, scope) is True


def test_path_literal_must_match_exactly() -> None:
    scope = _scope(allowed_path_patterns=("/health",))
    ok = FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/health")
    assert is_in_scope(ok, scope) is True
    miss = FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/healthz")
    assert is_in_scope(miss, scope) is False


def test_path_not_in_any_pattern_is_out_of_scope() -> None:
    scope = _scope(allowed_path_patterns=("/users/*",))
    ep = FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/admin")
    assert is_in_scope(ep, scope) is False


# --- ProposedRequest / payload-class matching --------------------------------


def test_proposed_request_in_scope_when_payload_allowed() -> None:
    scope = _scope(
        allowed_methods=("POST",),
        allowed_path_patterns=("/login",),
        payload_class_denylist=("destructive-sql",),
    )
    req = FakeProposedRequest(
        "POST", FakeHost("https", "api.example.com"), "/login", "benign-probe"
    )
    assert is_in_scope(req, scope) is True


def test_proposed_request_out_of_scope_when_payload_denied() -> None:
    scope = _scope(
        allowed_methods=("POST",),
        allowed_path_patterns=("/login",),
        payload_class_denylist=("destructive-sql",),
    )
    req = FakeProposedRequest(
        "POST", FakeHost("https", "api.example.com"), "/login", "destructive-sql"
    )
    assert is_in_scope(req, scope) is False


def test_proposed_request_out_of_scope_when_host_wrong_even_if_payload_ok() -> None:
    scope = _scope(host_patterns=("api.example.com",), allowed_methods=("*",))
    req = FakeProposedRequest(
        "POST", FakeHost("https", "evil.test"), "/login", "benign-probe"
    )
    assert is_in_scope(req, scope) is False


@pytest.mark.parametrize(
    "denied",
    ["destructive-sql", "ssrf-callback"],
)
def test_denylist_members_are_blocked(denied: PayloadClass) -> None:
    scope = _scope(
        allowed_methods=("*",),
        allowed_path_patterns=("/**",),
        payload_class_denylist=(denied,),
    )
    req = FakeProposedRequest(
        "GET", FakeHost("https", "api.example.com"), "/x", denied
    )
    assert is_in_scope(req, scope) is False
