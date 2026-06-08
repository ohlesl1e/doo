"""Scope patterns are glob/segment, not regex — load-time rejection (ADR-0035, #55).

The bug (#55): `is_in_scope` matches host patterns as exact / single-leading-`*.`
glob and path patterns segment-wise, but configs/fixtures declared regex
(`^.*$`, `^/.*$`). A regex scope matches nothing under the glob matcher, so
coverage silently returned empty with exit 0. ADR-0035 makes glob canonical and
requires the loader to reject regex patterns at `engagement start`, before the
Scope node is written.

These tests pin that behaviour at the `EngagementConfig` validation boundary
(hit by both `doo engagement start` via `load_engagement_from_yaml` and direct
programmatic construction): regex host/path patterns raise with an actionable
error naming the pattern; legitimate glob/segment patterns pass.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from doo.setup.config import EngagementConfig


def _config_dict(*, host_patterns: list[str], allowed_path_patterns: list[str]) -> dict:
    return {
        "engagement": {"id": "acme-2026", "name": "Acme"},
        "scope": {
            "host_patterns": host_patterns,
            "allowed_methods": ["GET", "POST"],
            "allowed_path_patterns": allowed_path_patterns,
        },
        "kill_switch": {"lease_ttl_seconds": 60, "refresh_interval_seconds": 30},
    }


# ---------------------------------------------------------------------------
# Rejection: regex patterns fail at load with an actionable, pattern-naming error.
# ---------------------------------------------------------------------------


def test_rejects_regex_host_pattern() -> None:
    """`^.*$` (the #55 host pattern) is rejected, naming the pattern."""

    d = _config_dict(host_patterns=["^.*$"], allowed_path_patterns=["/**"])
    with pytest.raises(ValidationError) as exc:
        EngagementConfig.model_validate(d)
    msg = str(exc.value)
    assert "^.*$" in msg
    assert "glob" in msg.lower()
    assert "regex" in msg.lower()


def test_rejects_regex_path_pattern() -> None:
    """`^/.*$` (the #55 path pattern) is rejected, naming the pattern."""

    d = _config_dict(host_patterns=["api.example.com"], allowed_path_patterns=["^/.*$"])
    with pytest.raises(ValidationError) as exc:
        EngagementConfig.model_validate(d)
    msg = str(exc.value)
    assert "^/.*$" in msg
    assert "glob" in msg.lower()


def test_rejects_escaped_dot_host_pattern() -> None:
    """The `^api\\.acme\\.example$` shape from the old fixtures is rejected."""

    d = _config_dict(
        host_patterns=["^api\\.acme\\.example$"], allowed_path_patterns=["/**"]
    )
    with pytest.raises(ValidationError):
        EngagementConfig.model_validate(d)


def test_rejects_character_class_and_alternation() -> None:
    d = _config_dict(
        host_patterns=["api.example.com"],
        allowed_path_patterns=["/api/v[0-9]+/.*"],
    )
    with pytest.raises(ValidationError) as exc:
        EngagementConfig.model_validate(d)
    msg = str(exc.value)
    # Names at least one of the disallowed tokens it found.
    assert "[" in msg or ".*" in msg


@pytest.mark.parametrize(
    "bad",
    ["^host", "host$", "a(b)", "a|b", "a+b", "a?b", "a[bc]d"],
)
def test_rejects_each_regex_metacharacter_in_host(bad: str) -> None:
    d = _config_dict(host_patterns=[bad], allowed_path_patterns=["/**"])
    with pytest.raises(ValidationError):
        EngagementConfig.model_validate(d)


# ---------------------------------------------------------------------------
# Acceptance: every legitimate glob/segment pattern passes.
# ---------------------------------------------------------------------------


def test_accepts_wildcard_subdomain_host() -> None:
    d = _config_dict(host_patterns=["*.example.com"], allowed_path_patterns=["/**"])
    cfg = EngagementConfig.model_validate(d)
    assert cfg.scope.host_patterns == ("*.example.com",)


def test_accepts_exact_host_and_ip_literal() -> None:
    d = _config_dict(
        host_patterns=["api.example.com", "172.30.146.0"],
        allowed_path_patterns=["/**"],
    )
    cfg = EngagementConfig.model_validate(d)
    assert cfg.scope.host_patterns == ("api.example.com", "172.30.146.0")


def test_accepts_scheme_and_port_pinned_host() -> None:
    d = _config_dict(
        host_patterns=["https://api.example.com:8443"], allowed_path_patterns=["/**"]
    )
    cfg = EngagementConfig.model_validate(d)
    assert cfg.scope.host_patterns == ("https://api.example.com:8443",)


def test_accepts_segment_glob_and_param_placeholder_paths() -> None:
    # `*` segment, trailing `**`, literal segments, and a `{param}` placeholder
    # are all valid glob/segment syntax and must pass.
    d = _config_dict(
        host_patterns=["api.example.com"],
        allowed_path_patterns=["/**", "/users/*", "/api/*/items", "/users/{user_id}"],
    )
    cfg = EngagementConfig.model_validate(d)
    assert cfg.scope.allowed_path_patterns == (
        "/**",
        "/users/*",
        "/api/*/items",
        "/users/{user_id}",
    )
