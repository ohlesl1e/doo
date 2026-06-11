"""Unit tests for the deterministic sink-parameter detector (S6) — pure, no graph."""

from __future__ import annotations

import pytest

from doo.planner.sink_params import (
    classify_sink_role,
    sink_role_for_parameter,
    sink_test_class_for_role,
)


@pytest.mark.parametrize(
    "name,expected",
    [
        ("redirect", "redirect_target"),
        ("redirect_uri", "redirect_target"),
        ("redirectUri", "redirect_target"),
        ("returnUrl", "redirect_target"),
        ("next", "redirect_target"),
        ("callback", "redirect_target"),
        ("url", "url_sink"),
        ("image_url", "url_sink"),
        ("webhook", "url_sink"),
        ("uri", "url_sink"),
        ("path", "file_path"),
        ("filename", "file_path"),
        ("template", "file_path"),
    ],
)
def test_sink_names_classified(name: str, expected: str) -> None:
    assert classify_sink_role(name) == expected


@pytest.mark.parametrize("name", ["id", "q", "page_size", "order_id", "limit", "sort", "page"])
def test_ordinary_names_unclassified(name: str) -> None:
    assert classify_sink_role(name) is None


def test_value_shape_promotes_generic_name() -> None:
    # A generic 'target' name carrying a URL value -> url_sink.
    assert classify_sink_role("target", "https://evil.example/cb") == "url_sink"
    # A 'data' param carrying a traversal-shaped value -> file_path.
    assert classify_sink_role("data", "../../etc/passwd") == "file_path"
    # 'page' with a plain int value stays unclassified (no path shape).
    assert classify_sink_role("page", "2") is None


def test_redirect_precedes_url() -> None:
    # A name with both redirect + url tokens classifies as the more specific redirect.
    assert classify_sink_role("redirect_url") == "redirect_target"


def test_sink_role_for_parameter_scans_values() -> None:
    assert sink_role_for_parameter("target", ("plain", "https://x.test/y")) == "url_sink"
    assert sink_role_for_parameter("id", ("1", "2")) is None


def test_default_test_class_per_role() -> None:
    assert sink_test_class_for_role("redirect_target") == "open-redirect"
    assert sink_test_class_for_role("url_sink") == "ssrf"
    assert sink_test_class_for_role("file_path") == "path-traversal"
