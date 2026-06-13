"""Bundle-generator unit tests (`policy/bundle.py`, ADR-0046).

`generate_data(ScopeRules, environment)` is deterministic and emits exactly the
`data.scope` shape the fixed Rego reads. Host patterns are pre-parsed (so the
Rego does plain comparisons, mirroring `policy.scope._parse_host_pattern`).
"""

from __future__ import annotations

from doo.policy.bundle import generate_data
from doo.setup.config import ScopeRules, TimeWindow


def _scope(**over: object) -> ScopeRules:
    return ScopeRules(
        host_patterns=tuple(over.get("host_patterns", ("api.example.com",))),  # type: ignore[arg-type]
        allowed_methods=tuple(over.get("allowed_methods", ("GET", "POST"))),  # type: ignore[arg-type]
        allowed_path_patterns=tuple(over.get("allowed_path_patterns", ("/**",))),  # type: ignore[arg-type]
        payload_class_denylist=tuple(over.get("payload_class_denylist", ())),  # type: ignore[arg-type]
        time_window=over.get("time_window"),  # type: ignore[arg-type]
    )


def test_generate_data_shape() -> None:
    """Emits `data.scope = {allowed_hosts, method_allowlist, path_globs,
    payload_class_denylist, time_window, environment}` (ADR-0046)."""
    data = generate_data(_scope(), environment="staging")
    assert set(data) == {"scope"}
    assert set(data["scope"]) == {  # type: ignore[arg-type]
        "allowed_hosts",
        "method_allowlist",
        "path_globs",
        "payload_class_denylist",
        "time_window",
        "environment",
    }
    assert data["scope"]["environment"] == "staging"  # type: ignore[index]


def test_host_patterns_are_preparsed() -> None:
    """Host patterns → `(scheme|null, hostname, port|null, is_glob, suffix)` so
    the Rego does plain comparisons, exactly mirroring `_parse_host_pattern`."""
    data = generate_data(
        _scope(
            host_patterns=(
                "api.example.com",
                "*.shop.example.com",
                "https://pinned.example.com:8443",
            )
        ),
        environment="staging",
    )
    hosts = {h["raw"]: h for h in data["scope"]["allowed_hosts"]}  # type: ignore[index]

    exact = hosts["api.example.com"]
    assert exact["scheme"] is None and exact["port"] is None
    assert exact["hostname"] == "api.example.com"
    assert exact["is_glob"] is False and exact["suffix"] is None

    glob = hosts["*.shop.example.com"]
    assert glob["is_glob"] is True
    assert glob["suffix"] == ".shop.example.com"

    pinned = hosts["https://pinned.example.com:8443"]
    assert pinned["scheme"] == "https"
    assert pinned["port"] == 8443
    assert pinned["hostname"] == "pinned.example.com"


def test_methods_are_uppercased_and_sorted() -> None:
    data = generate_data(_scope(allowed_methods=("post", "GET")), environment="staging")
    assert data["scope"]["method_allowlist"] == ["GET", "POST"]  # type: ignore[index]


def test_path_globs_preserve_declaration_order() -> None:
    """Path-glob order is semantic (first-match-wins, ADR-0035) — NOT sorted."""
    data = generate_data(
        _scope(allowed_path_patterns=("/api/**", "/orders/*", "/me")),
        environment="staging",
    )
    assert data["scope"]["path_globs"] == ["/api/**", "/orders/*", "/me"]  # type: ignore[index]


def test_time_window_serialised() -> None:
    tw = TimeWindow(start_hour_utc=9, end_hour_utc=17, weekdays=(5, 1, 3))
    data = generate_data(_scope(time_window=tw), environment="production")
    out = data["scope"]["time_window"]  # type: ignore[index]
    assert out == {"start_hour_utc": 9, "end_hour_utc": 17, "weekdays": [1, 3, 5]}


def test_generate_data_is_deterministic() -> None:
    """Same `ScopeRules` → byte-identical JSON (single source of truth, ADR-0046)."""
    import json

    s = _scope(host_patterns=("b.example.com", "a.example.com"))
    a = json.dumps(generate_data(s, environment="staging"), sort_keys=True)
    b = json.dumps(generate_data(s, environment="staging"), sort_keys=True)
    assert a == b
