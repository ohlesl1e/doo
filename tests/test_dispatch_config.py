"""`EngagementConfig.environment` + `dispatch:` mode-matrix validation (ADR-0042).

Asserts the loader rejects illegal `arming × interpreter` combos at LOAD time
(not at dispatch time), naming the rule. `environment` is REQUIRED — no default.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from doo.setup.config import DispatchConfig, EngagementConfig


def _base_yaml(environment: str, dispatch: dict | None = None) -> dict:
    doc: dict = {
        "engagement": {"id": "eng-x", "name": "x"},
        "environment": environment,
        "scope": {
            "host_patterns": ["api.example.com"],
            "allowed_methods": ["GET"],
            "allowed_path_patterns": ["/**"],
        },
    }
    if dispatch is not None:
        doc["dispatch"] = dispatch
    return doc


def test_tls_verify_defaults_true() -> None:
    assert DispatchConfig().tls_verify is True


def test_staging_permits_tls_verify_false_and_ca_path() -> None:
    cfg = EngagementConfig.model_validate(_base_yaml("staging", {"tls_verify": False}))
    assert cfg.dispatch.tls_verify is False
    cfg2 = EngagementConfig.model_validate(
        _base_yaml("staging", {"tls_verify": "/etc/ssl/internal-ca.pem"})
    )
    assert cfg2.dispatch.tls_verify == "/etc/ssl/internal-ca.pem"


def test_production_rejects_tls_verify_false() -> None:
    """Disabling TLS verification on a production target lets a MITM harvest
    spliced declared-principal credentials and decouples OPA's host check from
    the server actually reached."""
    with pytest.raises(ValidationError, match="tls_verify"):
        EngagementConfig.model_validate(_base_yaml("production", {"tls_verify": False}))


def test_production_permits_tls_verify_ca_path() -> None:
    """A CA-bundle path is the right answer for a production target with a
    private CA — verification still happens, just against the named bundle."""
    cfg = EngagementConfig.model_validate(
        _base_yaml("production", {"tls_verify": "/etc/ssl/private-ca.pem"})
    )
    assert cfg.dispatch.tls_verify == "/etc/ssl/private-ca.pem"


def test_environment_is_required() -> None:
    """ADR-0042: `environment` has no default; the tester is forced to state it."""
    doc = _base_yaml("staging")
    del doc["environment"]
    with pytest.raises(ValidationError, match="environment"):
        EngagementConfig.model_validate(doc)


def test_staging_permits_full_matrix() -> None:
    """All four `(arming, interpreter)` combinations are legal on staging."""
    for arming in ("review", "auto"):
        for interpreter in ("confirm", "freelance"):
            cfg = EngagementConfig.model_validate(
                _base_yaml("staging", {"arming": arming, "interpreter": interpreter})
            )
            assert cfg.dispatch.arming == arming
            assert cfg.dispatch.interpreter == interpreter


def test_production_rejects_auto_arming_at_load() -> None:
    """ADR-0042: `arming=auto` on production fails at LOAD, naming the rule."""
    with pytest.raises(ValidationError, match="arming=review"):
        EngagementConfig.model_validate(
            _base_yaml("production", {"arming": "auto", "interpreter": "confirm"})
        )


def test_production_rejects_freelance_interpreter_at_load() -> None:
    """ADR-0042: `interpreter=freelance` on production fails at LOAD."""
    with pytest.raises(ValidationError, match="interpreter=confirm"):
        EngagementConfig.model_validate(
            _base_yaml("production", {"arming": "review", "interpreter": "freelance"})
        )


def test_production_review_confirm_is_legal() -> None:
    """The ONLY legal production combo: `review + confirm` (ADR-0042 default)."""
    cfg = EngagementConfig.model_validate(_base_yaml("production"))
    assert cfg.environment == "production"
    assert cfg.dispatch.arming == "review"
    assert cfg.dispatch.interpreter == "confirm"


def test_dispatch_config_defaults() -> None:
    """`DispatchConfig` defaults: review + confirm + sane budgets."""
    d = DispatchConfig()
    assert d.arming == "review"
    assert d.interpreter == "confirm"
    assert d.request_budget >= 1
    assert d.wallclock_budget_s >= 1
    assert d.max_tool_calls >= 1
