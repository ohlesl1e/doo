"""`opa test` wrapper + `OpaEvalClient` integration (ADR-0046).

Per CLAUDE.md, tests for policy decisions are unit tests on Rego — `opa test`
is the authority. This pytest just shells out to it (so CI runs Rego tests in
the same `pytest` invocation) and exercises `OpaEvalClient` against a real
generated bundle. Both **skip with a clear reason** when `opa` is not on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from doo.dispatch.models import (
    DispatchRun,
    DispatchSelection,
    OpaInput,
    RunBudget,
)
from doo.ids import DispatchRunId, EngagementId, TraceId
from doo.policy.bundle import FIXED_REGO_PATH, Bundle, generate_data
from doo.policy.opa_client import OpaEvalClient, OpaUnavailableError, resolve_opa_binary
from doo.setup.config import ScopeRules

POLICY_DIR = Path(__file__).resolve().parent.parent / "src" / "doo" / "policy"


def _require_opa() -> str:
    opa = shutil.which("opa")
    if opa is None:
        pytest.skip(
            "opa binary not on PATH; cannot run Rego tests. Install OPA "
            "(https://www.openpolicyagent.org/docs/latest/#running-opa) or run "
            "`docker run --rm -v \"$PWD/src/doo/policy:/p\" "
            "openpolicyagent/opa:latest test /p/ -v` directly."
        )
    return opa


def test_opa_test_suite_passes() -> None:
    """`opa test src/doo/policy/` — the per-`request_role` Rego unit tests (ADR-0046)."""

    opa = _require_opa()
    proc = subprocess.run(
        [opa, "test", str(POLICY_DIR), "-v"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"`opa test` failed:\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    assert "PASS:" in proc.stdout
    assert "FAIL" not in proc.stdout


def _bundle() -> Bundle:
    scope = ScopeRules(
        host_patterns=("api.example.com",),
        allowed_methods=("GET",),
        allowed_path_patterns=("/orders/*",),
        payload_class_denylist=("destructive-sql",),
    )
    return Bundle(
        engagement_id=EngagementId("eng-x"),
        data=generate_data(scope, environment="staging"),
        rego_paths=(FIXED_REGO_PATH,),
    )


def _opa_input(*, host: str, payload_class: str) -> OpaInput:
    from doo.canonical.value_objects import HostRef
    from doo.dispatch.models import ConcreteRequest
    from doo.ids import AuthContextId

    run = DispatchRun(
        engagement_id=EngagementId("eng-x"),
        run_id=DispatchRunId("run-aaaaaaaaaaaa"),
        trace_id=TraceId("0" * 32),
        environment="staging",
        arming="review",
        interpreter="confirm",
        selection=DispatchSelection(),
        budget=RunBudget(request_budget=1, wallclock_budget_s=60, max_tool_calls=1),
        actor="t",
        armed_at=datetime.now(UTC),
    )
    req = ConcreteRequest(
        method="GET",
        host=HostRef(scheme="https", canonical_hostname=host),
        path="/orders/123",
        path_template="/orders/{order_id}",
        auth_context_id=AuthContextId("ac"),
    )
    return OpaInput.from_send(
        run=run,
        request=req,
        test_class="idor",
        payload_class=payload_class,  # type: ignore[arg-type]
        role="primary",
        principal_tier="declared",
        target_confidence=1.0,
        now=datetime.now(UTC),
    )


def test_opa_eval_client_allow_and_deny_with_reason() -> None:
    """`OpaEvalClient` over a real generated bundle: allow on in-scope; deny with
    a named reason on `payload_class_denylist` and on out-of-scope host."""

    _require_opa()
    client = OpaEvalClient(_bundle())
    try:
        # In-scope: allow.
        assert client.evaluate(
            _opa_input(host="api.example.com", payload_class="auth-token-swap")
        ).allow is True

        # payload_class denied: deny with the gate name in `reason`.
        d = client.evaluate(
            _opa_input(host="api.example.com", payload_class="destructive-sql")
        )
        assert d.allow is False
        assert "payload_class_denied" in str(d.reason)

        # Host out of scope: deny with the gate name.
        d = client.evaluate(
            _opa_input(host="evil.example.org", payload_class="auth-token-swap")
        )
        assert d.allow is False
        assert "host_not_in_scope" in str(d.reason)
    finally:
        client.close()


def test_resolve_opa_binary_raises_clear_error_when_absent(monkeypatch) -> None:
    """No `opa` on PATH and no `DOO_OPA_BIN` → `OpaUnavailableError` naming the fix."""

    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("DOO_OPA_BIN", raising=False)
    with pytest.raises(OpaUnavailableError, match="opa.*PATH"):
        resolve_opa_binary()
