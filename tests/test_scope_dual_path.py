"""Dual-path scope test (ADR-0020): Python `is_in_scope` vs. Rego must agree.

ADR-0020 makes this test mandatory: the same `(node, scope)` fixtures are fed
through both the Python helper (`doo.policy.scope.is_in_scope`) and the Rego
policy (`src/doo/policy/scope.rego`), and the answers must be identical. A drift
between the two produces silent bugs ("planner thinks in-scope, dispatcher
disagrees").

## OPA choice

We use the **`opa eval` CLI** (a single static binary), not the
`opa-python-client` library. Rationale:
- CLAUDE.md states "tests for policy decisions are unit tests on Rego"; the
  `opa eval` CLI runs the *actual* Rego the dispatcher will load, with no Python
  shim that could diverge from production evaluation.
- No extra Python dependency to pin/audit.

Install OPA (any one):
- `brew install opa`
- download the static binary from https://www.openpolicyagent.org/docs/latest/#running-opa
  and put it on `PATH`, or
- `docker run --rm -v "$PWD:/w" openpolicyagent/opa eval ...`

If `opa` is not on `PATH` this test **skips with a clear reason** (it does not
silently pass) — the Python-side assertions in `test_scope.py` still run.

## Slice-4 update (ADR-0046)

The Rego now has real rules. Fixtures cover BOTH `True` and `False` cases. The
`input` document is the ADR-0046 shape (`input.request.{scheme,method,host,
path,path_template}` + `payload_class`/`environment`/`request_role`/`now`); the
`data.scope` document is generated from the same `ScopeRules` the Python helper
reads, via `policy.bundle.generate_data` — so generation is exercised here too.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from doo.canonical.value_objects import Scheme
from doo.policy.bundle import FIXED_REGO_PATH, generate_data
from doo.policy.scope import is_in_scope
from doo.setup.config import ScopeRules

REGO_QUERY = "data.doo.scope.allow"


@dataclass(frozen=True)
class FakeHost:
    scheme: Scheme
    canonical_hostname: str
    port: int | None = None
    is_ip_literal: bool = False


@dataclass(frozen=True)
class FakeRequest:
    """A `ProposedRequestLike` for the Python helper + the source of the
    ADR-0046 `input.request` for the Rego."""

    method: str
    host: FakeHost
    path_template: str
    payload_class: str = "auth-token-swap"


# The Scope BOTH paths read: the Python helper takes it directly; the Rego
# reads `generate_data(_SCOPE)` (the bundle generator) — so generation is
# exercised dual-path too.
_SCOPE = ScopeRules(
    host_patterns=("api.example.com", "*.shop.example.com"),
    allowed_methods=("GET", "POST"),
    allowed_path_patterns=("/orders/*", "/me", "/api/**"),
    payload_class_denylist=("destructive-sql",),
)

# (name, node, expected) — both paths must return `expected`.
_FIXTURES: tuple[tuple[str, FakeRequest, bool], ...] = (
    # --- True (in-scope) cases: the slice-4 additions. ---
    (
        "in_scope_exact_host_one_segment",
        FakeRequest("GET", FakeHost("https", "api.example.com"), "/orders/123"),
        True,
    ),
    (
        "in_scope_glob_host_subdomain",
        FakeRequest("GET", FakeHost("https", "a.shop.example.com"), "/orders/42"),
        True,
    ),
    (
        "in_scope_globstar_path",
        FakeRequest("POST", FakeHost("https", "api.example.com"), "/api/v2/users/42"),
        True,
    ),
    (
        "in_scope_literal_path",
        FakeRequest("GET", FakeHost("https", "api.example.com"), "/me"),
        True,
    ),
    # --- False (out-of-scope) cases: the slice-1 set + new gates. ---
    (
        "out_of_scope_host",
        FakeRequest("GET", FakeHost("https", "evil.example.org"), "/orders/123"),
        False,
    ),
    (
        "glob_host_apex_not_matched",
        FakeRequest("GET", FakeHost("https", "shop.example.com"), "/orders/123"),
        False,
    ),
    (
        "method_not_allowed",
        FakeRequest("DELETE", FakeHost("https", "api.example.com"), "/orders/123"),
        False,
    ),
    (
        "path_extra_segment",
        FakeRequest("GET", FakeHost("https", "api.example.com"), "/orders/123/items"),
        False,
    ),
    (
        "payload_class_denied",
        FakeRequest(
            "GET",
            FakeHost("https", "api.example.com"),
            "/orders/123",
            payload_class="destructive-sql",
        ),
        False,
    ),
)


def _node_to_input(node: FakeRequest) -> dict[str, object]:
    """Serialise a fixture node to the ADR-0046 OPA `input` document.

    For the dual-path purpose the concrete `path` IS the `path_template` (these
    fixtures have no `{param}` placeholders that would distinguish them); the
    Rego matches on `path` (ADR-0046), the Python helper on `path_template`
    (ADR-0020) — the dual-path invariant is that those agree segment-wise.
    """

    return {
        "engagement_id": "eng-dual",
        "environment": "staging",
        "run_id": "run-dual",
        "request": {
            "scheme": node.host.scheme,
            "method": node.method,
            "host": node.host.canonical_hostname,
            "path": node.path_template,
            "path_template": node.path_template,
        },
        "test_class": "idor",
        "payload_class": node.payload_class,
        "request_role": "primary",
        "auth_context_id": "ac",
        "principal_tier": "declared",
        "target_confidence": 1.0,
        "now": "2026-06-12T10:00:00Z",
    }


def _opa_allow(node: FakeRequest, *, data_path: Path) -> bool:
    """Evaluate `data.doo.scope.allow` for one node via the `opa eval` CLI."""

    opa = shutil.which("opa")
    assert opa is not None  # guarded by the skip in the test below
    proc = subprocess.run(
        [
            opa,
            "eval",
            "--format",
            "json",
            "-d",
            str(FIXED_REGO_PATH),
            "-d",
            str(data_path),
            "--stdin-input",
            REGO_QUERY,
        ],
        input=json.dumps(_node_to_input(node)),
        capture_output=True,
        text=True,
        check=True,
    )
    parsed = json.loads(proc.stdout)
    results = parsed.get("result", [])
    if not results:
        return False
    return bool(results[0]["expressions"][0]["value"])


@pytest.fixture(scope="module")
def data_path() -> Path:
    """Materialise `generate_data(_SCOPE)` to a temp file for `opa eval -d`."""

    data = generate_data(_SCOPE, environment="staging")
    fd, path = tempfile.mkstemp(prefix="doo-dualpath-", suffix=".json")
    import os

    with os.fdopen(fd, "w") as f:
        json.dump(data, f, sort_keys=True)
    return Path(path)


@pytest.mark.parametrize(
    "name,node,expected", _FIXTURES, ids=[n for n, _, _ in _FIXTURES]
)
def test_python_helper_matches_expected(
    name: str, node: FakeRequest, expected: bool
) -> None:
    """Sanity: the Python side answers `expected` for every fixture (no OPA needed)."""

    assert is_in_scope(node, _SCOPE) is expected, name


@pytest.mark.parametrize(
    "name,node,expected", _FIXTURES, ids=[n for n, _, _ in _FIXTURES]
)
def test_python_and_rego_agree(
    name: str, node: FakeRequest, expected: bool, data_path: Path
) -> None:
    """The Python helper and the Rego policy must return identical answers."""

    if shutil.which("opa") is None:
        pytest.skip(
            "opa binary not on PATH; cannot run the Rego side of the dual-path "
            "test. Install OPA (brew install opa, or download the static binary) "
            "to exercise this. The Python-side assertions still run in "
            "test_python_helper_matches_expected and test_scope.py."
        )

    python_answer = is_in_scope(node, _SCOPE)
    rego_answer = _opa_allow(node, data_path=data_path)
    assert python_answer == rego_answer == expected, (
        f"dual-path disagreement for fixture {name!r}: "
        f"python={python_answer} rego={rego_answer} expected={expected}"
    )
