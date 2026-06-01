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

## Slice-1 invariant

The Rego is deny-all (`default allow := false`, no granting rule). So every
fixture here is constructed to be **out-of-scope for the Python helper too**
(host not in the allowlist, etc.), making the expected answer `False` for both
paths. When the real Rego lands in slice 4, `True`-expecting fixtures get added.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from doo.canonical.value_objects import Scheme
from doo.policy.scope import is_in_scope
from doo.setup.config import ScopeRules

REGO_PATH = Path(__file__).resolve().parent.parent / "src" / "doo" / "policy" / "scope.rego"
REGO_QUERY = "data.doo.scope.allow"


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


# Every fixture is OUT of scope for the Python helper (host not in allowlist),
# so the expected answer is False — matching the deny-all Rego.
_OUT_OF_SCOPE_SCOPE = ScopeRules(
    host_patterns=("in-scope.example.com",),
    allowed_methods=("GET",),
    allowed_path_patterns=("/**",),
)

_FIXTURES: tuple[tuple[str, object], ...] = (
    ("bare_out_of_scope_host", FakeHost("https", "out-of-scope-host")),
    ("other_domain_host", FakeHost("https", "evil.example.org")),
    ("ip_literal_not_allowed", FakeHost("http", "10.0.0.5", is_ip_literal=True)),
    (
        "endpoint_out_of_scope_host",
        FakeEndpoint("GET", FakeHost("https", "out-of-scope-host"), "/users/{user_id}"),
    ),
    (
        "endpoint_other_host",
        FakeEndpoint("POST", FakeHost("https", "evil.test"), "/admin"),
    ),
)


def _node_to_input(node: object) -> dict[str, object]:
    """Serialise a fixture node to the OPA `input` document shape.

    Forward-compatible with the slice-4 Rego: it carries host fields plus the
    optional endpoint fields. The deny-all policy ignores `input` entirely in
    slice 1, but we send a faithful document so the fixture set is reusable when
    the real rules land.
    """

    host = getattr(node, "host", node)
    doc: dict[str, object] = {
        "host": {
            "scheme": host.scheme,
            "canonical_hostname": host.canonical_hostname,
            "port": host.port,
            "is_ip_literal": host.is_ip_literal,
        }
    }
    if hasattr(node, "method"):
        doc["method"] = node.method  # type: ignore[attr-defined]
    if hasattr(node, "path_template"):
        doc["path_template"] = node.path_template  # type: ignore[attr-defined]
    return doc


def _opa_allow(node: object) -> bool:
    """Evaluate `data.doo.scope.allow` for one node via the `opa eval` CLI."""

    opa = shutil.which("opa")
    assert opa is not None  # guarded by the skip in the test below
    input_doc = json.dumps(_node_to_input(node))
    proc = subprocess.run(
        [
            opa,
            "eval",
            "--format",
            "json",
            "--data",
            str(REGO_PATH),
            "--stdin-input",
            REGO_QUERY,
        ],
        input=input_doc,
        capture_output=True,
        text=True,
        check=True,
    )
    parsed = json.loads(proc.stdout)
    # `opa eval` returns {"result": [{"expressions": [{"value": <bool>}]}]}.
    # An undefined result (no `allow` binding) yields an empty result list; the
    # deny-all default makes `allow` always defined as False, so we read it.
    results = parsed.get("result", [])
    if not results:
        return False
    return bool(results[0]["expressions"][0]["value"])


@pytest.mark.parametrize("name,node", _FIXTURES, ids=[n for n, _ in _FIXTURES])
def test_python_helper_says_false_for_every_slice1_fixture(name: str, node: object) -> None:
    """Sanity: the Python side is False for every slice-1 fixture (out of scope)."""

    assert is_in_scope(node, _OUT_OF_SCOPE_SCOPE) is False, name


@pytest.mark.parametrize("name,node", _FIXTURES, ids=[n for n, _ in _FIXTURES])
def test_python_and_rego_agree(name: str, node: object) -> None:
    """The Python helper and the Rego policy must return identical answers."""

    if shutil.which("opa") is None:
        pytest.skip(
            "opa binary not on PATH; cannot run the Rego side of the dual-path "
            "test. Install OPA (brew install opa, or download the static binary) "
            "to exercise this. The Python-side assertions still run in "
            "test_python_helper_says_false_for_every_slice1_fixture and test_scope.py."
        )

    python_answer = is_in_scope(node, _OUT_OF_SCOPE_SCOPE)
    rego_answer = _opa_allow(node)
    assert python_answer == rego_answer == False, (  # noqa: E712 - explicit about both
        f"dual-path disagreement for fixture {name!r}: "
        f"python={python_answer} rego={rego_answer}"
    )
