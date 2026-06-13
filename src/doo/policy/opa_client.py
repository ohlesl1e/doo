"""OPA client: `opa eval` over the generated bundle (ADR-0003/0046).

The dispatcher's authoritative policy gate. Per CLAUDE.md, the OPA check at
dispatch is **correctness** — not bypassable because the planner already
checked. The client shells out to the `opa` binary (the same evaluator the
dual-path test uses, ADR-0020) so there is no Python shim that could diverge
from production evaluation.

The query is `data.doo.scope` (the whole result document: `{allow,
deny_reasons}`), so a deny carries an actionable reason the dispatcher surfaces
as `dispatcher_blocked(opa_deny: <reasons>)`.

Implements the `OpaClient` Protocol from `dispatch/executor/dispatcher.py`; S1's
`StubOpaClient` remains as a named alternative (greppable: every place the real
client must be wired).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from doo.dispatch.executor.dispatcher import OpaDecision
from doo.dispatch.models import OpaInput
from doo.observability.logging import get_logger
from doo.policy.bundle import Bundle

log = get_logger(__name__)

REGO_QUERY = "data.doo.scope"


class OpaUnavailableError(Exception):
    """The `opa` binary is not on PATH (and `DOO_OPA_BIN` is unset).

    The dispatcher's OPA check is the *correctness* gate (CLAUDE.md hard rule):
    refusing to start is correct. The CLI surfaces install instructions and a
    `--unsafe-stub-opa` escape hatch (staging only; refuses on production).
    """


class OpaEvaluationError(Exception):
    """`opa eval` returned a non-zero exit or unparseable output.

    Fail-closed: the dispatcher treats this as a deny (`dispatcher_blocked
    (opa_deny: evaluation_error)`), never as an allow.
    """


def resolve_opa_binary() -> str:
    """Locate the `opa` binary: `DOO_OPA_BIN` override, else `PATH`.

    `DOO_OPA_BIN` may point at a wrapper (e.g. a `docker run
    openpolicyagent/opa` shim) for environments without a native binary.
    """

    override = os.environ.get("DOO_OPA_BIN")
    if override:
        return override
    found = shutil.which("opa")
    if found is None:
        raise OpaUnavailableError(
            "the `opa` binary is not on PATH. Install it (one of):\n"
            "  - download the static binary from "
            "https://www.openpolicyagent.org/docs/latest/#running-opa and put it "
            "on PATH\n"
            "  - `brew install opa` / `apt install opa` (where packaged)\n"
            "  - set DOO_OPA_BIN to a wrapper script\n"
            "The dispatcher's OPA check is the correctness gate (ADR-0046); it "
            "is not bypassable on production targets."
        )
    return found


class OpaEvalClient:
    """`OpaClient` backed by `opa eval -d <rego> -d <data.json> --stdin-input`.

    The bundle's `data` is written once to a temp file at construction; each
    `evaluate()` is one subprocess. Cheap (a few ms per call) and identical to
    what an OPA sidecar would compute. A long-running sidecar (`opa run
    --server`) is a drop-in alternative implementation of the same Protocol when
    per-call subprocess overhead matters.
    """

    def __init__(self, bundle: Bundle, *, opa_bin: str | None = None) -> None:
        self._opa = opa_bin or resolve_opa_binary()
        self._rego_paths = bundle.rego_paths
        # Materialise `data` to a temp file once; `opa eval -d` reads JSON files
        # the same way it reads `.rego`, so the data document loads as `data.*`.
        fd, path = tempfile.mkstemp(prefix="doo-opa-data-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(bundle.data, f, sort_keys=True)
        self._data_path = Path(path)
        log.info(
            "policy.opa_client.ready",
            engagement_id=bundle.engagement_id,
            opa_bin=self._opa,
            rego=[str(p) for p in self._rego_paths],
        )

    def evaluate(self, input: OpaInput) -> OpaDecision:
        """One `opa eval` over the ADR-0046 `input`; fail-closed on any error."""

        cmd = [self._opa, "eval", "--format", "json", "--stdin-input"]
        for p in self._rego_paths:
            cmd += ["-d", str(p)]
        cmd += ["-d", str(self._data_path), REGO_QUERY]

        input_json = input.model_dump_json()
        try:
            proc = subprocess.run(
                cmd, input=input_json, capture_output=True, text=True, check=False
            )
        except FileNotFoundError as exc:
            raise OpaUnavailableError(str(exc)) from exc

        if proc.returncode != 0:
            log.error(
                "policy.opa_eval.failed",
                returncode=proc.returncode,
                stderr=proc.stderr.strip(),
            )
            # Fail closed: an evaluation error is a deny, never an allow.
            return OpaDecision(
                allow=False, reason=f"evaluation_error: {proc.stderr.strip()[:200]}"
            )

        try:
            parsed = json.loads(proc.stdout)
            results = parsed.get("result", [])
            if not results:
                # Undefined result document → deny (no `data.scope`, missing
                # rules) — the ADR-0003 deny-default.
                return OpaDecision(allow=False, reason="undefined (no data.scope)")
            doc = results[0]["expressions"][0]["value"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise OpaEvaluationError(
                f"unparseable `opa eval` output: {proc.stdout[:200]!r}"
            ) from exc

        allow = bool(doc.get("allow", False))
        if allow:
            return OpaDecision(allow=True, reason=None)
        reasons = doc.get("deny_reasons") or doc.get("gate_failures") or []
        reason = ", ".join(str(r) for r in reasons) if reasons else "policy denied"
        return OpaDecision(allow=False, reason=reason)

    def close(self) -> None:
        """Remove the temp data file."""

        try:
            self._data_path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
