"""`doo dispatch` Typer sub-app — slice 4, S1 spine (ADR-0042/0043).

A thin wrapper: parses args, loads the engagement YAML (for `environment` + the
secret-store env-var refs, ADR-0012), builds the run dependencies (Neo4j, the
read-only Redis lease, the **stub** OPA client, the `httpx` sender, the dispatch
ledger), arms the run, and drains it. **The first command that sends traffic.**

`arming = review` (the default, and the ONLY legal value on `production`) prompts
before the first send. `--arming auto` skips the prompt (staging only — the
loader and `DispatchRun` both refuse it on production, ADR-0042).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from doo.dispatch.interpreter.loop import MultiTurnLLMCaller

from doo.canonical.identity import auth_context_id, compute_anonymous_auth_hash
from doo.dispatch.candidates import RedispatchCandidate, list_redispatch_candidates
from doo.dispatch.executor.dispatcher import OpaClient, RedisLeaseReader, StubOpaClient
from doo.dispatch.executor.liveness import LivenessPolicy
from doo.dispatch.executor.send import HttpxSender
from doo.dispatch.ledger import JsonFileDispatchLedger
from doo.dispatch.models import DispatchRun, DispatchSelection
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.run import RunDependencies, arm_run, execute_run
from doo.dispatch.secrets import (
    EnvSecretStore,
    SlotResolvingSecretStore,
    build_declared_slot_map,
)
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.redis_lease import RedisLease
from doo.observability.logging import configure_logging, get_logger
from doo.ontology.graph_state import Neo4jGraphState
from doo.setup.config import ArmingMode, EngagementConfig

__all__ = ["dispatch_app", "finding_app", "auth_helper_app", "StubOpaClient"]


def _rotation_path() -> Path:
    """Path the auth-helper writes rotated material to + the Executor reads (S6)."""

    override = os.environ.get("DOO_SECRET_ROTATION_PATH")
    if override:
        return Path(override)
    return Path(os.path.expanduser("~")) / ".doo" / "secret_rotation.json"

dispatch_app = typer.Typer(
    help="Dispatch: arm and drain a budget-bounded run over approved TestCases. "
    "The first command that SENDS traffic — kill-switch lease must be live "
    "(`doo engagement keepalive`).",
    no_args_is_help=True,
)

log = get_logger(__name__)


def _build_neo4j() -> Neo4jClient:
    from doo.cli_env import connect_neo4j_or_exit

    return connect_neo4j_or_exit(
        os.environ.get("DOO_NEO4J_URI", "bolt://localhost:7687"),
        os.environ.get("DOO_NEO4J_USER", "neo4j"),
        os.environ.get("DOO_NEO4J_PASSWORD", "password"),
    )


def _build_lease(engagement_id: EngagementId) -> RedisLeaseReader:
    """Read-only lease check against the keepalive's Redis key (ADR-0014)."""

    import redis

    client = redis.Redis.from_url(
        os.environ.get("DOO_REDIS_URL", "redis://localhost:6379/0")
    )
    return RedisLeaseReader(lease=RedisLease(client, engagement_id))


def _build_reactive() -> object:
    """Reactive token-refresh emitter (ADR-0014/0044) on the shared Redis stream.

    A dead attacker token (authz `primary` 4xx + liveness probe 4xx) publishes an
    `auth_invalid` event the S6 auth-helper consumes. A missing/unreachable Redis
    must not fail dispatch — fall back to a no-op recorder (logged once).
    """

    from typing import cast

    from doo.dispatch.reactive import FakeReactiveEmitter, StreamReactiveEmitter
    from doo.infra.streams import RedisStreamLike, StreamClient

    try:
        import redis

        client = redis.Redis.from_url(
            os.environ.get("DOO_REDIS_URL", "redis://localhost:6379/0")
        )
        return StreamReactiveEmitter(StreamClient(cast(RedisStreamLike, client)))
    except Exception as exc:  # noqa: BLE001
        typer.secho(
            f"warning: reactive stream unavailable ({exc!r}); auth_invalid events "
            "will not be emitted (auth-helper rotation disabled this run)",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return FakeReactiveEmitter()


def _default_ledger() -> JsonFileDispatchLedger:
    override = os.environ.get("DOO_DISPATCH_LEDGER_PATH")
    if override:
        return JsonFileDispatchLedger(Path(override))
    home = Path(os.path.expanduser("~"))
    return JsonFileDispatchLedger(home / ".doo" / "dispatch_ledger.json")


def _load_config(config_path: Path) -> EngagementConfig:
    import yaml

    raw = yaml.safe_load(config_path.read_text())
    return EngagementConfig.model_validate(raw)


def _build_opa(
    neo4j: Neo4jClient, engagement_id: EngagementId, *, environment: str, unsafe_stub: bool
) -> OpaClient:
    """Build the dispatcher's OPA client (ADR-0046).

    Generates the bundle from the `Scope` node (so planner-side `is_in_scope` and
    this gate cannot drift) and constructs an `OpaEvalClient`. If `opa` is not
    on PATH and `--unsafe-stub-opa` was passed: warn loudly and fall back to the
    always-allow stub — **staging only**; on `production` this combination is
    refused (the dispatcher's OPA check is the correctness gate, CLAUDE.md).
    """

    from doo.policy.bundle import build_bundle
    from doo.policy.opa_client import OpaEvalClient, OpaUnavailableError

    overlay = os.environ.get("DOO_OPA_OVERLAY")
    bundle = build_bundle(
        neo4j,
        engagement_id,
        overlay_rego=Path(overlay) if overlay else None,
    )
    try:
        return OpaEvalClient(bundle)
    except OpaUnavailableError as exc:
        if not unsafe_stub:
            typer.secho(f"refused: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=4) from exc
        if environment == "production":
            typer.secho(
                "refused: --unsafe-stub-opa is staging-only; the dispatcher's "
                "OPA check is the correctness gate on production (ADR-0046)",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=4) from exc
        typer.secho(
            "WARNING: `opa` not available; --unsafe-stub-opa active "
            "(ALWAYS-ALLOW). Staging only.",
            fg=typer.colors.YELLOW,
            bold=True,
            err=True,
        )
        return StubOpaClient(allow=True)


def _resolve_interpreter_model(
    cli_model: str | None,
    *,
    graph_interpreter_model: str | None = None,
    graph_model: str | None = None,
) -> str:
    """ADR-0051 model precedence for the Interpreter role.

    ``--model`` > ``DOO_INTERPRETER_MODEL`` > ``DOO_PLANNER_MODEL``
    > ``Engagement.llm_interpreter_model`` > ``Engagement.llm_model``
    > default (``anthropic/claude-opus-4-8``).
    """
    return (
        cli_model
        or os.environ.get("DOO_INTERPRETER_MODEL")
        or os.environ.get("DOO_PLANNER_MODEL")
        or graph_interpreter_model
        or graph_model
        or "anthropic/claude-opus-4-8"
    )


def _build_interpreter(model: str) -> MultiTurnLLMCaller | None:
    """Build the multi-turn Interpreter caller (ADR-0043: native loop, litellm).

    The model id is resolved upstream by :func:`_resolve_interpreter_model`
    (ADR-0051). ``api_base`` / ``api_key`` resolve via
    ``resolve_llm_api_base("interpreter")`` (``DOO_INTERPRETER_API_BASE`` →
    ``DOO_LLM_API_BASE`` → ``None``, and the matching ``*_API_KEY`` chain).
    ``None`` is the **normal state** — litellm prefix-routes via its own
    per-provider env vars. Set ``DOO_INTERPRETER_API_BASE`` or
    ``DOO_LLM_API_BASE`` only to *force-pin* every interpreter call to one
    endpoint regardless of model prefix; a non-``openai/`` prefix against a
    pinned base is a protocol mismatch and fails loud.

    ``DOO_NO_INTERPRETER=1`` disables it (S1/S2 behaviour: ``primary`` only, no
    verdict) — useful for a smoke run before the model is configured.
    """

    if os.environ.get("DOO_NO_INTERPRETER"):
        typer.secho(
            "DOO_NO_INTERPRETER set: confirm loop disabled (primary-only run).",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return None

    from doo.cli_env import resolve_llm_api_base, resolve_llm_api_key
    from doo.dispatch.interpreter.loop import LiteLLMMultiTurnCaller

    temperature_raw = os.environ.get("DOO_PLANNER_TEMPERATURE", "0.0").strip()
    temperature: float | None
    if temperature_raw == "" or temperature_raw.lower() == "none":
        temperature = None
    else:
        try:
            temperature = float(temperature_raw)
        except ValueError:
            temperature = 0.0
    return LiteLLMMultiTurnCaller(
        model,
        temperature=temperature,
        api_base=resolve_llm_api_base("interpreter"),
        api_key=resolve_llm_api_key("interpreter"),
        timeout_s=120.0,
    )


def _build_body_store() -> object:
    """Body store: MinIO `BlobClient` if configured, else drop bodies.

    A misconfigured / unreachable MinIO must not block dispatch — the agent send
    still records `EXECUTED_AS` + `response_status`; only raw response bytes are
    dropped (logged once).
    """

    if os.environ.get("DOO_S3_ENDPOINT") is None:
        return NoopBodyStore()
    try:
        from doo.infra.blobs import BlobClient

        return BlobClient.from_config(
            endpoint_url=os.environ["DOO_S3_ENDPOINT"],
            access_key=os.environ.get("DOO_S3_ACCESS_KEY", "minioadmin"),
            secret_key=os.environ.get("DOO_S3_SECRET_KEY", "minioadmin"),
            bucket=os.environ.get("DOO_S3_BUCKET", "doo-blobs"),
        )
    except Exception as exc:  # noqa: BLE001
        typer.secho(
            f"warning: blob store unavailable ({exc!r}); response bodies dropped",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return NoopBodyStore()


def _parse_select(select: list[str]) -> DispatchSelection:
    """Parse `--select key=value,...` into a `DispatchSelection`."""

    generators: list[str] = []
    test_classes: list[str] = []
    for s in select:
        for pair in s.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise typer.BadParameter(
                    f"--select expects key=value (e.g. test_class=idor); got {pair!r}"
                )
            k, _, v = pair.partition("=")
            if k == "generator":
                generators.append(v)
            elif k == "test_class":
                test_classes.append(v)
            else:
                raise typer.BadParameter(
                    f"unknown --select key {k!r} (expected generator|test_class)"
                )
    return DispatchSelection(
        generators=tuple(generators), test_classes=tuple(test_classes)  # type: ignore[arg-type]
    )


@dispatch_app.command("run")
def run_cmd(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id (must match the YAML)."
    ),
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to the engagement YAML (for environment + ${VAR} token refs).",
        exists=True,
        readable=True,
        resolve_path=True,
    ),
    select: list[str] = typer.Option(
        [],
        "--select",
        help="Selection predicate: key=value (generator=c2, test_class=idor). Repeatable.",
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-n", min=1, help="Top-N by expected_yield."
    ),
    arming: ArmingMode | None = typer.Option(
        None,
        "--arming",
        help="Override dispatch.arming (review|auto). auto refuses on production.",
    ),
    unsafe_stub_opa: bool = typer.Option(
        False,
        "--unsafe-stub-opa",
        help="STAGING ONLY: fall back to an always-allow OPA stub when `opa` is "
        "not on PATH. Refuses on production.",
    ),
    actor: str = typer.Option(
        os.environ.get("USER", "unknown"),
        "--actor",
        help="Tester identity for the dispatch ledger (stays out of the graph).",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        help="Override the interpreter LLM model id for this run (ADR-0051: beats "
        "DOO_INTERPRETER_MODEL/DOO_PLANNER_MODEL and the engagement default).",
    ),
) -> None:
    """Arm and drain one dispatch run over approved TestCases.

    The kill-switch lease (`doo engagement keepalive --engagement …`) MUST be
    running in another terminal — every send checks it; a dead lease is
    `dispatcher_blocked(kill_switch)`.
    """

    configure_logging()

    cfg = _load_config(config)
    if cfg.engagement.id != engagement:
        typer.secho(
            f"--engagement {engagement!r} does not match {config}'s engagement.id "
            f"{cfg.engagement.id!r}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    selection = _parse_select(select).model_copy(update={"limit": limit})
    try:
        run = arm_run(
            config=cfg, selection=selection, actor=actor, arming=arming
        )
    except ValueError as exc:
        # ADR-0042 environment-gates-modes refusal (e.g. --arming auto on prod).
        typer.secho(f"refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=3) from exc

    typer.echo(
        f"dispatch run {run.run_id} on engagement {run.engagement_id} "
        f"(environment={run.environment}, arming={run.arming}, "
        f"interpreter={run.interpreter})\n"
        f"  selection: {selection.describe()}\n"
        f"  budget: {run.budget.request_budget} requests / "
        f"{run.budget.wallclock_budget_s}s wallclock\n"
        f"  actor: {actor}"
    )

    if run.arming == "review":
        typer.secho(
            "\narming=review: this run will SEND traffic to the target. Proceed?",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm("arm run", default=False):
            typer.secho("not armed; aborting.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(code=0)

    _execute_and_render(
        cfg, run, engagement=engagement, model=model, unsafe_stub_opa=unsafe_stub_opa
    )
    sys.exit(0)


def _execute_and_render(
    cfg: EngagementConfig,
    run: DispatchRun,
    *,
    engagement: str,
    model: str | None,
    unsafe_stub_opa: bool,
) -> None:
    """Build run dependencies, drain the (already-armed) run, and render the summary.

    Shared by `doo dispatch run` and `doo dispatch redispatch --rerun` — both drain
    a `DispatchRun` through the identical gate (lease → OPA → budget → wire), so the
    rerun path picks up the #170 watermark guard + #168 verify with no special case.
    """

    neo4j = _build_neo4j()
    graph_llm_model, graph_llm_interpreter_model = Neo4jGraphState(
        neo4j
    ).get_engagement_llm_models(cfg.engagement.id)
    resolved_model = _resolve_interpreter_model(
        model,
        graph_interpreter_model=graph_llm_interpreter_model,
        graph_model=graph_llm_model,
    )
    # ADR-0049: one read at run-arm — every declared AuthContext id (all
    # generations) → its rotation-stable (principal_label, slot). Shared by the
    # secret store and the liveness policy so a stale plan-time id still arms.
    graph_map = build_declared_slot_map(neo4j, cfg.engagement.id)
    anon = auth_context_id(cfg.engagement.id, compute_anonymous_auth_hash())
    deps = RunDependencies(
        neo4j=neo4j,
        lease=_build_lease(cfg.engagement.id),
        # ADR-0046: bundle generated from the `Scope` node + fixed Rego ruleset.
        # The gate sequence (lease → OPA → budget → wire) is unchanged from S1.
        opa=_build_opa(
            neo4j,
            cfg.engagement.id,
            environment=cfg.environment,
            unsafe_stub=unsafe_stub_opa,
        ),
        sender=HttpxSender(verify=cfg.dispatch.tls_verify),
        secrets=SlotResolvingSecretStore(
            graph_map=graph_map,
            env=EnvSecretStore.from_config(cfg),
            anon_id=anon,
            rotation_path=_rotation_path(),
        ),
        bodies=_build_body_store(),  # type: ignore[arg-type]
        ledger=_default_ledger(),
        interpreter=_build_interpreter(resolved_model),
        # ADR-0044: declared liveness endpoints + body matchers, and the reactive
        # refresh emitter for a dead token.
        liveness=LivenessPolicy.from_config(cfg, graph_map=graph_map),
        reactive=_build_reactive(),  # type: ignore[arg-type]
    )

    result = execute_run(run, deps)

    typer.echo(
        f"\ndispatch run {result.run.run_id} complete: "
        f"{len(result.outcomes)} TestCase(s) drained, "
        f"{result.requests_sent} request(s) sent."
    )
    by_kind: dict[str, int] = {}
    for o in result.outcomes:
        by_kind[o.outcome] = by_kind.get(o.outcome, 0) + 1
    for kind, n in sorted(by_kind.items()):
        typer.echo(f"  {kind}: {n}")
    for o in result.outcomes:
        if o.outcome != "executed":
            typer.secho(
                f"  • {o.key_hash[:12]} [{o.test_class}] → {o.outcome}: {o.reason}",
                fg=typer.colors.YELLOW,
            )

    # #125: a `vulnerable` verdict that landed on an already-decided Finding
    # is surfaced here so the tester re-reviews (ADR-0045 keeps the prior
    # decision sticky; this is the visibility, not a reset).
    reasserted = [o for o in result.outcomes if o.finding_reasserted is not None]
    if reasserted:
        typer.secho(
            f"\n⚠ {len(reasserted)} Finding(s) re-asserted vulnerable against a "
            "prior decision:",
            fg=typer.colors.YELLOW,
            bold=True,
        )
        for o in reasserted:
            assert o.finding_reasserted is not None
            fk, prior = o.finding_reasserted
            typer.secho(
                f"  • {fk[:12]} was {prior!r}; re-review with "
                f"`doo finding review -e {engagement} --confirm/--reject {fk[:12]}`",
                fg=typer.colors.YELLOW,
            )

    if result.liveness_unverified:
        # ADR-0044 one-time flag: an authz 4xx fell back to `ok` because no
        # liveness endpoint resolved — those negatives are unverified.
        typer.secho(
            "\nWARNING: no liveness endpoint for ≥1 AuthContext — authz 4xx "
            "results were taken as 'boundary held' WITHOUT verifying the token is "
            "live (ADR-0044). Declare principals[].liveness_endpoint to verify.",
            fg=typer.colors.YELLOW,
            bold=True,
            err=True,
        )


# ---------------------------------------------------------------------------
# `doo dispatch review` (S5/#90) — triage refused TestCases + set hazard overrides.
# ---------------------------------------------------------------------------

# Outcomes worth a human's attention (a refused or blocked test, not an executed one).
_REVIEWABLE_OUTCOMES = frozenset(
    {
        "hazard_unresolved",
        "dispatcher_blocked",
        "constructor_missing",
        "auth_unverified",
        "waiting_on_rotation",
    }
)


@dispatch_app.command("review")
def review_cmd(
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    as_json: bool = typer.Option(False, "--json", help="Emit the reviewable outcomes as JSON."),
    set_hint: tuple[str, str, str] = typer.Option(
        ("", "", ""),
        "--set-hint",
        help="Supply a hazard source_hint: <key_hash> <kind> <url>. The next run reads it.",
    ),
    ignore_hazard: tuple[str, str] = typer.Option(
        ("", ""),
        "--ignore-hazard",
        help="Send anyway despite a hazard: <key_hash> <kind> (accepts replay_invalid risk).",
    ),
) -> None:
    """List refused/blocked TestCases from the dispatch ledger; set hazard overrides.

    The latest non-`executed` `RunOutcome` per TestCase (`hazard_unresolved` with
    its `{kind, param, reason}`, `dispatcher_blocked`, `constructor_missing`).
    `--set-hint` / `--ignore-hazard` append an override the next `doo dispatch run`
    consults before resolving that hazard.
    """

    import json as _json

    from doo.dispatch.ledger import record_override
    from doo.dispatch.models import RunOutcome
    from doo.ids import TestCaseKeyHash

    configure_logging()
    ledger = _default_ledger()
    eid = EngagementId(engagement)

    if set_hint[0]:
        key, kind, url = set_hint
        record_override(
            ledger, engagement_id=eid, key_hash=TestCaseKeyHash(key),
            action="set_hint", hazard_kind=kind, hint=url,
        )
        typer.echo(f"set-hint recorded: {key[:12]} {kind} → {url}")
        return
    if ignore_hazard[0]:
        key, kind = ignore_hazard
        record_override(
            ledger, engagement_id=eid, key_hash=TestCaseKeyHash(key),
            action="ignore_hazard", hazard_kind=kind,
        )
        typer.echo(f"ignore-hazard recorded: {key[:12]} {kind} (next run sends anyway)")
        return

    # List: latest non-executed outcome per key_hash.
    latest: dict[str, RunOutcome] = {}
    for ev in ledger.all_for_engagement(eid):
        if ev.kind == "outcome" and ev.outcome is not None:
            latest[str(ev.outcome.key_hash)] = ev.outcome
    reviewable = [o for o in latest.values() if o.outcome in _REVIEWABLE_OUTCOMES]

    if as_json:
        typer.echo(_json.dumps([o.model_dump(mode="json") for o in reviewable], indent=2))
        return
    if not reviewable:
        typer.echo(f"no reviewable (refused/blocked) outcomes in engagement {engagement!r}")
        return
    typer.echo(f"{len(reviewable)} reviewable outcome(s) in engagement {engagement!r}:\n")
    for o in reviewable:
        typer.secho(
            f"  {o.key_hash[:12]}  [{o.test_class}] → {o.outcome}",
            fg=typer.colors.YELLOW,
        )
        if o.hazard is not None:
            h = o.hazard
            typer.echo(f"      hazard {h.kind} on {h.param!r}: {h.reason}")
            typer.echo(
                f"      fix:  doo dispatch review -e {engagement} --set-hint "
                f"{o.key_hash} {h.kind} <url>\n"
                f"      skip: doo dispatch review -e {engagement} --ignore-hazard "
                f"{o.key_hash} {h.kind}"
            )
        elif o.reason:
            typer.echo(f"      {o.reason}")


# ---------------------------------------------------------------------------
# `doo dispatch redispatch` (ADR-0053, #171) — report stuck candidates + rerun.
# ---------------------------------------------------------------------------


def _echo_candidate(c: RedispatchCandidate) -> None:
    last = c.last_fail.isoformat() if c.last_fail is not None else "(unknown)"
    typer.echo(
        f"    {c.key_hash[:12]}  [{c.test_class}] {c.principal}:{c.slot} "
        f"failure={c.failure_kind} last_fail={last}"
    )


@dispatch_app.command("redispatch")
def redispatch_cmd(
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    config: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Engagement YAML — REQUIRED with --rerun (environment + ${VAR} tokens).",
        exists=True,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Emit the candidate report as JSON."
    ),
    rerun: bool = typer.Option(
        False,
        "--rerun",
        help="Re-dispatch the eligible candidates (needs --config). Default: report only.",
    ),
    key_hash: list[str] = typer.Option(
        [],
        "--key-hash",
        help="Narrow the rerun to these key_hash(es)/prefixes (repeatable). "
        "Default: all eligible.",
    ),
    arming: ArmingMode | None = typer.Option(
        None, "--arming", help="Override dispatch.arming (review|auto)."
    ),
    unsafe_stub_opa: bool = typer.Option(
        False,
        "--unsafe-stub-opa",
        help="STAGING ONLY: always-allow OPA stub when `opa` is not on PATH.",
    ),
    actor: str = typer.Option(
        os.environ.get("USER", "unknown"),
        "--actor",
        help="Tester identity for the dispatch ledger (stays out of the graph).",
    ),
    model: str | None = typer.Option(
        None, "--model", help="Override the interpreter LLM model id for the rerun."
    ),
) -> None:
    """Report re-dispatch candidates; `--rerun` re-sends the eligible ones.

    A candidate is an approved TestCase that failed `auth_invalid` / `auth_unverified`
    and never reached a clean `ok` primary (ADR-0053). `eligible` candidates have a
    credential slot that rotated past the failure (the #170 watermark); the rest are
    waiting on rotation. `--rerun` drains the eligible set through the SAME gate as
    `doo dispatch run`, so the #170 guard + #168 verify still apply.
    """

    import json as _json

    from doo.ids import TestCaseKeyHash

    configure_logging()
    neo4j = _build_neo4j()
    candidates = list_redispatch_candidates(
        neo4j, engagement_id=EngagementId(engagement)
    )
    eligible = [c for c in candidates if c.eligible]
    waiting = [c for c in candidates if not c.eligible]

    if not rerun:
        if as_json:
            typer.echo(
                _json.dumps(
                    [
                        {
                            "key_hash": c.key_hash,
                            "test_class": c.test_class,
                            "principal": c.principal,
                            "slot": c.slot,
                            "failure_kind": c.failure_kind,
                            "eligible": c.eligible,
                            "last_fail": (
                                c.last_fail.isoformat()
                                if c.last_fail is not None
                                else None
                            ),
                        }
                        for c in candidates
                    ],
                    indent=2,
                )
            )
            return
        if not candidates:
            typer.echo(f"no re-dispatch candidates in engagement {engagement!r}")
            return
        typer.echo(
            f"{len(candidates)} re-dispatch candidate(s) in engagement {engagement!r} "
            f"({len(eligible)} eligible, {len(waiting)} waiting on rotation):\n"
        )
        if eligible:
            typer.secho(f"  eligible now ({len(eligible)}):", fg=typer.colors.GREEN)
            for c in eligible:
                _echo_candidate(c)
        if waiting:
            typer.secho(
                f"  waiting on rotation ({len(waiting)}):", fg=typer.colors.YELLOW
            )
            for c in waiting:
                _echo_candidate(c)
        if eligible:
            typer.echo(
                f"\nrerun: doo dispatch redispatch -e {engagement} -c <config> --rerun"
            )
        return

    # --- rerun the eligible set (through the full run gate). ---
    if config is None:
        typer.secho("--rerun requires --config", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    cfg = _load_config(config)
    if cfg.engagement.id != engagement:
        typer.secho(
            f"--engagement {engagement!r} does not match {config}'s engagement.id "
            f"{cfg.engagement.id!r}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    want = set(key_hash)
    chosen = [
        c for c in eligible if not want or any(c.key_hash.startswith(k) for k in want)
    ]
    if not chosen:
        typer.echo(f"no eligible candidates to re-dispatch in engagement {engagement!r}")
        raise typer.Exit(code=0)
    selection = DispatchSelection(
        key_hashes=tuple(TestCaseKeyHash(c.key_hash) for c in chosen)
    )
    try:
        run = arm_run(config=cfg, selection=selection, actor=actor, arming=arming)
    except ValueError as exc:
        typer.secho(f"refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=3) from exc

    typer.echo(
        f"re-dispatching {len(chosen)} eligible candidate(s) on engagement "
        f"{run.engagement_id} (environment={run.environment}, arming={run.arming})"
    )
    if run.arming == "review":
        typer.secho(
            "\narming=review: this run will SEND traffic to the target. Proceed?",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm("arm re-dispatch", default=False):
            typer.secho("not armed; aborting.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(code=0)

    _execute_and_render(
        cfg, run, engagement=engagement, model=model, unsafe_stub_opa=unsafe_stub_opa
    )
    sys.exit(0)


# ---------------------------------------------------------------------------
# `doo finding review` (ADR-0045) — sibling of `doo planner review`.
# ---------------------------------------------------------------------------

finding_app = typer.Typer(
    help="Finding lifecycle: review proposed Findings. "
    "Only `confirmed` Findings feed reporting.",
    no_args_is_help=True,
)


def _default_finding_ledger() -> object:
    from doo.dispatch.finding import JsonFileFindingLedger

    override = os.environ.get("DOO_FINDING_LEDGER_PATH")
    if override:
        return JsonFileFindingLedger(Path(override))
    home = Path(os.path.expanduser("~"))
    return JsonFileFindingLedger(home / ".doo" / "finding_ledger.json")


@finding_app.command("review")
def finding_review_cmd(
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    confirm: str | None = typer.Option(
        None, "--confirm", help="Confirm one Finding by its finding_key (or 12-char prefix)."
    ),
    reject: str | None = typer.Option(
        None, "--reject", help="Reject one Finding by its finding_key (or 12-char prefix)."
    ),
    reason: str | None = typer.Option(
        None, "--reason", help="Why (recorded in the audit ledger)."
    ),
    actor: str = typer.Option(
        os.environ.get("USER", "unknown"),
        "--actor",
        help="Who is making this decision (recorded in the audit ledger).",
    ),
    include_reasserted: bool = typer.Option(
        True,
        "--include-reasserted/--no-include-reasserted",
        help="Also show decided Findings re-asserted vulnerable since the last "
        "decision (#125).",
    ),
) -> None:
    """List `proposed` Findings (with transcript link); confirm/reject one.

    With no action flag, lists the Findings a dispatch run committed at
    `finding_status = proposed`, each with a link to its confirm-loop transcript.
    `--confirm` / `--reject` (by finding_key or prefix) records the human
    decision; only `confirmed` Findings feed reporting.
    """

    from doo.dispatch.finding import (
        list_proposed_findings,
        list_reasserted_findings,
        resolve_finding_key,
        review_finding,
    )

    configure_logging()
    neo4j = _build_neo4j()
    ledger = _default_finding_ledger()
    eid = EngagementId(engagement)

    if confirm or reject:
        target = (confirm or reject or "").strip()
        # Resolve against ALL active Findings (not just proposed): a tester
        # may override a prior reject after re-test. The ledger records
        # `prior_status → new_status` so the audit trail is intact (ADR-0045).
        try:
            full_key = resolve_finding_key(neo4j, eid, target)
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from exc
        if full_key is None:
            typer.secho(
                f"no Finding matching {target!r} in engagement {engagement!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        decision = "confirm" if confirm else "reject"
        event = review_finding(
            neo4j,
            ledger,  # type: ignore[arg-type]
            engagement_id=eid,
            finding_key=full_key,
            decision=decision,  # type: ignore[arg-type]
            actor=actor,
            reason=reason,
        )
        typer.echo(
            f"Finding {full_key[:12]} {event.prior_status} → {event.new_status} by {actor}"
        )
        return

    proposed = list_proposed_findings(neo4j, eid)

    if not proposed:
        typer.echo(f"no proposed Findings in engagement {engagement!r}")
    else:
        typer.echo(
            f"{len(proposed)} proposed Finding(s) in engagement {engagement!r}:\n"
        )
        for f in proposed:
            typer.echo(
                f"  {f.finding_key[:12]}  [{f.severity:>8}] {f.category:<24} "
                f"affects {f.affects}"
            )
            typer.echo(f"      {f.title}")
            typer.echo(
                f"      references {len(f.referenced_testcases)} TestCase(s); "
                f"transcript: {f.transcript_key or '(not persisted)'}"
            )

    reasserted = (
        list_reasserted_findings(neo4j, eid, ledger)  # type: ignore[arg-type]
        if include_reasserted
        else []
    )
    if reasserted:
            typer.secho(
                f"\n⚠ {len(reasserted)} Finding(s) re-asserted vulnerable since "
                "last decision:",
                fg=typer.colors.YELLOW,
                bold=True,
            )
            for f in reasserted:
                typer.secho(
                    f"  {f.finding_key[:12]}  [{f.severity:>8}] {f.category:<24} "
                    f"affects {f.affects}  (was: {f.finding_status})",
                    fg=typer.colors.YELLOW,
                )

    if proposed or reasserted:
        typer.echo(
            "\nconfirm: doo finding review -e <eng> --confirm <key>\n"
            "reject:  doo finding review -e <eng> --reject <key> --reason '…'"
        )


# ---------------------------------------------------------------------------
# `doo auth-helper run` (ADR-0014/#91) — sibling of `doo engagement keepalive`.
# ---------------------------------------------------------------------------

auth_helper_app = typer.Typer(
    help="Auth-helper: rotate declared AuthContexts (proactive + reactive). "
    "A SIBLING process — holds refresh creds in its OWN env; the dispatcher "
    "never does. Run alongside `doo engagement keepalive`.",
    no_args_is_help=True,
)


@auth_helper_app.command("run")
def auth_helper_run_cmd(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id (must match the YAML)."
    ),
    config: Path = typer.Option(
        ..., "--config", "-c", exists=True, readable=True, resolve_path=True,
        help="Engagement YAML (auth_contexts[].refresh blocks + ${VAR} token refs).",
    ),
) -> None:
    """Rotate declared AuthContexts until SIGTERM (never the agent process).

    Proactive (per `validity_window_s`) + reactive (consumes the `auth_invalid`
    events the dispatcher emits) rotation, rate-limited per AuthContext. Refresh
    credentials come from THIS process's env. New material lands in the rotation
    file the dispatcher's `SlotResolvingSecretStore` reads.
    """

    from typing import cast

    from doo.dispatch.auth_helper import AuthHelper
    from doo.infra.streams import RedisStreamLike, StreamClient

    configure_logging()
    cfg = _load_config(config)
    if cfg.engagement.id != engagement:
        typer.secho(
            f"--engagement {engagement!r} != config engagement.id {cfg.engagement.id!r}",
            fg=typer.colors.RED, err=True,
        )
        raise typer.Exit(code=2)

    neo4j = _build_neo4j()
    streams: StreamClient | None = None
    try:
        import redis

        client = redis.Redis.from_url(
            os.environ.get("DOO_REDIS_URL", "redis://localhost:6379/0")
        )
        streams = StreamClient(cast(RedisStreamLike, client))
    except Exception as exc:  # noqa: BLE001
        typer.secho(
            f"warning: reactive stream unavailable ({exc!r}); proactive-only",
            fg=typer.colors.YELLOW, err=True,
        )

    helper = AuthHelper.from_config(
        cfg, neo4j=neo4j, rotation_path=_rotation_path(), streams=streams
    )
    if not helper.managed:
        typer.secho(
            "no AuthContexts declare a `refresh:` block — nothing to rotate.",
            fg=typer.colors.YELLOW, err=True,
        )
        raise typer.Exit(code=0)
    typer.echo(
        f"auth-helper for {engagement}: managing {len(helper.managed)} AuthContext(s); "
        f"rotation file {_rotation_path()}. Ctrl-C to stop."
    )
    raise typer.Exit(code=helper.run())
