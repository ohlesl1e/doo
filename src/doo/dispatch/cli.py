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

import typer

from doo.dispatch.executor.dispatcher import RedisLeaseReader, StubOpaClient
from doo.dispatch.executor.send import HttpxSender
from doo.dispatch.ledger import JsonFileDispatchLedger
from doo.dispatch.models import DispatchSelection
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.run import RunDependencies, arm_run, execute_run
from doo.dispatch.secrets import EnvSecretStore
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.redis_lease import RedisLease
from doo.observability.logging import configure_logging, get_logger
from doo.setup.config import ArmingMode, EngagementConfig

dispatch_app = typer.Typer(
    help="Dispatch: arm and drain a budget-bounded run over approved TestCases "
    "(slice 4, ADR-0042). The first command that SENDS traffic — kill-switch "
    "lease must be live (`doo engagement keepalive`).",
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
        help="Override dispatch.arming (review|auto). auto refuses on production (ADR-0042).",
    ),
    actor: str = typer.Option(
        os.environ.get("USER", "unknown"),
        "--actor",
        help="Tester identity for the dispatch ledger (ADR-0040: stays out of the graph).",
    ),
) -> None:
    """Arm and drain one dispatch run over approved TestCases (ADR-0042).

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

    deps = RunDependencies(
        neo4j=_build_neo4j(),
        lease=_build_lease(cfg.engagement.id),
        # S1: stub OPA (always-allow). S2 swaps in the generated-from-Scope Rego
        # client (ADR-0046). The gate sequence is unchanged.
        opa=StubOpaClient(allow=True),
        sender=HttpxSender(),
        secrets=EnvSecretStore.from_config(cfg),
        bodies=_build_body_store(),  # type: ignore[arg-type]
        ledger=_default_ledger(),
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

    sys.exit(0)
