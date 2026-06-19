"""Typer CLI: `doo engagement start` / `doo engagement status` / `... keepalive`.

T1 ships the engagement subcommand group (start/status); T7 adds `keepalive`.
The CLI is a thin wrapper: it parses args, builds the right graph dependency,
calls into `doo.setup.loader` (or `doo.engagement.keepalive`), and prints
results. No business logic here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from doo.cli_worker import register_worker
from doo.coverage.cli import coverage_app
from doo.dispatch.cli import auth_helper_app, dispatch_app, finding_app
from doo.engagement.cli_keepalive import register_keepalive
from doo.engagement.cli_migrate import register_migrate_testcase_keys
from doo.ingestion.cli_ingest import register_ingest
from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import bind_correlation, configure_logging, get_logger
from doo.planner.cli import planner_app
from doo.setup import EngagementMismatchError, ScopeChangeRequiresConfirmation
from doo.setup.loader import GraphState, JsonFileLedger, load_engagement_from_yaml

app = typer.Typer(
    help="DOO — Department of Offense. Black-box security testing copilot.",
    no_args_is_help=True,
    add_completion=False,
)

engagement_app = typer.Typer(
    help="Engagement lifecycle: create/attach, inspect, and keep the "
    "kill-switch lease alive.",
    no_args_is_help=True,
)
app.add_typer(engagement_app, name="engagement")

# Slice-2: mount the coverage analyzer sub-app (`doo coverage c1 ...`, ADR-0034).
app.add_typer(coverage_app, name="coverage")

# Slice-3: mount the planner sub-app (`doo planner propose|review`, ADR-0040).
app.add_typer(planner_app, name="planner")

# Slice-4: mount the dispatch sub-app (`doo dispatch run`, ADR-0042).
app.add_typer(dispatch_app, name="dispatch")

# Slice-4: mount the finding sub-app (`doo finding review`, ADR-0045).
app.add_typer(finding_app, name="finding")

# Slice-4: mount the auth-helper sub-app (`doo auth-helper run`, ADR-0014/#91).
app.add_typer(auth_helper_app, name="auth-helper")

log = get_logger(__name__)


@app.callback()
def _load_environment() -> None:
    """Load a `.env` from the current directory (if present) before any command
    reads `DOO_*` config, so connection vars don't have to be exported by hand."""

    from doo.cli_env import load_dotenv

    load_dotenv()


def _default_ledger() -> JsonFileLedger:
    """Default ledger path: `~/.doo/engagement_ledger.json`.

    Overridable via `DOO_LEDGER_PATH` (used by tests and scripted runs that
    must not touch the operator's home directory).
    """
    import os

    override = os.environ.get("DOO_LEDGER_PATH")
    if override:
        return JsonFileLedger(Path(override))
    home = Path(os.path.expanduser("~"))
    return JsonFileLedger(home / ".doo" / "engagement_ledger.json")


def _build_graph_state() -> GraphState:
    """Build the Neo4j-backed `GraphState` implementation (T2 onward).

    Connects to Neo4j from environment configuration (the same env vars the
    `ingest` and `keepalive` commands read) and bootstraps the schema
    constraints idempotently so a fresh `engagement start` against an empty
    database lands the engagement under the ADR-0017 uniqueness invariants.
    Tests may inject their own `GraphState` instead of calling this.
    """
    import os

    from doo.cli_env import connect_neo4j_or_exit
    from doo.ontology.graph_state import Neo4jGraphState
    from doo.ontology.schema import apply_schema

    client = connect_neo4j_or_exit(
        os.environ.get("DOO_NEO4J_URI", "bolt://localhost:7687"),
        os.environ.get("DOO_NEO4J_USER", "neo4j"),
        os.environ.get("DOO_NEO4J_PASSWORD", "password"),
    )
    with client.driver.session() as session:
        apply_schema(session, edition=client.server_edition())
    return Neo4jGraphState(client)


@engagement_app.command("start")
def start(
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to the engagement YAML.",
        exists=True,
        readable=True,
        resolve_path=True,
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Skip the interactive confirm-prompt on material Scope diffs.",
    ),
) -> None:
    """Create or re-attach an engagement (idempotent).

    Loads the tester-side facts from the YAML (scope, principals, kill-switch,
    dispatch settings) and reconciles them with the graph. On a material Scope
    change it prints a diff and asks to confirm; `--apply` skips the prompt. A
    cosmetic-only or unchanged config is a no-op.
    """

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())
    log.info("engagement.start.invoked", config_path=str(config), apply=apply)

    state = _build_graph_state()
    ledger = _default_ledger()
    try:
        result = load_engagement_from_yaml(
            config,
            state,
            ledger,
            apply=apply,
            stdin=sys.stdin,
            stdout=sys.stdout,
        )
    except EngagementMismatchError as exc:
        typer.secho(f"engagement.id mismatch: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    except ScopeChangeRequiresConfirmation as exc:
        typer.secho(f"refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=3) from exc

    if result.created:
        typer.echo(f"created engagement {result.engagement_id} (scope {result.scope_content_hash[:12]}...)")
    elif result.noop:
        typer.echo(f"noop: engagement {result.engagement_id} is unchanged")
    elif result.cosmetic_only:
        typer.echo(f"updated engagement {result.engagement_id} (cosmetic only)")
    else:
        typer.echo(
            f"updated engagement {result.engagement_id} "
            f"(material changes applied; scope {result.scope_content_hash[:12]}...)"
        )


@engagement_app.command("status")
def status(
    engagement_id: str = typer.Argument(..., help="Engagement id to read."),
) -> None:
    """Read-only: print an engagement's properties + Scope content_hash.

    Reports the stored id, name, environment, and the Scope content hash so you
    can confirm what is attached and spot drift from a config. Writes nothing.
    """

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())

    from doo.ids import EngagementId

    state = _build_graph_state()
    current = state.fetch_engagement_state(EngagementId(engagement_id))
    if current is None:
        typer.secho(f"engagement {engagement_id} not found", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"engagement {current.engagement_id} ({current.engagement_name!r})\n"
        f"  description: {current.engagement_description!r}\n"
        f"  scope_content_hash: {current.scope_content_hash}\n"
        f"  kill_switch.lease_ttl_seconds: {current.kill_switch_ttl_seconds}\n"
        f"  kill_switch.refresh_interval_seconds: {current.kill_switch_refresh_seconds}"
    )


# T7: register `doo engagement keepalive` (single line; keeps cli.py diff small).
register_keepalive(engagement_app)
# ADR-0049 / #120: register `doo engagement migrate-testcase-keys`.
register_migrate_testcase_keys(engagement_app)
# T2: register `doo ingest har`.
register_ingest(app)
# Slice-1: register `doo worker run` (drives the L2 + L3 pipeline workers).
register_worker(app)


if __name__ == "__main__":
    app()
