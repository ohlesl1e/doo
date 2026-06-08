"""`doo coverage` Typer sub-app — slice 2, `c1` first (ADR-0034).

A thin consumer of the shared coverage query library: it parses args, builds a
Neo4j client, calls `run_c1`, and renders. Two output modes from one
serialization (ADR-0034): a human-readable table by default, and `--json`
emitting the typed result models (round-trippable, the planner / fixture form).

**Settle-point assumption (ADR-0022).** Coverage reads at a settle point and
assumes ingestion has already drained and the deferred endpoint inference has
flushed (`doo worker run` reaching end-of-drain). This command does *not* itself
trigger a flush — it is a pure read — so run it after ingestion settles.
"""

from __future__ import annotations

import os

import typer

from doo.coverage.models import C1Result
from doo.coverage.queries import run_c1
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient

coverage_app = typer.Typer(
    help="Coverage analysis: deterministic read-only queries over the graph "
    "(slice 2, ADR-0033/0034). Run after ingestion settles.",
    no_args_is_help=True,
)


def _build_client() -> Neo4jClient:
    """Connect a read-only Neo4j client from the same env vars the rest of the
    CLI uses. Separate from `cli._build_graph_state` because coverage never
    bootstraps schema or writes — it only reads."""

    from doo.cli_env import connect_neo4j_or_exit

    return connect_neo4j_or_exit(
        os.environ.get("DOO_NEO4J_URI", "bolt://localhost:7687"),
        os.environ.get("DOO_NEO4J_USER", "neo4j"),
        os.environ.get("DOO_NEO4J_PASSWORD", "password"),
    )


def _render_c1_table(rows: list[C1Result]) -> None:
    if not rows:
        typer.echo("C1: no in-scope endpoints are dead (every in-scope endpoint has a HIT).")
        return
    typer.echo(f"C1 — dead endpoints (in-scope, never hit): {len(rows)}")
    typer.echo(f"{'METHOD':<7} {'HOST':<32} {'PATH':<40} {'CONF':>6}")
    for r in rows:
        typer.echo(
            f"{r.method:<7} {r.host:<32} {r.path_template:<40} {r.effective_confidence:>6.3f}"
        )


@coverage_app.command("c1")
def c1(
    engagement: str = typer.Option(..., "--engagement", help="Engagement id to analyze."),
    min_confidence: float = typer.Option(
        0.0,
        "--min-confidence",
        help="Drop rows below this effective (decayed) confidence. Default 0 = "
        "surface everything (low-confidence leads are never silently hidden).",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit the typed result models as JSON (round-trippable) instead of a table.",
    ),
) -> None:
    """C1: in-scope endpoints with no `HIT` edge of any kind (dead endpoints)."""

    from doo.observability.ids import new_span_id, new_trace_id
    from doo.observability.logging import bind_correlation, configure_logging

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())

    client = _build_client()
    try:
        rows = run_c1(client, EngagementId(engagement), min_confidence=min_confidence)
    finally:
        client.close()

    if as_json:
        import json as _json

        typer.echo(_json.dumps([r.model_dump(mode="json") for r in rows], indent=2))
    else:
        _render_c1_table(rows)
