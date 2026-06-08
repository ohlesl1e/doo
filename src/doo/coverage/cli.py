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

from doo.coverage.models import C1Result, C2bResult, C2Result, C3Result
from doo.coverage.queries import run_c1, run_c2, run_c2b, run_c3
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
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to analyze."
    ),
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


def _evidence_cell(ev: object) -> str:
    """Render a per-principal evidence tuple (or '-' when B never reached)."""

    if ev is None:
        return "-"
    status = getattr(ev, "status", None)
    size = getattr(ev, "response_size_bytes", None)
    return f"{status}/{size if size is not None else '?'}b"


def _render_c2_table(rows: list[C2Result]) -> None:
    if not rows:
        typer.echo("C2: no presence-differential authz gaps for the selected principals.")
        return
    typer.echo(f"C2 — reached as A but not as B (authz-coverage gaps): {len(rows)}")
    typer.echo(
        f"{'A':<16} {'B':<16} {'METHOD':<7} {'PATH':<32} "
        f"{'A(stat/sz)':<12} {'B(stat/sz)':<12} {'CONF':>6}"
    )
    for r in rows:
        typer.echo(
            f"{r.principal_a_label:<16} {r.principal_b_label:<16} {r.method:<7} "
            f"{r.path_template:<32} {_evidence_cell(r.evidence_a):<12} "
            f"{_evidence_cell(r.evidence_b):<12} {r.effective_confidence:>6.3f}"
        )


@coverage_app.command("c2")
def c2(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to analyze."
    ),
    as_label: str | None = typer.Option(
        None, "--as", help="Pin principal A by label (the side that reached). Default: all."
    ),
    not_as_label: str | None = typer.Option(
        None,
        "--not-as",
        help="Pin principal B by label (the side that did NOT reach). Default: all.",
    ),
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
    """C2: endpoints reached (2xx) as principal A but not as principal B."""

    from doo.observability.ids import new_span_id, new_trace_id
    from doo.observability.logging import bind_correlation, configure_logging

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())

    client = _build_client()
    try:
        rows = run_c2(
            client,
            EngagementId(engagement),
            as_label=as_label,
            not_as_label=not_as_label,
            min_confidence=min_confidence,
        )
    finally:
        client.close()

    if as_json:
        import json as _json

        typer.echo(_json.dumps([r.model_dump(mode="json") for r in rows], indent=2))
    else:
        _render_c2_table(rows)


def _render_c2b_table(rows: list[C2bResult]) -> None:
    if not rows:
        typer.echo(
            "C2b: no content-differential authz divergence "
            "(no endpoint was reached by ≥2 principals with differing responses)."
        )
        return
    typer.echo(
        f"C2b — reached by ≥2 principals with DIFFERING responses "
        f"(role-differentiated 200s): {len(rows)}"
    )
    typer.echo(f"{'METHOD':<7} {'PATH':<40} {'PRINCIPALS (label: stat/sz)':<48} {'CONF':>6}")
    for r in rows:
        cells = ", ".join(
            f"{ev.label}: {_evidence_cell(ev)}" for ev in r.evidence
        )
        typer.echo(f"{r.method:<7} {r.path_template:<40} {cells:<48} {r.effective_confidence:>6.3f}")


@coverage_app.command("c2b")
def c2b(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to analyze."
    ),
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
    """C2b: endpoints reached (2xx) by ≥2 principals whose responses differ (body/size)."""

    from doo.observability.ids import new_span_id, new_trace_id
    from doo.observability.logging import bind_correlation, configure_logging

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())

    client = _build_client()
    try:
        rows = run_c2b(client, EngagementId(engagement), min_confidence=min_confidence)
    finally:
        client.close()

    if as_json:
        import json as _json

        typer.echo(_json.dumps([r.model_dump(mode="json") for r in rows], indent=2))
    else:
        _render_c2b_table(rows)


_SHAPE_RANK_LABELS = {0: "specific", 1: "opaque", 2: "integer", 3: "other"}


def _render_c3_table(rows: list[C3Result]) -> None:
    if not rows:
        typer.echo(
            "C3: no leak-to-input pivots "
            "(no promoted value is both a response output and a request input "
            "to an in-scope endpoint)."
        )
        return
    typer.echo(f"C3 — leak-to-input pivots: {len(rows)}")
    typer.echo(
        f"{'SHAPE':<9} {'KIND':<16} {'PREVIEW':<18} {'TARGET (method path)':<32} "
        f"{'PARAM':<16} {'SOURCES':<28} {'CONF':>6}"
    )
    for r in rows:
        preview = r.value_preview if r.value_preview is not None else r.value_hash[:8]
        target = f"{r.target_method} {r.target_path_template}"
        sources = ", ".join(r.source_endpoints) if r.source_endpoints else "(same)"
        shape = _SHAPE_RANK_LABELS.get(r.shape_rank, str(r.shape_rank))
        param = r.parameter_name or "-"
        typer.echo(
            f"{shape:<9} {r.kind:<16} {preview:<18} {target:<32} "
            f"{param:<16} {sources:<28} {r.effective_confidence:>6.3f}"
        )


@coverage_app.command("c3")
def c3(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to analyze."
    ),
    include_same_endpoint: bool = typer.Option(
        False,
        "--include-same-endpoint",
        help="Also surface same-endpoint value reuse (e.g. a pagination token "
        "echoed back). Off by default: cross-endpoint pivots only.",
    ),
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
    """C3: values leaked in one endpoint's response and sent as input to another."""

    from doo.observability.ids import new_span_id, new_trace_id
    from doo.observability.logging import bind_correlation, configure_logging

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())

    client = _build_client()
    try:
        rows = run_c3(
            client,
            EngagementId(engagement),
            include_same_endpoint=include_same_endpoint,
            min_confidence=min_confidence,
        )
    finally:
        client.close()

    if as_json:
        import json as _json

        typer.echo(_json.dumps([r.model_dump(mode="json") for r in rows], indent=2))
    else:
        _render_c3_table(rows)
