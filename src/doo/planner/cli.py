"""`doo planner` Typer sub-app — slice 3, propose/review (ADR-0040).

Mirrors `doo coverage`: a thin consumer that parses args, builds a Neo4j client +
the review ledger, calls into the planner service, and renders (table by default,
`--json` for the typed models). Two commands:

- `doo planner propose` — run the enabled generators, validate, and commit
  `proposed` `TestCase`s. Deterministic C1 needs no extra deps; the LLM-proposing
  C2 generator (default-on) additionally builds a model caller + audit sink.
- `doo planner review` — show the deterministically-prioritised review queue and
  approve / reject a proposal. **Nothing is dispatched** (slice 3 is review-only).

**Settle-point assumption (ADR-0022)**, like coverage: run after ingestion drains
and the deferred inference has flushed; this command is a read + a planner write
(commit / review), it does not itself trigger a flush.
"""

from __future__ import annotations

import json as _json
import os
from pathlib import Path

import typer

from doo.ids import EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.planner.generators import PlannerConfig, requested_llm_generator_ids
from doo.planner.llm import LiteLLMCaller, LLMCaller
from doo.planner.llm_audit import BlobLLMAuditSink, LLMAuditSink
from doo.planner.models import ProposedTestCaseView
from doo.planner.review import (
    JsonFileReviewLedger,
    ReviewError,
    fetch_target_evidence,
    review_testcase,
)
from doo.planner.service import propose, review_queue

planner_app = typer.Typer(
    help="Planner: deterministic hypothesis generation + human review over the "
    "graph (slice 3, ADRs 0036–0041). Nothing is dispatched. Run after ingestion "
    "settles.",
    no_args_is_help=True,
)


def _build_client() -> Neo4jClient:
    """Connect a Neo4j client from the same env vars the rest of the CLI uses."""

    from doo.cli_env import connect_neo4j_or_exit

    return connect_neo4j_or_exit(
        os.environ.get("DOO_NEO4J_URI", "bolt://localhost:7687"),
        os.environ.get("DOO_NEO4J_USER", "neo4j"),
        os.environ.get("DOO_NEO4J_PASSWORD", "password"),
    )


def _build_llm_deps() -> tuple[LLMCaller, LLMAuditSink]:
    """Build the model caller + audit sink for an LLM-proposing planner run (ADR-0037).

    The model is `DOO_PLANNER_MODEL` (default Claude Opus 4.8). Two routing modes,
    both via litellm:
    - **Anthropic direct** — `DOO_PLANNER_MODEL=anthropic/claude-sonnet-4-6` with
      `ANTHROPIC_API_KEY` in the environment.
    - **Provider URL + key** (LiteLLM/OpenAI-compatible gateway, local proxy) —
      set `DOO_PLANNER_API_BASE` (+ `DOO_PLANNER_API_KEY`) and an `openai/<name>` id.
    `DOO_PLANNER_API_BASE` / `DOO_PLANNER_API_KEY` are optional overrides; unset, litellm
    resolves credentials from its provider env vars. The audit sink persists every
    proposing call to the same object storage as the rest of the CLI (`DOO_S3_*`).
    Built only when an LLM generator (C2) is actually requested.
    """

    from doo.infra.blobs import BlobClient

    model = os.environ.get("DOO_PLANNER_MODEL", "claude-opus-4-8")
    caller = LiteLLMCaller(
        model,
        api_base=os.environ.get("DOO_PLANNER_API_BASE") or None,
        api_key=os.environ.get("DOO_PLANNER_API_KEY") or None,
    )
    blobs = BlobClient.from_config(
        endpoint_url=os.environ.get("DOO_S3_ENDPOINT", "http://localhost:9000"),
        access_key=os.environ.get("DOO_S3_ACCESS_KEY", "minioadmin"),
        secret_key=os.environ.get("DOO_S3_SECRET_KEY", "minioadmin"),
        bucket=os.environ.get("DOO_S3_BUCKET", "doo-blobs"),
    )
    return caller, BlobLLMAuditSink(blobs)


def _default_ledger() -> JsonFileReviewLedger:
    """Default review ledger: `~/.doo/review_ledger.json` (or `DOO_REVIEW_LEDGER_PATH`)."""

    override = os.environ.get("DOO_REVIEW_LEDGER_PATH")
    if override:
        return JsonFileReviewLedger(Path(override))
    home = Path(os.path.expanduser("~"))
    return JsonFileReviewLedger(home / ".doo" / "review_ledger.json")


def _configure() -> None:
    from doo.observability.ids import new_span_id, new_trace_id
    from doo.observability.logging import bind_correlation, configure_logging

    configure_logging()
    bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())


@planner_app.command("propose")
def propose_cmd(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to plan against."
    ),
    generators: list[str] | None = typer.Option(
        None,
        "--generator",
        "-g",
        help="Enable only these candidate generators (repeatable). Default: all. "
        "The S1 spine ships 'c1' (deterministic dead-endpoint probes).",
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Emit the run summary as JSON instead of a table."
    ),
) -> None:
    """Run the deterministic generators and commit proposed `TestCase`s (no dispatch)."""

    _configure()
    config = (
        PlannerConfig(candidate_generators=tuple(generators))  # type: ignore[arg-type]
        if generators
        else PlannerConfig()
    )
    # Build the model caller + audit sink only when an LLM generator (C2) is in the
    # requested set; a deterministic-only run stays free of model / object-storage deps.
    llm_caller: LLMCaller | None = None
    llm_audit_sink: LLMAuditSink | None = None
    if requested_llm_generator_ids(config):
        llm_caller, llm_audit_sink = _build_llm_deps()

    client = _build_client()
    try:
        result = propose(
            client,
            engagement_id=EngagementId(engagement),
            config=config,
            llm_caller=llm_caller,
            llm_audit_sink=llm_audit_sink,
        )
    finally:
        client.close()

    if as_json:
        typer.echo(
            _json.dumps(
                {
                    "candidates": result.candidates,
                    "committed": result.committed,
                    "created": result.created,
                    "idempotent": result.idempotent,
                    "discarded": [
                        {"code": d.code, "reason": d.reason} for d in result.discarded
                    ],
                    "llm_rejected": [
                        {"code": r.code, "reason": r.reason}
                        for r in result.llm_rejected
                    ],
                    "llm_skipped": list(result.llm_skipped),
                },
                indent=2,
            )
        )
        return
    typer.echo(
        f"planner propose: {result.candidates} candidate(s) -> "
        f"{result.committed} committed ({result.created} new, "
        f"{result.idempotent} idempotent), {len(result.discarded)} discarded, "
        f"{len(result.llm_rejected)} llm-rejected, {len(result.llm_skipped)} skipped."
    )
    for d in result.discarded:
        typer.echo(f"  discarded [{d.code}]: {d.reason}")
    for r in result.llm_rejected:
        typer.echo(f"  llm-rejected [{r.code}]: {r.reason}")
    for reason in result.llm_skipped:
        typer.echo(f"  skipped: {reason}")


def _render_queue(rows: list[ProposedTestCaseView]) -> None:
    if not rows:
        typer.echo("planner review: no proposals awaiting review.")
        return
    typer.echo(f"planner review — proposals (prioritised): {len(rows)}")
    typer.echo(
        f"{'SCORE':>6} {'CLASS':<16} {'METHOD':<7} {'TARGET':<40} "
        f"{'YIELD':>6} {'HAZARDS':<24} {'KEY':<12}"
    )
    for r in rows:
        target = f"{r.host or '-'}{r.path_template or ''}"
        flag = " *resurfaced" if r.resurfaced else ""
        # ADR-0041 replay-fidelity: surface the detected replay-breakers so the
        # reviewer sees a naive replay would false-negative ("-" when none).
        hazards = ",".join(r.replay_hazards) if r.replay_hazards else "-"
        typer.echo(
            f"{r.priority_score:>6.3f} {r.test_class:<16} {r.method or '-':<7} "
            f"{target:<40} {r.expected_yield:>6.3f} {hazards:<24} "
            f"{r.key_hash[:12]}{flag}"
        )


@planner_app.command("review")
def review_cmd(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to review."
    ),
    top_n: int = typer.Option(
        20, "--top", help="Show only the top-N highest-priority proposals."
    ),
    approve: str | None = typer.Option(
        None,
        "--approve",
        help="Approve the proposal with this key_hash (prefix accepted). "
        "'approved' = cleared for dispatch CONSIDERATION, not authorisation.",
    ),
    reject: str | None = typer.Option(
        None, "--reject", help="Reject the proposal with this key_hash (prefix accepted)."
    ),
    disposition: str = typer.Option(
        "defer",
        "--disposition",
        help="On --reject: 'permanent' (never re-surface) or 'defer' (re-surface on "
        "new evidence). Default 'defer' (safe default).",
    ),
    actor: str | None = typer.Option(
        None, "--actor", help="Who is making this decision (recorded in the audit ledger)."
    ),
    reason: str | None = typer.Option(
        None, "--reason", help="Why (recorded in the audit ledger)."
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Emit the queue / decision as JSON instead of a table."
    ),
) -> None:
    """Show the prioritised review queue, or approve / reject a proposal (no dispatch)."""

    _configure()
    client = _build_client()
    ledger = _default_ledger()
    try:
        if approve is not None or reject is not None:
            if approve is not None and reject is not None:
                typer.secho("choose one of --approve / --reject", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            decision = "approve" if approve is not None else "reject"
            key_prefix = approve if approve is not None else reject
            assert key_prefix is not None
            key_hash = _resolve_key(client, EngagementId(engagement), key_prefix)
            if actor is None:
                typer.secho("--actor is required to record a decision", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            evidence = fetch_target_evidence(client, EngagementId(engagement), key_hash)
            try:
                result = review_testcase(
                    client,
                    ledger,
                    engagement_id=EngagementId(engagement),
                    key_hash=key_hash,
                    decision=decision,  # type: ignore[arg-type]
                    actor=actor,
                    reason=reason,
                    disposition=(disposition if decision == "reject" else None),  # type: ignore[arg-type]
                    evidence=evidence,
                )
            except ReviewError as exc:
                typer.secho(f"review refused: {exc}", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=3) from exc
            if as_json:
                typer.echo(_json.dumps(result.event.model_dump(mode="json"), indent=2))
            else:
                typer.echo(
                    f"{result.prior_status} -> {result.new_status}: {key_hash[:12]} "
                    f"by {actor}"
                    + (f" ({disposition})" if decision == "reject" else "")
                )
            return

        rows = review_queue(
            client, ledger, engagement_id=EngagementId(engagement), top_n=top_n
        )
    finally:
        client.close()

    if as_json:
        typer.echo(_json.dumps([r.model_dump(mode="json") for r in rows], indent=2))
    else:
        _render_queue(rows)


def _resolve_key(
    client: Neo4jClient, engagement_id: EngagementId, key_prefix: str
) -> TestCaseKeyHash:
    """Resolve a key_hash (full or unambiguous prefix) to one active TestCase."""

    from doo.ontology.queries import for_engagement

    frag = for_engagement(engagement_id, var="t")
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase)
        {frag.and_("t.status = 'active' AND t.key_hash STARTS WITH $prefix")}
        RETURN t.key_hash AS key_hash
        """,
        prefix=key_prefix,
        **frag.parameters,
    )
    if not rows:
        typer.secho(
            f"no active TestCase with key_hash starting {key_prefix!r}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    if len(rows) > 1:
        typer.secho(
            f"key_hash prefix {key_prefix!r} is ambiguous ({len(rows)} matches); "
            "use a longer prefix",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    return TestCaseKeyHash(str(rows[0]["key_hash"]))
