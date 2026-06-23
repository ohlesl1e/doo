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

import contextlib
import json as _json
import os
import sys
from collections import Counter
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path
from typing import cast

import typer

from doo.ids import EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.planner.generators import (
    LLMProgressCallback,
    PlannerConfig,
    requested_llm_generator_ids,
)
from doo.planner.llm import LiteLLMCaller, LLMCaller
from doo.planner.llm_audit import BlobLLMAuditSink, LLMAuditSink
from doo.planner.models import GENERATOR_IDS, GeneratorId, ProposedTestCaseView
from doo.planner.review import (
    JsonFileReviewLedger,
    ReviewError,
    fetch_target_evidence,
    review_testcase,
)
from doo.planner.service import propose, review_queue

# Human-readable aliases for the coverage-derived generator ids. CLI sugar
# only: the canonical ids (c1..c4) stay authoritative in the graph, the
# coverage subcommands, and the ADRs; aliases normalise to them before
# reaching `PlannerConfig`. `tenant`/`sink` are already descriptive.
GENERATOR_ALIASES: dict[str, GeneratorId] = {
    "dead": "c1",
    "asym": "c2",
    "diff": "c2b",
    "leak": "c3",
    "tier": "c4",
}

# CLI-local choice enum for `-g/--generator`, generated from the canonical
# `GENERATOR_IDS` tuple plus the alias keys so it cannot drift (issue #111).
# Typer renders the members in `--help` and rejects unknown values with a
# clean Click error instead of a Pydantic traceback. `GeneratorId` itself
# stays a `Literal`. mypy can't infer members from a non-literal mapping; the
# drift unit test (`test_generator_opt_tracks_canonical_ids`) is the guard.
GeneratorOpt = StrEnum(  # type: ignore[misc]
    "GeneratorOpt",
    {g: g for g in (*GENERATOR_IDS, *GENERATOR_ALIASES)},
)


def _canonical_generator(opt: str) -> GeneratorId:
    """Resolve a `-g` value (canonical id or alias) to its canonical `GeneratorId`."""
    return GENERATOR_ALIASES.get(opt, cast("GeneratorId", opt))


planner_app = typer.Typer(
    help="Planner: deterministic hypothesis generation + human review over the "
    "graph. Nothing is dispatched. Run after ingestion settles.",
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


def _resolve_planner_model(
    cli_model: str | None,
    *,
    graph_model: str | None = None,
) -> str:
    """ADR-0051 model precedence for the Planner role.

    ``--model`` > ``DOO_PLANNER_MODEL`` > ``Engagement.llm_model`` > default
    (``anthropic/claude-opus-4-8``).
    """
    return (
        cli_model
        or os.environ.get("DOO_PLANNER_MODEL")
        or graph_model
        or "anthropic/claude-opus-4-8"
    )


def _build_llm_deps(model: str) -> tuple[LLMCaller, LLMAuditSink]:
    """Build the model caller + audit sink for an LLM-proposing planner run (ADR-0037).

    The model is `DOO_PLANNER_MODEL` (default Claude Opus 4.8). Two routing modes,
    both via litellm:
    - **Anthropic direct** — `DOO_PLANNER_MODEL=anthropic/claude-sonnet-4-6` with
      `ANTHROPIC_API_KEY` in the environment.
    - **Provider URL + key** (LiteLLM/OpenAI-compatible gateway, local proxy) —
      set `DOO_PLANNER_API_BASE` (+ `DOO_PLANNER_API_KEY`) and an `openai/<name>` id.
    `DOO_PLANNER_API_BASE` / `DOO_PLANNER_API_KEY` are optional overrides; unset, litellm
    resolves credentials from its provider env vars. `DOO_PLANNER_TIMEOUT_S` bounds
    a single proposing attempt (default 60s; `0`/empty disables) and
    `DOO_PLANNER_NUM_RETRIES` is the litellm per-call retry count (default 0 —
    re-running `propose` is the retry, idempotent per ADR-0007). Generators call
    the model once per gap sequentially, so an unbounded stalled call would
    otherwise hang the whole run; with the bound the run is capped at roughly
    `gaps × timeout_s × (num_retries + 1)`. The audit sink persists every proposing
    call to the same object storage as the rest of the CLI (`DOO_S3_*`). Built only
    when an LLM generator (C2) is actually requested.
    """

    from doo.infra.blobs import BlobClient

    timeout_raw = os.environ.get("DOO_PLANNER_TIMEOUT_S", "60")
    timeout_s: float | None
    try:
        timeout_s = float(timeout_raw) if timeout_raw else None
    except ValueError:
        timeout_s = 60.0
    if timeout_s is not None and timeout_s <= 0:
        timeout_s = None
    try:
        num_retries = max(0, int(os.environ.get("DOO_PLANNER_NUM_RETRIES", "0")))
    except ValueError:
        num_retries = 0
    tool_choice_mode = os.environ.get("DOO_PLANNER_TOOL_CHOICE", "force").strip().lower()
    if tool_choice_mode not in ("force", "auto"):
        tool_choice_mode = "force"
    temperature: float | None
    temperature_raw = os.environ.get("DOO_PLANNER_TEMPERATURE", "0.0").strip()
    if temperature_raw == "" or temperature_raw.lower() == "none":
        temperature = None
    else:
        try:
            temperature = float(temperature_raw)
        except ValueError:
            temperature = 0.0
    caller = LiteLLMCaller(
        model,
        temperature=temperature,
        api_base=os.environ.get("DOO_PLANNER_API_BASE") or None,
        api_key=os.environ.get("DOO_PLANNER_API_KEY") or None,
        timeout_s=timeout_s,
        num_retries=num_retries,
        tool_choice_mode=tool_choice_mode,
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


@contextlib.contextmanager
def _llm_progress_bar(*, enabled: bool) -> Iterator[LLMProgressCallback | None]:
    """A `rich` per-generator progress bar for the LLM-proposing loop.

    Yields a callback the driver invokes once per gap (`generator, i, total,
    outcome`). One bar per generator, sized on the `i == 0` "start" tick so the
    bar appears before the first (possibly slow) call returns. The description
    shows running proposed/rejected/skipped counts. Structlog output (the
    `coverage.*.complete` lines) is redirected above the live bar so it does not
    corrupt rendering.

    When `enabled` is False (no LLM generators, `--json`, or stderr is not a TTY)
    yields **None** — the driver then falls back to its
    `planner.generator.llm.progress` log line, so non-interactive runs keep
    per-gap observability.
    """

    if not enabled or not sys.stderr.isatty():
        yield None
        return

    from rich.console import Console
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskID,
        TextColumn,
        TimeElapsedColumn,
    )

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.fields[generator]:>6}[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("{task.description}"),
        console=Console(file=sys.stderr),
        transient=False,
        redirect_stdout=True,
        redirect_stderr=True,
    )
    tasks: dict[str, TaskID] = {}
    counts: dict[str, Counter[str]] = {}

    def _describe(generator: str) -> str:
        c = counts[generator]
        return (
            f"proposed {c['proposed']} · rejected {c['rejected']} · "
            f"skipped {c['skipped']}"
        )

    def on_progress(generator: str, i: int, total: int, outcome: str) -> None:
        if generator not in tasks:
            counts[generator] = Counter()
            tasks[generator] = progress.add_task(
                _describe(generator), total=max(total, 1), generator=generator
            )
        if outcome != "start":
            counts[generator][outcome] += 1
        progress.update(
            tasks[generator],
            completed=i,
            total=max(total, 1),
            description=_describe(generator),
        )

    with progress:
        yield on_progress


@planner_app.command("propose")
def propose_cmd(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement id to plan against."
    ),
    generators: list[GeneratorOpt] | None = typer.Option(
        None,
        "--generator",
        "-g",
        help="Enable only these candidate generators (repeatable; aliases in "
        "parens above). Default: all.",
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Run-summary as JSON instead of a table."
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        help="Override the planner LLM model id for this run (ADR-0051: beats "
        "DOO_PLANNER_MODEL and the engagement default).",
    ),
) -> None:
    """Run the deterministic generators and commit proposed `TestCase`s (no dispatch).

    Selects targets with the candidate generators (C1 is deterministic; the
    rest ask the LLM for a structured proposal), validates and scopes each, and
    commits survivors at `review_status = proposed`. `-g` limits to specific
    generators. Nothing is sent — approval happens in `doo planner review`.

    \b
    Generators (canonical id / alias — c1-c4 mirror 'doo coverage' queries):
      c1   (dead)  endpoints with no HIT edge of any kind
      c2   (asym)  endpoints reached 2xx as principal A but not B
      c2b  (diff)  endpoints reached 2xx by ≥2 principals, responses differ
      c3   (leak)  values leaked in one response and sent as input to another
      c4   (tier)  endpoints a stronger token reached that its weaker did not
      tenant       cross-tenant TrustBoundary replay
      sink         URL/path-shaped params (SSRF / open-redirect / path-traversal)
    """

    _configure()
    # Normalise aliases → canonical ids and dedupe (`-g dead -g c1` ⇒ one `c1`),
    # preserving CLI order. Every surviving value is a `GeneratorId` by
    # construction (drift-tested); mypy can't see that, hence the helper's cast.
    requested = (
        tuple(dict.fromkeys(_canonical_generator(g.value) for g in generators))
        if generators
        else None
    )
    config = (
        PlannerConfig(candidate_generators=requested)
        if requested is not None
        else PlannerConfig()
    )
    client = _build_client()
    try:
        # Build the model caller + audit sink only when an LLM generator (C2) is in
        # the requested set; a deterministic-only run stays free of model /
        # object-storage deps.
        llm_caller: LLMCaller | None = None
        llm_audit_sink: LLMAuditSink | None = None
        if requested_llm_generator_ids(config):
            resolved = _resolve_planner_model(model)
            llm_caller, llm_audit_sink = _build_llm_deps(resolved)

        with _llm_progress_bar(
            enabled=bool(llm_caller) and not as_json
        ) as on_progress:
            result = propose(
                client,
                engagement_id=EngagementId(engagement),
                config=config,
                llm_caller=llm_caller,
                llm_audit_sink=llm_audit_sink,
                on_llm_progress=on_progress,
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
                    "llm_skipped": [
                        {"code": s.code, "reason": s.reason}
                        for s in result.llm_skipped
                    ],
                },
                indent=2,
            )
        )
        return
    # Group skips by code: per-code count + one sample reason. The full list is
    # available via --json; on a real engagement N× call_timeout would otherwise
    # be N table lines.
    skip_by_code: dict[str, list[str]] = {}
    for s in result.llm_skipped:
        skip_by_code.setdefault(s.code, []).append(s.reason)
    skip_summary = (
        " (" + ", ".join(f"{c}: {len(rs)}" for c, rs in sorted(skip_by_code.items())) + ")"
        if skip_by_code
        else ""
    )
    typer.echo(
        f"planner propose: {result.candidates} candidate(s) -> "
        f"{result.committed} committed ({result.created} new, "
        f"{result.idempotent} idempotent), {len(result.discarded)} discarded, "
        f"{len(result.llm_rejected)} llm-rejected, "
        f"{len(result.llm_skipped)} skipped{skip_summary}."
    )
    for d in result.discarded:
        typer.echo(f"  discarded [{d.code}]: {d.reason}")
    for r in result.llm_rejected:
        typer.echo(f"  llm-rejected [{r.code}]: {r.reason}")
    for code, reasons in sorted(skip_by_code.items()):
        typer.echo(f"  skipped [{code}] e.g.: {reasons[0]} (× {len(reasons)})")


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
    """Show the prioritised review queue, or approve / reject a proposal (no dispatch).

    With no action flag, prints the top proposals ranked by priority. `--approve`
    / `--reject` (by key_hash or unambiguous prefix) record a provenanced
    decision in the audit ledger; a rejection's `--disposition` controls whether
    it can re-surface. `approved` means cleared for consideration, not authorized
    to send.
    """

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
