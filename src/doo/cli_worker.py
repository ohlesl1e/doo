"""`doo worker run` — drive the L2 + L3 pipeline workers (slice-1).

`doo ingest har` only does L1: it uploads the blob and drops an `IngestionEnvelope`
on the Redis `ingest` stream. This command runs the **extraction (L2)** and
**commit (L3)** workers that consume the streams and actually build the Neo4j
graph (`ingest` -> `l2-events` -> `l3-events`).

Two modes:

    doo worker run            # run continuously (Ctrl-C to stop)
    doo worker run --once     # drain everything currently queued, then exit

`--once` is the ergonomic "try it out" path: `engagement start`, `ingest har`,
then `worker run --once`, then explore the graph in Neo4j Browser.

Connection config comes from the same `DOO_*` env vars as `doo ingest har`
(see `.env.example`); the defaults match the local `docker-compose` stack except
the credentials, which you must export to match compose.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from typing import Annotated, cast

import typer

from doo.events.l2 import L2Event, ParseFailure
from doo.observability.logging import configure_logging, get_logger

log = get_logger(__name__)


def _truncate(text: str, limit: int = 160) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."


def _report_parse_failures(failures: list[ParseFailure]) -> None:
    """Print a grouped-by-kind summary of the ParseFailures from a drain, so a
    HAR that didn't ingest explains itself without a Neo4j query."""

    if not failures:
        return
    typer.echo("")
    typer.secho(
        f"{len(failures)} parse failure(s) — entries that did not ingest:",
        fg=typer.colors.YELLOW,
    )
    by_kind: Counter[str] = Counter(f.error_kind for f in failures)
    sample: dict[str, ParseFailure] = {}
    for f in failures:
        sample.setdefault(f.error_kind, f)
    for kind, count in by_kind.most_common():
        s = sample[kind]
        where = f" [{s.location_hint}]" if s.location_hint else ""
        typer.secho(f"  {kind} x{count}: {_truncate(s.error_message)}{where}", fg=typer.colors.YELLOW)
    typer.secho(
        "  full detail: MATCH (f:ParseFailure) "
        "RETURN f.error_kind, f.error_message, f.location_hint",
        fg=typer.colors.YELLOW,
    )


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _drain_once(*, run_l2: Callable[[], int], run_l3: Callable[[], int]) -> tuple[int, int]:
    """Alternate L2 and L3 drains until a full pass yields nothing.

    Returns `(envelopes_extracted, l2_events_committed)`. Pure modulo the two
    injected runners, so the loop is unit-testable without infrastructure. A
    pass runs L2 (ingest -> l2-events) then L3 (l2-events -> graph); repeats
    because each L2 batch feeds new work to L3.
    """

    total_l2 = total_l3 = 0
    while True:
        n2 = run_l2()
        n3 = run_l3()
        total_l2 += n2
        total_l3 += n3
        if n2 == 0 and n3 == 0:
            return total_l2, total_l3


@contextlib.contextmanager
def _worker_progress(
    *, enabled: bool
) -> Iterator[tuple[Callable[[int], None], Callable[[], None]]]:
    """A `rich` progress bar for `doo worker run` — extracted (total) vs committed.

    Mirrors `planner/cli.py::_llm_progress_bar`. L2 extraction grows the bar's
    `total` (`on_extracted(n)`); L3 commit advances `completed` (`on_committed()`),
    so the bar starts indeterminate and fills as the drain interleaves. Structlog
    output is redirected above the live bar. When disabled (non-TTY or `--json`)
    yields no-op callbacks so the raw structured-log path is unchanged.
    """

    if not enabled or not sys.stderr.isatty():
        yield (lambda _n: None), (lambda: None)
        return

    from rich.console import Console
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]ingest[/]"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("{task.description}"),
        console=Console(file=sys.stderr),
        transient=False,
        redirect_stdout=True,
        redirect_stderr=True,
    )
    state = {"total": 0, "done": 0}

    with progress:
        task = progress.add_task("extracted 0 · committed 0", total=None)

        def _describe() -> str:
            return f"extracted {state['total']} · committed {state['done']}"

        def on_extracted(n: int) -> None:
            state["total"] += n
            progress.update(task, total=state["total"], description=_describe())

        def on_committed() -> None:
            state["done"] += 1
            progress.update(task, completed=state["done"], description=_describe())

        yield on_extracted, on_committed


@contextlib.contextmanager
def _finalizing(*, enabled: bool) -> Iterator[Callable[[str, int, int], None]]:
    """A `rich`, phase-aware progress bar for the post-drain flush (`orchestrator.flush`).

    The commit bar tracks *events*; the deferred-inference settle step (ADR-0022)
    runs once after all commits across several phases, so a full commit bar would
    read as hung. This yields flush's `on_progress(phase, completed, total)` callback
    and renders it: the cohort re-templating phase (the dominant cost) fills a
    **determinate** bar (`templating cohorts 42/118`), while the subsequent
    promotion / identity / inference passes — single per-engagement steps reported
    with `total = 0` — show a **pulsing** bar with the phase label, so it's clear
    which phase is running rather than a frozen full bar. When disabled (non-TTY /
    `--json`) yields a no-op callback — the structured `flush.applied` log covers it.
    """

    if not enabled or not sys.stderr.isatty():
        yield lambda _phase, _completed, _total: None
        return

    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]finalizing[/]"),
        BarColumn(),
        TimeElapsedColumn(),
        TextColumn("{task.description}"),
        console=Console(file=sys.stderr),
        transient=False,
        redirect_stdout=True,
        redirect_stderr=True,
    )

    with progress:
        task = progress.add_task("starting…", total=None)
        last_paint = 0.0

        def on_progress(phase: str, completed: int, total: int) -> None:
            # A heavy synchronous phase (e.g. value promotion is CPU-bound Python over
            # thousands of values) holds the GIL, starving rich's background refresh —
            # so the bar AND the elapsed timer freeze. Force a main-thread repaint,
            # throttled to ~12/sec, so the display keeps moving through such a phase.
            nonlocal last_paint
            now = time.monotonic()
            paint = (now - last_paint) > 0.08 or (total > 0 and completed >= total)
            if paint:
                last_paint = now
            if total > 0:  # determinate phase (cohort re-templating / value promotion)
                progress.update(
                    task, description=f"{phase} {completed}/{total}",
                    completed=completed, total=total, refresh=paint,
                )
            else:  # indeterminate per-engagement phase — pulse with the label
                progress.update(
                    task, description=f"{phase}…", completed=0, total=None, refresh=paint,
                )

        yield on_progress


class _WorkerRuntime:
    """Env-configured L2/L3 worker collaborators plus their closeables."""

    def __init__(self) -> None:
        import redis

        from doo.cli_env import connect_neo4j_or_exit
        from doo.infra.blobs import BlobClient
        from doo.infra.streams import RedisStreamLike, StreamClient
        from doo.ingestion.l2_worker import L2WorkerDeps
        from doo.ontology.commit import CommitOrchestrator, RedisSetNX
        from doo.ontology.l3_worker import L3WorkerDeps
        from doo.ontology.schema import apply_schema

        self._neo4j = connect_neo4j_or_exit(
            _env("DOO_NEO4J_URI", "bolt://localhost:7687"),
            _env("DOO_NEO4J_USER", "neo4j"),
            _env("DOO_NEO4J_PASSWORD", "password"),
        )
        # Idempotent, edition-aware schema bootstrap (so a fresh DB is ready).
        with self._neo4j.driver.session() as session:
            apply_schema(session, edition=self._neo4j.server_edition())

        # Workers read the streams, so decode payloads to str (matches the tested
        # pipeline path); the same client backs the L3 idempotency SETNX.
        self._redis = redis.Redis.from_url(
            _env("DOO_REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
        )
        streams = StreamClient(cast("RedisStreamLike", self._redis))
        blobs = BlobClient.from_config(
            endpoint_url=_env("DOO_S3_ENDPOINT", "http://localhost:9000"),
            access_key=_env("DOO_S3_ACCESS_KEY", "minioadmin"),
            secret_key=_env("DOO_S3_SECRET_KEY", "minioadmin"),
            bucket=_env("DOO_S3_BUCKET", "doo-blobs"),
        )
        self.l2_deps = L2WorkerDeps(blobs=blobs, streams=streams)
        # expected_engagement_id=None: a shared worker commits events from any
        # engagement; each event stamps its own engagement_id and the resolvers +
        # DB uniqueness constraints enforce isolation (ADR-0017).
        orchestrator = CommitOrchestrator(
            neo4j=self._neo4j,
            idempotency=RedisSetNX(self._redis),
            streams=streams,
            expected_engagement_id=None,
        )
        self.l3_deps = L3WorkerDeps(orchestrator=orchestrator, streams=streams)

    def close(self) -> None:
        self._neo4j.close()
        self._redis.close()


def register_worker(app: typer.Typer) -> None:
    """Register the `worker` subcommand group on the root Typer app."""

    worker_app = typer.Typer(
        help="Run the L2 (extraction) + L3 (commit) pipeline workers.",
        no_args_is_help=True,
    )

    @worker_app.command("run")
    def run_cmd(
        once: Annotated[
            bool,
            typer.Option(
                "--once",
                help="Drain everything currently queued and exit (otherwise run forever).",
            ),
        ] = False,
        batch: Annotated[
            int,
            typer.Option("--batch", help="Max messages drained per L2/L3 pass."),
        ] = 500,
        as_json: bool = typer.Option(
            False,
            "--json",
            help="Keep the raw structured (JSON) logs instead of a progress bar "
            "(for piping / debugging / non-interactive runs).",
        ),
    ) -> None:
        """Consume `ingest` -> `l2-events` -> `l3-events`, building the graph."""

        # Interactive default: a live progress bar + quiet logs. `--json` (or a
        # non-TTY stderr) keeps the full per-event structured logs as before.
        show_bar = sys.stderr.isatty() and not as_json
        configure_logging(level="WARNING" if show_bar else "INFO")

        from doo.ingestion.l2_worker import run_l2_worker
        from doo.ontology.l3_worker import run_l3_worker

        runtime = _WorkerRuntime()
        orchestrator = runtime.l3_deps.orchestrator
        failures: list[ParseFailure] = []
        once_summary: tuple[int, int, int, int, int] | None = None

        try:
            drain_counts: tuple[int, int] | None = None
            with _worker_progress(enabled=show_bar) as (on_extracted, on_committed):

                def _collect(events: list[L2Event]) -> None:
                    failures.extend(e for e in events if isinstance(e, ParseFailure))
                    on_extracted(len(events))

                def _stream(events: list[L2Event]) -> None:
                    on_extracted(len(events))
                    for e in events:
                        if isinstance(e, ParseFailure):
                            where = f" [{e.location_hint}]" if e.location_hint else ""
                            typer.secho(
                                f"  parse failure [{e.error_kind}]{where}: "
                                f"{_truncate(e.error_message)}",
                                fg=typer.colors.YELLOW,
                                err=True,
                            )

                def _run_l2(block_ms: int, on_events: Callable[[list[L2Event]], None]) -> int:
                    return run_l2_worker(
                        runtime.l2_deps, max_messages=batch, block_ms=block_ms,
                        on_events=on_events,
                    )

                def _run_l3(block_ms: int) -> int:
                    return run_l3_worker(
                        runtime.l3_deps, max_messages=batch, block_ms=block_ms,
                        on_event=on_committed,
                    )

                if once:
                    drain_counts = _drain_once(
                        run_l2=lambda: _run_l2(500, _collect), run_l3=lambda: _run_l3(500)
                    )
                else:
                    typer.echo(
                        "worker running — consuming ingest -> l2-events -> l3-events "
                        "(Ctrl-C to stop)"
                    )
                    try:
                        while True:
                            _run_l2(1000, _stream)
                            _run_l3(1000)
                            orchestrator.flush()  # re-template dirty cohorts each pass
                    except KeyboardInterrupt:
                        typer.echo("\nstopped")

            # The progress bar is now closed. Run the deferred-inference settle step
            # (ADR-0022) under a "finalizing…" spinner so the (full) bar doesn't read
            # as hung while templating + inference churn over the drained cohorts.
            if drain_counts is not None:
                extracted, committed = drain_counts
                with _finalizing(enabled=show_bar) as on_progress:
                    flushed = orchestrator.flush(on_progress=on_progress)
                once_summary = (
                    extracted, committed,
                    flushed.endpoints, flushed.parameters, flushed.cohorts,
                )
        finally:
            runtime.close()

        # Printed after the progress bar closes, so the summary + parse-failure
        # report render cleanly below it.
        if once_summary is not None:
            extracted, committed, n_endpoints, n_parameters, n_cohorts = once_summary
            typer.echo(
                f"drained: {extracted} envelope(s) extracted, "
                f"{committed} L2 event(s) committed; "
                f"templated {n_endpoints} endpoint(s) / "
                f"{n_parameters} parameter(s) across {n_cohorts} cohort(s)"
            )
            _report_parse_failures(failures)

    app.add_typer(worker_app, name="worker")
