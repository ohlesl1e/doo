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

import os
from collections import Counter
from collections.abc import Callable
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
    ) -> None:
        """Consume `ingest` -> `l2-events` -> `l3-events`, building the graph."""

        configure_logging()

        from doo.ingestion.l2_worker import run_l2_worker
        from doo.ontology.l3_worker import run_l3_worker

        runtime = _WorkerRuntime()
        failures: list[ParseFailure] = []

        def _collect(events: list[L2Event]) -> None:
            failures.extend(e for e in events if isinstance(e, ParseFailure))

        def _stream(events: list[L2Event]) -> None:
            for e in events:
                if isinstance(e, ParseFailure):
                    where = f" [{e.location_hint}]" if e.location_hint else ""
                    typer.secho(
                        f"  parse failure [{e.error_kind}]{where}: {_truncate(e.error_message)}",
                        fg=typer.colors.YELLOW,
                        err=True,
                    )

        def _run_l2(block_ms: int, on_events: Callable[[list[L2Event]], None]) -> int:
            return run_l2_worker(
                runtime.l2_deps, max_messages=batch, block_ms=block_ms, on_events=on_events
            )

        def _run_l3(block_ms: int) -> int:
            return run_l3_worker(runtime.l3_deps, max_messages=batch, block_ms=block_ms)

        orchestrator = runtime.l3_deps.orchestrator
        try:
            if once:
                extracted, committed = _drain_once(
                    run_l2=lambda: _run_l2(500, _collect), run_l3=lambda: _run_l3(500)
                )
                # Deferred endpoint inference (ADR-0022): re-template the cohorts
                # this drain touched (and any left un-HIT by a prior crashed run).
                flushed = orchestrator.flush()
                typer.echo(
                    f"drained: {extracted} envelope(s) extracted, "
                    f"{committed} L2 event(s) committed; "
                    f"templated {flushed.endpoints} endpoint(s) / "
                    f"{flushed.parameters} parameter(s) across {flushed.cohorts} cohort(s)"
                )
                _report_parse_failures(failures)
                return
            typer.echo("worker running — consuming ingest -> l2-events -> l3-events (Ctrl-C to stop)")
            try:
                while True:
                    _run_l2(1000, _stream)
                    _run_l3(1000)
                    orchestrator.flush()  # re-template dirty cohorts each pass
            except KeyboardInterrupt:
                typer.echo("\nstopped")
        finally:
            runtime.close()

    app.add_typer(worker_app, name="worker")
