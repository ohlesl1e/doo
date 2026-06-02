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
from collections.abc import Callable
from typing import Annotated, cast

import typer

from doo.observability.logging import configure_logging, get_logger

log = get_logger(__name__)


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

        from doo.infra.blobs import BlobClient
        from doo.infra.neo4j_driver import Neo4jClient
        from doo.infra.streams import RedisStreamLike, StreamClient
        from doo.ingestion.l2_worker import L2WorkerDeps
        from doo.ontology.commit import CommitOrchestrator, RedisSetNX
        from doo.ontology.l3_worker import L3WorkerDeps
        from doo.ontology.schema import apply_schema

        self._neo4j = Neo4jClient.connect(
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

        def _run_l2(block_ms: int) -> int:
            return run_l2_worker(runtime.l2_deps, max_messages=batch, block_ms=block_ms)

        def _run_l3(block_ms: int) -> int:
            return run_l3_worker(runtime.l3_deps, max_messages=batch, block_ms=block_ms)

        try:
            if once:
                extracted, committed = _drain_once(
                    run_l2=lambda: _run_l2(500), run_l3=lambda: _run_l3(500)
                )
                typer.echo(
                    f"drained: {extracted} envelope(s) extracted, "
                    f"{committed} L2 event(s) committed"
                )
                return
            typer.echo("worker running — consuming ingest -> l2-events -> l3-events (Ctrl-C to stop)")
            try:
                while True:
                    _run_l2(1000)
                    _run_l3(1000)
            except KeyboardInterrupt:
                typer.echo("\nstopped")
        finally:
            runtime.close()

    app.add_typer(worker_app, name="worker")
