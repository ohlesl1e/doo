"""`doo ingest har --engagement <id> <har_path>` (slice-1 T2).

Thin CLI wrapper: it reads the HAR file, builds the L1 intake collaborators from
environment configuration (Neo4j / MinIO / Redis), and calls `ingest_har`
directly (the same core the FastAPI route uses). No business logic here.

Connection config comes from environment variables so the CLI works against the
local docker-compose stack without flags:

    DOO_NEO4J_URI         (default bolt://localhost:7687)
    DOO_NEO4J_USER        (default neo4j)
    DOO_NEO4J_PASSWORD    (default password)
    DOO_REDIS_URL         (default redis://localhost:6379/0)
    DOO_S3_ENDPOINT       (default http://localhost:9000)
    DOO_S3_ACCESS_KEY     (default minioadmin)
    DOO_S3_SECRET_KEY     (default minioadmin)
    DOO_S3_BUCKET         (default doo-blobs)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, cast

import typer

if TYPE_CHECKING:
    from doo.ingestion.intake import IntakeDeps

from doo.ids import EngagementId
from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import bind_correlation, configure_logging, get_logger

log = get_logger(__name__)


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _build_intake_deps() -> IntakeDeps:
    """Construct real intake collaborators from environment config."""

    import redis

    from doo.cli_env import connect_neo4j_or_exit
    from doo.infra.blobs import BlobClient
    from doo.infra.streams import RedisStreamLike, StreamClient
    from doo.ingestion.intake import IntakeDeps
    from doo.ontology.graph_state import Neo4jGraphState

    neo4j = connect_neo4j_or_exit(
        _env("DOO_NEO4J_URI", "bolt://localhost:7687"),
        _env("DOO_NEO4J_USER", "neo4j"),
        _env("DOO_NEO4J_PASSWORD", "password"),
    )
    redis_client = redis.Redis.from_url(_env("DOO_REDIS_URL", "redis://localhost:6379/0"))
    blobs = BlobClient.from_config(
        endpoint_url=_env("DOO_S3_ENDPOINT", "http://localhost:9000"),
        access_key=_env("DOO_S3_ACCESS_KEY", "minioadmin"),
        secret_key=_env("DOO_S3_SECRET_KEY", "minioadmin"),
        bucket=_env("DOO_S3_BUCKET", "doo-blobs"),
    )
    return IntakeDeps(
        engagements=Neo4jGraphState(neo4j),
        blobs=blobs,
        streams=StreamClient(cast(RedisStreamLike, redis_client)),
    )


def register_ingest(app: typer.Typer) -> None:
    """Register the `ingest` subcommand group on the root Typer app."""

    ingest_app = typer.Typer(
        help="Ingest passive testing data (HAR, ...) into the pipeline.",
        no_args_is_help=True,
    )

    @ingest_app.command("har")
    def ingest_har_cmd(
        har_path: Annotated[
            Path,
            typer.Argument(
                help="Path to the HAR file to ingest.",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        engagement: Annotated[
            str,
            typer.Option("--engagement", "-e", help="Engagement id to ingest under."),
        ],
    ) -> None:
        """Upload a HAR file: blob to storage, envelope onto the `ingest` stream."""

        configure_logging()
        bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())

        from doo.ingestion.intake import UnknownEngagementError, ingest_har

        data = har_path.read_bytes()
        deps = _build_intake_deps()
        try:
            result = ingest_har(
                deps,
                engagement_id=EngagementId(engagement),
                filename=har_path.name,
                data=data,
            )
        except UnknownEngagementError as exc:
            typer.secho(f"refused: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc

        typer.echo(
            f"ingested {har_path.name}: blob {result.blob_sha256[:12]}... -> "
            f"{result.blob_ref} (envelope {result.event_id}, "
            f"stream msg {result.stream_message_id})"
        )

    app.add_typer(ingest_app, name="ingest")
