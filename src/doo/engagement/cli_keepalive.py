"""Typer subcommand: `doo engagement keepalive <engagement_id>` (T7).

Kept in its own module so the diff to `src/doo/cli.py` is a single import + a
single `register_keepalive(engagement_app)` call — a sibling agent (T2) also
edits `cli.py`, so the registration footprint is intentionally tiny.

The command:
  1. reads the Engagement's kill-switch config from Neo4j,
  2. opens a writable Redis lease client,
  3. runs `run_keepalive`, which blocks until SIGTERM, then releases the lease
     and exits 0.

Construction of the Neo4j reader and Redis client is lazy/local so importing
this module (e.g. during `--help`) does not require live infra.
"""

from __future__ import annotations

import os

import typer

from doo.engagement.keepalive import (
    EngagementNotFoundError,
    LeaseConfigReader,
    resolve_keepalive_config,
    run_keepalive,
)
from doo.ids import EngagementId
from doo.infra.redis_lease import RedisLease
from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import bind_correlation, configure_logging, get_logger
from doo.setup.config import KillSwitchConfig

log = get_logger(__name__)


class _Neo4jLeaseConfigReader:
    """Reads `Engagement.kill_switch` from Neo4j and maps it to KillSwitchConfig.

    The loader (ADR-0019) persists `kill_switch` as a **JSON string** on the
    `Engagement` node — Neo4j cannot store nested maps as node properties, so
    the writer (`ontology/graph_state.py`) `json.dumps` it. We read just that
    property and decode it here (same guard as the `graph_state` reader).
    """

    def __init__(self, session: object) -> None:
        self._session = session

    def read_kill_switch_config(
        self, engagement_id: EngagementId
    ) -> KillSwitchConfig | None:
        import json

        records = list(
            self._session.run(  # type: ignore[attr-defined]
                "MATCH (e:Engagement {id: $id}) RETURN e.kill_switch AS kill_switch",
                id=engagement_id,
            )
        )
        if not records:
            return None
        ks = records[0]["kill_switch"]
        if ks is None:
            # Node exists but no kill_switch persisted — fall back to defaults.
            return KillSwitchConfig()
        if isinstance(ks, str):
            ks = json.loads(ks)
        return KillSwitchConfig(
            lease_ttl_seconds=int(ks.get("lease_ttl_seconds", 60)),
            refresh_interval_seconds=int(ks.get("refresh_interval_seconds", 30)),
        )


def _build_reader() -> LeaseConfigReader:  # pragma: no cover - needs live Neo4j
    from neo4j import GraphDatabase

    uri = os.environ.get("DOO_NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("DOO_NEO4J_USER", "neo4j")
    password = os.environ.get("DOO_NEO4J_PASSWORD", "password")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    session = driver.session()
    return _Neo4jLeaseConfigReader(session)


def _build_lease(engagement_id: EngagementId) -> RedisLease:  # pragma: no cover - needs live Redis
    import redis

    url = os.environ.get("DOO_REDIS_URL", "redis://localhost:6379/0")
    client = redis.Redis.from_url(url)
    return RedisLease(client, engagement_id)


def register_keepalive(engagement_app: typer.Typer) -> None:
    """Register the `keepalive` command onto the engagement Typer group.

    Called from `cli.py` with a single line to keep that file's diff minimal.
    """

    @engagement_app.command("keepalive")
    def keepalive(  # noqa: D401 - Typer command body
        engagement_id: str = typer.Argument(
            ..., help="Engagement id whose kill-switch lease to keep alive."
        ),
    ) -> None:
        """Hold the kill-switch lease alive until SIGTERM.

        Started explicitly by the tester after `doo engagement start`. SIGTERM
        releases the lease and exits 0; SIGKILL lets it expire within the TTL.
        The agent process never runs this — it has read-only lease access.
        """

        configure_logging()
        bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())
        eng_id = EngagementId(engagement_id)
        log.info("engagement.keepalive.invoked", engagement_id=eng_id)

        reader = _build_reader()
        try:
            config = resolve_keepalive_config(eng_id, reader)
        except EngagementNotFoundError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from exc

        lease = _build_lease(eng_id)
        code = run_keepalive(config, lease)
        raise typer.Exit(code=code)
