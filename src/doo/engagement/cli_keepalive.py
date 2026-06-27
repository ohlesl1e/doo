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
from pathlib import Path

import typer

from doo.engagement.auth_helper_child import HelperSupervisor, build_auth_helper_argv
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
from doo.setup.config import EngagementConfig, KillSwitchConfig

log = get_logger(__name__)


def _load_config(config_path: Path) -> EngagementConfig:
    """Load + validate the engagement YAML (mirrors `dispatch/cli.py:_load_config`)."""

    import yaml

    raw = yaml.safe_load(config_path.read_text())
    return EngagementConfig.model_validate(raw)


def _has_managed_slots(config: EngagementConfig) -> bool:
    """True iff any declared AuthContext carries a `refresh:` block (ADR-0054).

    Mirrors `AuthHelper.from_config(...).managed` non-emptiness without standing up
    Neo4j in the parent — the child runs the full `from_config` itself. This keeps
    the safety-critical keepalive parent infra-light (ADR-0054 "parent stays simple").
    """

    return any(
        decl.refresh is not None
        for p in config.principals
        for decl in p.auth_contexts
    )


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


def _resolve_child(
    engagement_id: str,
    *,
    with_auth_helper: bool,
    config_path: Path | None,
) -> HelperSupervisor | None:
    """Decide whether to co-launch the auth-helper child (ADR-0054, #182).

    Pure config (no Neo4j in the parent). Returns a `HelperSupervisor` to spawn, or
    `None` for lease-only — printing a hint when there are managed slots but the
    flag was not passed. Raises `typer.Exit` on bad input (missing/ mismatched
    `--config`). The four branches map to the ADR's launch decision.
    """

    # The flag was not passed: lease-only. If a config was supplied and it has
    # rotatable slots, hint at the co-launch (the common "forgot the flag" case).
    if not with_auth_helper:
        if config_path is not None:
            cfg = _load_config(config_path)
            if _has_managed_slots(cfg):
                typer.secho(
                    "note: this engagement declares `refresh:` slots but "
                    "--with-auth-helper was not passed; running lease-only. Pass "
                    "--with-auth-helper to co-launch the auth-helper, or run "
                    "`doo auth-helper run` in a separate terminal.",
                    fg=typer.colors.YELLOW,
                    err=True,
                )
        return None

    if config_path is None:
        typer.secho(
            "--with-auth-helper requires --config <yaml> (the auth-helper child "
            "reads its refresh blocks from it).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    cfg = _load_config(config_path)
    if cfg.engagement.id != engagement_id:
        typer.secho(
            f"engagement id {engagement_id!r} does not match {config_path}'s "
            f"engagement.id {cfg.engagement.id!r}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    if not _has_managed_slots(cfg):
        typer.secho(
            "--with-auth-helper set but no AuthContext declares a `refresh:` block "
            "— nothing to rotate; running lease-only.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return None

    typer.echo(
        f"co-launching auth-helper child for {engagement_id} "
        f"(config {config_path}); the lease heartbeat runs in this process."
    )
    return HelperSupervisor(
        argv=build_auth_helper_argv(engagement_id, str(config_path))
    )


def register_keepalive(engagement_app: typer.Typer) -> None:
    """Register the `keepalive` command onto the engagement Typer group.

    Called from `cli.py` with a single line to keep that file's diff minimal.
    """

    @engagement_app.command("keepalive")
    def keepalive(  # noqa: D401 - Typer command body
        engagement_id: str = typer.Argument(
            ..., help="Engagement id whose kill-switch lease to keep alive."
        ),
        with_auth_helper: bool = typer.Option(
            False,
            "--with-auth-helper",
            help="Co-launch the auth-helper as an isolated child subprocess "
            "(ADR-0054), collapsing the workflow to two terminals. Requires "
            "--config; spawns only when the engagement has `refresh:` slots.",
        ),
        config: Path | None = typer.Option(
            None,
            "--config",
            "-c",
            exists=True,
            readable=True,
            resolve_path=True,
            help="Engagement YAML — required with --with-auth-helper (the child "
            "reads its refresh blocks + ${VAR} token refs from it).",
        ),
    ) -> None:
        """Hold the kill-switch lease alive until SIGTERM.

        Started explicitly by the tester after `doo engagement start`. SIGTERM
        releases the lease and exits 0; SIGKILL lets it expire within the TTL.
        The agent process never runs this — it has read-only lease access.

        `--with-auth-helper` (ADR-0054) co-launches the auth-helper as an isolated
        child so a dispatch needs two terminals instead of three; the child's death
        never touches the lease (bounded restart, then fail-loud).
        """

        configure_logging()
        bind_correlation(trace_id=new_trace_id(), span_id=new_span_id())
        eng_id = EngagementId(engagement_id)
        log.info("engagement.keepalive.invoked", engagement_id=eng_id)

        # Resolve the (optional) child BEFORE touching infra so bad --config fails
        # fast without writing a lease.
        child = _resolve_child(
            engagement_id, with_auth_helper=with_auth_helper, config_path=config
        )

        reader = _build_reader()
        try:
            kcfg = resolve_keepalive_config(eng_id, reader)
        except EngagementNotFoundError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from exc

        lease = _build_lease(eng_id)
        code = run_keepalive(kcfg, lease, child=child)
        raise typer.Exit(code=code)
