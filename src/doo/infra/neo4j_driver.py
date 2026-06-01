"""Neo4j driver wrapper (slice-1 T2).

A thin wrapper over the official `neo4j` driver exposing the two things L3
needs: a write transaction that runs Cypher with parameters, and a read query
that returns plain dict rows. The driver is injected so tests can pass a
testcontainer-backed driver.

Edition detection lives here (`server_edition`) because the schema bootstrap
needs it: property-existence constraints require Neo4j Enterprise, but the
project standard is `neo4j:5-community` (see docker-compose.yml). See
`apply_schema` for how the bootstrap degrades gracefully on Community.
"""

from __future__ import annotations

from typing import Any

from neo4j import Driver, GraphDatabase

from doo.observability.logging import get_logger

log = get_logger(__name__)


class Neo4jClient:
    """Narrow wrapper around an injected `neo4j.Driver`."""

    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    @classmethod
    def connect(cls, uri: str, user: str, password: str) -> Neo4jClient:
        """Open a driver to `uri` with basic auth and verify connectivity."""

        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return cls(driver)

    @property
    def driver(self) -> Driver:
        return self._driver

    def close(self) -> None:
        self._driver.close()

    def server_edition(self) -> str:
        """Return the server edition string (`"enterprise"` / `"community"`).

        Used by the schema bootstrap to decide whether property-existence
        constraints (Enterprise-only) can be applied. Falls back to
        `"community"` on any error so the conservative path is taken.
        """

        try:
            with self._driver.session() as session:
                rec = session.run(
                    "CALL dbms.components() YIELD edition RETURN edition"
                ).single()
                if rec is not None:
                    return str(rec["edition"]).lower()
        except Exception as exc:  # noqa: BLE001 - degrade to the safe assumption
            log.warning("neo4j.edition_detect_failed", error=repr(exc))
        return "community"

    def execute_write(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        """Run `cypher` in a write transaction; return rows as dicts."""

        with self._driver.session() as session:
            return session.execute_write(_run_collect, cypher, params)

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        """Run `cypher` in a read transaction; return rows as dicts."""

        with self._driver.session() as session:
            return session.execute_read(_run_collect, cypher, params)


def _run_collect(tx: Any, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    result = tx.run(cypher, **params)
    return [dict(record) for record in result]
