"""Shared pytest fixtures.

The Neo4j testcontainer fixture is module-scoped so the heavy container start
amortises across the schema-bootstrap tests. Module scope is fine because the
schema tests reset state explicitly between test cases.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import datetime, timezone

import pytest


@pytest.fixture
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def neo4j_container() -> Iterator[object]:
    """Start a Neo4j testcontainer and yield it.

    Skips if testcontainers / docker is not available so the rest of the suite
    still runs in environments without docker (e.g. CI lint-only stages).
    """

    if os.getenv("DOO_SKIP_TESTCONTAINERS"):
        pytest.skip("DOO_SKIP_TESTCONTAINERS set; skipping testcontainer-backed test")

    try:
        from testcontainers.neo4j import Neo4jContainer  # type: ignore[import-not-found]
    except Exception:
        pytest.skip("testcontainers[neo4j] not installed; skipping testcontainer-backed test")

    container = Neo4jContainer("neo4j:5-community")
    try:
        container.start()
    except Exception as exc:  # docker not running, etc.
        pytest.skip(f"Could not start Neo4j testcontainer: {exc!r}")

    try:
        yield container
    finally:
        container.stop()
