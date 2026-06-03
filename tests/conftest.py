"""Shared pytest fixtures.

The Neo4j testcontainer fixture is module-scoped so the heavy container start
amortises across the schema-bootstrap tests. Module scope is fine because the
schema tests reset state explicitly between test cases.

The Redis testcontainer fixture (T7) is function-scoped: the kill-switch tests
need a clean lease key per case and the container is light.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest


@pytest.fixture
def utc_now() -> datetime:
    return datetime.now(UTC)


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


@pytest.fixture
def redis_url() -> Iterator[str]:
    """Start a Redis testcontainer and yield its connection URL (T7).

    Skips cleanly when docker / testcontainers is unavailable so the rest of the
    suite still runs. Used by the kill-switch keepalive integration tests.
    """

    if os.getenv("DOO_SKIP_TESTCONTAINERS"):
        pytest.skip("DOO_SKIP_TESTCONTAINERS set; skipping testcontainer-backed test")

    try:
        from testcontainers.redis import RedisContainer  # type: ignore[import-not-found]
    except Exception:
        pytest.skip(
            "testcontainers[redis] not installed; skipping Redis testcontainer test "
            "(pip install 'testcontainers[redis]')"
        )

    container = RedisContainer("redis:7-alpine")
    try:
        container.start()
    except Exception as exc:
        pytest.skip(f"Could not start Redis testcontainer: {exc!r}")

    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
    finally:
        container.stop()


@pytest.fixture
def minio_config() -> Iterator[dict[str, str]]:
    """Start a MinIO testcontainer and yield its boto3 connection config (T2).

    Yields `{endpoint_url, access_key, secret_key}` for `BlobClient.from_config`.
    Skips cleanly when docker / testcontainers[minio] is unavailable.
    """

    if os.getenv("DOO_SKIP_TESTCONTAINERS"):
        pytest.skip("DOO_SKIP_TESTCONTAINERS set; skipping testcontainer-backed test")

    try:
        from testcontainers.minio import MinioContainer  # type: ignore[import-not-found]
    except Exception:
        pytest.skip(
            "testcontainers[minio] not installed; skipping MinIO testcontainer test "
            "(pip install 'testcontainers[minio]')"
        )

    container = MinioContainer("minio/minio:latest")
    try:
        container.start()
    except Exception as exc:
        pytest.skip(f"Could not start MinIO testcontainer: {exc!r}")

    try:
        cfg = container.get_config()
        yield {
            "endpoint_url": f"http://{cfg['endpoint']}",
            "access_key": cfg["access_key"],
            "secret_key": cfg["secret_key"],
        }
    finally:
        container.stop()
