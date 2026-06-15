"""Shared pytest fixtures.

The testcontainer fixtures (Neo4j / Redis / MinIO) are **session-scoped**: the
heavy container start happens once per session and is amortised across the whole
suite (per-test container startup dominated CI wall-clock — see #97). Per-test
isolation is restored by the autouse cleanup fixtures below, which reset state
between tests *only* when a container was actually started this session — so the
many pure-unit tests never pay to spin one up:

- `_clean_neo4j_between_tests` deletes all graph **data** before each test (the
  schema constraints/indexes are idempotent and stay).
- `_flush_redis_between_tests` flushes Redis before each test (the kill-switch
  lease keys must be clean per case).

MinIO needs no per-test wipe: blob keys are content-addressed + engagement-scoped,
so writes are idempotent and cannot collide across tests.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

# Module-level handles so the autouse cleanup fixtures can act ONLY when a
# session container has actually been started — without declaring a dependency on
# the container fixtures (which would force every test to start them).
_NEO4J_CONTAINER: object | None = None
_REDIS_URL: str | None = None


@pytest.fixture
def utc_now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture(scope="session")
def neo4j_container() -> Iterator[object]:
    """Start a Neo4j testcontainer once per session and yield it.

    Skips if testcontainers / docker is not available so the rest of the suite
    still runs in environments without docker (e.g. CI lint-only stages).
    Per-test data isolation is handled by `_clean_neo4j_between_tests`.
    """

    global _NEO4J_CONTAINER

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

    _NEO4J_CONTAINER = container
    try:
        yield container
    finally:
        _NEO4J_CONTAINER = None
        container.stop()


@pytest.fixture(autouse=True)
def _clean_neo4j_between_tests() -> Iterator[None]:
    """Wipe graph data before each test if a session Neo4j container is running.

    Restores per-test isolation under the session-scoped container without
    forcing container creation for tests that never touch Neo4j. Deletes nodes +
    relationships only; the idempotent schema constraints/indexes stay.
    """

    if _NEO4J_CONTAINER is not None:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            _NEO4J_CONTAINER.get_connection_url(),  # type: ignore[attr-defined]
            auth=(
                _NEO4J_CONTAINER.username,  # type: ignore[attr-defined]
                _NEO4J_CONTAINER.password,  # type: ignore[attr-defined]
            ),
        )
        try:
            with driver.session() as sess:
                sess.run("MATCH (n) DETACH DELETE n")
        finally:
            driver.close()
    yield


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    """Start a Redis testcontainer once per session and yield its connection URL (T7).

    Skips cleanly when docker / testcontainers is unavailable so the rest of the
    suite still runs. Per-test isolation (clean lease keys) is handled by
    `_flush_redis_between_tests`.
    """

    global _REDIS_URL

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

    host = container.get_container_host_ip()
    port = container.get_exposed_port(6379)
    url = f"redis://{host}:{port}/0"
    _REDIS_URL = url
    try:
        yield url
    finally:
        _REDIS_URL = None
        container.stop()


@pytest.fixture(autouse=True)
def _flush_redis_between_tests() -> Iterator[None]:
    """Flush Redis before each test if a session Redis container is running.

    Keeps kill-switch lease keys + the dedup ledger clean per case under the
    session-scoped container, without forcing creation for tests that never use
    Redis.
    """

    if _REDIS_URL is not None:
        import redis

        client = redis.Redis.from_url(_REDIS_URL)
        try:
            client.flushall()
        finally:
            client.close()
    yield


@pytest.fixture(scope="session")
def minio_config() -> Iterator[dict[str, str]]:
    """Start a MinIO testcontainer once per session and yield its boto3 config (T2).

    Yields `{endpoint_url, access_key, secret_key}` for `BlobClient.from_config`.
    Skips cleanly when docker / testcontainers[minio] is unavailable. No per-test
    wipe: blob keys are content-addressed + engagement-scoped, so writes are
    idempotent and cannot collide across tests.
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
