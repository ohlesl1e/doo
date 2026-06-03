"""Re-expose the pipeline container fixtures for the e2e package.

The `neo4j_client` / `redis_client` / `blob_client` fixtures are defined in
`tests/test_pipeline_e2e.py`; importing them here makes pytest discover them for
`tests/e2e/` without the test module importing fixture names (which would trip
F811 against the test functions' parameters).
"""

from __future__ import annotations

from tests.test_pipeline_e2e import (  # noqa: F401  (re-exposed pytest fixtures)
    blob_client,
    neo4j_client,
    redis_client,
)
