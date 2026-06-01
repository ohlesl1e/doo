"""Test/ops entrypoint: run the keepalive against a real Redis from env.

Not part of the public CLI (the CLI command in `cli_keepalive.py` also reads
the Engagement config from Neo4j). This thin runner skips the graph read and
takes the lease parameters directly from the environment so the integration
tests can launch a real subprocess (to exercise SIGTERM / SIGKILL signal
handling) without standing up Neo4j.

Environment:
- `DOO_KEEPALIVE_ENGAGEMENT_ID` (required)
- `DOO_REDIS_URL` (default `redis://localhost:6379/0`)
- `DOO_KEEPALIVE_TTL_SECONDS` (default 60)
- `DOO_KEEPALIVE_REFRESH_SECONDS` (default 30)

Exits 0 on SIGTERM (after releasing the lease).
"""

from __future__ import annotations

import os
import sys

from doo.engagement.keepalive import KeepaliveConfig, run_keepalive
from doo.ids import EngagementId
from doo.infra.redis_lease import RedisLease


def main() -> int:
    import redis

    engagement_id = os.environ.get("DOO_KEEPALIVE_ENGAGEMENT_ID")
    if not engagement_id:
        print("DOO_KEEPALIVE_ENGAGEMENT_ID is required", file=sys.stderr)
        return 2

    url = os.environ.get("DOO_REDIS_URL", "redis://localhost:6379/0")
    ttl = int(os.environ.get("DOO_KEEPALIVE_TTL_SECONDS", "60"))
    refresh = int(os.environ.get("DOO_KEEPALIVE_REFRESH_SECONDS", "30"))

    config = KeepaliveConfig(
        engagement_id=EngagementId(engagement_id),
        lease_ttl_seconds=ttl,
        refresh_interval_seconds=refresh,
    )
    client = redis.Redis.from_url(url)
    lease = RedisLease(client, config.engagement_id)
    return run_keepalive(config, lease)


if __name__ == "__main__":
    raise SystemExit(main())
