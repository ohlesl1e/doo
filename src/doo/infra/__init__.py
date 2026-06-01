"""Infrastructure adapters.

Slice 1 / T7 adds the thin Redis lease client (`redis_lease`) the kill-switch
keepalive needs. Broader infra (Redis Streams client, MinIO, Neo4j driver
bootstrapping) lands alongside the layers that need it; T2 may add its own
clients here — merge reconciles.
"""

from doo.infra.redis_lease import LEASE_VALUE_ACTIVE, RedisLease, lease_key

__all__ = [
    "LEASE_VALUE_ACTIVE",
    "RedisLease",
    "lease_key",
]
