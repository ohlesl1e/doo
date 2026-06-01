"""Infrastructure adapters.

Slice 1 / T7 adds the thin Redis lease client (`redis_lease`) the kill-switch
keepalive needs. Broader infra (Redis Streams client, MinIO, Neo4j driver
bootstrapping) lands alongside the layers that need it; T2 may add its own
clients here — merge reconciles.
"""

from doo.infra.blobs import BlobClient, har_blob_key, sha256_hex
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.redis_lease import LEASE_VALUE_ACTIVE, RedisLease, lease_key
from doo.infra.streams import (
    INGEST_STREAM,
    L2_EVENTS_STREAM,
    L3_EVENTS_STREAM,
    StreamClient,
)

__all__ = [
    "LEASE_VALUE_ACTIVE",
    "RedisLease",
    "lease_key",
    "BlobClient",
    "har_blob_key",
    "sha256_hex",
    "Neo4jClient",
    "StreamClient",
    "INGEST_STREAM",
    "L2_EVENTS_STREAM",
    "L3_EVENTS_STREAM",
]
