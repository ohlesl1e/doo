"""Object-storage blob client (slice-1 T2, MinIO/S3 via boto3).

Per ADR-0015 / ARCHITECTURE.md: raw blobs (whole HAR uploads, request/response
bodies) live in object storage; the graph holds only hashes + metadata + the
storage key. This client owns the bucket layout and the streaming put/get.

Key layout (T2 spec): `engagement/{engagement_id}/source/har/{blob_sha256}.har`.

The client is constructed from explicit endpoint/credentials so the same code
talks to MinIO (testcontainer / dev) and real S3 (prod) — only config differs.
"""

from __future__ import annotations

import hashlib
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.client import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from doo.ids import BlobKey, EngagementId, Sha256Hex


def har_blob_key(engagement_id: EngagementId, blob_sha256: Sha256Hex) -> BlobKey:
    """Object key for a whole HAR upload (T2 layout).

    `engagement/{engagement_id}/source/har/{blob_sha256}.har`.
    """

    return BlobKey(f"engagement/{engagement_id}/source/har/{blob_sha256}.har")


def sha256_hex(data: bytes) -> Sha256Hex:
    """Lowercase-hex sha256 of `data` (the blob integrity + idempotency input)."""

    return Sha256Hex(hashlib.sha256(data).hexdigest())


class BlobClient:
    """boto3-backed object-storage client scoped to one bucket.

    Construct via `from_config`; the bucket is ensured on first use. Methods are
    deliberately narrow: `put_har`, `get`, `exists`. No generic `execute`.
    """

    def __init__(self, s3: Any, bucket: str) -> None:
        self._s3 = s3
        self._bucket = bucket

    @classmethod
    def from_config(
        cls,
        *,
        endpoint_url: str | None,
        access_key: str,
        secret_key: str,
        bucket: str,
        region: str = "us-east-1",
    ) -> BlobClient:
        """Build a `BlobClient` for MinIO or S3 and ensure the bucket exists."""

        s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=Config(signature_version="s3v4"),
        )
        client = cls(s3, bucket)
        client.ensure_bucket()
        return client

    @property
    def bucket(self) -> str:
        return self._bucket

    def ensure_bucket(self) -> None:
        """Create the bucket if it doesn't already exist (idempotent)."""

        try:
            self._s3.head_bucket(Bucket=self._bucket)
        except ClientError:
            self._s3.create_bucket(Bucket=self._bucket)

    def put_har(
        self, engagement_id: EngagementId, blob_sha256: Sha256Hex, data: bytes
    ) -> BlobKey:
        """Store a whole HAR blob under the T2 key layout; return the key.

        Idempotent at the storage layer: the same `(engagement, sha256)` maps to
        one key, so re-uploading overwrites identical bytes (a no-op in effect).
        """

        key = har_blob_key(engagement_id, blob_sha256)
        self._s3.put_object(
            Bucket=self._bucket,
            Key=str(key),
            Body=data,
            ContentType="application/json",
        )
        return key

    def get(self, key: BlobKey) -> bytes:
        """Fetch the bytes at `key`."""

        resp = self._s3.get_object(Bucket=self._bucket, Key=str(key))
        body: bytes = resp["Body"].read()
        return body

    def exists(self, key: BlobKey) -> bool:
        """True if an object exists at `key`."""

        try:
            self._s3.head_object(Bucket=self._bucket, Key=str(key))
        except ClientError:
            return False
        return True
