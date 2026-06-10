"""Persistence of the planner's LLM proposal calls (ADR-0037 replayability).

Every LLM proposal — committed or rejected — is persisted verbatim so a reviewer
can later replay exactly what the model saw and said (the audit trail that matters
for disclosure, and the only way to debug a bad proposal without re-running a
non-deterministic call). The request/response are content-addressed JSON; the
committed `TestCase` carries the returned storage key as provenance.

`LLMAuditSink` is the one seam the service writes through:
- `BlobLLMAuditSink` persists to object storage (MinIO/S3) for real runs.
- `InMemoryLLMAuditSink` keeps the JSON in a dict for tests (no boto3, no bucket),
  while still returning a stable content-addressed key so the commit path is
  exercised end to end.
"""

from __future__ import annotations

import hashlib
import json
from typing import Protocol, runtime_checkable

from doo.ids import EngagementId
from doo.infra.blobs import BlobClient
from doo.planner.llm import LLMCallResult


def _canonical_bytes(call: LLMCallResult) -> bytes:
    """Canonical JSON bytes of a call's verbatim request + response (the audit body).

    Sorted keys so the content address is stable across runs; the draft is included
    as the parsed projection alongside the raw I/O for human-readable replay.
    """

    body = {
        "request": call.request,
        "response": call.response,
        "draft": call.draft.model_dump(mode="json"),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


@runtime_checkable
class LLMAuditSink(Protocol):
    """Persist one verbatim planner LLM call and return its storage key."""

    def record(self, engagement_id: EngagementId, call: LLMCallResult) -> str: ...


class BlobLLMAuditSink:
    """Persist planner LLM calls to object storage (MinIO/S3) via `BlobClient`."""

    def __init__(self, blobs: BlobClient) -> None:
        self._blobs = blobs

    def record(self, engagement_id: EngagementId, call: LLMCallResult) -> str:
        key = self._blobs.put_planner_llm_call(
            engagement_id, data=_canonical_bytes(call)
        )
        return str(key)


class InMemoryLLMAuditSink:
    """A dict-backed sink for tests: same content-addressed key, no object storage.

    Mirrors the blob key layout so a test can assert the committed node carries a
    real, stable `llm_audit_key` without standing up MinIO.
    """

    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def record(self, engagement_id: EngagementId, call: LLMCallResult) -> str:
        data = _canonical_bytes(call)
        sha = hashlib.sha256(data).hexdigest()
        key = f"engagement/{engagement_id}/planner/llm/{sha}.json"
        self.stored[key] = data
        return key
