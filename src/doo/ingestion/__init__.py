"""L1 ingestion.

Slice-1 T2 ships the L1 intake (FastAPI `POST /ingest/har` + the `ingest_har`
core), the L2 extraction worker, and the `doo ingest har` CLI. The
`IngestionEnvelope` contract they emit lives in `doo.events`.
"""

from doo.ingestion.intake import (
    IntakeDeps,
    IntakeResult,
    UnknownEngagementError,
    build_app,
    compute_idempotency_key,
    ingest_har,
)
from doo.ingestion.l2_worker import L2WorkerDeps, process_envelope, run_l2_worker

__all__ = [
    "IntakeDeps",
    "IntakeResult",
    "UnknownEngagementError",
    "build_app",
    "compute_idempotency_key",
    "ingest_har",
    "L2WorkerDeps",
    "process_envelope",
    "run_l2_worker",
]
