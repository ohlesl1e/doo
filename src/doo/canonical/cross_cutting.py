"""Cross-cutting properties per ADR-0005.

`Provenanced` is the seven-field mixin on every node and edge. `Inferred` adds
the two inference-only fields (`inferred_at`, `code_version`). Both are strict
Pydantic v2 models with `extra = "forbid"`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

ConfidenceMethod = Literal["heuristic", "manual", "llm-self-reported", "calibrated"]
CONFIDENCE_METHODS: tuple[ConfidenceMethod, ...] = (
    "heuristic",
    "manual",
    "llm-self-reported",
    "calibrated",
)

Status = Literal["active", "retracted", "expired", "paused", "archived"]
"""Node status. `active` and `retracted` are universal; `expired`/`paused`/`archived`
apply to specific node types (AuthContext, Engagement)."""

# Closed source enum mirrors `IngestionEnvelope.source` plus L3-internal sources.
SourceTag = Literal[
    "har",
    "burp-streamed",
    "nuclei",
    "agent",
    "manual",
    "logger++",
    "ffuf",
    "subfinder",
    "deterministic-templating",
    "deterministic-promotion",
    "llm-asset-promotion",
    "llm-parameter-semantic",
    "llm-tenant-inference",
    "llm-entity-resolution",
]
SOURCES: tuple[SourceTag, ...] = (
    "har",
    "burp-streamed",
    "nuclei",
    "agent",
    "manual",
    "logger++",
    "ffuf",
    "subfinder",
    "deterministic-templating",
    "deterministic-promotion",
    "llm-asset-promotion",
    "llm-parameter-semantic",
    "llm-tenant-inference",
    "llm-entity-resolution",
)


class Provenanced(BaseModel):
    """The seven Step-4 cross-cutting fields, plus `status`. Every entity inherits."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=False)

    source: SourceTag
    source_id: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_method: ConfidenceMethod
    first_seen: datetime
    last_seen: datetime
    ingested_at: datetime
    status: Status = "active"

    @model_validator(mode="after")
    def _times_monotone(self) -> Self:
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be <= last_seen")
        return self


class Inferred(Provenanced):
    """Inference-layer entities add two fields per ADR-0005."""

    inferred_at: datetime
    code_version: str = Field(min_length=1)
