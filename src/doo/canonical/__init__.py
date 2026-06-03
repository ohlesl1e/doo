"""Canonical Pydantic models — one representation per concept.

The seven cross-cutting fields (ADR-0005) live as a mixin; small value objects
(`HostRef`, `BlobRef`, `AuthContextCue`) used by L2 events live here so they're
not duplicated across event-kind modules.
"""

from doo.canonical.cross_cutting import (
    CONFIDENCE_METHODS,
    SOURCES,
    ConfidenceMethod,
    Inferred,
    Provenanced,
    SourceTag,
    Status,
)
from doo.canonical.value_objects import (
    AuthContextCue,
    BlobRef,
    HostRef,
)

__all__ = [
    "AuthContextCue",
    "BlobRef",
    "CONFIDENCE_METHODS",
    "ConfidenceMethod",
    "HostRef",
    "Inferred",
    "Provenanced",
    "SOURCES",
    "SourceTag",
    "Status",
]
