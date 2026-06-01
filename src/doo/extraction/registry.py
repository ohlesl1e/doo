"""Parser registry keyed by `(source, blob_format)` (slice-1 T2).

The L2 worker looks up a parser by the envelope's `(source, blob_format)` pair
and calls it with `(blob, envelope)`. Registering parsers in one place keeps the
dispatch table explicit and makes "what can L2 parse?" answerable by reading one
module.

Slice-1 ships exactly one parser: HAR 1.2 (`("har", "har-1.2")`). New sources
register here; an envelope whose pair has no parser is a hard configuration
error surfaced to the worker (which records a whole-blob ParseFailure).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import L2Event
from doo.extraction.har import parse_har

# A parser turns a raw blob + its envelope into a stream of L2 events.
Parser = Callable[[bytes, IngestionEnvelope], Iterator[L2Event]]


class UnknownParserError(LookupError):
    """No parser registered for the given `(source, blob_format)` pair."""


_REGISTRY: dict[tuple[str, str], Parser] = {
    ("har", "har-1.2"): parse_har,
}


def get_parser(source: str, blob_format: str) -> Parser:
    """Return the parser for `(source, blob_format)` or raise `UnknownParserError`."""

    try:
        return _REGISTRY[(source, blob_format)]
    except KeyError as exc:
        raise UnknownParserError(
            f"no parser registered for (source={source!r}, blob_format={blob_format!r})"
        ) from exc


def has_parser(source: str, blob_format: str) -> bool:
    """True if a parser is registered for `(source, blob_format)`."""

    return (source, blob_format) in _REGISTRY
