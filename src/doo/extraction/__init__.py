"""L2 extraction.

Slice-1 T2 ships the HAR 1.2 parser and the `(source, blob_format)` parser
registry; the `L2Event` contract they emit lives in `doo.events`.
"""

from doo.extraction.har import parse_har
from doo.extraction.registry import (
    Parser,
    UnknownParserError,
    get_parser,
    has_parser,
)

__all__ = [
    "parse_har",
    "Parser",
    "UnknownParserError",
    "get_parser",
    "has_parser",
]
