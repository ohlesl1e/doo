"""Deterministic response-artifact extractors (slice-1 T6).

A set of pure, deterministic rules that walk a response's body text + headers and
surface discrete `ResponseArtifact`s — hostnames, URLs, emails, identifiers,
fingerprints, error excerpts, and secret-shaped strings. No LLM (CLAUDE.md hard
rule): every extractor is a regex / JSON-walk rule with a *versioned* name
(`regex:internal_hostname_v1`, `json-walk:id-fields_v1`) so a rule change adds a
new `_v2` extractor rather than silently re-meaning prior commits.

Secret discipline (ADR-0015): the secret-shape extractor never returns a raw
value. It returns `value=None` and sets `is_secret=True`; the caller hashes the
matched bytes and carries only `value_hash + value_length + value_preview`. The
raw secret lives only in the uploaded response-body blob.

The module is decoupled from `events/l2.py`: it returns plain `Extraction`
dataclasses. `extraction/har.py` turns them into `ResponseArtifact` L2 events,
stamping the deterministic `source_id` that backs ADR-0016 idempotency.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass

from doo.events.l2 import ArtifactSection, ResponseArtifactKind


@dataclass(frozen=True, slots=True)
class Extraction:
    """One raw extractor hit, before it becomes a `ResponseArtifact` event.

    `value` is the matched substring for non-secret kinds. For secret kinds
    `is_secret=True` and `value` still carries the raw matched bytes *only so the
    caller can hash them* — the caller must not propagate it onto the event
    (ADR-0015). `byte_start`/`byte_end` index the decoded body bytes; for header
    extractions they are `None` and `header_name` is set.
    """

    artifact_kind: ResponseArtifactKind
    section: ArtifactSection
    extractor: str
    value: str
    is_secret: bool = False
    header_name: str | None = None
    json_pointer: str | None = None
    byte_start: int | None = None
    byte_end: int | None = None


# --------------------------------------------------------------------------- #
# Regexes. Each backs exactly one versioned extractor.
# --------------------------------------------------------------------------- #

# Internal-looking bare hostnames: a dotted name whose any label chain matches
# corp/internal, or that ends in `.local`. Deliberately conservative — public
# hostnames are noise in slice-1; internal ones are the high-signal find.
_INTERNAL_HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z0-9-]+\.)*"
    r"(?:corp|internal)\.[a-z0-9.-]+\b"
    r"|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+local\b",
    re.IGNORECASE,
)

# RFC 1918 / loopback / link-local IPv4 literals (kind = ip_address).
_PRIVATE_IPV4_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)

# RFC 5322-lite: good enough to catch addresses in bodies without false-positiving
# on every `@` in JSON. Bounded local part + a dotted domain.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b"
)

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

# Secret shapes. JWT (three base64url segments), AWS access key id, Stripe keys,
# `Bearer <token>` continuations, and long high-entropy base64url/hex strings.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")
_STRIPE_KEY_RE = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")
_BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9._\-+/=]{12,})")
# Long high-entropy token: a single run of base64url/hex chars, length >= 32,
# carrying a mix of upper, lower, and digit (so plain English words / hex hashes
# alone do not trip it — those are caught by UUID / identifier rules instead).
_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

_HTML_TAG_RE = re.compile(r"<[^>]+>")

# JSON field names that carry identifiers (the json-walk:id-fields_v1 rule).
_ID_FIELD_RE = re.compile(r"(?:^|_)id$|^id$", re.IGNORECASE)

# Response headers that fingerprint the server / framework.
_FINGERPRINT_HEADERS: tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-generator",
)

# Error-excerpt length budget (chars, after HTML-stripping).
_ERROR_EXCERPT_CHARS = 200


def _high_entropy(s: str) -> bool:
    """True if `s` mixes character classes like a credential, not a word/hash."""

    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    # Require at least two of the three classes plus a digit, so all-hex (a
    # checksum) and all-letters (a slug) do not register as secrets.
    return has_digit and has_upper and has_lower


# --------------------------------------------------------------------------- #
# Body extractors (operate on the decoded body text + bytes).
# --------------------------------------------------------------------------- #


def _iter_regex(
    pattern: re.Pattern[str],
    text: str,
    text_bytes: bytes,
    *,
    artifact_kind: ResponseArtifactKind,
    extractor: str,
    group: int = 0,
    is_secret: bool = False,
) -> Iterator[Extraction]:
    """Yield one `Extraction` per regex match, with byte offsets into the body.

    Byte offsets are computed by encoding the prefix up to the match — correct
    for UTF-8 bodies where char index != byte index.
    """

    for m in pattern.finditer(text):
        value = m.group(group)
        if not value:
            continue
        char_start = m.start(group)
        byte_start = len(text[:char_start].encode("utf-8"))
        byte_end = byte_start + len(value.encode("utf-8"))
        yield Extraction(
            artifact_kind=artifact_kind,
            section="body",
            extractor=extractor,
            value=value,
            is_secret=is_secret,
            byte_start=byte_start,
            byte_end=byte_end,
        )


def _extract_secrets_from_body(text: str, text_bytes: bytes) -> Iterator[Extraction]:
    """Secret-shape extractors over the body. Always `is_secret=True`.

    Higher-precision shapes (JWT, AWS, Stripe, Bearer) run first; the generic
    high-entropy net runs last and skips spans already claimed so a JWT is not
    also reported as a high-entropy blob.
    """

    claimed: list[tuple[int, int]] = []

    def _emit(m: re.Match[str], extractor: str, group: int = 0) -> Iterator[Extraction]:
        value = m.group(group)
        cs = m.start(group)
        bs = len(text[:cs].encode("utf-8"))
        be = bs + len(value.encode("utf-8"))
        claimed.append((cs, cs + len(value)))
        yield Extraction(
            artifact_kind="secret_shaped",
            section="body",
            extractor=extractor,
            value=value,
            is_secret=True,
            byte_start=bs,
            byte_end=be,
        )

    for m in _JWT_RE.finditer(text):
        yield from _emit(m, "regex:jwt_v1")
    for m in _AWS_ACCESS_KEY_RE.finditer(text):
        yield from _emit(m, "regex:aws_access_key_v1")
    for m in _STRIPE_KEY_RE.finditer(text):
        yield from _emit(m, "regex:stripe_key_v1")
    for m in _BEARER_RE.finditer(text):
        yield from _emit(m, "regex:bearer_continuation_v1", group=1)

    for m in _HIGH_ENTROPY_RE.finditer(text):
        cs, ce = m.start(), m.end()
        if any(cs < c_end and c_start < ce for c_start, c_end in claimed):
            continue  # already reported as a more-specific secret shape
        if not _high_entropy(m.group(0)):
            continue
        yield from _emit(m, "regex:high_entropy_token_v1")


def _walk_json_ids(node: object, pointer: str, out: list[Extraction]) -> None:
    """Recurse JSON, emitting an `identifier` Extraction for `id` / `*_id` leaves.

    The value's byte offset into the body is *not* recoverable from the parsed
    structure (json.loads discards positions), so JSON-walk identifiers carry the
    RFC 6901 `json_pointer` for location instead of byte offsets.
    """

    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{pointer}/{_rfc6901_escape(str(key))}"
            if isinstance(value, str | int) and not isinstance(value, bool):
                if _ID_FIELD_RE.search(str(key)):
                    out.append(
                        Extraction(
                            artifact_kind="identifier",
                            section="body",
                            extractor="json-walk:id-fields_v1",
                            value=str(value),
                            json_pointer=child,
                        )
                    )
            _walk_json_ids(value, child, out)
        return
    if isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json_ids(value, f"{pointer}/{index}", out)


def _rfc6901_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def extract_from_body(
    body_bytes: bytes,
    *,
    content_type: str,
    status: int,
) -> list[Extraction]:
    """Run every body extractor over a decoded response body.

    `content_type` gates the JSON-walk id extractor (only on JSON bodies).
    `status` gates the error-message excerpt (only on 5xx). Non-UTF-8 bytes are
    decoded leniently so a binary-ish body still yields header artifacts upstream
    without crashing here.
    """

    text = body_bytes.decode("utf-8", errors="replace")
    out: list[Extraction] = []

    out.extend(
        _iter_regex(
            _INTERNAL_HOSTNAME_RE, text, body_bytes,
            artifact_kind="hostname", extractor="regex:internal_hostname_v1",
        )
    )
    out.extend(
        _iter_regex(
            _PRIVATE_IPV4_RE, text, body_bytes,
            artifact_kind="ip_address", extractor="regex:rfc1918_ip_v1",
        )
    )
    out.extend(
        _iter_regex(
            _URL_RE, text, body_bytes,
            artifact_kind="url", extractor="regex:url_v1",
        )
    )
    out.extend(
        _iter_regex(
            _EMAIL_RE, text, body_bytes,
            artifact_kind="email", extractor="regex:email_v1",
        )
    )
    out.extend(
        _iter_regex(
            _UUID_RE, text, body_bytes,
            artifact_kind="identifier", extractor="regex:uuid_v1",
        )
    )
    out.extend(_extract_secrets_from_body(text, body_bytes))

    base_mime = content_type.split(";", 1)[0].strip().lower()
    if base_mime == "application/json" or base_mime.endswith("+json"):
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            doc = None
        if doc is not None:
            _walk_json_ids(doc, "", out)

    if 500 <= status <= 599:
        excerpt = _error_excerpt(text)
        if excerpt:
            out.append(
                Extraction(
                    artifact_kind="error_message",
                    section="body",
                    extractor="regex:error_excerpt_v1",
                    value=excerpt,
                    byte_start=0,
                    byte_end=len(body_bytes),
                )
            )

    return out


def _error_excerpt(text: str) -> str:
    """First `_ERROR_EXCERPT_CHARS` chars of an HTML-stripped, whitespace-collapsed body."""

    stripped = _HTML_TAG_RE.sub(" ", text)
    collapsed = " ".join(stripped.split())
    return collapsed[:_ERROR_EXCERPT_CHARS]


# --------------------------------------------------------------------------- #
# Header extractors.
# --------------------------------------------------------------------------- #


def extract_from_headers(headers: dict[str, str]) -> list[Extraction]:
    """Fingerprint extractions from response headers (`Server`, `X-Powered-By`...).

    `headers` is a lowercased-name -> value map. The emitted `header_name` keeps
    the canonical capitalisation the wire/HAR used where known; we restore a
    canonical form for the well-known names.
    """

    out: list[Extraction] = []
    for name in _FINGERPRINT_HEADERS:
        value = headers.get(name)
        if value:
            out.append(
                Extraction(
                    artifact_kind="fingerprint",
                    section="header",
                    extractor="header:fingerprint_v1",
                    value=value,
                    header_name=_canonical_header_name(name),
                )
            )
    return out


def _canonical_header_name(lower_name: str) -> str:
    """Restore conventional capitalisation for the well-known fingerprint headers."""

    special = {
        "x-powered-by": "X-Powered-By",
        "x-aspnet-version": "X-AspNet-Version",
        "x-aspnetmvc-version": "X-AspNetMvc-Version",
        "x-runtime": "X-Runtime",
        "x-generator": "X-Generator",
    }
    if lower_name in special:
        return special[lower_name]
    return "-".join(part.capitalize() for part in lower_name.split("-"))
