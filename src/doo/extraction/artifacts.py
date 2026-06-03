"""Deterministic response value-candidate extractors (ADR-0023, was slice-1 T6).

A set of pure, deterministic rules that walk a response's body text + headers and
surface two things:

1. **Candidate value occurrences** — hostnames, URLs, emails, identifiers, and
   secret-shaped strings — each a `(value_hash, kind, location, role="output",
   extractor)` plus the raw value for non-secret kinds. These are recorded
   *inline* on the `RequestObservation` (ADR-0023); a deferred promotion pass at
   flush mints an `ObservedValue` only for those whose `kind` clears the
   shape-allowlist (or, in later slices, cross-context signal). No node per
   extraction — that was the retired `ResponseArtifact` (the 277k collapse).
2. **Diagnostics** — the technology fingerprint (`Server` / `X-Powered-By`) and a
   5xx error-body excerpt — returned separately by `extract_diagnostics`. These
   are one-per-response and never cross-context, so they become inline
   `RequestObservation` properties, not values (ADR-0023).

No LLM (CLAUDE.md hard rule): every extractor is a regex / JSON-walk rule with a
*versioned* name (`regex:internal_hostname_v1`, `json-walk:id-fields_v1`) so a
rule change adds a new `_v2` extractor rather than silently re-meaning prior data.

Secret discipline (ADR-0015): the secret-shape extractor never lets a raw value
leave on a promotable field. A secret candidate carries `value_hash` + length +
8-char preview only (`value=None`); the raw matched bytes are used solely to
compute the hash here and are then dropped. The raw secret lives only in the
uploaded response-body blob.

The module is decoupled from `events/l2.py` and the graph: it returns plain
dataclasses (`CandidateOccurrence`, `ResponseDiagnostics`). `extraction/har.py`
records them inline on the emitted `RequestObservation`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass

from doo.canonical.values import CandidateKind, hash_for, is_secret_kind
from doo.ids import Sha256Hex

# Candidate location section: where in the response the value was found.
CandidateSection = str  # one of {"body", "header"}


@dataclass(frozen=True, slots=True)
class CandidateOccurrence:
    """One extracted value occurrence, recorded inline on a `RequestObservation`.

    `role` is `"output"` for values surfaced in a *response* (the `extract_*`
    functions here); `"input"` for values *sent* as request parameters
    (`extract_input_candidates`, #16) — the leak-to-input pivot.

    For non-secret kinds `value` is the raw matched substring and `value_hash` is
    the hash of its normalised form. For secret kinds (ADR-0015) `value` is `None`
    and only `value_hash` + `value_length` + `value_preview` (8 chars) are carried;
    the raw matched bytes are hashed here and then dropped.

    `section` is `"body"` or `"header"`. Body occurrences carry byte offsets into
    the decoded body and, for JSON-walk hits, an RFC 6901 `json_pointer`; header
    occurrences carry the source `header_name`. `parameter_name` is set for
    `"input"`-role occurrences (the request parameter that carried the value).
    """

    value_hash: Sha256Hex
    kind: CandidateKind
    extractor: str
    role: str = "output"
    section: CandidateSection = "body"
    value: str | None = None
    value_length: int | None = None
    value_preview: str | None = None
    header_name: str | None = None
    json_pointer: str | None = None
    byte_start: int | None = None
    byte_end: int | None = None
    parameter_name: str | None = None

    @property
    def is_secret(self) -> bool:
        return is_secret_kind(self.kind)

    def location_key(self) -> str:
        """A secret-free structural key for this occurrence (ADR-0016 idempotency).

        Fully determined by section + structural location; never includes the raw
        value, so it is safe to feed into a semantic key alongside `value_hash`.
        """

        if self.section == "header":
            return f"header:{self.header_name}"
        return f"body:{self.json_pointer or ''}:{self.byte_start}:{self.byte_end}"


@dataclass(frozen=True, slots=True)
class ResponseDiagnostics:
    """One-per-response diagnostics that become inline `RequestObservation` props.

    `server_fingerprint` is the first present `Server` / `X-Powered-By`-style
    fingerprint header value; `error_excerpt` is an HTML-stripped excerpt of a 5xx
    body. Both are `None` when absent. Never values / nodes (ADR-0023).
    """

    server_fingerprint: str | None = None
    error_excerpt: str | None = None


# --------------------------------------------------------------------------- #
# Regexes. Each backs exactly one versioned extractor.
# --------------------------------------------------------------------------- #

# Internal-looking bare hostnames: a dotted name whose any label chain matches
# corp/internal, or that ends in `.local`. Deliberately conservative — public
# hostnames are noise; internal ones are the high-signal find.
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
    # Require a digit plus upper and lower, so all-hex (a checksum) and all-letters
    # (a slug) do not register as secrets.
    return has_digit and has_upper and has_lower


# --------------------------------------------------------------------------- #
# Candidate construction (with secret discipline at the construction edge).
# --------------------------------------------------------------------------- #


def _candidate(
    kind: CandidateKind,
    raw: str,
    *,
    extractor: str,
    section: CandidateSection = "body",
    header_name: str | None = None,
    json_pointer: str | None = None,
    byte_start: int | None = None,
    byte_end: int | None = None,
) -> CandidateOccurrence:
    """Build a `CandidateOccurrence`, applying ADR-0015 at the construction edge.

    Secret kinds drop the raw value, carrying only `value_hash` (over the raw
    matched bytes) + length + an 8-char preview. The preview is emitted ONLY when
    the value is longer than the preview window (`len > 8`); a short secret (e.g.
    a 7-char password sent as an `input` param) would otherwise be revealed in
    full by its own preview, violating ADR-0015. Non-secret kinds carry the raw
    value and a `value_hash` over its normalised form (`canonical/values.py`).
    """

    vh = hash_for(kind, raw)
    if is_secret_kind(kind):
        return CandidateOccurrence(
            value_hash=vh,
            kind=kind,
            extractor=extractor,
            section=section,
            value=None,
            value_length=len(raw.encode("utf-8")),
            value_preview=raw[:8] if len(raw) > 8 else None,
            header_name=header_name,
            json_pointer=json_pointer,
            byte_start=byte_start,
            byte_end=byte_end,
        )
    return CandidateOccurrence(
        value_hash=vh,
        kind=kind,
        extractor=extractor,
        section=section,
        value=raw,
        header_name=header_name,
        json_pointer=json_pointer,
        byte_start=byte_start,
        byte_end=byte_end,
    )


def _iter_regex(
    pattern: re.Pattern[str],
    text: str,
    *,
    kind: CandidateKind,
    extractor: str,
    group: int = 0,
) -> Iterator[CandidateOccurrence]:
    """Yield one candidate per regex match, with byte offsets into the body.

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
        yield _candidate(
            kind, value, extractor=extractor, byte_start=byte_start, byte_end=byte_end
        )


def _extract_secrets_from_body(text: str) -> Iterator[CandidateOccurrence]:
    """Secret-shape extractors over the body. Higher-precision shapes run first.

    The generic high-entropy net runs last and skips spans already claimed so a
    JWT is not also reported as a high-entropy blob.
    """

    claimed: list[tuple[int, int]] = []

    def _emit(
        m: re.Match[str], extractor: str, group: int = 0
    ) -> Iterator[CandidateOccurrence]:
        value = m.group(group)
        cs = m.start(group)
        bs = len(text[:cs].encode("utf-8"))
        be = bs + len(value.encode("utf-8"))
        claimed.append((cs, cs + len(value)))
        yield _candidate(
            "secret", value, extractor=extractor, byte_start=bs, byte_end=be
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


def _walk_json_ids(
    node: object, pointer: str, out: list[CandidateOccurrence]
) -> None:
    """Recurse JSON, emitting an `identifier` candidate for `id` / `*_id` leaves.

    The value's byte offset into the body is not recoverable from the parsed
    structure (json.loads discards positions), so JSON-walk identifiers carry the
    RFC 6901 `json_pointer` for location instead of byte offsets.
    """

    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{pointer}/{_rfc6901_escape(str(key))}"
            if isinstance(value, str | int) and not isinstance(value, bool):
                if _ID_FIELD_RE.search(str(key)):
                    out.append(
                        _candidate(
                            "identifier",
                            str(value),
                            extractor="json-walk:id-fields_v1",
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


def extract_candidates(
    body_bytes: bytes,
    *,
    content_type: str,
) -> list[CandidateOccurrence]:
    """Run every value-candidate extractor over a decoded response body.

    `content_type` gates the JSON-walk id extractor (only on JSON bodies). Returns
    `output`-role candidate occurrences. Diagnostics (fingerprint, error excerpt)
    are NOT values — get them from `extract_diagnostics`. Non-UTF-8 bytes are
    decoded leniently so a binary-ish body still yields nothing here without
    crashing.
    """

    text = body_bytes.decode("utf-8", errors="replace")
    out: list[CandidateOccurrence] = []

    out.extend(
        _iter_regex(
            _INTERNAL_HOSTNAME_RE, text,
            kind="internal_hostname", extractor="regex:internal_hostname_v1",
        )
    )
    out.extend(
        _iter_regex(
            _PRIVATE_IPV4_RE, text,
            kind="ip_address", extractor="regex:rfc1918_ip_v1",
        )
    )
    out.extend(
        _iter_regex(_URL_RE, text, kind="url", extractor="regex:url_v1")
    )
    out.extend(
        _iter_regex(_EMAIL_RE, text, kind="email", extractor="regex:email_v1")
    )
    out.extend(
        _iter_regex(_UUID_RE, text, kind="identifier", extractor="regex:uuid_v1")
    )
    out.extend(_extract_secrets_from_body(text))

    base_mime = content_type.split(";", 1)[0].strip().lower()
    if base_mime == "application/json" or base_mime.endswith("+json"):
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            doc = None
        if doc is not None:
            _walk_json_ids(doc, "", out)

    return out


# --------------------------------------------------------------------------- #
# #16: request-input value candidates (the leak-to-input pivot, ADR-0023).
# --------------------------------------------------------------------------- #

# Secret-conventional parameter *names* (lowercased): a non-trivial value under
# one of these is treated as a `secret` input regardless of its shape (ADR-0015),
# so its raw value is hashed and never carried — mirroring the body-param
# suppression in `extraction/har.py`.
_SECRET_INPUT_NAMES: frozenset[str] = frozenset(
    (
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "client_secret",
        "private_key",
    )
)

# Anchored variants for classifying a *whole* parameter value (not a substring of
# a body). A query/body leaf value is the entire candidate, so we full-match.
_FULL_INTERNAL_HOSTNAME_RE = re.compile(rf"^(?:{_INTERNAL_HOSTNAME_RE.pattern})$", re.IGNORECASE)
_FULL_PRIVATE_IPV4_RE = re.compile(rf"^(?:{_PRIVATE_IPV4_RE.pattern})$")
_FULL_URL_RE = re.compile(rf"^(?:{_URL_RE.pattern})$", re.IGNORECASE)
_FULL_EMAIL_RE = re.compile(rf"^(?:{_EMAIL_RE.pattern})$")
_FULL_UUID_RE = re.compile(rf"^(?:{_UUID_RE.pattern})$", re.IGNORECASE)


def classify_input_kind(name: str, value: str) -> CandidateKind:
    """Classify a request-parameter value's `CandidateKind` (deterministic, #16).

    Secret-conventional names and JWT-shaped values classify as `secret` (their raw
    value is then hashed, never carried; ADR-0015). Otherwise the value is matched
    against the same shape rules the response extractors use, anchored to the whole
    value. Anything unclassified falls back to `identifier` — the high-cardinality
    catch-all that promotes only on cross-context signal (leak-to-input / multiplicity).
    """

    if name.lower() in _SECRET_INPUT_NAMES and value:
        return "secret"
    if _JWT_RE.fullmatch(value) or _AWS_ACCESS_KEY_RE.fullmatch(value) or (
        _STRIPE_KEY_RE.fullmatch(value)
    ):
        return "secret"
    if _FULL_INTERNAL_HOSTNAME_RE.match(value):
        return "internal_hostname"
    if _FULL_EMAIL_RE.match(value):
        return "email"
    if _FULL_PRIVATE_IPV4_RE.match(value):
        return "ip_address"
    if _FULL_URL_RE.match(value):
        return "url"
    if _FULL_UUID_RE.match(value):
        return "identifier"
    return "identifier"


def extract_input_candidate(
    name: str, value: str, *, extractor: str
) -> CandidateOccurrence:
    """Build one `input`-role `CandidateOccurrence` for a request-parameter value.

    The value is canonicalised through the same `hash_for` as response outputs, so a
    value that *leaked* in a response and is later *sent* as an input collapses to
    one `value_hash` (the leak-to-input pivot, ADR-0023 / ADR-0009). Secret-shaped
    inputs carry hash + length only, with an 8-char preview ONLY when the value is
    longer than the preview window — a short secret (e.g. a 7-char `password`)
    would otherwise be revealed in full by its own preview (ADR-0015); the raw
    value is always dropped.
    """

    kind = classify_input_kind(name, value)
    vh = hash_for(kind, value)
    if is_secret_kind(kind):
        return CandidateOccurrence(
            value_hash=vh,
            kind=kind,
            extractor=extractor,
            role="input",
            value=None,
            value_length=len(value.encode("utf-8")),
            value_preview=value[:8] if len(value) > 8 else None,
            parameter_name=name,
        )
    return CandidateOccurrence(
        value_hash=vh,
        kind=kind,
        extractor=extractor,
        role="input",
        value=value,
        parameter_name=name,
    )


def _error_excerpt(text: str) -> str:
    """First `_ERROR_EXCERPT_CHARS` chars of an HTML-stripped, whitespace-collapsed body."""

    stripped = _HTML_TAG_RE.sub(" ", text)
    collapsed = " ".join(stripped.split())
    return collapsed[:_ERROR_EXCERPT_CHARS]


def extract_diagnostics(
    body_bytes: bytes | None,
    headers: dict[str, str],
    *,
    status: int,
) -> ResponseDiagnostics:
    """Extract one-per-response diagnostics for inline observation properties.

    `headers` is a lowercased-name -> value map. The server fingerprint is the
    first present fingerprint header (`Server`, `X-Powered-By`, ...). The error
    excerpt is computed only on 5xx, over the decoded body. Both `None` when
    absent. These are never values / nodes (ADR-0023).
    """

    server_fingerprint: str | None = None
    for name in _FINGERPRINT_HEADERS:
        value = headers.get(name)
        if value:
            server_fingerprint = value
            break

    error_excerpt: str | None = None
    if 500 <= status <= 599 and body_bytes is not None:
        text = body_bytes.decode("utf-8", errors="replace")
        excerpt = _error_excerpt(text)
        error_excerpt = excerpt or None

    return ResponseDiagnostics(
        server_fingerprint=server_fingerprint, error_excerpt=error_excerpt
    )
