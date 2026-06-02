"""Deterministic canonicalisation + identity helpers (slice-1 T2, deep module A).

Pure functions — no I/O, no graph, no Redis. These implement the CONTEXT.md
"Identity rules" section so that L2 (HAR parser) and L3 (entity resolution)
share one canonical representation per concept.

What lives here:

- `canonicalize_host(scheme, host, port)` -> `HostRef`. Host identity per
  CONTEXT.md: lowercase hostname, ToASCII for IDN, strip trailing dot, strip the
  scheme-default port (`:443` https / `:80` http), keep non-default ports, keep
  IP literals distinct from hostnames.
- `canonicalize_path(path)` -> the canonical concrete path: strip trailing slash
  (except root), RFC-3986 percent-encoding normalisation, **preserve path case**.
  The raw concrete path is still what gets stored on the RequestObservation; the
  canonical concrete path is what templating (T3, `canonical/templating.py`)
  runs over to infer an Endpoint's `path_template`.
- `compute_auth_hash(token_kind, token_value)` -> `auth_hash` per CONTEXT.md
  AuthContext identity = `sha256(token_kind || ":" || token_value)`. The
  anonymous singleton uses a fixed sentinel token value.
- `derive_har_source_id(entry_index, started_at)` -> the per-entry stable
  `source_id` for HAR ingestion (ADR-0016): `f"{entry_index}|{started_at}"`.

Node-id composition helpers (`host_id`, `endpoint_id`, ...) live here too: L3
needs a stable string id per node, derived deterministically from the identity
tuple, so re-delivery converges to the same node.
"""

from __future__ import annotations

import hashlib
import ipaddress
from urllib.parse import quote, unquote

from doo.canonical.value_objects import HostRef, Scheme
from doo.ids import (
    AuthContextId,
    EngagementId,
    HostId,
    ParameterId,
    PrincipalId,
    Sha256Hex,
    SourceId,
)

# Token kinds permitted in an auth_hash, per CONTEXT.md AuthContext identity.
TokenKind = str  # one of {bearer, cookie, api_key, basic_auth, anonymous}

# Fixed sentinel value for the anonymous AuthContext. The anonymous singleton is
# one node per engagement (CONTEXT.md / ADR-0010), so its hash is a constant.
ANONYMOUS_TOKEN_KIND = "anonymous"
ANONYMOUS_TOKEN_VALUE = ""  # nothing to hash; the kind alone identifies it.


def _is_ip_literal(host: str) -> bool:
    """True if `host` is an IPv4 / IPv6 literal (kept distinct from hostnames)."""

    candidate = host
    # Allow bracketed IPv6 literals (`[::1]`).
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def canonicalize_host(scheme: str, host: str, port: int | None) -> HostRef:
    """Canonicalise `(scheme, host, port)` into a `HostRef` (CONTEXT.md identity).

    - hostname lowercased and IDN-encoded to ASCII (ToASCII); trailing dot
      stripped,
    - default port for the scheme dropped (`None`); non-default kept,
    - IP literals are flagged and never lowercased through IDN.

    Raises `ValueError` for an unsupported scheme so bad input fails fast at the
    parser boundary rather than producing a junk Host.
    """

    scheme_lower = scheme.lower()
    if scheme_lower not in ("http", "https"):
        raise ValueError(f"unsupported scheme {scheme!r}; slice-1 supports http/https only")
    typed_scheme: Scheme = "https" if scheme_lower == "https" else "http"

    is_ip = _is_ip_literal(host)

    if is_ip:
        # Normalise the IP form (e.g. compress IPv6) but do not IDN/lowercase.
        bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        canonical_hostname = str(ipaddress.ip_address(bare))
    else:
        # Strip trailing dot, lowercase, ToASCII (IDN -> punycode).
        h = host.rstrip(".").lower()
        if h == "":
            raise ValueError("host must be non-empty")
        try:
            canonical_hostname = h.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            # Already-ASCII hostnames with characters `idna` rejects (e.g. an
            # underscore in a label) fall back to the lowercased form.
            canonical_hostname = h

    default_port = 443 if typed_scheme == "https" else 80
    canonical_port = None if (port is None or port == default_port) else port

    return HostRef(
        scheme=typed_scheme,
        canonical_hostname=canonical_hostname,
        port=canonical_port,
        is_ip_literal=is_ip,
    )


def canonicalize_path(path: str) -> str:
    """Canonicalise a concrete request path (CONTEXT.md "Canonicalization").

    - ensure it is absolute (leading `/`),
    - strip a single trailing slash (but keep the root `/`),
    - RFC-3986 percent-encoding normalisation (decode then re-encode so
      equivalent encodings collapse),
    - **preserve path case** — backends may be case-sensitive; case differences
      are a normalisation-discrepancy signal, not an identity merge.

    The query string is NOT part of the path identity (query inputs are
    Parameters). Callers strip it before calling.
    """

    if not path.startswith("/"):
        path = "/" + path

    # Percent-encoding normalisation, segment by segment so `/` separators are
    # preserved. Decode each segment fully, then re-encode with a stable safe
    # set. `quote` with `safe=""` re-encodes reserved sub-delims consistently.
    segments = path.split("/")
    normalised = "/".join(quote(unquote(seg), safe="~") for seg in segments)

    # Strip a single trailing slash, but never reduce the root to empty.
    if len(normalised) > 1 and normalised.endswith("/"):
        normalised = normalised[:-1]

    return normalised


def compute_auth_hash(token_kind: str, token_value: str) -> Sha256Hex:
    """`sha256(token_kind || ":" || token_value)` per CONTEXT.md AuthContext id.

    The raw `token_value` is never persisted; only this hash. For the anonymous
    singleton, use `compute_anonymous_auth_hash()`.
    """

    digest = hashlib.sha256(f"{token_kind}:{token_value}".encode()).hexdigest()
    return Sha256Hex(digest)


def compute_anonymous_auth_hash() -> Sha256Hex:
    """The fixed `auth_hash` of the anonymous AuthContext singleton."""

    return compute_auth_hash(ANONYMOUS_TOKEN_KIND, ANONYMOUS_TOKEN_VALUE)


def derive_har_source_id(entry_index: int, started_at: str) -> SourceId:
    """Per-entry stable `source_id` for HAR ingestion (ADR-0016).

    `f"{entry_index}|{startedDateTime}"`. Stable across re-extraction of the same
    blob, so L3 idempotency (`commit:{eng}:{kind}:{source}:{source_id}`) collapses
    re-delivered events for the same HAR entry.
    """

    return SourceId(f"{entry_index}|{started_at}")


# ---------------------------------------------------------------------------
# Deterministic node-id composition. L3 needs a stable string id per node so
# re-delivery converges. Each id is a sha256 over the engagement-scoped identity
# tuple, matching the uniqueness constraints in `ontology/schema.py`.
# ---------------------------------------------------------------------------


def _hash_tuple(*parts: str) -> str:
    """sha256 over a `|`-joined identity tuple (order-significant)."""

    joined = "|".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def host_id(engagement_id: EngagementId, host: HostRef) -> HostId:
    """Stable `Host` node id over `(engagement_id, scheme, hostname, port)`."""

    port_part = "" if host.port is None else str(host.port)
    return HostId(
        _hash_tuple(engagement_id, host.scheme, host.canonical_hostname, port_part)
    )


def endpoint_id(
    engagement_id: EngagementId, method: str, host_node_id: HostId, path_template: str
) -> str:
    """Stable `Endpoint` node id over `(engagement_id, method, host_id, path_template)`."""

    return _hash_tuple(engagement_id, method.upper(), host_node_id, path_template)


def parameter_id(
    engagement_id: EngagementId, endpoint_node_id: str, location: str, name: str
) -> ParameterId:
    """Stable `Parameter` node id over `(engagement_id, endpoint_id, location, name)`.

    Matches the `Parameter` uniqueness constraint in `ontology/schema.py`. A
    Parameter is an emergent L3 aggregate keyed to one Endpoint, so the
    Endpoint's node id is part of its identity (CONTEXT.md / ADR-0017).
    """

    return ParameterId(_hash_tuple(engagement_id, endpoint_node_id, location, name))


def auth_context_id(engagement_id: EngagementId, auth_hash: Sha256Hex) -> AuthContextId:
    """Stable `AuthContext` node id over `(engagement_id, auth_hash)`."""

    return AuthContextId(_hash_tuple(engagement_id, auth_hash))


def anonymous_principal_identity_key() -> str:
    """The `identity_key` of the anonymous Principal singleton (CONTEXT.md)."""

    return "anonymous"


def principal_id(engagement_id: EngagementId, identity_key: str) -> PrincipalId:
    """Stable `Principal` node id over `(engagement_id, identity_key)` (ADR-0010)."""

    return PrincipalId(_hash_tuple(engagement_id, identity_key))
