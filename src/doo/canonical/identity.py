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
import re
from collections.abc import Mapping
from typing import Literal
from urllib.parse import quote, unquote

from doo.canonical.value_objects import AuthContextCue, HostRef, Scheme
from doo.ids import (
    AuthContextId,
    EngagementId,
    HostId,
    ObservedValueId,
    ParameterId,
    PrincipalId,
    Sha256Hex,
    SourceId,
    TenantId,
    TrustBoundaryId,
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


def compute_cue_auth_hash(cue: AuthContextCue) -> Sha256Hex:
    """The AuthContext identity `auth_hash` for a (non-anonymous) cue.

    The hash is deterministic over the cue's already-hashed credential material,
    so two requests carrying the same credential collapse to one AuthContext.

    A pure-bearer cue's `auth_hash` equals its `bearer_token_hash` — which is
    `sha256("bearer:" || token)` — so a discovered bearer AuthContext shares the
    identity of the declared AuthContext set up from the same token (ADR-0017),
    and re-attaches rather than duplicating.

    For multi-credential or non-bearer cues, the identity is a sha256 over the
    sorted, kind-tagged hash material — still deterministic and secret-free.
    """

    if cue.is_anonymous:
        return compute_anonymous_auth_hash()

    parts: list[str] = []
    if cue.bearer_token_hash is not None:
        parts.append(f"bearer={cue.bearer_token_hash}")
    for ch in sorted(cue.cookie_session_hashes):
        parts.append(f"cookie={ch}")
    for name in sorted(cue.api_key_headers):
        parts.append(f"api_key={name.lower()}:{cue.api_key_headers[name]}")
    if cue.basic_auth_user_hash is not None:
        parts.append(f"basic_auth={cue.basic_auth_user_hash}")

    # Single bearer credential: identity *is* the bearer hash, so a discovered
    # bearer AuthContext converges onto the declared one from the same token.
    if parts == [f"bearer={cue.bearer_token_hash}"] and cue.bearer_token_hash is not None:
        return cue.bearer_token_hash

    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return Sha256Hex(digest)


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


def observed_value_id(
    engagement_id: EngagementId, value_hash: Sha256Hex
) -> ObservedValueId:
    """Stable `ObservedValue` node id over `(engagement_id, value_hash)` (ADR-0009).

    Matches the `ObservedValue` uniqueness constraint in `ontology/schema.py`, so
    the same value in one engagement converges to one node (the promotion dedup).
    """

    return ObservedValueId(_hash_tuple(engagement_id, value_hash))


def tenant_id(
    engagement_id: EngagementId, kind: str, normalized_value: str
) -> TenantId:
    """Stable `Tenant` node id over `(engagement_id, kind, normalized_value)` (ADR-0008).

    Matches the `Tenant` uniqueness constraint in `ontology/schema.py`, so the same
    tenant (e.g. `org_id=42`) converges to one node within an engagement.
    """

    return TenantId(_hash_tuple(engagement_id, kind, normalized_value))


def trust_boundary_id(
    engagement_id: EngagementId,
    kind: str,
    between_a_id: str,
    between_b_id: str,
) -> TrustBoundaryId:
    """Stable `TrustBoundary` node id over `(engagement_id, kind, between_a_id, between_b_id)`.

    Matches the `TrustBoundary` uniqueness constraint in `ontology/schema.py`
    (ADR-0002 / ADR-0008 / ADR-0039). The boundary is an **undirected** pair, so
    callers must pass the two endpoint node ids in a canonical order
    (`min`/`max`); `between_a_id` is the lexicographically smaller. This collapses
    the (a, b) and (b, a) orderings to one node per unordered pair.
    """

    return TrustBoundaryId(
        _hash_tuple(engagement_id, kind, between_a_id, between_b_id)
    )


def anonymous_principal_identity_key() -> str:
    """The `identity_key` of the anonymous Principal singleton (CONTEXT.md)."""

    return "anonymous"


def principal_id(engagement_id: EngagementId, identity_key: str) -> PrincipalId:
    """Stable `Principal` node id over `(engagement_id, identity_key)` (ADR-0010)."""

    return PrincipalId(_hash_tuple(engagement_id, identity_key))


def declared_principal_identity_key(label: str) -> str:
    """The `identity_key` of a declared Principal — its manual label (ADR-0010).

    Declared Principals key on the tester-set label directly so re-loading the
    same YAML converges to the same node.
    """

    return f"declared:{label}"


# Identity claims that can *key* a discovered Principal, account-unique first
# (ADR-0030). The first present, scalar, non-empty claim wins. The list spans all
# sources (JWT cue, response header, self-endpoint body, SSO id_token / SAML) —
# the *source* is provenance only; identity is the claim/value. Every listed claim
# is account-unique per user (issuer-scoped for `sub`), so keying on any of them is
# merge-safe. `email` is LAST: it is person-level (one human can own several
# accounts), so it keys only as a last resort and is otherwise an alias. A
# `transient` SAML NameID is per-session and is therefore NOT in this list (it
# never keys); a `persistent`/`emailAddress` NameID arrives pre-mapped to one of
# these claim names by the SAML extractor (ADR-0031), so it needs no special case
# here.
_IDENTITY_CLAIM_PRIORITY: tuple[str, ...] = (
    "sub",
    "uid",
    "user_id",
    "uuid",
    "_id",
    "username",
    "uname",
    "preferred_username",
    "email",
)


# Source-qualifier prefixes that the tester may attach to `auth.identity_key`
# (ADR-0032). Stripped to a bare claim name before use — full source routing is
# out of scope for this ADR.
_SOURCE_PREFIXES: tuple[str, ...] = ("claim:", "header:", "body:")


def _strip_source_prefix(name: str) -> str:
    """Strip an optional source-qualifier prefix from an `auth.identity_key` value.

    ``claim:_id`` → ``_id``, ``header:x-user-id`` → ``x-user-id``,
    ``body:accountRef`` → ``accountRef``. A bare name is returned unchanged.
    Pure helper so the resolver stays readable.
    """

    for prefix in _SOURCE_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _scalar_claim(claims: Mapping[str, object], name: str) -> str | None:
    """The normalised scalar string value of one claim, or ``None``.

    Scalar (str/int, not bool), stripped, non-empty. ``email`` is lowercased
    (case-insensitive in practice; ADR-0027). Shared by the discovered-key
    resolver and the declared↔discovered claim matcher (ADR-0048).
    """

    raw = claims.get(name)
    if not isinstance(raw, str | int) or isinstance(raw, bool):
        return None
    value = str(raw).strip()
    if not value:
        return None
    if name == "email":
        value = value.lower()
    return value


# Sentinel returned by `match_identity_claims` when the highest-priority claim
# present on both sides DISAGREES — the two credentials provably belong to
# different actors, so the caller must not fall through to a weaker match
# against THIS declared AuthContext (merge-safety, ADR-0048).
DISAGREE: Literal["disagree"] = "disagree"

IdentityClaimMatch = tuple[str, str]


def match_identity_claims(
    a: Mapping[str, object],
    b: Mapping[str, object],
    *,
    preferred_claim: str | None = None,
) -> IdentityClaimMatch | Literal["disagree"] | None:
    """Walk-and-intersect two `identity_claims` dicts (ADR-0048 priority-0).

    Walks the ADR-0030 claim priority — `preferred_claim` (ADR-0032,
    source-prefix stripped) first when set, then `_IDENTITY_CLAIM_PRIORITY`
    (`sub` issuer-scoped → … → `email` last). For each claim K in order:

    - both sides carry K (scalar, non-empty) and the values **agree** →
      return ``(K, value)`` — same actor by the strongest shared signal.
    - both carry K and values **disagree** → return ``DISAGREE`` — provably
      different actors; the caller stops considering this pair (no fall-through
      to a weaker claim that might coincidentally agree).
    - only one side carries K → continue to the next claim.

    Returns ``None`` when no claim is present on both sides — undecidable from
    claims alone; the caller falls through to `known_signals` (the opaque-token
    fallback) or the synthetic key.

    For ``sub``: when both sides also carry ``iss`` and the issuers disagree,
    the result is ``DISAGREE`` even if the ``sub`` values match (OIDC ``sub`` is
    unique only within its issuer; ADR-0030/0031). A missing ``iss`` on either
    side is treated as compatible (single-issuer engagement).

    Pure + deterministic; the same function backs the resolve-time forward match
    (`_match_declared_principal`) and the flush/loader retroactive sweep
    (`reconcile_discovered_to_declared`), so both directions reconcile via the
    same priority — the CONTEXT.md "declared and discovered reconcile via the
    same priority" property made literal.
    """

    order: list[str] = []
    if preferred_claim is not None:
        order.append(_strip_source_prefix(preferred_claim))
    for claim in _IDENTITY_CLAIM_PRIORITY:
        if claim not in order:
            order.append(claim)

    for claim in order:
        va = _scalar_claim(a, claim)
        vb = _scalar_claim(b, claim)
        if va is None or vb is None:
            continue
        if claim == "sub":
            iss_a = _scalar_claim(a, "iss")
            iss_b = _scalar_claim(b, "iss")
            if iss_a is not None and iss_b is not None and iss_a != iss_b:
                return DISAGREE
        if va == vb:
            return claim, va
        return DISAGREE
    return None


def discovered_principal_identity_key(
    auth_hash: Sha256Hex,
    *,
    identity_claims: Mapping[str, object] | None = None,
    preferred_claim: str | None = None,
) -> str:
    """`identity_key` for a discovered (undeclared) Principal (ADR-0010 step 5; ADR-0030).

    Source-agnostic: keyed on `discovered:{claim}:{value}` over the first present of
    `_IDENTITY_CLAIM_PRIORITY` (`sub` -> ... -> `email` last, `email` lowercased).
    `sub` is **issuer-scoped** when an `iss` claim is present
    (`discovered:sub:{iss}:{sub}`) — OIDC `sub` is unique only within its issuer.

    When `preferred_claim` is set (from `auth.identity_key`, ADR-0032) **and** that
    claim is present, scalar, and non-empty in `identity_claims`, it overrides the
    heuristic priority list. The key is formed on `discovered:{claim}:{value}` with
    the same email-lowercasing and sub-issuer-scoping rules. When the declared claim
    is absent, the function falls back to the heuristic priority without penalty —
    absence is not punished into a synthetic. Any source-qualifier prefix
    (``claim:``, ``header:``, ``body:``) is stripped before use.

    The SAME scheme is produced at resolve-time (from a credential's decoded JWT
    claims) and at flush-time (from a response's observed identities), so a bearer
    `sub` and the same actor's `/me` `sub` MERGE on the identity key into one
    Principal — no explicit cross-path merge (ADR-0030, superseding the split
    `discovered:jwt:*` / `discovered:observed:*` namespaces). A user's reissued
    tokens — same stable claim, different per-token `auth_hash` — collapse to one
    discovered Principal. Tagging by claim name keeps the key honest: identities
    exposing *different* claims fragment rather than wrongly merge. Falls back to
    the per-credential `auth_hash` only when no listed claim is present (an opaque
    / non-JWT credential, no observed identity). Pure + deterministic, so re-ingest
    converges.
    """

    if identity_claims:
        # ADR-0032: preferred_claim overrides the priority when present + scalar + non-empty.
        if preferred_claim is not None:
            claim = _strip_source_prefix(preferred_claim)
            raw = identity_claims.get(claim)
            if isinstance(raw, str | int) and not isinstance(raw, bool):
                value = str(raw).strip()
                if value:
                    if claim == "email":
                        value = value.lower()
                    if claim == "sub":
                        iss = identity_claims.get("iss")
                        if isinstance(iss, str) and iss.strip():
                            return f"discovered:sub:{iss.strip()}:{value}"
                    return f"discovered:{claim}:{value}"
            # Declared claim absent → fall through to heuristic.

        for claim in _IDENTITY_CLAIM_PRIORITY:
            raw = identity_claims.get(claim)
            # Scalar identity claims only; bool is an int subclass but never an id.
            if not isinstance(raw, str | int) or isinstance(raw, bool):
                continue
            value = str(raw).strip()
            if not value:
                continue
            if claim == "email":
                value = value.lower()
            if claim == "sub":
                # OIDC: `sub` is unique only within its issuer (`iss`) — it can even
                # be pairwise per client. Scope it by `iss` so two IdPs that mint the
                # same `sub` for different people never merge. No `iss` → bare `sub`
                # (a single-issuer token), backward-compatible.
                iss = identity_claims.get("iss")
                if isinstance(iss, str) and iss.strip():
                    return f"discovered:sub:{iss.strip()}:{value}"
            return f"discovered:{claim}:{value}"
    return f"discovered:{auth_hash}"


# The synthetic discovered key is `discovered:{auth_hash}` — the per-credential
# fallback (64 lowercase hex chars after the prefix, no claim segment). A
# claim-keyed discovered Principal is `discovered:{claim}:{value}` and always
# carries a further `:` separator, so the two are distinguishable by shape alone.
_SYNTHETIC_KEY_RE = re.compile(r"^discovered:[0-9a-f]{64}$")


def is_synthetic_discovered_key(identity_key: str) -> bool:
    """True iff `identity_key` is the synthetic `discovered:{auth_hash}` form (ADR-0030).

    Distinguishes a low-confidence per-credential discovered Principal (safe to
    re-key on a stronger observed identity) from a claim-keyed / declared one
    (never re-keyed by a weaker signal — the merge-safety invariant).
    """

    return _SYNTHETIC_KEY_RE.match(identity_key) is not None
