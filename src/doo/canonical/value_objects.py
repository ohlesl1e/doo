"""Small canonical value objects used inside L2 events.

These are not graph nodes; they're embedded shapes the layer contracts share.
"""

from __future__ import annotations

import re
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.ids import Sha256Hex

Scheme = Literal["http", "https"]

# Lowercase hex sha256 (64 chars).
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class HostRef(BaseModel):
    """A canonicalised host reference.

    Identity rule per CONTEXT.md: lowercase hostname, ToASCII for IDN, strip
    trailing dot, strip default port (`:443` https / `:80` http), keep
    non-default ports. IP literals stay distinct from hostnames.

    `port` is `None` when the observed port is the scheme default; explicit when
    non-default. This is the source of truth that L3 uses to compose a `Host` id.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    scheme: Scheme
    canonical_hostname: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    is_ip_literal: bool = False

    @model_validator(mode="after")
    def _canonical(self) -> Self:
        if self.canonical_hostname != self.canonical_hostname.lower() and not self.is_ip_literal:
            raise ValueError("canonical_hostname must be lowercased (per CONTEXT.md identity rule)")
        if self.canonical_hostname.endswith("."):
            raise ValueError("canonical_hostname trailing dot must be stripped")
        # Default-port stripping.
        default = 443 if self.scheme == "https" else 80
        if self.port == default:
            raise ValueError(
                f"port must be None for scheme default ({default}); got explicit {self.port}"
            )
        return self


class BlobRef(BaseModel):
    """Object-storage reference for a request/response body or whole-blob upload.

    Per ADR-0015, bodies live in object storage; the graph holds only hashes
    and metadata. L2 events carry `BlobRef`s; L3 stores the hash and metadata
    on graph properties.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    key: str = Field(min_length=1)
    sha256: Sha256Hex
    content_type: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    encoding: str | None = None

    @model_validator(mode="after")
    def _sha256_format(self) -> Self:
        if not _SHA256_HEX_RE.match(self.sha256):
            raise ValueError("sha256 must be 64 lowercase hex chars")
        return self


class AuthContextCue(BaseModel):
    """Per-request auth fingerprint emitted by L2.

    Hashes and parsed-but-unverified claims only — never raw tokens, per
    ADR-0015 ("L2 is the secrets-hashing boundary"). The dispatcher reads the
    raw bearer token from a separate secret store keyed by AuthContext id; the
    graph and any downstream stream see only hashes.

    `is_anonymous = True` carries the singleton-anonymous semantics from
    ADR-0010 — one anonymous AuthContext per Engagement.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    is_anonymous: bool
    bearer_token_hash: Sha256Hex | None = None
    # Cookie session values, one hash per cookie name (sorted by name).
    cookie_session_hashes: tuple[Sha256Hex, ...] = ()
    # API-key-bearing headers: header name -> hash of its value. Names are
    # non-secret; the value hash is the secret-safe representation (ADR-0015).
    api_key_headers: dict[str, Sha256Hex] = Field(default_factory=dict)
    basic_auth_user_hash: Sha256Hex | None = None
    # JWT decoded *without verification* (planner-side claim peek, not a trust
    # decision), from the primary credential — the bearer `Authorization` JWT, or
    # (ADR-0027) a JWT session cookie. Empty dict when absent / not parseable.
    identity_claims: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _anon_vs_credentials(self) -> Self:
        carries_creds = (
            self.bearer_token_hash is not None
            or self.cookie_session_hashes
            or self.api_key_headers
            or self.basic_auth_user_hash is not None
            or self.identity_claims
        )
        if self.is_anonymous and carries_creds:
            raise ValueError("anonymous AuthContextCue must not carry any credential hashes")
        if not self.is_anonymous and not carries_creds:
            raise ValueError("non-anonymous AuthContextCue must carry at least one credential hash")
        # All hashes must be sha256-hex shaped.
        all_hashes = (
            self.bearer_token_hash,
            self.basic_auth_user_hash,
            *self.cookie_session_hashes,
            *self.api_key_headers.values(),
        )
        for h in all_hashes:
            if h is not None and not _SHA256_HEX_RE.match(h):
                raise ValueError("auth hash must be 64 lowercase hex chars")
        return self


class ObservedIdentity(BaseModel):
    """A single claim-tagged actor identity revealed by a *response* (ADR-0030).

    Extracted at L2 from a response the actor's request elicited — an identity
    response header, or a self-endpoint body claim — and correlated at flush back
    to the request's `AuthContext`. `claim` is the **semantic id kind**
    (`sub`/`uid`/`_id`/`username`/`email`/`nameid`/the identity header name…), so
    a body `_id` and a body `email` stay distinct identities rather than both
    collapsing to one `signal="body"`. The *source* of the identity is provenance
    only; the unified key resolver (`discovered_principal_identity_key`) turns the
    claim/value into the source-agnostic `discovered:{claim}:{value}` key, so the
    same actor's identity from any source converges (ADR-0030). `value` must be
    globally unique per user for an account-unique claim (the merge-safety
    requirement); `email` is person-level (last-resort key, always an alias).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    claim: str = Field(min_length=1)
    value: str = Field(min_length=1)
