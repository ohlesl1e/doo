"""`EngagementConfig` Pydantic model and `Scope.content_hash` computation.

Per ADR-0012 setup declares only tester-side facts. T1 covers Engagement
metadata + Scope rules + kill-switch config. Declared Principals (the
`principals:` block) ship in T4 — intentionally absent here.

Per ADR-0017 the Scope identity is `sha256(canonicalized(rule_document))`. The
canonicalisation is "sort all keys, sort list items where order does not
matter, no surrounding whitespace, no comments." The canonicaliser lives here
because it's also what the loader uses to detect material vs cosmetic diffs
(ADR-0019).
"""

from __future__ import annotations

import hashlib
import json
from typing import Self

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from doo.events.slice4 import PayloadClass
from doo.ids import EngagementId, EngagementName, ScopeContentHash

PathPattern = str  # Regex-or-glob pattern; canonical Scope rule format.

HttpMethod = str  # Kept open here; OPA's data bundle constrains it strictly.


def _list_to_tuple(v: Any) -> Any:
    """Coerce YAML sequences (lists) into tuples at the config boundary.

    The config models are the external-YAML edge: strict mode is kept for
    internal layer contracts, but YAML's `safe_load` yields lists where our
    frozen models declare immutable tuples. Coercing here keeps the immutability
    guarantee without making the whole model lax.
    """

    return tuple(v) if isinstance(v, list) else v


class TimeWindow(BaseModel):
    """Active hours for testing. Both bounds inclusive.

    Times are wall-clock hours in UTC (`hour ∈ [0, 23]`) and days are ISO
    weekday numbers (1=Monday..7=Sunday). A missing time window means "always."
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    start_hour_utc: int = Field(ge=0, le=23)
    end_hour_utc: int = Field(ge=0, le=23)
    weekdays: tuple[int, ...] = Field(default=(1, 2, 3, 4, 5, 6, 7))

    _coerce_weekdays = field_validator("weekdays", mode="before")(_list_to_tuple)

    @model_validator(mode="after")
    def _weekday_range(self) -> Self:
        for d in self.weekdays:
            if d < 1 or d > 7:
                raise ValueError("weekdays use ISO 1..7 (Mon..Sun)")
        if len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError("weekdays must be unique")
        return self


class RateLimit(BaseModel):
    """Per-host rate limit. Stateful guards live in the dispatcher (ADR-0003).

    Carried on `Scope` so the OPA `data` bundle can include it.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    requests_per_second: float = Field(gt=0)
    burst: int = Field(ge=1)


class ScopeRules(BaseModel):
    """The Scope rule document. Hashed for `Scope.content_hash` (ADR-0017).

    `host_patterns` are the allowlist (regex). `payload_class_denylist` is the
    program's prohibited payload classes (per CONTEXT.md PayloadClass).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    host_patterns: tuple[str, ...] = Field(min_length=1)
    allowed_methods: tuple[HttpMethod, ...] = Field(min_length=1)
    allowed_path_patterns: tuple[PathPattern, ...] = Field(min_length=1)
    payload_class_denylist: tuple[PayloadClass, ...] = ()
    rate_limit: RateLimit | None = None
    time_window: TimeWindow | None = None
    required_headers: tuple[str, ...] = ()
    notes: str | None = None  # cosmetic; ignored for content hash

    _coerce_sequences = field_validator(
        "host_patterns",
        "allowed_methods",
        "allowed_path_patterns",
        "payload_class_denylist",
        "required_headers",
        mode="before",
    )(_list_to_tuple)


class KillSwitchConfig(BaseModel):
    """Kill-switch lease configuration.

    Per ARCHITECTURE.md L5 the lease lives in Redis, keyed
    `engagement:{id}:lease`. TTL default 60s; refresh 30s. Production targets
    drop both. T1 does not yet implement the keepalive process; it ships in T7.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    lease_ttl_seconds: int = Field(default=60, ge=5)
    refresh_interval_seconds: int = Field(default=30, ge=1)

    @model_validator(mode="after")
    def _refresh_lt_ttl(self) -> Self:
        if self.refresh_interval_seconds >= self.lease_ttl_seconds:
            raise ValueError(
                "refresh_interval_seconds must be < lease_ttl_seconds "
                "(otherwise the lease expires before each refresh)"
            )
        return self


class EngagementMeta(BaseModel):
    """Engagement-root metadata. `id` is immutable (ADR-0019)."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    id: EngagementId
    name: EngagementName
    description: str | None = None
    # Engagement-level time window: when this campaign is *active*. Distinct
    # from `ScopeRules.time_window`, which is the program's allowed hours.
    time_window: TimeWindow | None = None


class EngagementConfig(BaseModel):
    """The whole YAML file, validated."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    engagement: EngagementMeta
    scope: ScopeRules
    kill_switch: KillSwitchConfig = Field(default_factory=KillSwitchConfig)


# ---------------------------------------------------------------------------
# Canonicalisation: deterministic Scope.content_hash and loader diffing.
# ---------------------------------------------------------------------------


def _canonicalise_scope(rules: ScopeRules) -> str:
    """Deterministic JSON-string canonicalisation of the rule document.

    Cosmetic-only fields (`notes`) are stripped before hashing — a change in
    notes is not a material rule change. Tuples are converted to sorted lists
    where the order is not semantic (host patterns, methods, payload classes,
    required headers). Path patterns keep declaration order — order matters
    for "first match wins" semantics in path-template work.
    """

    body = {
        "host_patterns": sorted(rules.host_patterns),
        "allowed_methods": sorted(rules.allowed_methods),
        "allowed_path_patterns": list(rules.allowed_path_patterns),
        "payload_class_denylist": sorted(rules.payload_class_denylist),
        "rate_limit": rules.rate_limit.model_dump() if rules.rate_limit else None,
        "time_window": rules.time_window.model_dump() if rules.time_window else None,
        "required_headers": sorted(rules.required_headers),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def compute_scope_content_hash(rules: ScopeRules) -> ScopeContentHash:
    """`sha256(canonicalized(rule_document))` per ADR-0017."""

    canonical = _canonicalise_scope(rules)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return ScopeContentHash(digest)
