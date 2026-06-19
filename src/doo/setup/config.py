"""`EngagementConfig` Pydantic model and `Scope.content_hash` computation.

Per ADR-0012 setup declares only tester-side facts: Engagement metadata, Scope
rules, kill-switch config, and (T4) declared `Principal`s — the test accounts the
tester controls, their `AuthContext` token material (as env-var references, never
inline), and any identifying signals the tester observed from warm-up traffic
against their own accounts.

Per ADR-0017 the Scope identity is `sha256(canonicalized(rule_document))`. The
canonicalisation is "sort all keys, sort list items where order does not
matter, no surrounding whitespace, no comments." The canonicaliser lives here
because it's also what the loader uses to detect material vs cosmetic diffs
(ADR-0019).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from doo.events.slice4 import PayloadClass
from doo.ids import EngagementId, EngagementName, ScopeContentHash

PathPattern = str  # Glob/segment pattern; canonical Scope rule format (ADR-0035).

HttpMethod = str  # Kept open here; OPA's data bundle constrains it strictly.


# ---------------------------------------------------------------------------
# Scope-pattern syntax guard (ADR-0035): patterns are glob/segment, NOT regex.
#
# `is_in_scope` (src/doo/policy/scope.py) matches host patterns as exact /
# single-leading-`*.` glob and path patterns segment-wise (`*` = one segment,
# trailing `**` = the rest). A regex pattern (`^.*$`, `^/.*$`) is matched
# *literally* and so matches nothing real — a silent false-negative (#55). We
# reject regex at load so the failure is loud and actionable instead.
#
# The rejected set is the regex-only metacharacters that are NOT meaningful glob
# syntax. We must NOT reject the characters a legitimate glob/segment pattern
# uses:
#   - `*`        — glob wildcard (`*.example.com`, `*` segment, trailing `**`)
#   - `.`        — hostname label separator (`api.example.com`)
#   - `/`        — path segment separator
#   - `{` `}`    — `{param}` path-template placeholder a `*` segment matches
#   - `:` `-`    — port pin (`:8443`), scheme (`https://`), hostname hyphens
# Rejected (regex-only, never valid glob here):
#   ^  $        — anchors
#   [ ]         — character class
#   ( )         — group
#   |           — alternation
#   +  ?        — quantifiers
#   \           — escape
#   .*          — the dot-star regex idiom (a bare `.` is fine; `.*` is not, it
#                 is the single most common regex-scope mistake and unambiguous)
# ---------------------------------------------------------------------------

# Single regex-only metacharacters that are never valid glob/segment syntax.
_REGEX_ONLY_CHARS = frozenset("^$[]()|+?\\")
# Multi-char regex idiom that uses otherwise-legal glob chars (`.` and `*`) but
# is unambiguously regex when adjacent.
_REGEX_DOT_STAR = ".*"


def _reject_regex_pattern(pattern: str, *, field: str) -> None:
    """Raise if `pattern` contains regex-only metacharacters (ADR-0035).

    Glob/segment is the one canonical scope syntax; a regex pattern silently
    matches nothing (#55), so we fail fast at load with an actionable error
    naming the offending pattern and the disallowed token.
    """

    offending = sorted({ch for ch in pattern if ch in _REGEX_ONLY_CHARS})
    if _REGEX_DOT_STAR in pattern:
        offending.append(_REGEX_DOT_STAR)
    if offending:
        tokens = ", ".join(repr(t) for t in offending)
        raise ValueError(
            f"{field} pattern {pattern!r} looks like regex, but Scope patterns are "
            f"glob/segment, not regex (ADR-0035). Disallowed token(s): {tokens}. "
            f"Use glob instead, e.g. host '*.example.com' or an exact host, and "
            f"path '/**' (all paths) or '/users/*' (one segment)."
        )


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

    Patterns are **glob/segment, not regex** (ADR-0035) — the exact syntax
    `is_in_scope` (`src/doo/policy/scope.py`) and the future Rego evaluate:

    - `host_patterns` — the host allowlist. Each entry is an exact host
      (case-insensitive, e.g. ``api.example.com`` or an IP literal
      ``172.30.146.0``) or a single leading ``*.`` wildcard
      (``*.example.com`` matches sub-domains, not the apex). A pattern may pin a
      scheme (``https://host``) and/or a port (``host:8443``). IP literals match
      exact patterns only, never a wildcard.
    - `allowed_path_patterns` — segment-wise path globs. A ``*`` segment matches
      exactly one path-template segment (including a ``{param}`` placeholder); a
      trailing ``**`` (i.e. ``/**``) matches all remaining segments; literal
      segments match exactly. ``/users/*`` matches ``/users/{user_id}``;
      ``/**`` matches every path.
    - `payload_class_denylist` — the program's prohibited payload classes (per
      CONTEXT.md PayloadClass).

    Regex is rejected at load (``^``, ``$``, ``.*``, ``[``, ``(``, ``|`` …): a
    regex pattern matches nothing under the glob matcher and would silently
    return empty coverage (#55), so the loader fails fast naming the pattern.
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

    @model_validator(mode="after")
    def _patterns_are_glob_not_regex(self) -> Self:
        """Reject regex host/path patterns at load (ADR-0035, #55)."""

        for p in self.host_patterns:
            _reject_regex_pattern(p, field="host")
        for p in self.allowed_path_patterns:
            _reject_regex_pattern(p, field="path")
        return self


class KillSwitchConfig(BaseModel):
    """Kill-switch lease configuration.

    Per ARCHITECTURE.md L5 the lease lives in Redis, keyed
    `engagement:{id}:lease`. TTL default 60s; refresh 30s. Production targets
    drop both. T7 implements the keepalive process that refreshes it.

    `backend` is a forward-compatible knob: the mechanism (Redis) is reversible
    per ARCHITECTURE.md (file lock / etcd / watchdog all satisfy the trust
    split). Slice 1 only implements `"redis"`.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    backend: Literal["redis"] = "redis"
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


# ---------------------------------------------------------------------------
# Declared Principals (T4, ADR-0010 + ADR-0012).
# ---------------------------------------------------------------------------

# Auth schemes a tester may declare for a Principal's AuthContext. These are the
# token *kinds* understood by the L2 secrets-hashing boundary (ADR-0015) and the
# `auth_hash` identity rule (ADR-0017).
AuthContextKind = Literal["bearer", "cookie", "api_key", "basic_auth"]

# `${ENV_VAR}` reference. Tokens never appear inline per ADR-0012 — only the name
# of the environment variable the loader resolves at load time.
_ENV_REF_RE = re.compile(r"^\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}$")

# Stable kebab-case label for a declared Principal (the manual `identity_key`).
_LABEL_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# Labels reserved for system-generated principals; a declared label may not
# collide. `anon` is the anonymous-singleton display label the coverage layer
# emits (`_principal_label`); letting a tester declare it would make the two
# indistinguishable in C2/C2b output and `--as/--not-as` pins.
_RESERVED_LABELS = frozenset({"anon"})


# Token-refresh mechanism for the auth-helper sibling process (ADR-0014, S6).
RefreshMechanism = Literal["command", "oauth_refresh", "http"]


class RefreshConfig(BaseModel):
    """How the auth-helper rotates one declared `AuthContext` (ADR-0014, #91).

    The helper — NEVER the dispatcher — acts on this. Refresh credentials live in
    the **helper's** env (referenced by var name here), never inline, never in the
    dispatcher's env. The loader validates shape only; the helper executes:

    - `command`: shell out to a tester script (`command`); fresh token on stdout.
    - `oauth_refresh`: a refresh-grant POST to `token_url` using
      `refresh_token_env` (+ optional client id/secret env).
    - `http`: a templated request to `http_url`; `${VAR}` in `http_body` is
      substituted from the helper's env.

    `validity_window_s` drives the proactive timer (refresh at
    `now + validity_window_s − margin_s`); `max_refreshes_per_hour` bounds the
    reactive path so an `auth_invalid` storm cannot hammer the IdP.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    mechanism: RefreshMechanism
    # `command`
    command: str | None = None
    # `oauth_refresh`
    token_url: str | None = None
    refresh_token_env: str | None = None
    client_id_env: str | None = None
    client_secret_env: str | None = None
    # `http`
    http_url: str | None = None
    http_method: str = "POST"
    http_headers: dict[str, str] = Field(default_factory=dict)
    http_body: str | None = None
    # Timing / rate-limit.
    validity_window_s: int | None = Field(default=None, ge=1)
    margin_s: int = Field(default=60, ge=0)
    max_refreshes_per_hour: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def _mechanism_shape(self) -> Self:
        if self.mechanism == "command" and not self.command:
            raise ValueError("refresh.mechanism=command requires `command`")
        if self.mechanism == "oauth_refresh" and not (
            self.token_url and self.refresh_token_env
        ):
            raise ValueError(
                "refresh.mechanism=oauth_refresh requires `token_url` + `refresh_token_env`"
            )
        if self.mechanism == "http" and not self.http_url:
            raise ValueError("refresh.mechanism=http requires `http_url`")
        return self


class DeclaredAuthContext(BaseModel):
    """One declared `AuthContext` for a Principal (ADR-0012).

    `token` is an env-var reference (`${VAR}`), never an inline secret. The loader
    resolves it at load time, hashes it at the boundary, and discards the raw
    value — it never reaches the graph (ADR-0015). `refresh` (optional) tells the
    auth-helper sibling process how to rotate it (ADR-0014, S6).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    kind: AuthContextKind
    token: str = Field(min_length=1)
    # Rotation-stable handle for this credential within its Principal (ADR-0049).
    # Defaults to `kind` so a single-credential principal needs no explicit slot;
    # explicit `slot:` is only required to disambiguate ≥2 ACs of the same kind
    # (e.g. session vs. step-up cookie). `(principal.label, slot)` is unique per
    # engagement — enforced on `EngagementConfig`.
    slot: str | None = None
    refresh: RefreshConfig | None = None

    @model_validator(mode="after")
    def _default_slot_to_kind(self) -> Self:
        if self.slot is None:
            object.__setattr__(self, "slot", self.kind)
        return self

    @model_validator(mode="after")
    def _token_is_env_ref(self) -> Self:
        if not _ENV_REF_RE.match(self.token):
            raise ValueError(
                f"auth_contexts[].token must be an env-var reference like ${{VAR}} "
                f"(ADR-0012: tokens never inline); got {self.token!r}"
            )
        return self

    @property
    def env_var_name(self) -> str:
        """The `VAR` name inside the `${VAR}` reference."""

        m = _ENV_REF_RE.match(self.token)
        assert m is not None  # guaranteed by the validator
        return m.group("name")


class KnownSignals(BaseModel):
    """Identifying signals the tester observed from warm-up traffic (ADR-0012).

    These drive declared-vs-discovered reconciliation (ADR-0010): a discovered
    AuthContext whose signal matches one of these attaches to this declared
    Principal rather than spawning a phantom twin.

    All fields optional; a Principal may be declared with token material alone.
    `headers` maps an identifying header name to its expected value (e.g.
    `{"X-User-Id": "42"}`).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    jwt_sub: str | None = None
    me_user_id: str | None = None
    email: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class LivenessEndpoint(BaseModel):
    """A Principal's known-allowed warm-up request, for the ADR-0044 liveness probe.

    The tester's own warm-up knowledge (ADR-0012-legal): a request that returns
    2xx while the Principal's token is live (e.g. `GET /me`). The Executor sends
    it under the *same* `AuthContext` to disambiguate an authz `primary`'s 4xx —
    probe 2xx ⇒ token live (the boundary genuinely held); probe 4xx ⇒ token dead
    (`auth_invalid` + ADR-0014 reactive refresh). Optional: undeclared falls back
    to the first observed self-endpoint (`/me`/`/userinfo`/…).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    method: HttpMethod = "GET"
    path: str = Field(min_length=1)

    @model_validator(mode="after")
    def _normalise(self) -> Self:
        if not self.path.startswith("/"):
            raise ValueError(
                f"liveness_endpoint.path must be absolute (start with /); got {self.path!r}"
            )
        object.__setattr__(self, "method", self.method.upper())
        return self


class DeclaredPrincipal(BaseModel):
    """A test account the tester controls (ADR-0012 + ADR-0010).

    `label` is the stable kebab-case `identity_key` for the declared tier. The
    `auth_contexts` carry env-var token references; `known_signals` carry the
    identifying signals used for reconciliation.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    label: str = Field(min_length=1)
    description: str | None = None
    auth_contexts: tuple[DeclaredAuthContext, ...] = ()
    known_signals: KnownSignals = Field(default_factory=KnownSignals)
    # Optional known-allowed warm-up request for the ADR-0044 liveness probe.
    # Undeclared → the Executor falls back to an inferred self-endpoint.
    liveness_endpoint: LivenessEndpoint | None = None

    _coerce_auth_contexts = field_validator("auth_contexts", mode="before")(_list_to_tuple)

    @model_validator(mode="after")
    def _label_is_kebab(self) -> Self:
        if not _LABEL_RE.match(self.label):
            raise ValueError(
                f"principal label must be kebab-case ([a-z0-9-]); got {self.label!r}"
            )
        if self.label in _RESERVED_LABELS:
            raise ValueError(
                f"principal label {self.label!r} is reserved for a system principal "
                "(the anonymous singleton); choose another label"
            )
        return self


class AuthConfig(BaseModel):
    """Auth-identity hints for interpreting captured traffic (ADR-0026).

    `session_cookie_names` is the authoritative, engagement-global allowlist of
    cookie names that carry the session credential. When non-empty, ONLY these
    cookies feed the `AuthContext` identity (the shape heuristic is bypassed);
    empty means fall back to the heuristic. A flat list is correct across a
    multi-host engagement because cookies are host-scoped at request time, so the
    union partitions naturally. Cookie names are matched exactly (case-sensitive,
    per RFC 6265).

    `identity_key` is the authoritative engagement-global claim name that
    identifies a user (ADR-0032). When set and an actor exposes that claim, it
    overrides the heuristic claim-priority. When absent or the actor never
    exposes the claim, the resolver falls back to the heuristic. Accepts an
    optional source-qualifier prefix (`claim:`, `header:`, `body:`); the prefix
    is stripped — only the claim name is used for keying (full source routing is
    out of scope for this ADR).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    session_cookie_names: tuple[str, ...] = ()
    identity_key: str | None = None

    _coerce_names = field_validator("session_cookie_names", mode="before")(_list_to_tuple)


# ---------------------------------------------------------------------------
# Dispatch (slice 4, ADR-0042): two orthogonal mode axes; `environment` gates
# the legal matrix at LOAD time (not at dispatch time).
# ---------------------------------------------------------------------------

# Tester-declared engagement environment (ADR-0042). A fact about the tester's
# setup, not the target's internals (ADR-0012-legal). REQUIRED — no default — so
# the tester is forced to state it; the loader rejects illegal mode combos for
# `production` at load.
Environment = Literal["staging", "production"]

# `arming`: does a human press go before each dispatch run? (ADR-0042). `auto`
# skips the arm prompt; the run still drains *approved* tests only.
ArmingMode = Literal["review", "auto"]

# `interpreter`: may the agent expand the target set in-run? (ADR-0042). MVP
# ships `confirm` only; `freelance` is a designed-for seam (staging-only).
InterpreterMode = Literal["confirm", "freelance"]


class DispatchConfig(BaseModel):
    """Per-engagement dispatch defaults (ADR-0042).

    `arming` × `interpreter` are orthogonal axes; `EngagementConfig.environment`
    constrains which combinations are legal — on `production` ONLY
    `review + confirm` is representable. The constraint is enforced by
    `EngagementConfig`'s model validator (it needs both this block AND
    `environment`), not here.

    Budgets are per-run defaults; `doo dispatch run` may tighten them. The kill
    switch and the OPA gate are containment, not consent — the human arming
    decision is consent (ADR-0042).
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    arming: ArmingMode = "review"
    interpreter: InterpreterMode = "confirm"
    # Per-run hard caps (ADR-0042: budget-bounded). `request_budget` counts EVERY
    # wire send (primary, baselines, hazard-warmup, liveness — ADR-0043/0044).
    request_budget: int = Field(default=200, ge=1)
    wallclock_budget_s: int = Field(default=1800, ge=1)
    # Per-`TestCase` Interpreter tool-call cap (ADR-0042). Distinct from the
    # run-wide `request_budget` (one tool call may cost >1 wire send, ADR-0043).
    max_tool_calls: int = Field(default=6, ge=1)
    # Optional per-engagement body-match overrides (ADR-0044): regexes (the
    # sqlmap `--string` shape) run against an authz `primary`'s 4xx body BEFORE
    # the liveness probe and short-circuit it. `auth_invalid_match` ⇒ token dead;
    # `replay_invalid_match` ⇒ the replay (not the token) is stale. Validated to
    # compile here so a bad pattern is a loud load-time error, not a run-time one.
    auth_invalid_match: str | None = None
    replay_invalid_match: str | None = None

    @model_validator(mode="after")
    def _match_patterns_compile(self) -> Self:
        for name, pat in (
            ("auth_invalid_match", self.auth_invalid_match),
            ("replay_invalid_match", self.replay_invalid_match),
        ):
            if pat is not None:
                try:
                    re.compile(pat)
                except re.error as exc:
                    raise ValueError(
                        f"dispatch.{name} is not a valid regex: {exc}"
                    ) from exc
        return self


class LLMConfig(BaseModel):
    """LLM provider routing for the slice-3 planner (ADR-0037, S2a).

    The planner is the highest-leverage reasoning task, so it codes against one
    gateway client and the concrete provider is *config, not code*. `provider`
    routes through the org-standard LiteLLM gateway by default; a per-engagement
    `local` override keeps structural/claims data on-network for internal
    engagements under org data-policy (opt-in — bug-bounty external defaults to the
    API). `model` is the gateway model id (default Claude Opus 4.8). Tokens / API
    keys are never declared here — the gateway resolves credentials at call time,
    the same env-reference discipline as ADR-0012.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    provider: Literal["gateway", "local"] = "gateway"
    model: str = "claude-opus-4-8"


class EngagementConfig(BaseModel):
    """The whole YAML file, validated."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    engagement: EngagementMeta
    # ADR-0042: REQUIRED, no default. A fact about the tester's setup
    # (ADR-0012-legal), and the gate on the dispatch-mode matrix below.
    environment: Environment
    scope: ScopeRules
    kill_switch: KillSwitchConfig = Field(default_factory=KillSwitchConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    dispatch: DispatchConfig = Field(default_factory=DispatchConfig)
    principals: tuple[DeclaredPrincipal, ...] = ()

    _coerce_principals = field_validator("principals", mode="before")(_list_to_tuple)

    @model_validator(mode="after")
    def _unique_principal_labels(self) -> Self:
        labels = [p.label for p in self.principals]
        if len(set(labels)) != len(labels):
            raise ValueError("principal labels must be unique within an engagement")
        return self

    @model_validator(mode="after")
    def _unique_principal_slots(self) -> Self:
        """`(principal.label, slot)` is unique per engagement (ADR-0049).

        The slot is the rotation-stable attacker identity; a collision would make
        secrets lookup and TestCase keying ambiguous. The fix is an explicit
        `slot:` on each colliding declaration.
        """

        seen: set[tuple[str, str]] = set()
        for p in self.principals:
            for ac in p.auth_contexts:
                assert ac.slot is not None  # guaranteed by _default_slot_to_kind
                if ac.slot == "anonymous":
                    raise ValueError(
                        f"principal {p.label!r}: slot 'anonymous' is reserved for the "
                        "anonymous attacker sentinel (ADR-0049); choose another slot"
                    )
                key = (p.label, ac.slot)
                if key in seen:
                    raise ValueError(
                        f"credential slot ({p.label!r}, {ac.slot!r}) declared more "
                        f"than once. When a principal has multiple AuthContexts of "
                        f"kind {ac.kind!r}, give each an explicit `slot:` (ADR-0049)."
                    )
                seen.add(key)
        return self

    @model_validator(mode="after")
    def _environment_gates_dispatch_modes(self) -> Self:
        """Reject illegal `arming × interpreter` combos at LOAD time (ADR-0042).

        On `environment = production` the ONLY legal combination is
        `review + confirm`: the kill switch and run budget are containment, not
        consent; on a production target consent means a human saw the test. A
        human *arming* a `freelance` run does not satisfy that — they will not
        see what it actually sends. Enforced here (not at dispatch) so a
        misconfigured engagement fails loud and early, naming the rule.
        """

        if self.environment == "production":
            if self.dispatch.arming != "review":
                raise ValueError(
                    f"environment=production requires dispatch.arming=review "
                    f"(got {self.dispatch.arming!r}); auto-arming is staging-only "
                    "(ADR-0042: human-in-the-loop on production targets)"
                )
            if self.dispatch.interpreter != "confirm":
                raise ValueError(
                    f"environment=production requires dispatch.interpreter=confirm "
                    f"(got {self.dispatch.interpreter!r}); freelance is staging-only "
                    "(ADR-0042: a human arming a freelance run is not "
                    "human-in-the-loop for what it actually sends)"
                )
        return self


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
