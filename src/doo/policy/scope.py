"""Pure `is_in_scope` Scope evaluator (ADR-0020).

This is the query-time / planner-side mirror of the dispatcher's OPA decision.
Per ADR-0020 the helper is **deterministic and side-effect-free**: no graph
access, no Redis, no I/O. Coverage queries, the planner's gap-surfacing logic,
and audit tooling all call it to filter `Host` / `Endpoint` (and, forward-
compatibly, a `ProposedRequest`) against the current Engagement's `Scope` rules.

The semantics here MUST match the future Rego policy exactly (same host-pattern
matching, same path-template handling, same method/payload-class matching) —
ADR-0020 makes a dual-path test (this helper vs. the Rego) mandatory. In slice 1
the Rego is deny-all, so the dual-path test constructs only out-of-scope
fixtures; when the real Rego lands in slice 4 the `true` cases get added.

Matching rules (the contract the Rego must reproduce):

- **Host pattern** — a Scope `host_patterns` entry matches a node when:
  - scheme matches (the pattern may pin a scheme via `https://` prefix; bare
    patterns match any scheme),
  - port matches (a pattern may pin `:8443`; bare patterns match the node's
    canonical port, where `None` means the scheme default),
  - hostname matches either exactly (case-insensitive) or via a single leading
    `*.` glob label (`*.example.com` matches `a.example.com` and
    `a.b.example.com` but NOT the apex `example.com`). IP literals only ever
    match explicit (non-glob) patterns.
- **Method** — `allowed_methods` containing `*` allows any method; otherwise the
  node's (upper-cased) method must be a member.
- **Path template** — an `allowed_path_patterns` entry matches an Endpoint's
  `path_template` when the pattern, read segment-by-segment, matches the
  template. A `*` pattern segment matches any single template segment
  (including a `{param}` placeholder). A literal pattern segment must equal the
  template segment exactly. A trailing `/**` pattern segment matches any number
  of remaining template segments. `/users/*` therefore matches `/users/{user_id}`.
- **Payload class** — a `ProposedRequest` whose `payload_class` is in the
  Scope's `payload_class_denylist` is out of scope, regardless of host/method/
  path.

All four predicates must pass for `is_in_scope` to return `True`; any failure
(including "host not in any pattern") returns `False`. Fail-closed.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from doo.canonical.value_objects import Scheme
from doo.events.execution import PayloadClass
from doo.setup.config import ScopeRules

# ---------------------------------------------------------------------------
# Node shapes the evaluator accepts.
#
# These are structural Protocols, not the L3 graph node classes, so the helper
# stays decoupled from the ontology layer (which T2 owns) and from Pydantic.
# Any object exposing the named read-only attributes works — a graph node, a
# dataclass fixture, or a Pydantic model. This keeps `is_in_scope` a pure
# function of plain data, exactly as the Rego is a pure function of `input`.
# ---------------------------------------------------------------------------


@runtime_checkable
class HostLike(Protocol):
    """A `Host`-shaped value: scheme + canonical hostname + optional port."""

    @property
    def scheme(self) -> Scheme: ...

    @property
    def canonical_hostname(self) -> str: ...

    @property
    def port(self) -> int | None: ...

    @property
    def is_ip_literal(self) -> bool: ...


@runtime_checkable
class EndpointLike(Protocol):
    """An `Endpoint`-shaped value: method + host + path template.

    `path_template` is the revisable `(method, host, path-template)` inference
    from CONTEXT.md — e.g. `/users/{user_id}`.
    """

    @property
    def method(self) -> str: ...

    @property
    def host(self) -> HostLike: ...

    @property
    def path_template(self) -> str: ...


@runtime_checkable
class ProposedRequestLike(Protocol):
    """A forward-compatible proposed-request shape (slice 4 exercises this).

    In slice 1 only `Host` and `Endpoint` are exercised by callers; this
    Protocol is here so the helper's signature is stable when the planner begins
    proposing concrete requests carrying a `PayloadClass`.
    """

    @property
    def method(self) -> str: ...

    @property
    def host(self) -> HostLike: ...

    @property
    def path_template(self) -> str: ...

    @property
    def payload_class(self) -> PayloadClass: ...


ScopeNode = HostLike | EndpointLike | ProposedRequestLike


def _scheme_default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _effective_port(scheme: str, port: int | None) -> int:
    """Resolve the node's port to a concrete number for comparison.

    `None` means "the scheme default" (the canonicalisation rule from
    `HostRef`); resolve it so a pattern that omits the default port still
    matches a node that omits it too.
    """

    return _scheme_default_port(scheme) if port is None else port


def _parse_host_pattern(pattern: str) -> tuple[str | None, str, int | None]:
    """Split a host pattern into `(scheme | None, hostname, port | None)`.

    A pattern may pin a scheme (`https://host`) and/or a port (`host:8443`).
    Bare patterns leave scheme/port unconstrained (`None`). Hostname is
    lower-cased for case-insensitive comparison.
    """

    scheme: str | None = None
    rest = pattern
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        scheme = scheme.lower()

    port: int | None = None
    # Only treat a trailing `:digits` as a port; avoids mis-parsing IPv6 (we
    # don't support bracketed IPv6 literals in slice-1 patterns).
    if ":" in rest:
        head, maybe_port = rest.rsplit(":", 1)
        if maybe_port.isdigit():
            rest = head
            port = int(maybe_port)

    return scheme, rest.lower(), port


def _hostname_matches(pattern_host: str, node_host: str, *, is_ip_literal: bool) -> bool:
    """Exact (case-insensitive) or single-leading-`*.` glob hostname match.

    IP literals never match a glob pattern — only an explicit equal pattern.
    """

    node_host = node_host.lower()
    if pattern_host.startswith("*."):
        if is_ip_literal:
            return False
        suffix = pattern_host[1:]  # ".example.com"
        # `*.example.com` matches `a.example.com`, `a.b.example.com`, but not
        # the apex `example.com`.
        return node_host.endswith(suffix) and len(node_host) > len(suffix)
    return pattern_host == node_host


def _host_pattern_matches(pattern: str, host: HostLike) -> bool:
    p_scheme, p_host, p_port = _parse_host_pattern(pattern)
    if p_scheme is not None and p_scheme != host.scheme:
        return False
    if not _hostname_matches(p_host, host.canonical_hostname, is_ip_literal=host.is_ip_literal):
        return False
    if p_port is not None:
        if _effective_port(host.scheme, host.port) != p_port:
            return False
    return True


def _host_in_scope(host: HostLike, scope: ScopeRules) -> bool:
    return any(_host_pattern_matches(p, host) for p in scope.host_patterns)


def _method_in_scope(method: str, scope: ScopeRules) -> bool:
    if "*" in scope.allowed_methods:
        return True
    return method.upper() in {m.upper() for m in scope.allowed_methods}


def _path_segments(path: str) -> list[str]:
    """Split a path/template into segments, dropping empty (leading-slash) parts."""

    return [seg for seg in path.split("/") if seg != ""]


def _path_pattern_matches(pattern: str, path_template: str) -> bool:
    """Segment-wise match of a Scope path pattern against an Endpoint template.

    - `*` pattern segment  -> matches exactly one template segment (any value,
      including a `{param}` placeholder).
    - `**` (only meaningful as the final pattern segment) -> matches the rest.
    - literal pattern segment -> must equal the template segment exactly.
    """

    p_segs = _path_segments(pattern)
    t_segs = _path_segments(path_template)

    i = 0
    for pi, p in enumerate(p_segs):
        if p == "**":
            # Trailing globstar swallows all remaining template segments.
            return pi == len(p_segs) - 1
        if i >= len(t_segs):
            return False
        if p == "*":
            i += 1
            continue
        if p != t_segs[i]:
            return False
        i += 1
    return i == len(t_segs)


def _path_in_scope(path_template: str, scope: ScopeRules) -> bool:
    return any(_path_pattern_matches(p, path_template) for p in scope.allowed_path_patterns)


def _payload_class_in_scope(payload_class: PayloadClass, scope: ScopeRules) -> bool:
    return payload_class not in scope.payload_class_denylist


def is_in_scope(node: ScopeNode, scope: ScopeRules) -> bool:
    """Return whether `node` is in scope under `scope` (deny-closed).

    Accepts a `Host`-shaped, `Endpoint`-shaped, or `ProposedRequest`-shaped
    value (structural; see the Protocols above). Pure: no graph, no Redis, no
    I/O — the same property the Rego policy has. Any unmet predicate yields
    `False`.

    - Host: host-pattern match only.
    - Endpoint: host-pattern AND method AND path-template match.
    - ProposedRequest: Endpoint checks PLUS payload-class not denied.
    """

    # ProposedRequest is the richest shape; check it first because it is a
    # structural superset of EndpointLike.
    if _has_payload_class(node):
        host = node.host  # type: ignore[union-attr]
        return (
            _host_in_scope(host, scope)
            and _method_in_scope(node.method, scope)  # type: ignore[union-attr]
            and _path_in_scope(node.path_template, scope)  # type: ignore[union-attr]
            and _payload_class_in_scope(node.payload_class, scope)  # type: ignore[union-attr]
        )

    if _is_endpoint_like(node):
        host = node.host  # type: ignore[union-attr]
        return (
            _host_in_scope(host, scope)
            and _method_in_scope(node.method, scope)  # type: ignore[union-attr]
            and _path_in_scope(node.path_template, scope)  # type: ignore[union-attr]
        )

    # Otherwise treat as a bare Host.
    return _host_in_scope(node, scope)  # type: ignore[arg-type]


def _has_payload_class(node: object) -> bool:
    return (
        hasattr(node, "payload_class")
        and hasattr(node, "host")
        and hasattr(node, "method")
        and hasattr(node, "path_template")
    )


def _is_endpoint_like(node: object) -> bool:
    return (
        hasattr(node, "host")
        and hasattr(node, "method")
        and hasattr(node, "path_template")
    )
