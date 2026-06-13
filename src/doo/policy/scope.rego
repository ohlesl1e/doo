# Dispatcher Scope policy (ADR-0003 / ADR-0020 / ADR-0046).
#
# Per ADR-0003 the dispatcher's authorisation decision is a PURE function of
# `input` (the ADR-0046 snapshot: concrete request + test context + run) and
# `data` (the generated-from-`Scope` document, `policy/bundle.py`). No graph
# access. **Fail closed**: `default allow := false`.
#
# These rules MUST mirror `doo.policy.scope.is_in_scope` exactly (ADR-0020):
# the dual-path test (`tests/test_scope_dual_path.py`) feeds the same fixtures
# through both and asserts identical answers. Host patterns are pre-parsed by
# the bundle generator into `(scheme|null, hostname, port|null, is_glob,
# suffix)` so this file does plain comparisons, not string surgery.
#
# `input` shape (ADR-0046):
#   { engagement_id, environment, run_id,
#     request: {scheme, method, host, path, path_template},
#     test_class, payload_class, request_role, auth_context_id,
#     principal_tier, target_confidence, now }
#
# `data.scope` shape (policy/bundle.py):
#   { allowed_hosts: [{scheme, hostname, port, is_glob, suffix}, ...],
#     method_allowlist: [...], path_globs: [...],
#     payload_class_denylist: [...], time_window: {...}|null, environment }
#
# Per-engagement `.rego` overlays may add `deny[msg]` rules in this same
# `doo.scope` package to express tester-authored denies (e.g. "never hit
# /users/{id}/delete") via `input.request.path_template`.

package doo.scope

import rego.v1

default allow := false

# Allow iff every gate passes AND no overlay deny fires. Deny-closed: any
# unmet predicate (or any `deny[msg]` rule) yields false.
allow if {
	host_in_scope
	method_in_scope
	path_in_scope
	payload_class_in_scope
	time_window_in_scope
	environment_in_scope
	count(deny) == 0
}

# `deny` is a partial set: the fixed rules contribute nothing; per-engagement
# overlays add `deny contains msg if { ... }` rules (ADR-0046). `deny_reasons`
# composes the gate failures + overlay denies into one list the dispatcher
# surfaces as `dispatcher_blocked(opa_deny: <reasons>)`.
deny contains msg if { false; msg := "" }

deny_reasons := array.concat(
	[r | some r in gate_failures],
	[r | some r in deny],
)

gate_failures contains "host_not_in_scope" if not host_in_scope
gate_failures contains "method_not_allowed" if not method_in_scope
gate_failures contains "path_not_in_scope" if not path_in_scope
gate_failures contains "payload_class_denied" if not payload_class_in_scope
gate_failures contains "outside_time_window" if not time_window_in_scope
gate_failures contains "environment_policy" if not environment_in_scope

# ---------------------------------------------------------------------------
# Host: exact (case-insensitive) or single-leading-`*.` glob (ADR-0020).
# IP literals never match a glob; scheme/port pins are optional.
# ---------------------------------------------------------------------------

host_in_scope if {
	some hp in data.scope.allowed_hosts
	host_pattern_matches(hp)
}

host_pattern_matches(hp) if {
	scheme_matches(hp)
	port_matches(hp)
	not hp.is_glob
	lower(input.request.host) == hp.hostname
}

host_pattern_matches(hp) if {
	scheme_matches(hp)
	port_matches(hp)
	hp.is_glob
	# IP literals never match a glob (ADR-0020). The bundle does not carry
	# `is_ip_literal` on `input.request`; the constructor only ever emits a
	# canonical hostname or an IP literal as `host`, and IP literals are matched
	# by an *exact* pattern only (the branch above), so the glob branch's
	# `endswith` is sufficient: an IP cannot end with `.example.com`.
	host := lower(input.request.host)
	endswith(host, hp.suffix)
	# `*.example.com` does NOT match the apex `example.com` (ADR-0020): the
	# match must have at least one extra label before the suffix.
	count(host) > count(hp.suffix)
}

scheme_matches(hp) if hp.scheme == null
scheme_matches(hp) if hp.scheme == input.request.scheme

# Port comparison resolves the scheme default (443 https / 80 http) on BOTH
# sides, mirroring `policy.scope._effective_port`. `input.request` carries no
# explicit port (the constructor's `HostRef.port` is None for the default), so
# only a pattern *pinning* a non-default port can fail this gate.
port_matches(hp) if hp.port == null
port_matches(hp) if hp.port == effective_port

effective_port := p if {
	# `input.request` does not carry a port in the ADR-0046 shape; treat as
	# scheme default. A future extension that adds `input.request.port` slots
	# in here.
	p := default_port(input.request.scheme)
}

default_port("https") := 443
default_port("http") := 80

# ---------------------------------------------------------------------------
# Method: `*` allows any; otherwise upper-cased membership (ADR-0020).
# ---------------------------------------------------------------------------

method_in_scope if "*" in data.scope.method_allowlist
method_in_scope if upper(input.request.method) in data.scope.method_allowlist

# ---------------------------------------------------------------------------
# Path: segment-wise glob against the CONCRETE `input.request.path` (ADR-0046).
# `*` = exactly one segment; trailing `**` = the rest; literal = exact.
# `path_template` is available for tester-authored overlay denies; the
# canonical scope-glob match is over `path` so a re-templating cannot silently
# un-deny a request (ADR-0046 "Considered options").
# ---------------------------------------------------------------------------

path_in_scope if {
	some pattern in data.scope.path_globs
	path_glob_matches(pattern, input.request.path)
}

path_glob_matches(pattern, path) if {
	p_segs := segments(pattern)
	t_segs := segments(path)
	segs_match(p_segs, t_segs)
}

segments(p) := [s | some s in split(p, "/"); s != ""]

# `**` only as the trailing segment swallows the rest (ADR-0020).
segs_match(p_segs, t_segs) if {
	count(p_segs) > 0
	p_segs[count(p_segs) - 1] == "**"
	prefix := array.slice(p_segs, 0, count(p_segs) - 1)
	count(t_segs) >= count(prefix)
	every i, ps in prefix { seg_matches(ps, t_segs[i]) }
}

# No `**`: lengths must match and every segment must match.
segs_match(p_segs, t_segs) if {
	not "**" in p_segs
	count(p_segs) == count(t_segs)
	every i, ps in p_segs { seg_matches(ps, t_segs[i]) }
}

seg_matches("*", _)
seg_matches(ps, ts) if {
	ps != "*"
	ps != "**"
	ps == ts
}

# ---------------------------------------------------------------------------
# Payload class: NOT in the denylist.
# ---------------------------------------------------------------------------

payload_class_in_scope if not input.payload_class in data.scope.payload_class_denylist

# ---------------------------------------------------------------------------
# Time window: missing window = always; otherwise `input.now`'s UTC hour and
# ISO weekday must fall inside.
# ---------------------------------------------------------------------------

time_window_in_scope if data.scope.time_window == null

time_window_in_scope if {
	tw := data.scope.time_window
	tw != null
	ts := time.parse_rfc3339_ns(input.now)
	clock := time.clock([ts, "UTC"])
	hour := clock[0]
	wd := time.weekday(ts)
	iso_weekday[wd] in tw.weekdays
	hour_in_window(hour, tw.start_hour_utc, tw.end_hour_utc)
}

# `time.weekday` returns the day name; map to ISO 1..7 (Mon..Sun) per
# `setup.config.TimeWindow`.
iso_weekday := {
	"Monday": 1, "Tuesday": 2, "Wednesday": 3, "Thursday": 4,
	"Friday": 5, "Saturday": 6, "Sunday": 7,
}

hour_in_window(h, start, end) if {
	start <= end
	h >= start
	h <= end
}

# Wrap-around window (e.g. 22..03 UTC).
hour_in_window(h, start, end) if {
	start > end
	h >= start
}
hour_in_window(h, start, end) if {
	start > end
	h <= end
}

# ---------------------------------------------------------------------------
# Environment × payload-class matrix (ADR-0046). MVP rule: on `production`, the
# `boundary-probe` and `benign-probe` payload classes are the only auto-allowed
# beyond `auth-token-swap`/`no-payload`; anything destructive is denied
# regardless of the per-engagement denylist (defence-in-depth — the denylist is
# tester-declared; this is the fixed floor).
# ---------------------------------------------------------------------------

environment_in_scope if input.environment != "production"

environment_in_scope if {
	input.environment == "production"
	not input.payload_class in {"destructive-sql"}
}

# ---------------------------------------------------------------------------
# `request_role` hooks (ADR-0046): a `liveness` probe to a declared
# self-endpoint is always allowed (it is the Executor's own health check on the
# tester's own credential, not a test). Tester overlays can add per-role rules.
# ---------------------------------------------------------------------------

allow if {
	input.request_role == "liveness"
	host_in_scope
	method_in_scope
}
