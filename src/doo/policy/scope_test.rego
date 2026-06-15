# `opa test` fixtures for the dispatcher Scope policy (ADR-0046).
#
# Per CLAUDE.md: tests for policy decisions are unit tests on Rego, not
# integration tests. One fixture `input` per `request_role` + the gate matrix
# (host / method / path / payload_class / time_window / environment). Run with
# `opa test src/doo/policy/`.
#
# `with data.scope as fixture_scope` (NOT `with data as ...`) so the override
# does not shadow this test package itself (which lives under `data.doo.*`).

package doo.scope_test

import data.doo.scope
import rego.v1

# A canonical generated-from-`Scope` `data.scope` document (ADR-0046 / `bundle.py`).
fixture_scope := {
	"allowed_hosts": [
		{"raw": "api.example.com", "scheme": null, "hostname": "api.example.com",
		 "port": null, "is_glob": false, "suffix": null},
		{"raw": "*.shop.example.com", "scheme": null, "hostname": "*.shop.example.com",
		 "port": null, "is_glob": true, "suffix": ".shop.example.com"},
	],
	"method_allowlist": ["GET", "POST"],
	"path_globs": ["/orders/*", "/me", "/api/**"],
	"payload_class_denylist": ["destructive-sql"],
	"time_window": null,
	"environment": "staging",
}

# A canonical ADR-0046 `input` for an in-scope IDOR `primary`.
base_input(role) := {
	"engagement_id": "eng-x",
	"environment": "staging",
	"run_id": "run-aaaaaaaaaaaa",
	"request": {
		"scheme": "https", "method": "GET", "host": "api.example.com",
		"path": "/orders/123", "path_template": "/orders/{order_id}",
	},
	"test_class": "idor",
	"payload_class": "auth-token-swap",
	"request_role": role,
	"auth_context_id": "ac-attacker",
	"principal_tier": "declared",
	"target_confidence": 0.87,
	"now": "2026-06-12T10:00:00Z",
}

# ---------------------------------------------------------------------------
# allow path: every gate passes for an in-scope `primary`.
# ---------------------------------------------------------------------------

test_primary_in_scope_allows if {
	scope.allow with input as base_input("primary") with data.scope as fixture_scope
}

test_baseline_victim_in_scope_allows if {
	scope.allow with input as base_input("baseline_victim") with data.scope as fixture_scope
}

test_baseline_negative_in_scope_allows if {
	scope.allow with input as base_input("baseline_negative") with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# host gate: out-of-scope host denies; `*.` glob matches subdomains, not apex.
# ---------------------------------------------------------------------------

test_host_not_in_allowlist_denies if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/host", "value": "evil.example.org"}])
	not scope.allow with input as inp with data.scope as fixture_scope
	"host_not_in_scope" in scope.deny_reasons with input as inp with data.scope as fixture_scope
}

test_glob_host_matches_subdomain if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/host", "value": "a.shop.example.com"}])
	scope.allow with input as inp with data.scope as fixture_scope
}

test_glob_host_does_not_match_apex if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/host", "value": "shop.example.com"}])
	not scope.allow with input as inp with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# method gate.
# ---------------------------------------------------------------------------

test_method_not_in_allowlist_denies if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/method", "value": "DELETE"}])
	not scope.allow with input as inp with data.scope as fixture_scope
	"method_not_allowed" in scope.deny_reasons with input as inp with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# path gate: matched on the CONCRETE `path` (ADR-0046).
# ---------------------------------------------------------------------------

test_path_glob_star_matches_one_segment if {
	# `/orders/*` matches `/orders/123` (one segment).
	scope.allow with input as base_input("primary") with data.scope as fixture_scope
}

test_path_glob_star_rejects_extra_segment if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/path", "value": "/orders/123/items"}])
	not scope.allow with input as inp with data.scope as fixture_scope
	"path_not_in_scope" in scope.deny_reasons with input as inp with data.scope as fixture_scope
}

test_path_globstar_matches_rest if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/path", "value": "/api/v2/users/42"}])
	scope.allow with input as inp with data.scope as fixture_scope
}

test_path_literal_exact if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/request/path", "value": "/me"}])
	scope.allow with input as inp with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# payload_class gate.
# ---------------------------------------------------------------------------

test_payload_class_denylist_denies if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/payload_class", "value": "destructive-sql"}])
	not scope.allow with input as inp with data.scope as fixture_scope
	"payload_class_denied" in scope.deny_reasons with input as inp with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# environment × payload-class floor (ADR-0046): production hard-denies
# destructive-sql even if the tester's denylist forgot it.
# ---------------------------------------------------------------------------

test_production_floor_denies_destructive if {
	d := json.patch(fixture_scope,
		[{"op": "replace", "path": "/payload_class_denylist", "value": []},
		 {"op": "replace", "path": "/environment", "value": "production"}])
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/payload_class", "value": "destructive-sql"},
		 {"op": "replace", "path": "/environment", "value": "production"}])
	not scope.allow with input as inp with data.scope as d
	"environment_policy" in scope.deny_reasons with input as inp with data.scope as d
}

test_production_allows_auth_token_swap if {
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/environment", "value": "production"}])
	scope.allow with input as inp with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# time_window gate.
# ---------------------------------------------------------------------------

test_time_window_null_always_allows if {
	scope.time_window_in_scope with input as base_input("primary")
		with data.scope as fixture_scope
}

test_time_window_inside_allows if {
	d := json.patch(fixture_scope, [{"op": "replace", "path": "/time_window",
		"value": {"start_hour_utc": 9, "end_hour_utc": 17, "weekdays": [1,2,3,4,5]}}])
	# 2026-06-12 is a Friday (ISO weekday 5), 10:00 UTC.
	scope.allow with input as base_input("primary") with data.scope as d
}

test_time_window_outside_denies if {
	d := json.patch(fixture_scope, [{"op": "replace", "path": "/time_window",
		"value": {"start_hour_utc": 9, "end_hour_utc": 17, "weekdays": [1,2,3,4,5]}}])
	inp := json.patch(base_input("primary"),
		[{"op": "replace", "path": "/now", "value": "2026-06-12T03:00:00Z"}])
	not scope.allow with input as inp with data.scope as d
	"outside_time_window" in scope.deny_reasons with input as inp with data.scope as d
}

# ---------------------------------------------------------------------------
# request_role: `liveness` allowed on host+method alone (path/payload bypassed).
# ---------------------------------------------------------------------------

test_liveness_bypasses_path_and_payload if {
	inp := json.patch(base_input("liveness"),
		[{"op": "replace", "path": "/request/path", "value": "/nowhere"},
		 {"op": "replace", "path": "/payload_class", "value": "destructive-sql"}])
	scope.allow with input as inp with data.scope as fixture_scope
}

test_liveness_still_requires_host if {
	inp := json.patch(base_input("liveness"),
		[{"op": "replace", "path": "/request/host", "value": "evil.example.org"}])
	not scope.allow with input as inp with data.scope as fixture_scope
}

# ---------------------------------------------------------------------------
# default: missing `data.scope` → fail closed (ADR-0003 deny-default).
# ---------------------------------------------------------------------------

test_missing_data_fails_closed if {
	not scope.allow with input as base_input("primary") with data.scope as {}
}
