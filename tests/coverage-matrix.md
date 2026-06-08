# Slice-1 user-story coverage matrix

Maps every user story in the slice-1 PRD (GitHub issue #2) to the test(s) that
exercise it. Keeps coverage auditable: a story with no test, or a test with no
story, is a gap to close. `file::test` where a single case is decisive;
file-level where a story is covered broadly across a module's cases.

| # | User story (abbrev.) | Test(s) |
|---|---|---|
| 1 | Capture target traffic in Burp → evidence | `tests/test_har_corpus.py::test_burp_form_postdata_params_tolerated` (Burp HAR ingested). *Live Burp capture is deferred (HAR-first MVP, per grill-queue); the Burp export is the evidence path.* |
| 2 | Export HAR from Burp/Chrome/Firefox/Charles | `tests/test_har_corpus.py::test_exporter_variant_parses_without_error` |
| 3 | Declare an Engagement in YAML | `tests/test_loader.py` (config parse + apply) |
| 4 | Declared test accounts → `Principal` tier=declared + provenance | `tests/test_loader.py` (principals); `tests/test_pipeline_e2e.py::test_bearer_har_reconciles_to_declared_principal_no_raw_token` |
| 5 | JWT cross-checked against `known_signals` at load | `tests/test_loader.py` (JWT sub/jwt_sub mismatch fails loudly) |
| 6 | Raw tokens never persisted to the graph | `tests/test_pipeline_e2e.py::test_bearer_har_reconciles_…`, `…::test_bodies_har_…`, `…::test_response_values_full_pipeline_…`; `tests/test_observed_value_e2e.py`; `tests/e2e/test_slice1_full.py::test_slice1_comprehensive_pipeline` |
| 7 | External `engagement-keepalive` lease | `tests/test_keepalive.py` |
| 8 | Upload a HAR via a single command | `tests/test_intake_api.py`, `tests/test_intake_unit.py`; CLI `doo ingest har` |
| 9 | Unique `trace_id` propagated L1→L2→L3 | `tests/test_trace_propagation.py` |
| 10 | Re-uploading same HAR is idempotent no-op | `tests/test_pipeline_e2e.py::test_reupload_same_har_is_idempotent`; `tests/e2e/test_slice1_full.py::test_slice1_comprehensive_reingest_is_idempotent` |
| 11 | Malformed entries → first-class `ParseFailure` | `tests/test_har_parser.py`, `tests/test_pipeline_e2e.py::test_malformed_entry_produces_parse_failure_with_backref` |
| 12 | Host canonicalisation | `tests/test_canonical_identity.py` |
| 13 | Path templates inferred by multiplicity + shape priors | `tests/test_templating_unit.py`, `tests/test_templating_e2e.py` |
| 14 | Templates are a revisable inference (ADR-0004) | `tests/test_templating_e2e.py` (re-templating retracts old, keeps ROs) |
| 15 | One `Endpoint` per target endpoint within an engagement | `tests/test_templating_e2e.py`, `tests/test_pipeline_e2e.py::test_anon_har_full_pipeline` |
| 16 | Each Engagement is an isolated subgraph root | `tests/test_cross_engagement.py`, `tests/test_pipeline_e2e.py::test_cross_engagement_isolation` |
| 17 | New campaign vs same target: no prior-campaign leak | `tests/test_cross_engagement.py::test_same_identity_under_different_engagement_is_allowed`, `…::test_deleting_engagement_a_leaves_engagement_b_untouched` |
| 18 | Identical `Scope` rules share one node by content hash | `tests/test_loader.py` (scope content_hash upsert) |
| 19 | Day-2 re-attach via same `engagement start` | `tests/test_loader.py` (idempotent re-attach, ADR-0019) |
| 20 | Printed diff + confirm before material change | `tests/test_loader.py` (diff-and-confirm; principal/scope changes are material) |
| 21 | View the graph in Neo4j Browser | *Manual / ops tooling — not unit-tested (Neo4j Browser ships with the container).* |
| 22 | Cross-cutting provenance fields on every node/edge (ADR-0005) | `tests/test_l2_events.py`, `tests/test_l3_events.py`; commit path stamps them (`tests/test_commit_unit.py`) |
| 23 | Observation vs inference layers kept distinct (ADR-0001) | `tests/test_templating_e2e.py` (retraction keeps ROs); `tests/test_l2_events.py` |
| 24 | Anonymous singleton AuthContext + Principal | `tests/test_pipeline_e2e.py::test_anon_har_full_pipeline`; `tests/e2e/test_slice1_full.py` (anon count == 1) |
| 25 | Bodies in object storage, hashes referenced from graph | `tests/test_har_bodies.py`, `tests/test_pipeline_e2e.py::test_bodies_har_full_pipeline_blobs_params_and_secrets` |
| 26 | Secret-shaped values → hash+length+preview only | `tests/test_candidate_extraction.py`, `tests/test_value_canonicalisation.py`, `tests/test_pipeline_e2e.py::test_response_values_full_pipeline_…`, `tests/test_observed_value_e2e.py` |
| 27 | Out-of-scope hosts still ingested (ADR-0020) | `tests/test_scope_dual_path.py`, `tests/test_scope.py` (scope governs dispatch/query, not ingestion) |
| 28 | Single `is_in_scope` helper for all in-scope filtering | `tests/test_scope.py`, `tests/test_scope_dual_path.py` |
| 29 | `trace_id`/`span_id` through envelope→L2→l3-events (ADR-0018) | `tests/test_trace_propagation.py`, `tests/test_l3_events.py` |
| 30 | Structured logs with trace/span/engagement bound | `tests/test_logging.py` |
| 31 | `engagement_id` in every scoped node's identity (ADR-0017) | `tests/test_cross_engagement.py::test_duplicate_endpoint_identity_within_engagement_is_rejected`, `tests/test_schema_bootstrap.py` |
| 32 | L3 commit gate refuses cross-engagement edges | `tests/test_commit_unit.py::test_scope_gate_refuses_mismatched_engagement` |
| 33 | Commit idempotency keyed semantically (ADR-0016) | `tests/test_idempotency_keys.py`, `tests/test_commit_unit.py::test_redelivery_of_same_semantic_key_is_noop` |
| 34 | Declared/discovered Principal reconciliation (ADR-0010) | `tests/test_pipeline_e2e.py::test_bearer_har_reconciles_…`; `tests/e2e/test_slice1_full.py` (no phantom twin) |
| 35 | Data persisted across restarts | *`docker-compose.yml` mounts Neo4j/MinIO volumes; not unit-tested (testcontainers are ephemeral by design).* |
| 36 | Schema bootstrapped idempotently on every L3 startup | `tests/test_schema_bootstrap.py::test_apply_schema_against_live_neo4j_is_idempotent` |
| 37 | HAR fixture corpus for exporter quirks | `tests/test_har_corpus.py` |
| 38 | Every scoped Cypher query filters via one helper | `tests/test_for_engagement.py` |
| 39 | L1 validates envelopes but not blobs | `tests/test_intake_unit.py`, `tests/test_har_parser.py` (malformed flows through to ParseFailure) |
| 40 | Stable per-parser `source_id` (ADR-0016) | `tests/test_idempotency_keys.py`, `tests/test_canonical_identity.py` (`derive_har_source_id`) |
| 41 | Keepalive is a separate, tester-owned process | `tests/test_keepalive.py` (subprocess lifecycle: start / SIGTERM-release / SIGKILL-expire) |
| 42 | Typer CLI with clear subcommands | `src/doo/cli.py` (engagement start/status/keepalive, ingest har); exercised by `tests/test_keepalive.py` + intake tests |
| 43 | All layer-boundary data validated by strict Pydantic | `tests/test_envelope.py`, `tests/test_l2_events.py`, `tests/test_l3_events.py` (strict, extra=forbid) |

## Slice-2 coverage queries (issue #49 / #50)

Maps each coverage query (per ADR-0033 / ADR-0034) to the test(s) that exercise
it. Extends the slice-1 matrix above.

| Query | What it surfaces | Test(s) |
|-------|------------------|---------|
| C1 | In-scope `Endpoint`s with no `HIT` edge of any kind (dead endpoints); "hit" = any `HIT` regardless of status/source, asymmetric from C2's "reached" (ADR-0033); in-scope decided by `is_in_scope` in Python (ADR-0020); engagement-scoped + `status='active'` (ADR-0017); effective confidence decayed (ADR-0005), `--min-confidence` opt-in. | `tests/test_coverage_c1_e2e.py::test_c1_returns_only_in_scope_never_hit_endpoints` (golden e2e: in-scope-never-hit returned, any-HIT excluded, out-of-scope-hit excluded), `…::test_c1_min_confidence_does_not_hide_by_default`; `tests/test_coverage_c1_unit.py` (any-HIT-not-dead, scope filter, decay + `--min-confidence`, JSON round-trip); `tests/test_coverage_cli.py` (table + `--json` rendering) |
| C2 | Endpoints reached as principal A but not as B (presence-differential authz coverage); `reached(e,P)` requires a **2xx** observation under P's AuthContext — deliberately asymmetric from C1's any-`HIT` "hit" (ADR-0033), so a 401/403/404/5xx (or no request) on the B side surfaces a bypass candidate instead of suppressing it; all active principal tiers (declared + discovered + anonymous) pair, A/B pinnable via `--as`/`--not-as`; each row carries per-principal evidence `(status, response_size_bytes, response_body_sha256)`; in-scope via `is_in_scope` (ADR-0020), engagement-scoped + `status='active'` (ADR-0017), decayed effective confidence + `--min-confidence` (ADR-0005); no `dispatch_status` filter (slice 4). | `tests/test_coverage_reached_unit.py` (the `reached` predicate: 2xx-reached, 401/403/404/5xx/3xx not-reached, the C1-vs-C2 asymmetry, strongest-evidence retention, null tolerance); `tests/test_coverage_c2_unit.py` (A∧¬B differential, evidence A-real/B-null, both-reached-no-gap, anonymous pairing, `--as`/`--not-as` pinning, scope filter, decay + `--min-confidence`, JSON round-trip); `tests/test_coverage_c2_e2e.py::test_c2_surfaces_admin_only_endpoint_and_respects_direction` (golden e2e: 200-to-admin / 401-to-user `/admin/panel` surfaces in C2(admin,user) not C2(user,admin), shared-200 endpoint excluded, promoted `response_size_bytes` on node); `tests/test_coverage_cli.py` (c2 table + `--json` + pin pass-through rendering) |
| C2b | Endpoints reached (2xx) by ≥2 principals whose responses **differ** by `response_body_sha256` OR `response_size_bytes` — the content-differential sibling of C2, surfacing *role-differentiated 200s* (every principal gets a 200 but the body is rendered per role/account) where BOLA/IDOR lives; C2's presence query is blind to these (both "reached"). Reuses the `reached_map` 2xx traversal (no re-derived predicate); comparison is **pure metadata** — no body parsed or fetched (ADR-0033); endpoints reached by ≥2 principals with IDENTICAL hash AND size are excluded, and <2-principal groups can never diverge; each row carries the full per-principal evidence list `(status, response_size_bytes, response_body_sha256)`; in-scope via `is_in_scope` (ADR-0020), engagement-scoped + `status='active'` (ADR-0017), decayed effective confidence + `--min-confidence` (ADR-0005); no `dispatch_status` filter (slice 4). | `tests/test_coverage_c2b_unit.py` (differing-hash included, differing-size included, identical-hash-and-size excluded, <2-principals excluded, three-principals-one-differs, evidence tuple shaping, scope filter, decay + `--min-confidence`, JSON round-trip); `tests/test_coverage_c2b_e2e.py::test_c2b_surfaces_role_differentiated_200` (golden e2e: `/orders/1` 200-to-both-with-different-bodies surfaces, identical-body `/dashboard` excluded, single-principal `/admin/panel` excluded, promoted `response_body_sha256`+`response_size_bytes` on node); `tests/test_coverage_cli.py` (c2b table + `--json` rendering) |
| C3 | Leak-to-input pivots. | *Deferred to a later slice-2 tracer (C3 leak-to-input).* |

## Comprehensive integration

`tests/e2e/test_slice1_full.py::test_slice1_comprehensive_pipeline` exercises
stories 4, 6, 9–16, 24–26, 31–34 together through one HAR, catching cross-feature
regressions the per-tracer tests miss.

## Honest gaps (not unit-tested, by design)

- **#1 live Burp capture** and **#21 Neo4j Browser** — operator/tooling concerns,
  not pipeline logic.
- **#35 persistence across restarts** — a property of the `docker-compose` volume
  config, not of the code; testcontainers are intentionally ephemeral.
