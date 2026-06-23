# How to write an engagement config

The engagement config is the one YAML file that drives every `doo` command: ingestion, coverage, the
Planner, dispatch (`dispatch run`, `dispatch review`, `finding review`), and the `auth-helper`. It is
the tester's **declared, black-box-legal** setup: who you are testing as, what is in scope, how the
kill switch leases, and how a dispatch run is allowed to behave.

The schema is the Pydantic model `EngagementConfig` in
[`src/doo/setup/config.py`](../src/doo/setup/config.py) (`extra="forbid"` — an unknown key is a load
error, so every field is enumerable). A copy-pasteable, complete example lives at
[`docs/examples/engagement.yaml`](examples/engagement.yaml).

## Hard rules a config author must respect

1. **Tokens are `${ENV_VAR}` references, never inline secrets.** The loader resolves the env var,
   hashes it at the secrets boundary, and discards the raw value — it never reaches the graph. A
   literal token in `auth_contexts[].token` is rejected at load.
2. **Scope patterns are glob/segment, never regex.** A regex pattern (`^/.*$`) matches nothing under
   the glob matcher and would silently return empty coverage, so the loader rejects regex
   metacharacters (`^ $ [ ] ( ) | + ? \` and the `.*` idiom) and names the offender.
3. **Refresh credentials belong to the auth-helper process, not the dispatcher.** The optional
   `refresh` block tells the `auth-helper` sibling how to rotate a token; the actual refresh secret
   lives in the **helper's** env (referenced by var name), never the dispatcher's, never inline.
4. **`environment` is required and gates the dispatch-mode matrix.** On `production` only
   `dispatch.arming=review` + `dispatch.interpreter=confirm` will load.

## Complete annotated example

```yaml
engagement:
  id: acme-test
  name: Acme staging dispatch
  description: Dispatch walkthrough against the Acme staging image.

# REQUIRED, no default. `staging` permits the full arming × interpreter matrix;
# `production` forces dispatch.arming=review + interpreter=confirm.
environment: staging

scope:                            # glob/segment patterns, NOT regex
  host_patterns:
    - "api.example.com"           # exact host; "*.example.com" matches sub-domains
  allowed_methods: [GET, POST, PUT, PATCH, DELETE]
  allowed_path_patterns:
    - "/**"                       # all paths; "/users/*" = one segment under /users
  payload_class_denylist:
    - destructive-sql
  # rate_limit: {requests_per_second: 5, burst: 10}   # optional, dispatcher-enforced
  # time_window: {start_hour_utc: 9, end_hour_utc: 18, weekdays: [1,2,3,4,5]}

auth:
  session_cookie_names: [token]   # authoritative session-cookie allowlist
  # identity_key: sub             # engagement-global user-id claim

kill_switch:                      # external lease; refresh < ttl
  lease_ttl_seconds: 60
  refresh_interval_seconds: 30

llm:                              # per-role model defaults (ADR-0051)
  model: claude-opus-4-8          # planner default; persisted on the Engagement node
  # interpreter_model: anthropic/claude-sonnet-4-6   # optional; falls back to model

dispatch:                         # production ⇒ review+confirm only
  arming: review                  # human presses go before each run (`auto` = staging-only)
  interpreter: confirm            # `freelance` is staging-only and not yet available
  request_budget: 200             # every wire send counts (primary, baselines, warm-ups)
  wallclock_budget_s: 1800
  max_tool_calls: 6
  # auth_invalid_match: "(?i)token (expired|invalid)"   # regex, short-circuits liveness probe
  # replay_invalid_match: "(?i)csrf token mismatch"

principals:
  - label: test-user-a            # victim — kebab-case `identity_key`
    description: Primary victim account.
    auth_contexts:
      - kind: bearer
        token: "${DOO_TEST_TOKEN_A}"     # env-ref only
    known_signals:
      jwt_sub: uuid-aaa                   # reconciles discovered traffic to this principal
    liveness_endpoint: {method: GET, path: /me}    # warm-up probe

  - label: test-user-b            # attacker the dispatcher acts AS
    description: Attacker account (rotated by the auth-helper).
    auth_contexts:
      - kind: bearer
        token: "${DOO_TEST_TOKEN_B}"
        refresh:                          # auth-helper rotates this
          mechanism: command              # creds in the HELPER's env, not here
          command: ./scripts/mint-token-b.sh
          validity_window_s: 3600
          margin_s: 60
          max_refreshes_per_hour: 3
    known_signals:
      jwt_sub: uuid-bbb
    liveness_endpoint: {method: GET, path: /me}
```

## Field reference

### `engagement` — root metadata (`EngagementMeta`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | str | — (required) | Immutable engagement id; the partition key on every node. |
| `name` | str | — (required) | Human label. |
| `description` | str | `null` | Optional free text. |
| `time_window` | `TimeWindow` | `null` | When this *campaign* is active (UTC hours + ISO weekdays). Distinct from `scope.time_window` (the program's allowed hours). |

### `environment` — `staging` \| `production` (required, no default)

A fact about the tester's setup. **Required** so the tester is forced to state it. Gates the
`dispatch` mode matrix at load time: on `production` only `arming=review` + `interpreter=confirm` is
representable (see `dispatch`). Consumed by: `dispatch run`.

### `scope` — Scope rules (`ScopeRules`)

Patterns are **glob/segment, not regex**. Hashed into the Scope content id; the OPA data bundle is
built from this block. Consumed by: coverage, the Planner Validator, the Dispatcher OPA gate.

| Field | Type | Default | Notes |
|---|---|---|---|
| `host_patterns` | list[str] | — (≥1) | Exact host (`api.example.com`, IP literal) or single leading `*.` wildcard (`*.example.com`, sub-domains not apex). May pin scheme (`https://host`) / port (`host:8443`). |
| `allowed_methods` | list[str] | — (≥1) | HTTP methods in scope; OPA constrains the set strictly. |
| `allowed_path_patterns` | list[str] | — (≥1) | Segment-wise globs: `*` = one segment (incl. a `{param}`), trailing `**` = the rest, literals exact. `/users/*` matches `/users/{id}`; `/**` matches everything. Declaration order is preserved (first-match semantics). |
| `payload_class_denylist` | list[`PayloadClass`] | `[]` | Program-prohibited classes. Values: `destructive-sql`, `non-destructive-sql`, `ssrf-callback`, `benign-probe`, `auth-token-swap`, `boundary-probe`, `no-payload`. |
| `rate_limit` | `{requests_per_second: float>0, burst: int≥1}` | `null` | Per-host throttle carried into the OPA bundle. |
| `time_window` | `TimeWindow` | `null` | The *program's* allowed hours (UTC). |
| `required_headers` | list[str] | `[]` | Headers every in-scope request must carry. |
| `notes` | str | `null` | Cosmetic; stripped before the content hash. |

`TimeWindow`: `start_hour_utc` / `end_hour_utc` ∈ [0,23] inclusive; `weekdays` ISO 1..7 (Mon..Sun),
default all seven, must be unique.

### `auth` — identity hints (`AuthConfig`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `session_cookie_names` | list[str] | `[]` | Authoritative allowlist of cookie names that carry the session credential. When non-empty, ONLY these feed `AuthContext` identity (the shape heuristic is bypassed). Matched exactly, case-sensitive (RFC 6265). |
| `identity_key` | str | `null` | Engagement-global claim name that identifies a user. Overrides the heuristic claim-priority. Accepts a `claim:`/`header:`/`body:` prefix (stripped — only the name keys). |

### `kill_switch` — external lease (`KillSwitchConfig`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `backend` | `redis` | `redis` | Forward-compat knob; only `redis` is implemented. |
| `lease_ttl_seconds` | int ≥5 | `60` | Lease TTL in Redis (`engagement:{id}:lease`). |
| `refresh_interval_seconds` | int ≥1 | `30` | Keepalive cadence; **must be `< lease_ttl_seconds`** or the lease expires before each refresh. |

Run the keeper with `doo engagement keepalive <id>` (a separate process — the kill switch lives
outside the agent). The dispatcher reads the lease on every send.

### `llm` — per-role model defaults (`LLMConfig`, ADR-0051)

| Field | Type | Default | Notes |
|---|---|---|---|
| `model` | str | `claude-opus-4-8` | Planner default; persisted as `Engagement.llm_model`. |
| `interpreter_model` | str \| null | `null` | Interpreter override; persisted as `Engagement.llm_interpreter_model`. Falls back to `model` at resolution time when unset. |

> Persisted on the `Engagement` node at `engagement start`. Per-role resolution order is
> `--model` flag → `DOO_*_MODEL` env → these graph-persisted values → built-in default
> (ADR-0051). Provider routing is litellm's (model prefix → provider env vars); doo does not
> model a `provider` field.

The model the Planner and Interpreter actually use comes from the `DOO_PLANNER_*` env, resolved at
call time (credentials are never in the YAML):

- `DOO_PLANNER_MODEL` — the litellm model id (default `anthropic/claude-opus-4-8`).
- `ANTHROPIC_API_KEY` — for an `anthropic/<name>` id (direct), **or**
- `DOO_PLANNER_API_BASE` + `DOO_PLANNER_API_KEY` — a gateway URL + key for an `openai/<name>` id.
- `DOO_PLANNER_TIMEOUT_S`, `DOO_PLANNER_TEMPERATURE`, `DOO_PLANNER_NUM_RETRIES` — optional knobs.

One model id serves both the Planner and the Interpreter.

### `dispatch` — run defaults (`DispatchConfig`)

`arming` × `interpreter` are orthogonal axes; `environment` constrains the legal matrix. Budgets are
per-run defaults that `doo dispatch run` may tighten. Consumed by: `dispatch run`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `arming` | `review` \| `auto` | `review` | Does a human press go before each run? `auto` skips the arm prompt (staging-only) but still drains *approved* tests only. |
| `interpreter` | `confirm` \| `freelance` | `confirm` | May the agent expand the target set in-run? Only `confirm` is available today; `freelance` is reserved for staging and not yet implemented. |
| `request_budget` | int ≥1 | `200` | Run-wide hard cap counting **every** wire send (primary, baselines, hazard warm-up, liveness). |
| `wallclock_budget_s` | int ≥1 | `1800` | Run wall-clock cap. |
| `max_tool_calls` | int ≥1 | `6` | Per-`TestCase` Interpreter tool-call cap (one tool call may cost >1 wire send). |
| `auth_invalid_match` | str (regex) | `null` | Optional body-match override: runs against an authz `primary`'s 4xx body *before* the liveness probe and short-circuits it — a match ⇒ token dead. Compiled at load. |
| `replay_invalid_match` | str (regex) | `null` | Same shape; a match ⇒ the replay (not the token) is stale. Compiled at load. |

**Production constraint:** with `environment: production` the loader rejects anything but
`arming: review` + `interpreter: confirm`. The kill switch and budgets are *containment*, not
*consent*; on a production target consent means a human saw what the test sends.

### `principals[]` — declared test accounts (`DeclaredPrincipal`)

The accounts the tester controls. Labels must be unique within the engagement.

| Field | Type | Default | Notes |
|---|---|---|---|
| `label` | str (kebab-case) | — (required) | The stable `identity_key` for this declared tier (`[a-z0-9-]`). `anon` is reserved (the system anonymous singleton). |
| `description` | str | `null` | Optional. |
| `auth_contexts` | list[`DeclaredAuthContext`] | `[]` | Token material for this principal (below). |
| `known_signals` | `KnownSignals` | `{}` | Identifying signals observed from warm-up traffic, for declared-vs-discovered reconciliation: `jwt_sub`, `me_user_id`, `email`, `headers` (a `{name: value}` map). A discovered context matching one attaches here instead of spawning a phantom twin. |
| `liveness_endpoint` | `{method, path}` | `null` | Known-allowed warm-up request for the liveness probe. The Executor sends it under the same `AuthContext` to disambiguate an authz 4xx: probe 2xx ⇒ token live (the boundary held), probe 4xx ⇒ token dead (`auth_invalid` + reactive refresh). `path` must be absolute; `method` defaults to `GET`. Undeclared → the Executor falls back to an inferred self-endpoint (`/me`, `/userinfo`, …). |

#### `auth_contexts[]` (`DeclaredAuthContext`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `kind` | `bearer` \| `cookie` \| `api_key` \| `basic_auth` | — (required) | Token scheme understood by the secrets-hashing boundary. |
| `token` | str | — (required) | **`${ENV_VAR}` reference only**, never inline. The loader resolves, hashes, and discards the raw value. |
| `refresh` | `RefreshConfig` | `null` | How the **auth-helper** rotates this token (below). |

#### `refresh` (`RefreshConfig`)

Acted on by the `auth-helper` sibling, **never** the dispatcher. Refresh creds live in the helper's
env (by var name). The loader validates shape only; the helper executes. `validity_window_s` drives
the proactive timer (refresh at `now + validity_window_s − margin_s`); `max_refreshes_per_hour`
bounds the reactive path so an `auth_invalid` storm can't hammer the IdP.

| Field | Type | Default | Applies to | Notes |
|---|---|---|---|---|
| `mechanism` | `command` \| `oauth_refresh` \| `http` | — (required) | — | Selects the rotation path. |
| `command` | str | `null` | `command` | Tester script; fresh token on stdout. **Required** for `command`. |
| `token_url` | str | `null` | `oauth_refresh` | Token endpoint. **Required** with `refresh_token_env`. |
| `refresh_token_env` | str | `null` | `oauth_refresh` | Env-var name holding the refresh token (helper's env). |
| `client_id_env` / `client_secret_env` | str | `null` | `oauth_refresh` | Optional client-credential env-var names. |
| `http_url` | str | `null` | `http` | Templated request URL. **Required** for `http`. |
| `http_method` | str | `POST` | `http` | — |
| `http_headers` | map | `{}` | `http` | — |
| `http_body` | str | `null` | `http` | `${VAR}` placeholders substituted from the helper's env. |
| `validity_window_s` | int ≥1 | `null` | all | Token lifetime; drives proactive refresh. |
| `margin_s` | int ≥0 | `60` | all | Refresh this many seconds before expiry. |
| `max_refreshes_per_hour` | int ≥1 | `3` | all | Reactive-path rate limit. |

## Validating a config

```sh
# Schema check (no stack needed):
.venv/bin/python -c "import yaml; from doo.setup.config import EngagementConfig; \
  EngagementConfig.model_validate(yaml.safe_load(open('docs/examples/engagement.yaml')))"

# Full attach (needs the env vars + a running stack):
export DOO_TEST_TOKEN_A=... DOO_TEST_TOKEN_B=...
.venv/bin/doo engagement start --config docs/examples/engagement.yaml
```
