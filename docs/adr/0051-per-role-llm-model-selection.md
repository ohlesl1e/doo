# LLM model selection is per-role and graph-persisted; provider routing is litellm's, not doo's

`LLMConfig` drops `provider` and becomes `{model, interpreter_model: str | None}` — two
model ids, planner and interpreter, persisted on the `Engagement` node at
`engagement start` and overridable per-invocation by a `--model` flag on
`planner propose` / `dispatch run`. doo does **not** implement LLM provider routing
or data-locality enforcement: litellm's model-prefix mechanism (`anthropic/…`,
`openai/…`) routes by its own per-provider env vars, and the `DOO_*_API_BASE`
overrides exist only to force-pin a role to a single endpoint when prefix routing
is explicitly not wanted.

## Why

The slice-3 `LLMConfig.provider: gateway | local` enum modeled a per-engagement
data-policy constraint ("internal engagements route LLM traffic on-network") that
turned out to be **speculative** — no engagement has required it, and the field has
never been read at runtime (`planner/cli.py` / `dispatch/cli.py` build the caller
from `DOO_PLANNER_*` env only). Enforcing data locality is the deploying team's
concern (network egress rules, LiteLLM proxy allowlists), the same posture doo
takes for `DOO_S3_ENDPOINT` / Neo4j — it points at infra, it doesn't audit it.

The real friction is two orthogonal needs the `provider` enum didn't serve:

- **Per-invocation experimentation** — try a different model on one run without
  editing an env file. → `--model` flag per command.
- **Per-engagement, per-role durable defaults** — Planner (one-shot per gap) and
  Interpreter (multi-turn × N TestCases) have structurally different cost
  profiles; once a cheaper interpreter model is established, that's an engagement
  fact you pin, not a flag you re-type. → `interpreter_model` in the schema,
  persisted on the `Engagement` node so `planner propose` stays id-only and
  `dispatch run` reads it the same way it already reads `Scope`.

Multi-provider access ("planner via local gateway, interpreter via Anthropic
direct") falls out of litellm's existing prefix routing: leave `DOO_*_API_BASE`
unset, set `ANTHROPIC_API_KEY` + `OPENAI_API_BASE=<gateway>` (litellm's own vars),
and the model id alone — `anthropic/claude-…` vs `openai/qwen3` — picks the
destination. `--model` switches provider with no other change.

## Resolution order

Per role, most-specific wins:

| | Planner | Interpreter |
|---|---|---|
| 1 | `planner propose --model` | `dispatch run --model` |
| 2 | `DOO_PLANNER_MODEL` | `DOO_INTERPRETER_MODEL` |
| 3 | — | `DOO_PLANNER_MODEL` *(historical shared var; both roles read it today)* |
| 4 | `Engagement.llm_model` | `Engagement.llm_interpreter_model` |
| 5 | — | `Engagement.llm_model` |
| 6 | `anthropic/claude-opus-4-8` | `anthropic/claude-opus-4-8` |

`api_base` (and the matching `api_key`) is **env-only** — operator infrastructure,
not an engagement fact (ADR-0012 env-reference discipline; same class as the Neo4j
URI). Per role: role-specific → shared → `None`:

- Planner: `DOO_PLANNER_API_BASE` → `DOO_LLM_API_BASE` → `None`
- Interpreter: `DOO_INTERPRETER_API_BASE` → `DOO_LLM_API_BASE` → `None`

`None` is the **normal state**: litellm prefix-routes via its own provider env
vars. Setting any of these is a **force-pin** — every call for that role goes to
that one endpoint regardless of model prefix; the model id must then be whatever
that endpoint registered (typically `openai/<name>` for an OpenAI-compat proxy).
A non-`openai/` prefix against a pinned `api_base` fails loud at the proxy
(protocol mismatch) — diagnosable, not silent.

## Considered Options

- **Keep `provider` as a YAML-only policy pin** (`local` ⇒ both roles must use
  `DOO_LOCAL_LLM_BASE`, refuse otherwise) — rejected: enforces a constraint no
  engagement has; teams that need it enforce at the gateway/network layer where it
  can actually be verified.
- **Per-role `provider`** — rejected: as *policy* it's incoherent (Interpreter data
  ⊇ Planner data in sensitivity, so a policy that locks one and not the other is
  not a policy anyone would write); as *routing* it's `api_base` with an extra
  enum hop.
- **`api_base` in `LLMConfig`** — rejected: puts an operator-host URL in a
  shareable engagement YAML; same reason credential values stay out (ADR-0012).
- **`--api-base` CLI flag** — rejected: `api_base` changes rarely; the
  multi-provider case is solved by *not* setting it and letting prefix routing
  work, not by overriding it per run.
- **`planner propose` grows `--config` and re-reads YAML** — rejected: extends the
  re-read-from-disk pattern this ADR's sibling question (`dispatch run --config`)
  already flags as redundant. Persisting `llm_*` on the `Engagement` node keeps
  `propose` id-only, matching how it already reads `Scope`/`Principal`s.
- **One shared `model`, no `interpreter_model`** — rejected: the
  one-shot-vs-multi-turn cost asymmetry is structural; once a durable split is
  established, pinning it via `--model` on every `dispatch run` recreates the
  env-file friction this ADR exists to remove.
- **Drop `LLMConfig` entirely** (CLI > env > default only) — rejected: loses the
  per-engagement durable tier; model choice would be ambient shell state.

## Consequences

- **`setup/config.py`** — `LLMConfig` loses `provider`, gains
  `interpreter_model: str | None = None`. Docstring rewritten; the ADR-0037
  mis-citation (which never covered provider routing) is dropped in favour of this
  ADR.
- **`setup/loader.py`** — persists `cfg.llm.model` / `cfg.llm.interpreter_model` as
  `llm_model` / `llm_interpreter_model` properties on the `Engagement` node. An
  `llm`-only diff is **cosmetic** (no confirm prompt). Idempotent per ADR-0019.
- **`planner/cli.py`** — `propose` gains `--model`. `_build_llm_deps()` resolves
  per the table above; reads `llm_model` off the `Engagement` node it already
  fetches (no `--config`). `api_base` resolves
  `DOO_PLANNER_API_BASE → DOO_LLM_API_BASE → None`.
- **`dispatch/cli.py`** — `run` gains `--model`. `_build_interpreter()` resolves
  per the table; `api_base` resolves
  `DOO_INTERPRETER_API_BASE → DOO_LLM_API_BASE → None`. The redundant
  `cfg.environment` read and the remaining `--config` dependency are unchanged
  here — see the parked follow-up below.
- **Migration** — `extra="forbid"` on `LLMConfig` means any YAML with
  `llm.provider:` will fail validation once the field is removed. The field was
  never read at runtime, so this is a grep-and-delete; no graph migration.
- **ADR-0037** — unchanged; it requires the *resolved* model id be persisted with
  every LLM request for replay/audit, and says nothing about how the id is chosen.
  This ADR is the missing reference for that.
- **`freelance` interpreter mode** (ADR-0042, post-MVP) mints `TestCase`s in-run —
  planner-shaped work inside the interpreter process. When it ships, it resolves
  against `llm_model` (the planner default), not `llm_interpreter_model`.
- **Parked, separate grill** — persist credential env-var refs + `DispatchConfig`
  on the graph so `dispatch run` / `auth-helper run` can drop `--config` and become
  id-only like `planner propose`. Touches ADR-0012 (var *names* on `AuthContext`
  nodes) and ADR-0019 (loader scope). Tracked in `docs/grill-queue.md`.
