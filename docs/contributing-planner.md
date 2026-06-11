# Contributing: the Planner (candidate generators + LLM proposals)

The Planner (slice 3, `src/doo/planner/`) turns coverage gaps into reviewable
`TestCase`s. It is the first slice with an LLM — and the LLM is fenced in hard:
**deterministic code selects targets, validates, and commits; the LLM only proposes
(enums + handle references, never request bytes).** This guide is how to add to it.

See `ARCHITECTURE.md` ("Build order") and ADRs 0036–0041 for the rationale.

## The pipeline (one `doo planner propose` run)

```
candidate generator → (context pack → LLM → resolve)? → PlannerProposal
                    → Validator → ValidatedTestCase → commit (review_status=proposed)
```

- **Candidate generators** (`generators.py`) select targets from a deterministic
  signal (usually the shared coverage library). Each is either:
  - **deterministic-proposing** — builds the `PlannerProposal` itself, no LLM
    (`C1Generator`: a dead endpoint → a `forced_browsing` probe); or
  - **LLM-proposing** — assembles a bounded **context pack**, calls the model for a
    structured draft, and resolves the draft's handles back to concrete ids
    (`C2`/`C2b`/`C3`/`C4`/`tenant`/`sink`).
- The **Validator** (`validator.py`) is the deterministic correctness core: it
  resolves the target, enforces scope via the shared `is_in_scope`, resolves the
  `payload_spec` to a real `payload_hash`, and computes the ADR-0007 `key_hash`. A
  bad proposal (hallucinated handle, out-of-scope, unresolvable payload) is
  **discarded and logged, never committed**.
- **Commit** (`commit.py`) MERGEs a content-addressed `TestCase`; re-proposing the
  same content is a no-op. LLM proposals commit `source = "llm-planner"`.

## Adding a deterministic-proposing generator

Mirror `C1Generator`: implement `generate(client, engagement_id, *, now) ->
[Candidate]` (read a deterministic signal, emit one `Candidate` per target with a
`reason`) and `propose(candidate) -> PlannerProposal` (fixed enums, no LLM).
Register the instance in `_REGISTRY` and add its id to `GeneratorId` /
`GENERATOR_IDS` (`models.py`). The service runs it with no model.

## Adding an LLM-proposing generator

This is the common case. Four pieces:

1. **A coverage/detection signal.** Reuse the shared library (`run_cN`) or a
   deterministic detector (`replay_hazards.py`, `sink_params.py`) — never have the
   LLM *find* targets. Add the coverage query first if it doesn't exist.
2. **A context-pack assembler** (`assemble.py`). Build a `ContextPack`: the target
   as a pack-local **handle** (`T1`, `kind ∈ {endpoint, parameter, boundary}`), the
   candidate auth contexts as handles (`A1`, attacker side marked), and a
   `candidate_reason`. **Id-free and secret-free** — `to_llm_dict()` strips raw node
   ids; bodies/tokens never appear, only claim *names* and safe shapes (ADR-0015).
   Carry the real ids on the typed objects (the resolver reads them); never serialise
   them into the prompt.
3. **A prompt + forced tool + resolver** (`llm.py`). Add a system prompt and a
   forced-tool schema (a constrained `test_class` enum for your gap) and route them
   in `_select_prompt_tool` by `candidate_kind`. The model returns an
   `LLMProposalDraft`; your `resolve_*_draft(pack, draft)` maps each handle back to a
   concrete id, **rejecting any handle absent from the pack** (the hallucination
   guard — `_reject(...)`), and fixes the payload deterministically (`payload_class`
   + `payload_spec`; the LLM never chooses bytes). Stamp the `generator` id.
4. **The generator** (`generators.py`). Implement the `LLMProposingGenerator`
   protocol — `run(client, engagement_id, *, now) -> LLMRunResult` — looping
   selection → assemble → `caller.propose(pack)` → `resolve_*_draft`, collecting
   `proposed` / `rejected` (resolver said no) / `skipped` (unproposable before any
   call). Add the id to `GeneratorId`/`GENERATOR_IDS`, `_LLM_GENERATOR_IDS`, and the
   `enabled_llm_generators` `builders` dict.

The Validator/commit usually need **no change** — but a new *target kind* or
*payload kind* does: see `_resolve_parameter` / `_resolve_boundary` and the
`observed_value` / `configured` resolvers in `validator.py` for the pattern (resolve
to an in-scope endpoint, then a real `payload_hash`). Neither `hold`/`replay_hazards`
nor the transformation strategy is part of `key_hash` (ADR-0007/0041).

## The contracts you must respect

- **No LLM in parsing, policy, validation, or payload construction** (CLAUDE.md).
  The model selects handles + classifies; everything else is deterministic.
- **`payload_spec` is never bytes** (ADR-0037): `none` (authz replays), or
  `observed_value(value_hash)` (C3), or `configured(config_key)` (sink). The
  Validator resolves it to a `payload_hash`.
- **Provenance + replayability**: every committed node carries `source`; every LLM
  call (committed or rejected) is persisted to object storage via the audit sink,
  keyed onto the node (`llm_audit_key`).
- **Test every LLM path with both a weak and a strong gateway model** and document
  the comparison — weak models expose contract ambiguities a strong model hides
  (this is how the `hold` and `test_class` prompt steers were found).

## Where things live

`models.py` (contracts + enums) · `generators.py` (generators + registry) ·
`assemble.py` (context packs) · `llm.py` (prompts, tools, callers, resolvers) ·
`validator.py` (resolution + scope + payload + identity) · `commit.py` (content-
addressed commit) · `prioritize.py` · `review.py` (lifecycle + ledger) ·
`service.py` (orchestration) · `cli.py` (`doo planner`).
