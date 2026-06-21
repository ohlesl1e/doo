# Ontology

**Status: work in progress.** Step 1 (entity catalog) is drafted; its three open questions are now resolved (see `CONTEXT.md` and `docs/adr/0001`–`0003`). Steps 2-6 are not yet started.

## What this is

The ontology is the contract between the deterministic pipeline and the LLM. When the planner asks "what should I test next?" it queries this graph, not raw logs. The vocabulary of the ontology defines what the planner can reason about. If we don't model "tenant boundary," the planner cannot propose cross-tenant tests.

It is three things stacked:

1. **A schema** — the types of things and their properties.
2. **A relationship catalog** — how things connect.
3. **A set of rules and invariants** — constraints that hold across the data.

## Black-box constraint

Everything in the graph is an observation or an inference from observations. No declarative seeding. Implications:

- **Provenance and confidence are first-class.** Every node and edge knows where it came from (Burp / agent / nuclei / inferred) and how certain it is.
- **The ontology must represent ignorance.** A black-box tester's most important question is often "what don't I know?" Gaps are explicit: parameters seen in responses but never sent as inputs, hosts referenced but never probed, auth contexts observed but never exercised against specific endpoints. These are nodes in a "suspected but unconfirmed" state, not absences in the graph.
- **Inference is a graph operation.** When the system concludes "this parameter is probably a tenant ID," that conclusion is a node or labeled edge with its own provenance and confidence. Inferences can be wrong and need to be retractable without losing the underlying observations.

## Runtime flow

```
Raw input
   │
   ▼
Extraction parses to intermediate entities
   │
   ▼
Ontology layer:
   - Match against existing nodes (entity resolution)
   - Create or update nodes/edges
   - Validate invariants
   - Emit events for downstream consumers
   │
   ▼
Available for query by:
   - Planner (what to test)
   - Coverage analyzer (what's been touched)
   - Policy engine (scope/ROE references)
   - Reporting (finding traceability)
```

Concrete example. A streamed Burp request:

```
POST /api/v2/orgs/42/projects HTTP/1.1
Authorization: Bearer eyJ...
Content-Type: application/json

{"name": "test", "visibility": "private"}
```

The ontology layer decides:

- Is there already an `Endpoint(POST, /api/v2/orgs/{org_id}/projects)` node, or is this new? (Path templating: `/orgs/42` and `/orgs/43` should collapse to the same Endpoint with `org_id` as a path parameter.)
- Is the `AuthContext` represented by that bearer token already known? Link this request to it.
- Are `name` and `visibility` known `Parameter` nodes for this endpoint? If not, create them with observed types.
- What `Principal` does this token represent? Do we know its role/tenant from prior responses?

That decision logic — entity resolution, deduplication, relationship inference — is the meat of the ontology layer.

## Design tensions to resolve

These show up everywhere. Naming them upfront prevents going in circles.

- **Granularity.** Is `/orgs/42/projects` one Endpoint or two? Too coarse loses hierarchy; too fine explodes the graph.
- **Identity.** What makes two things the same? Trailing slashes, version prefixes, query string variants.
- **Closed vs. open world.** Absence of a fact = false, or just unknown? In security, "no Finding on this Endpoint" could mean secure OR untested. The ontology must distinguish.
- **Time.** Endpoints change, parameters appear and disappear, auth contexts expire. Start simple with `first_seen` / `last_seen` timestamps on everything. Bitemporal modeling if/when needed.
- **Provenance.** Every node and edge knows its source.
- **Confidence.** Some relationships are certain ("this request hit this endpoint"); others inferred ("this parameter is probably a tenant ID"). Confidence lets the planner weight things.

## Step 1: Entity catalog (DRAFT)

Marked **core** (essential), **probable** (likely needed), or **deferred** (later).

### Target surface — what exists out there

- **`Host`** *(core)* — a network identity (`api.example.com`). Distinct from Scope: one Scope can include multiple Hosts; one Host can appear in multiple Scopes over time.
- **`Endpoint`** *(core)* — `(method, path-template, host)` triple. `POST /api/v2/orgs/{org_id}/projects` on `api.example.com`. The unit the planner reasons about.
- **`Parameter`** *(core)* — a named input to an Endpoint. Location (path / query / header / body / cookie), name, observed types, observed value patterns.
- **`Asset`** *(probable — OPEN QUESTION 1)* — a backend resource referenced but not directly addressable. Leaked bucket names, internal hostnames in error messages, database identifiers. Leads, not directly testable, but they often become Hosts/Endpoints later.

### Identity & access — who's acting

- **`Principal`** *(core)* — an identity the tester controls or observes. "Test user A," "admin account," "anonymous." The actor, not the credential.
- **`AuthContext`** *(core)* — a specific authenticated state. Bearer token, session cookie, API key. Belongs to a Principal; has a validity window; has observed scopes/roles.
- **`Role` / `Permission`** *(deferred)* — only if explicit RBAC modeling becomes necessary. Often AuthContext with observed-capability tags is enough.

### Observations — what we saw

- **`RequestObservation`** *(core)* — a single concrete HTTP exchange. Full request/response (or references to blobs in object storage), timestamp, source (Burp / agent / nuclei), AuthContext used, Endpoint hit.
- **`ResponseArtifact`** *(probable)* — things found in responses worth tracking independently: identifiers, URLs, error messages, technology fingerprints. Important for black-box work: "this response leaked X" → "this other endpoint takes X as input" is how a lot of "what next" reasoning happens.

### Inferences — what we think we know

- **`ParameterSemantic`** *(probable)* — an inferred meaning for a Parameter. "This `org_id` is probably a tenant identifier." Distinct from Parameter because inference is separate from observation.
- **`TrustBoundary`** *(probable — OPEN QUESTION 2)* — an inferred boundary where authorization should change. Between Principals, between tenants, between user/admin scopes. The planner uses these to propose boundary-violation tests.

### Testing — what we did and found

- **`TestCase`** *(core)* — a proposed or executed test. Class (IDOR, SSRF, auth-bypass-variant), target (usually Endpoint + Parameter), payload reference, expected vs. observed outcome, status (proposed / approved / executed / completed). Identity is content-addressed over `(engagement_id, test_class, target_*, payload_class, payload_hash, attacker_principal, attacker_slot)` — the rotation-stable credential **slot**, not `auth_context_id`, which is non-key evidence (ADR-0007 + ADR-0049).
- **`Payload`** *(core — OPEN QUESTION 3)* — a specific input used in a test. Separated from TestCase to enable reasoning about payload classes for ROE enforcement.
- **`Finding`** *(core)* — a confirmed vulnerability. Severity, category, references the TestCase(s) that demonstrated it, the Endpoint(s) affected.

### Scope & engagement — where we're allowed

- **`Scope`** *(core)* — the boundary of an engagement. Internal-product-X-staging, or bug-bounty-program-Y. Rules: which Hosts, which methods, which payload classes, rate limits, time windows. Read by the ROE layer.
- **`Engagement`** *(probable)* — a specific testing campaign within a Scope. Useful for separating "the IDOR hunt last Tuesday" from "the auth review last month" when querying findings.

### Coverage — what's been touched

**Not a node type.** Derived view from RequestObservations, TestCases, and the Endpoints/Parameters they reference. Schema must support the queries efficiently.

### Deliberately excluded (with rationale)

- **No `Vulnerability` separate from `Finding`** — Findings are vulnerabilities in our data. CVE/CWE classification is a property of the Finding.
- **No `User` or `Account`** — domain-specific to each target. `Principal` is the abstract concept; what counts as a user is captured through observed AuthContext properties.
- **No `Session` separate from `AuthContext`** — a session is just an AuthContext with a particular validity model. Adding it now is premature.
- **No `VulnerabilityClass` as a node** — test class names (IDOR, SSRF, etc.) are enums/tags on TestCases. Promote later if needed for reasoning about relationships between classes.

## Open questions (Step 1) — all resolved

### OPEN QUESTION 1: `Asset` as a node type — yes or no?

- **For:** in real testing, a lot of time is spent chasing leads (leaked bucket name, internal hostname in error message) that aren't yet testable but might become so. Modeling them lets the planner say "we saw `internal-billing.corp.example` referenced 4 times but never reached it."
- **Against:** category can sprawl. Risk of becoming a dumping ground.
- **RESOLVED — yes, keep it.** `Asset` is the *inference* layer; `ResponseArtifact` is the *observation* layer that evidences it (the same observation→inference pattern as `RequestObservation`→`Endpoint`). Sprawl lands in `ResponseArtifact`, which is fine; promotion to `Asset` requires an inference step with confidence. See `CONTEXT.md` and ADR-0001.

### OPEN QUESTION 2: `TrustBoundary` as a node vs. as a relationship

- **As a node:** easier to attach properties and findings to. Easier to query "show me all boundaries with no boundary-violation tests."
- **As a labeled edge between AuthContexts or Principals:** more natural for traversal.
- **RESOLVED — node.** Decisive reason: a Neo4j relationship can't be an endpoint of another relationship, so an edge couldn't carry an attached `Finding` or be a `TestCase` target. Two tiers by `kind`: *identity* boundaries between `Principal`s, *capability* boundaries between `AuthContext`s of the same Principal (the latter is what the "auth state transitions not exercised" coverage query needs). See `CONTEXT.md` and ADR-0002.

### OPEN QUESTION 3: How explicit should Payloads be?

- **Maximalist:** every payload string the system has considered is a node; payloads have categories; queries like "show every test that used a payload from `destructive-sql`" are possible. Pays off when writing ROE policies like "no payload from class X against scope Y" — OPA can evaluate against actual graph state.
- **Minimalist:** Payload is just a property on TestCase.
- **RESOLVED — neither; the first-class concept is `PayloadClass`.** The maximalist premise was wrong: OPA evaluates the *proposed request* (its `PayloadClass` travels in `input`), not graph state, so no payload-string nodes are needed for ROE. `PayloadClass` is a tag/enum (promote to a node only for class-to-class relationships); the payload instance is a property/reference on the TestCase; a reusable payload library is deferred. See `CONTEXT.md`, ADR-0003, and the ROE split in `ARCHITECTURE.md`.

## Step 2: Relationship catalog (DRAFT)

Every edge in the graph, with cardinality and notes. Cardinality reads as `(source : target)`. All edges carry the cross-cutting fields (Step 4). Inference edges — those establishing a derived fact, like `HIT`, `EVIDENCES`, `CONTAINS_VALUE`, `DERIVED_FROM`, `BETWEEN`, `PROMOTED_TO` — additionally carry `inferred_at` and `code_version` and are **revisable**.

Edge-naming convention: `VERB` for actions (`HIT`, `YIELDED`, `EXECUTED_AS`, `REFERENCES`), `OF_*` / `IN_*` / `ON_*` for membership, `DERIVED_FROM` / `PROMOTED_TO` / `BETWEEN` for inference structure.

### Target surface

| Edge | From | To | Cardinality | Notes |
|---|---|---|---|---|
| `ON_HOST` | `Endpoint` | `Host` | N:1, mandatory | Endpoint identity includes Host; different ports on the same hostname are distinct Hosts. |
| `HIT` | `RequestObservation` | `Endpoint` | N:1, revisable | Each RO HITs exactly one Endpoint at a given time. Revisable when path-templating re-groups (ADR-0004). |
| `YIELDED` | `RequestObservation` | `ResponseArtifact` | 1:N | Each RO produces zero or more artifacts (one per identifier / URL / error / fingerprint extracted). |
| `EVIDENCES` | `ResponseArtifact` | `Asset` | M:N | Promotion evidence — many artifacts can evidence one Asset; an Asset can be evidenced by many. |
| `PROMOTED_TO` | `Asset` | `Host` *or* `Endpoint` | 0..1 → N:0..N | Set when an Asset becomes reachable. The Asset node is kept (lineage preserved); the edge points to the realized entity. |
| `CONTAINS_VALUE` | `ResponseArtifact` | `ObservedValue` | M:N | Promoted values found in responses (ADR-0009). |
| `SAME_VALUE_AS` | `Asset` | `ObservedValue` | M:N, optional | Connects an Asset to the ObservedValue carrying the same underlying string when both exist (ADR-0011). Lets queries pivot between lead-status and cross-context views. |
| `HAS_PARAMETER` | `Endpoint` | `Parameter` | 1:N | An Endpoint's observed input positions; each `Parameter` belongs to exactly one Endpoint. Enables `ParameterSemantic -[:DERIVED_FROM]-> Parameter`. |

### Identity & access

| Edge | From | To | Cardinality | Notes |
|---|---|---|---|---|
| `USED_AUTH` | `RequestObservation` | `AuthContext` | N:1, mandatory | Every RO has exactly one AuthContext (anonymous is its own AuthContext). |
| `OF_PRINCIPAL` | `AuthContext` | `Principal` | N:1, mandatory | Each AuthContext belongs to exactly one Principal. (Renamed from `BELONGS_TO` to disambiguate from the TestCase→Engagement edge.) |
| `OF_TENANT` | `Principal` | `Tenant` | M:N, optional | Multi-org membership is normal; single-tenant targets just have zero edges (ADR-0008). |
| `BETWEEN` | `TrustBoundary` | `Tenant` / `Principal` / `AuthContext` | exactly 2 edges per TrustBoundary, **polymorphic by `kind`** | `kind=tenant` → Tenant; `role`/`ownership` → Principal; capability tier → AuthContext. ADR-0002 refined by ADR-0008. |

### Action & findings

| Edge | From | To | Cardinality | Notes |
|---|---|---|---|---|
| `TARGETS_ENDPOINT` | `TestCase` | `Endpoint` | N:1 | Route-level test (whole Endpoint, no specific Parameter). **3-way XOR** with `TARGETS_PARAMETER` / `TARGETS_BOUNDARY`. |
| `TARGETS_PARAMETER` | `TestCase` | `Parameter` | N:1 | Parameter-level test. The Endpoint is reachable via `HAS_PARAMETER`. **3-way XOR** with `TARGETS_ENDPOINT` / `TARGETS_BOUNDARY`. |
| `TARGETS_BOUNDARY` | `TestCase` | `TrustBoundary` | N:1 | Boundary test. **3-way XOR** with `TARGETS_ENDPOINT` / `TARGETS_PARAMETER`. |
| `AFFECTS` | `Finding` | `Endpoint` *or* `TrustBoundary` | M:N | The thing(s) the finding affects, polymorphic. *Not* XOR — a Finding can affect both Endpoints *and* a TrustBoundary (e.g. a cross-tenant data leak). At least one `AFFECTS` edge required per Finding. |
| `EXECUTED_AS` | `TestCase` | `RequestObservation` (with `source = "agent"`) | 1:N | Retries / parameter sweeps add edges, not new TestCases (ADR-0006). |
| `SENT_VALUE` | `RequestObservation` | `ObservedValue` | M:N | Edge property `parameter_name`. The value-as-input side of C3 (ADR-0009). |
| `IN_ENGAGEMENT` | `TestCase` | `Engagement` | N:1, mandatory | Engagement is part of the TestCase identity hash (ADR-0007). (Renamed from `BELONGS_TO`.) |
| `REFERENCES` | `Finding` | `TestCase` | M:N | A Finding may reference multiple TestCases that together demonstrated it. |

### Scope & engagement

| Edge | From | To | Cardinality | Notes |
|---|---|---|---|---|
| `INCLUDES_HOST` | `Scope` | `Host` | M:N | Materialized as Hosts are discovered to match `host_patterns`. Endpoint-in-Scope is *not* materialized — derived at query time (gap #1). |
| `UNDER_SCOPE` | `Engagement` | `Scope` | N:1, mandatory | One Scope per Engagement; a campaign that straddles scopes must split into multiple Engagements. |

### Cross-cutting

| Edge | From | To | Cardinality | Notes |
|---|---|---|---|---|
| `DERIVED_FROM` | any inference node | any observation node | ≥1 per inference, M:N overall | Lineage backbone (ADR-0001). Every inference has at least one edge to an evidencing observation; observations can feed many inferences. |

### Invariants implied by the catalog (preview of Step 5)

- A `RequestObservation` has **exactly one** `HIT` edge and **exactly one** `USED_AUTH` edge.
- A `TestCase` has **exactly one** of (`TARGETS_ENDPOINT` xor `TARGETS_PARAMETER` xor `TARGETS_BOUNDARY`), **exactly one** `IN_ENGAGEMENT`.
- A `Finding` has **at least one** `AFFECTS` edge (to an `Endpoint` or `TrustBoundary`) and **at least one** `REFERENCES` edge to a `TestCase`.
- An `Endpoint` has **zero or more** `HAS_PARAMETER` edges; each `Parameter` has **exactly one** incoming `HAS_PARAMETER`.
- A `TrustBoundary` has **exactly two** `BETWEEN` edges; both endpoints have the type expected by its `kind`.
- For a `TrustBoundary` with `kind ∈ {scope, mfa, freshness}` (capability tier), both endpoint `AuthContext`s' `OF_PRINCIPAL` targets must be the **same** `Principal`.
- Every inference node has **at least one** `DERIVED_FROM` edge.
- An `Engagement` references **exactly one** `Scope` via `UNDER_SCOPE`.
- An `Endpoint` has **exactly one** `ON_HOST`.
- An `AuthContext` has **exactly one** `OF_PRINCIPAL`.

Step 5 will turn these into Pydantic validators + Cypher property/relationship-existence constraints.

## Step 3: Identity rules (DRAFT)

Per-node-type rules for what makes two instances the same. `TestCase` (Gap #4, ADR-0007) and `ObservedValue` (Gap #2, ADR-0009) are documented in their Step 6 gap resolutions and not duplicated here. `AuthContext`, `Tenant`, `Host`, `Asset` are still pending.

### Endpoint

Endpoint identity is a **revisable inference**, not a value frozen at ingest (ADR-0004). The concrete path lives on `RequestObservation`; the template lives on `Endpoint`; the `HIT` edge (which observation belongs to which template) is the inference that gets revised. Re-templating re-groups edges — it never moves or destroys observations.

**Identity key:** `(method, host, path-template)`.

**Canonicalization** (applied before templating; the raw concrete path is always kept on the `RequestObservation`):

- **Query string excluded** — query inputs are `Parameter`s (location=query), not part of path identity.
- **Trailing slash** stripped (`/projects` ≡ `/projects/`).
- **Host** lowercased, default port dropped (`:443` on https); non-default ports kept; an IP is a different Host from a hostname.
- **Percent-encoding** normalized per RFC 3986 — decode unreserved, uppercase hex, remove dot-segments.
- **Path case preserved** — paths are case-sensitive per spec; never lowercased.

**Normalization-discrepancy signal:** when two raw concrete paths that canonicalize to the *same* Endpoint return materially different responses (status, auth outcome, body shape), raise a discrepancy signal instead of treating them as interchangeable. Case/slash/encoding ACL inconsistencies are themselves vulnerabilities (auth bypass, path traversal); collapsing them silently would delete the finding.

**Deriving the template (deterministic, primary):**

- Build a trie over observed concrete paths.
- **Multiplicity:** a position taking ≥2 distinct values with the rest of the path fixed (siblings that reconverge to the same continuation) collapses to a parameter.
- **Cold-start prior (value shape):** on a single observation, ID-like segments (UUID, hash, long/sequential int) are templated as params at low confidence; ordinary words stay literal. Multiplicity later confirms and raises confidence.
- **Confidence** = f(distinct values seen, ID-likeness of those values). Drives planner weighting and keeps retraction cheap.

**Guards & special cases:**

- **Version segments** (`v\d+`) stay literal even under multiplicity. Plus a per-engagement literal allowlist.
- **Mixed position:** a position may be both a parameter and host literal sibling routes. `/users/{user_id}` and `/users/settings` coexist; the literal match wins (router precedence).
- **Self-reference values:** `me`/`current`/`self` are values of the parameter, flagged self-reference — authz-relevant for IDOR.

**LLM role:** entity resolution may *propose* a template for ambiguous segments (L3, allowed); it is recorded with `source: "llm-…"` and confidence. Deterministic multiplicity stays primary.

### Principal

Two-tier identity, revisable (ADR-0010) — same observation→inference pattern as `Endpoint`, but with two populations of Principals coexisting per Engagement.

**Declared Principals** (we control them — `test_user_a`, `admin`, `anonymous`):

- Identity = a manual label set at engagement config.
- `source = "manual"`, `confidence = 1.0`.
- Any known signals (JWT `sub`, `/me` id, headers, email) are recorded as identity hints used for later reconciliation.

**Discovered Principals** (actors observed in passive traffic):

- Identity = the strongest available stable signal, in priority order:
  1. **JWT `sub` claim** parsed from the AuthContext.
  2. **Observed user-id** from a `/me` / `/whoami` introspection response, extracted as an `ObservedValue` tied to the AuthContext that fetched it.
  3. **Stable identifying header** — `X-User-Id`, `X-Actor`, etc.
  4. **Email** observed in responses tied to the AuthContext (weaker; emails can be aliased).
  5. **Synthetic fallback** seeded from the first observed AuthContext's `auth_hash`, low confidence, flagged `unmerged`.
- The synthetic fallback id is *deterministic* over the first AuthContext's hash, so re-ingesting the same traffic produces the same synthetic Principal — important for replay.

**Reconciliation.** When a discovered signal matches a declared Principal's known one, the discovered `AuthContext` resolves to the **declared** Principal — no phantom twin gets created.

**Merging two synthetics later proven the same** (e.g., a JWT `sub` surfaces tying them) is **`OF_PRINCIPAL` edge re-pointing**, not node deletion:

1. Move every `OF_PRINCIPAL` edge from the orphan to the survivor.
2. Mark the orphan node `status = "retracted"`, keep its `DERIVED_FROM` edges intact (lineage preserved per ADR-0001).
3. Step 5 invariants enforce that an `AuthContext` always has exactly one `OF_PRINCIPAL` edge, including across merges.

**Anonymous is a singleton per Engagement.** All unauthenticated requests `USED_AUTH` → one anonymous `AuthContext` → one anonymous `Principal`. Anonymity has no identity; synthesizing differentiated anonymous Principals (e.g., one per IP) would invent identity we don't have.

### AuthContext

Content-addressed on the credential:

```
auth_hash = sha256( token_kind || ":" || token_value )
token_kind ∈ { bearer, cookie, api_key, basic_auth, anonymous }
```

The raw `token_value` is **never persisted** in the graph — only the hash, plus parsed claims (JWT `sub` / `exp` / `scope`), observed capabilities, and a validity window. Same secrets-handling discipline as ADR-0009. Token rotation produces a new AuthContext with a different `auth_hash`; the new and old both keep `OF_PRINCIPAL` to the same Principal via the Principal-reconciliation rule (ADR-0010). Anonymous AuthContexts use sentinel `sha256("anonymous:" + engagement_id)`.

### Tenant

Content-addressed on `(kind, normalized_value)`:

```
kind ∈ { org_id, workspace, account_namespace, subdomain, … }
normalized_value  e.g. "42" (from /orgs/42), "acme-corp" (from JWT org claim), "acme.example.com" (from subdomain)
```

Merging mechanic: when the same tenant is later revealed under an alternate identifier (URL position *and* JWT claim pointing at one tenant), `OF_TENANT` edges re-point to the surviving Tenant; the orphan is marked `retracted`, lineage preserved — same mechanic as Principal-merge (ADR-0010).

### Host

Content-addressed on `(canonical_hostname, port)` with the canonicalization rules from Endpoint's identity work:

- lowercase hostname,
- ToASCII for IDN (punycode),
- strip trailing dot on FQDNs,
- strip default port (`:443` https, `:80` http); keep non-default ports,
- IP literals stay distinct from hostnames (never resolved).

### Asset

Content-addressed on `(kind, normalized_value)`:

```
kind ∈ { internal_hostname, bucket_name, database_id, signed_url, internal_path, … }
```

`Asset` and `ObservedValue` **coexist as distinct node types** (ADR-0011) and may refer to the same underlying string. When they do, an optional `Asset -[:SAME_VALUE_AS]-> ObservedValue` edge connects them, letting queries pivot between the lead-status view (`Asset`, C6) and the cross-context-value view (`ObservedValue`, C3). The merge-via-re-pointing mechanic applies here too: when alternate identifiers reveal sameness, edges move to the surviving Asset and the orphan is marked retracted.

## Step 4: Cross-cutting properties (DRAFT)

Provenance, confidence, and time apply to **every node and every edge**. To make "no exceptions" actually true (CLAUDE.md), the field set is defined here once and enforced by a Pydantic mixin plus matching Cypher property-existence constraints. See ADR-0005.

### The seven fields (on every node and every edge)

| Field | Type | Meaning |
|---|---|---|
| `source` | `str` | Origin tag — `burp`, `har`, `nuclei`, `deterministic-templating`, `llm-asset-promotion`, … A flat string so filtering stays cheap (`WHERE source = 'burp'`). |
| `source_id` | `str?` | Within-source identifier (Burp item UUID, HAR entry hash, LLM request id). Lets debugging navigate back to the original artifact. |
| `confidence` | `float` in `[0,1]` | How sure we are. Observations at `1.0` *when parser validation was clean* (a flagged parse carries less); inferences below. Set at creation, **never re-written for decay**. |
| `confidence_method` | enum | `heuristic` / `manual` / `llm-self-reported` / `calibrated`. Carried alongside the number so queries can discount LLM scores in aggregate without parsing `source` strings. |
| `first_seen` | `datetime` | **Event time** — earliest evidence of the fact. For observations, the request's own timestamp. For inferences, the `min` over contributing observations. |
| `last_seen` | `datetime` | **Event time** — latest evidence. Updated on every new contributing observation. |
| `ingested_at` | `datetime` | **Transaction time** — when *we* recorded it. Diverges from `first_seen` when older artifacts are uploaded (old HAR files). Needed for replay/audit ("what did the agent know at time T?"). |

### Two more fields, only on inferences

| Field | Type | Meaning |
|---|---|---|
| `inferred_at` | `datetime` | When the inference was *computed* (vs `first_seen`, which is when the *evidence* dates from). |
| `code_version` | `str` | Algorithm/prompt version that produced it. When heuristics change, this identifies what is stale and re-derivable. |

### Lineage via edges, not properties

Every inference node has explicit **`DERIVED_FROM`** edges back to each observation that contributed. Lineage is a Cypher path traversal, not a denormalized list-of-ids on the node. Concretely: `Endpoint` → its contributing `RequestObservation`s; `Asset` → its evidencing `ResponseArtifact`s; `TrustBoundary` → the `Principal`/`AuthContext` observations that inferred it.

### Decay at query time, not in storage

`confidence` is set once. Consumers (planner, coverage analyzer) compute *effective* confidence at query time from `confidence` and `last_seen` — e.g. `confidence * exp(-age_days / half_life)`. This avoids re-writing the graph on every tick, keeps the audit trail intact, and makes the decay shape tunable per consumer.

### Enforcement

- A `Provenanced` Pydantic mixin every entity model inherits — guards the application boundary.
- Matching Cypher constraints (`CREATE CONSTRAINT FOR (n:Entity) REQUIRE n.source IS NOT NULL`, …) — guards the graph if a future code path slips.

## Step 5: Invariants (DRAFT)

Three layers of enforcement, each catching a different class of violation:

1. **Pydantic validators** — at the application boundary; misshape rejected before reaching the graph.
2. **Cypher constraints** — defense in depth at the graph boundary (uniqueness + required-field existence).
3. **Invariant queries** — for cardinalities and cross-node rules Neo4j can't natively enforce; run as pre-commit hooks on the hot path, or as a periodic drift-detection pass.

This step extends Step 4 by adding one field: **`status: "active" | "retracted"`** on every node. Retraction is a flag, not deletion — orphaned nodes from merges (Principal/Asset/Tenant) stay for audit/lineage; planner queries filter to `status = "active"` by default.

### Pydantic — the base mixins

```python
class Provenanced(BaseModel):
    """Every entity inherits. The seven Step-4 fields + status."""
    source: str = Field(min_length=1)
    source_id: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_method: Literal["heuristic", "manual", "llm-self-reported", "calibrated"]
    first_seen: datetime
    last_seen: datetime
    ingested_at: datetime
    status: Literal["active", "retracted"] = "active"

    @model_validator(mode="after")
    def _times_monotone(self) -> Self:
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be <= last_seen")
        return self


class Inferred(Provenanced):
    """Inference-layer entities add two fields."""
    inferred_at: datetime
    code_version: str = Field(min_length=1)
```

### Cypher — uniqueness + required-field existence

```cypher
-- Required-field existence on every entity (the seven cross-cutting + status)
CREATE CONSTRAINT entity_source         FOR (n:Entity) REQUIRE n.source IS NOT NULL;
CREATE CONSTRAINT entity_confidence     FOR (n:Entity) REQUIRE n.confidence IS NOT NULL;
CREATE CONSTRAINT entity_conf_method    FOR (n:Entity) REQUIRE n.confidence_method IS NOT NULL;
CREATE CONSTRAINT entity_first_seen     FOR (n:Entity) REQUIRE n.first_seen IS NOT NULL;
CREATE CONSTRAINT entity_last_seen      FOR (n:Entity) REQUIRE n.last_seen IS NOT NULL;
CREATE CONSTRAINT entity_ingested_at    FOR (n:Entity) REQUIRE n.ingested_at IS NOT NULL;
CREATE CONSTRAINT entity_status         FOR (n:Entity) REQUIRE n.status IS NOT NULL;

-- Identity uniqueness, one per node type (Step 3)
CREATE CONSTRAINT testcase_unique       FOR (n:TestCase)      REQUIRE n.key_hash IS UNIQUE;
CREATE CONSTRAINT authcontext_unique    FOR (n:AuthContext)   REQUIRE n.auth_hash IS UNIQUE;
CREATE CONSTRAINT observedvalue_unique  FOR (n:ObservedValue) REQUIRE n.value_hash IS UNIQUE;
CREATE CONSTRAINT host_unique           FOR (n:Host)          REQUIRE (n.canonical_hostname, n.port) IS UNIQUE;
CREATE CONSTRAINT asset_unique          FOR (n:Asset)         REQUIRE (n.kind, n.normalized_value) IS UNIQUE;
CREATE CONSTRAINT tenant_unique         FOR (n:Tenant)        REQUIRE (n.kind, n.normalized_value) IS UNIQUE;
CREATE CONSTRAINT endpoint_unique       FOR (n:Endpoint)      REQUIRE (n.method, n.host_id, n.path_template) IS UNIQUE;
CREATE CONSTRAINT principal_unique      FOR (n:Principal)     REQUIRE (n.engagement_id, n.identity_key) IS UNIQUE;
```

Principal uses a derived `identity_key` (the manual label for declared, the priority-list hash for discovered) so one constraint covers both tiers.

### Relationship cardinalities — invariant queries

Neo4j cannot natively enforce "node X must have ≥1 outgoing edge Y". These run as **pre-commit hooks** in the writer for hot-path rules, plus a **periodic full-graph pass** for drift detection.

```cypher
-- RO has exactly one HIT and one USED_AUTH
MATCH (r:RequestObservation)
WHERE size([(r)-[:HIT]->() | 1]) <> 1
   OR size([(r)-[:USED_AUTH]->() | 1]) <> 1
RETURN r;

-- Endpoint has exactly one ON_HOST
MATCH (e:Endpoint)
WHERE size([(e)-[:ON_HOST]->() | 1]) <> 1
RETURN e;

-- AuthContext has exactly one OF_PRINCIPAL
MATCH (a:AuthContext)
WHERE size([(a)-[:OF_PRINCIPAL]->() | 1]) <> 1
RETURN a;

-- TestCase: exactly one IN_ENGAGEMENT, exactly one of (TARGETS_ENDPOINT xor TARGETS_PARAMETER xor TARGETS_BOUNDARY)
MATCH (t:TestCase)
WITH t,
     size([(t)-[:IN_ENGAGEMENT]->() | 1]) AS eng,
     size([(t)-[:TARGETS_ENDPOINT]->() | 1]) AS e,
     size([(t)-[:TARGETS_PARAMETER]->() | 1]) AS p,
     size([(t)-[:TARGETS_BOUNDARY]->() | 1]) AS b
WHERE eng <> 1 OR (e + p + b) <> 1
RETURN t;

-- Finding: ≥1 REFERENCES TestCase AND ≥1 AFFECTS (Endpoint | TrustBoundary)
MATCH (f:Finding)
WHERE size([(f)-[:REFERENCES]->(:TestCase) | 1]) = 0
   OR size([(f)-[:AFFECTS]->() | 1]) = 0
RETURN f;

-- AFFECTS edge target must be Endpoint or TrustBoundary
MATCH (f:Finding)-[:AFFECTS]->(x)
WHERE NOT (x:Endpoint OR x:TrustBoundary)
RETURN f, x;

-- HAS_PARAMETER: each Parameter has exactly one incoming HAS_PARAMETER
MATCH (p:Parameter)
WHERE size([()-[:HAS_PARAMETER]->(p) | 1]) <> 1
RETURN p;

-- TrustBoundary has exactly two BETWEEN
MATCH (b:TrustBoundary)
WHERE size([(b)-[:BETWEEN]->() | 1]) <> 2
RETURN b;

-- Engagement has exactly one UNDER_SCOPE
MATCH (e:Engagement)
WHERE size([(e)-[:UNDER_SCOPE]->() | 1]) <> 1
RETURN e;

-- ResponseArtifact has exactly one incoming YIELDED
MATCH (r:ResponseArtifact)
WHERE size([()-[:YIELDED]->(r) | 1]) <> 1
RETURN r;

-- Agent-source RequestObservation has exactly one incoming EXECUTED_AS
MATCH (r:RequestObservation {source: 'agent'})
WHERE size([()-[:EXECUTED_AS]->(r) | 1]) <> 1
RETURN r;

-- Every inference node has at least one DERIVED_FROM
MATCH (n)
WHERE any(l IN labels(n) WHERE l IN
      ['Endpoint','ParameterSemantic','Asset','TrustBoundary','Tenant','ObservedValue','Finding'])
  AND NOT (n)-[:DERIVED_FROM]->()
RETURN n;

```

### Polymorphism — TrustBoundary `BETWEEN` endpoints match `kind`

```cypher
-- kind=tenant → both endpoints are Tenant
MATCH (b:TrustBoundary {kind: 'tenant'})-[:BETWEEN]->(x)
WHERE NOT x:Tenant
RETURN b, x;

-- kind in {role, ownership} → both endpoints are Principal
MATCH (b:TrustBoundary)-[:BETWEEN]->(x)
WHERE b.kind IN ['role','ownership'] AND NOT x:Principal
RETURN b, x;

-- kind in {scope, mfa, freshness} (capability tier) → both endpoints are AuthContext
MATCH (b:TrustBoundary)-[:BETWEEN]->(x)
WHERE b.kind IN ['scope','mfa','freshness'] AND NOT x:AuthContext
RETURN b, x;

-- Capability tier: both AuthContexts share the same Principal
MATCH (b:TrustBoundary)-[:BETWEEN]->(a1:AuthContext),
      (b)-[:BETWEEN]->(a2:AuthContext)
WHERE b.kind IN ['scope','mfa','freshness']
  AND elementId(a1) < elementId(a2)
  AND NOT EXISTS { MATCH (a1)-[:OF_PRINCIPAL]->(p)<-[:OF_PRINCIPAL]-(a2) }
RETURN b;
```

### Hash-content invariants (Pydantic, per node type)

Every content-addressed node must verify its hash matches its fields. Sketch for `TestCase`:

```python
class TestCase(Inferred):
    engagement_id: str
    test_class: str
    target_endpoint_id: str | None = None
    target_parameter_id: str | None = None
    target_trust_boundary_id: str | None = None
    payload_class: str
    payload_hash: str
    attacker_principal: str  # ADR-0049: rotation-stable attacker identity
    attacker_slot: str
    auth_context_id: str  # non-key evidence; rotates per token
    key_hash: str

    @model_validator(mode="after")
    def _target_xor(self) -> Self:
        targets = [
            self.target_endpoint_id is not None,
            self.target_parameter_id is not None,
            self.target_trust_boundary_id is not None,
        ]
        if sum(targets) != 1:
            raise ValueError(
                "TestCase target is exactly one of "
                "target_endpoint_id / target_parameter_id / target_trust_boundary_id"
            )
        return self

    @model_validator(mode="after")
    def _key_hash_matches(self) -> Self:
        if self.key_hash != compute_testcase_key_hash(self):
            raise ValueError("key_hash does not match content")
        return self
```

Parallel validators for `AuthContext.auth_hash` (which also enforces the `token_value`-never-stored rule by simply not having that field), `ObservedValue.value_hash`, `Host`/`Asset`/`Tenant` composite-identity equality.

### Time invariants

- `first_seen ≤ last_seen` (Pydantic, strict).
- For inference nodes, `first_seen` = `min(DERIVED_FROM observations' first_seen)`, `last_seen` = `max(...)` — recomputed on every new `DERIVED_FROM` edge (app-layer, soft).
- For inference nodes, `inferred_at ≥ max(contributing observations' ingested_at)` — sanity check, soft (warn, don't reject).
- On a merge: surviving node's `first_seen` = `min(orphan.first_seen, survivor.first_seen)`, `last_seen` = `max(...)`.

### Retraction invariants

- Default planner / coverage queries filter `WHERE n.status = "active"`. Audit and replay queries can opt out.
- A node marked `retracted` must have **zero** *active* edges of the type that originally referenced it. Concretely: a retracted Principal has zero active `OF_PRINCIPAL` incoming edges (they've all been re-pointed to the surviving Principal); same for Asset/Tenant.
- Retraction does **not** propagate transitively — retracting an Endpoint does not retract its `HIT`ing RequestObservations; those stay, and the `HIT` edges re-point to whatever new Endpoint absorbs them.

### Strict vs eventual

Two classes of invariant, enforced differently:

- **Strict** (must hold *at all times*) — uniqueness, field existence, time monotonicity, hash-content match. Native Pydantic + Cypher. Violations are errors.
- **Eventual** (may briefly violate during a multi-step write, must hold post-commit) — relationship cardinalities (a TestCase exists momentarily before its `IN_ENGAGEMENT` edge is added), inference-side `first_seen`/`last_seen` aggregation after a new `DERIVED_FROM`. Enforced by pre-commit hooks inside transactional writers, and by the periodic full-graph pass for drift.

## Step 6: Query patterns & resulting schema decisions (DRAFT)

Working method: pick a small canonical set of queries each consumer needs, then back into the schema each one demands. Schema gaps surface as queries that are awkward to write. Resolutions land here; the resulting edges/identity rules get folded into Step 2 and Step 3.

### Canonical query set

**Coverage analyzer:**
- C1. Endpoints in `Scope`, never hit by any `RequestObservation`.
- C2. Endpoints hit as `Principal` A but not as `Principal` B.
- C3. Identifiers seen in `ResponseArtifact`s that also appear as `Parameter` inputs to other Endpoints (leak-to-input pivot).
- C4. Capability-tier coverage — the **capability-tier analog of C2** (ADR-0033, slice 3). A capability `TrustBoundary` orders two `AuthContext`s of one Principal (weak → strong); C4 surfaces endpoints the **strong** context reached (2xx) that the **weak** context never reached or was blocked on. A passive observation differential (not "boundaries with no *executed* test" — that degenerate reading is C5's slice-4 shape). Lives in the shared coverage library next to C2 (ADR-0034); consumes the capability boundary node only for tier ordering. Evidence-gated: needs `scope`/`acr`/`amr`/`auth_time` claims to tell tiers apart — absent claims → no boundary inferred → C4 truthfully empty there (tenant coverage is correspondingly broader).
- C5. `TrustBoundary`s with no `TestCase` targeting them.

**Planner:**
- C6. `Asset`s with strong evidence not yet reached as `Host`/`Endpoint`.
- C7. Cross-tenant access — same `Endpoint` accessed by `Principal`s from different tenants.

**Validator (stateful guards, ADR-0003):**
- C8. Has this exact `TestCase` been executed before? (dedup)
- C9. Requests to host H in last N seconds; tests run for `Engagement` E (rate limit / budget).

**Audit / reporting:**
- C10. Trace this `Finding` to root observations; "what did the agent know at time T?" (already covered by `DERIVED_FROM` + bitemporal `ingested_at`, Step 4).

### Gap #5 — agent-sent requests are `RequestObservation`s, not a separate entity (RESOLVED — ADR-0006)

Our dispatcher's outbound HTTP requests are stored as `RequestObservation` nodes with `source = "agent"`, unified with passive Burp/HAR traffic. The authoring `TestCase` points at each resulting observation via an `EXECUTED_AS` edge (cardinality 0..N — retries and parameter sweeps add edges). Coverage and rate-limit queries run over one observation set; `source` filters active from passive only when a query needs to.

The `EXECUTED_AS` edge carries `dispatch_status` + `request_role` + `run_id` (ADR-0013/0042/0043), plus `dispatch_reason: str | None` — the dispatcher's human-readable cause when `dispatch_status != "ok"` (today the stringified transport exception on a `transport_error` send; `null` otherwise) so post-hoc diagnosis is Cypher-queryable without correlating `trace_id` against logs (#136). A blocked send (`sent = False`, e.g. OPA-deny / kill-switch / budget) commits no observation and no edge — "nothing observed" — so its reason lives on the dispatch-ledger `RunOutcome.reason`, not the graph.

### Gap #4 — `TestCase` identity is content-addressed and Engagement-scoped (RESOLVED — ADR-0007)

TestCase identity is `key_hash = sha256(canonicalized(engagement_id, test_class, target_endpoint_id?, target_parameter_id?, target_trust_boundary_id?, payload_class, payload_hash, attacker_principal, attacker_slot))`, stored as a unique-indexed property. The attacker is keyed by **(principal, credential slot)** — the rotation-stable identity (ADR-0049); `auth_context_id` is carried as non-key evidence and updated `ON MATCH SET` when the same logical test is re-proposed under a fresh token. Same content + same Engagement → same node. The target is **three-way XOR**: exactly one of `target_endpoint_id` (route-level test), `target_parameter_id` (parameter-level test; the Endpoint is reachable via `HAS_PARAMETER`), or `target_trust_boundary_id` (boundary test); the unused two normalize to null and fall out of canonicalization. The matching graph edge is one of `TARGETS_ENDPOINT` / `TARGETS_PARAMETER` / `TARGETS_BOUNDARY`. `payload_hash` is over the concrete bytes the dispatcher will send (sentinel `sha256("")` for no-payload tests; never SQL null). C8 (dedup) reduces to `MATCH (tc:TestCase {key_hash}) WHERE EXISTS { (tc)-[:EXECUTED_AS]->() }`.

Retries / re-runs add `EXECUTED_AS` edges to the same node. Payload sweeps (50 SQLi variants) create 50 different nodes (different `payload_hash`) — each is its own auditable test. Cross-Engagement reuse ("catalog of known tests") is a deferred concept (`TestTemplate`), not a TestCase.

### Gap #1 — `Scope` ↔ `Endpoint` is host-materialized, endpoint-derived (RESOLVED)

Scope rules (`host_patterns`, `allowed_methods`, `allowed_path_patterns`, `payload_class_denylist`, `rate_limit`, `time_window`) live as properties on the `Scope` node — **the single source of truth**; the OPA `data` bundle is generated from Scope nodes, not maintained separately. Edges introduced:

- `(Endpoint) -[:ON_HOST]-> (Host)` — every Endpoint sits on exactly one Host.
- `(Scope) -[:INCLUDES_HOST]-> (Host)` — materialized as Hosts are discovered and matched against `host_patterns`.
- `(Engagement) -[:UNDER_SCOPE]-> (Scope)` — one Scope per Engagement (force a separate Engagement to straddle scopes); keeps the audit boundary clean.

Endpoint-in-Scope is **not materialized** — it is derived at query time from host-in-scope + method/path-pattern match. Avoids cascade churn when Endpoint templates re-template (ADR-0004). C1 in Cypher:

```cypher
MATCH (s:Scope {id: $sid})-[:INCLUDES_HOST]->(:Host)<-[:ON_HOST]-(e:Endpoint)
WHERE e.method IN s.allowed_methods
  AND any(p IN s.allowed_path_patterns WHERE e.path_template =~ p)
  AND NOT EXISTS { (e)<-[:HIT]-(:RequestObservation) }
RETURN e
```

### Gap #3 — `Tenant` is a first-class inference node (RESOLVED — ADR-0008)

`Tenant` is an inference-layer node, evidenced by URL positions (`/orgs/{org_id}`), headers (`X-Org-Id`), JWT claims on the AuthContext, and response-body fields. `(Principal) -[:OF_TENANT]-> (Tenant)` is **M:N** (multi-org membership is normal). Tenant-related findings ("tenant 42's data was readable from tenant 43") attach to Tenant nodes.

This refines ADR-0002 / Q2: identity-tier `TrustBoundary`s with `kind = tenant` are drawn **between `Tenant` nodes**, not `Principal`s; `role` / `ownership` boundaries still draw between `Principal`s; capability-tier still between `AuthContext`s. The `BETWEEN` endpoint type is polymorphic by `kind`. C7 (cross-tenant access) becomes a one-line `collect(DISTINCT t)` query.

**Single-tenant / partial-tenancy targets.** The model is emergent: no tenant evidence → no `Tenant` nodes → no `OF_TENANT` edges → no `kind="tenant"` `TrustBoundary`s → C7 returns zero (the truthful answer). Role and capability boundaries continue to work. Mixed cases (e.g., a global admin Principal alongside tenant-scoped ones) drop out of C7 joins naturally. False-negative tenant *detection* is an inference-quality problem, not a schema problem; mitigation if needed is a per-Engagement `target_is_multi_tenant` hint, not declarative seeding of tenant data.

### Gap #2 — `ObservedValue` is a promoted inference node for cross-context value matching (RESOLVED — ADR-0009)

To answer C3 (leak-to-input pivot) as a single traversal, *promoted* values become first-class `ObservedValue` nodes — junk strings (HTML, timestamps, common words) stay inline on the originating observation. Promotion is deterministic-first in L2 enrichment: shape match (UUID, URL, email, hostname, JWT) or multiplicity ≥2 across observations. The LLM may propose ambiguous promotions at lower starting confidence.

```
ObservedValue {
  value_hash       sha256 of normalized value (dedup key, indexed)
  value_preview    first 32 chars (debugging; truncated)
  normalized_value canonicalized form (lowercased host, decoded percent-enc, etc.)
  kind             identifier | url | email | hostname | token | secret | other
  + cross-cutting fields + inferred_at + code_version
}
```

Edges introduced:

- `(RequestObservation) -[:YIELDED]-> (ResponseArtifact)` — finally an explicit attachment from a response to the observation that produced it.
- `(ResponseArtifact) -[:CONTAINS_VALUE]-> (ObservedValue)`.
- `(RequestObservation) -[:SENT_VALUE { parameter_name }]-> (ObservedValue)` — edge property records *which* Parameter carried the value.
- `(ObservedValue) -[:DERIVED_FROM]-> <observation>` — same lineage pattern as every other inference.

**Secrets handling.** For `kind ∈ {token, secret}` (JWTs, API keys, high-entropy credentials), the node stores `value_hash` + length + first-N chars only. The full value lives only in the originating observation in object storage; reading it back requires explicit access. The graph is not a credential store.

C3 in Cypher:

```cypher
MATCH (req_from:RequestObservation)-[:YIELDED]->(:ResponseArtifact)
  -[:CONTAINS_VALUE]->(v:ObservedValue)
  <-[sv:SENT_VALUE]-(req_to:RequestObservation)-[:HIT]->(e_to:Endpoint)
WHERE req_from <> req_to
RETURN v, req_from, e_to, sv.parameter_name
```

## Steps 2-6 (not yet started)

2. **The relationship catalog** — ✅ drafted above (Step 2). Every edge with cardinality and the invariants it implies.
3. **Identity rules** — ✅ all node types drafted: Endpoint (path templating, ADR-0004), Principal (two-tier, ADR-0010), AuthContext / Tenant / Host / Asset (content-addressed; Asset/ObservedValue coexistence in ADR-0011), TestCase (Gap #4 / ADR-0007), ObservedValue (Gap #2 / ADR-0009).
5. **Invariants** — ✅ drafted above (Step 5). Strict vs eventual, Pydantic mixins, Cypher constraints, polymorphism queries, retraction rules. Adds `status` to every node.
4. **Cross-cutting properties** — drafted above (Step 4).
6. **Query patterns** — drafted above (Step 6); the canonical query set is fixed, the gaps it surfaces are being resolved one at a time.
4. **Cross-cutting properties** — provenance, confidence, temporal fields, source attribution. These attach to almost everything; decide the pattern once.
5. **Invariants** — rules that must hold. "Every TestCase has exactly one Scope." "An AuthContext cannot outlive its Principal." Becomes validation logic and graph constraints.
6. **Query patterns** — specific queries the planner and coverage analyzer will need. Working backward from queries reveals whether the schema actually supports the use cases.
