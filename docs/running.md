# Running doo (slice 1)

How to stand up the local stack and turn a HAR file into a queryable knowledge
graph. Slice 1 is the ingestion → graph half of the pipeline: drop in HAR
traffic, get an engagement-isolated Neo4j graph of the target (hosts, templated
endpoints, parameters, principals, response artifacts) with provenance on every
node. There is no active testing yet.

## 1. Prerequisites

- **Docker** (for the Neo4j / Redis / MinIO stack and the testcontainer-based tests).
- **Python 3.12** and the project venv.

```bash
cd /path/to/doo
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

(Examples below call binaries as `.venv/bin/doo`; activate the venv if you prefer
bare `doo`.)

## 2. Start the infrastructure

```bash
docker compose up -d --wait      # Neo4j (7474/7687), Redis (6379), MinIO (9000/9001)
```

`--wait` blocks until all three are healthy. Web UIs:

- **Neo4j Browser** — http://localhost:7474 — user `neo4j`, password `doo-dev-password`
- **MinIO Console** — http://localhost:9001 — user `doo-dev`, password `doo-dev-password`

## 3. Configure the connection env

The CLI reads `DOO_*` env vars; its built-in defaults do **not** match the
compose credentials, so set them. The easiest way is the committed template:

```bash
cp .env.example .env
```

`doo` auto-loads `.env` from the current directory, so as long as you run it from
the repo root you don't need to export anything. (Explicit `export`s still win
over `.env`.) The vars, if you'd rather export them:

```bash
export DOO_NEO4J_URI=bolt://localhost:7687 DOO_NEO4J_USER=neo4j DOO_NEO4J_PASSWORD=doo-dev-password
export DOO_REDIS_URL=redis://localhost:6379/0
export DOO_S3_ENDPOINT=http://localhost:9000 DOO_S3_ACCESS_KEY=doo-dev DOO_S3_SECRET_KEY=doo-dev-password DOO_S3_BUCKET=doo-blobs
```

## 4. The workflow

### a. Declare and create an engagement

Write an engagement YAML (or use the fixture
`tests/fixtures/yaml/acme-test.yaml`). It declares the `Scope`, kill-switch
parameters, and any declared `Principal`s. Token values are **env-var references**
(`${VAR}`) — never inline a token:

```bash
# the fixture references ${DOO_TEST_TOKEN_A}; export a JWT whose `sub` matches
# its known_signals.jwt_sub (uuid-aaa) — here, the one baked into the fixtures:
export DOO_TEST_TOKEN_A=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1dWlkLWFhYSIsImV4cCI6NDEwMjQ0NDgwMH0.g32AFQCk2wGfExJCjL61A7bgUXAqwvfY1AF0-w5I-K0

.venv/bin/doo engagement start --config tests/fixtures/yaml/acme-test.yaml
```

This is idempotent. Re-running with a changed YAML prints a diff and asks for
confirmation before applying a material change (declared-Principal or Scope edit);
`--apply` skips the prompt. `doo engagement status <id>` reads it back.

### b. (Optional) arm the kill switch

```bash
.venv/bin/doo engagement keepalive acme-test     # separate process; Ctrl-C / SIGTERM releases the lease
```

It does nothing visible in slice 1 — it's the external stop signal later slices'
dispatcher will honour. Safe to skip for ingestion-only use.

### c. Ingest a HAR

```bash
.venv/bin/doo ingest har --engagement acme-test path/to/capture.har
```

This is **L1 only**: it uploads the raw bytes to MinIO and drops an envelope on
the Redis `ingest` stream. Re-ingesting the same file is an idempotent no-op.
You can ingest a HAR for any target under any engagement — **scope does not gate
ingestion** (out-of-scope hosts land anyway, by design).

### d. Build the graph

```bash
.venv/bin/doo worker run --once        # drain everything queued, then exit
# or:  .venv/bin/doo worker run        # run continuously (Ctrl-C to stop)
```

The L2 (extraction) + L3 (commit) workers consume the streams and build the
Neo4j graph. `--once` prints a summary and, if any HAR entries failed to parse,
a grouped report of why:

```
drained: 1 envelope(s) extracted, 9 L2 event(s) committed

1 parse failure(s) — entries that did not ingest:
  missing_required_field x1: entry missing `startedDateTime` [log.entries[9]]
  full detail: MATCH (f:ParseFailure) RETURN f.error_kind, f.error_message, f.location_hint
```

### e. Explore

In **Neo4j Browser**:

```cypher
// node counts for an engagement
MATCH (n {engagement_id:'acme-test'}) RETURN labels(n)[0] AS label, count(*) ORDER BY label;

// the templated endpoints
MATCH (e:Endpoint {engagement_id:'acme-test'}) RETURN e.method, e.path_template;

// what got extracted from responses
MATCH (:RequestObservation)-[:YIELDED]->(a:ResponseArtifact)
RETURN a.artifact_kind, a.value, a.extractor LIMIT 50;

// which observations back an endpoint (evidence)
MATCH (r:RequestObservation)-[:HIT]->(e:Endpoint {path_template:'/users/{user_id}'})
RETURN r.concrete_path, r.observed_at;
```

Bodies live in MinIO (the graph holds `BlobRef`s); browse the `doo-blobs` bucket
in the MinIO console.

## 5. Command reference

| Command | What it does |
|---|---|
| `doo engagement start --config <yaml> [--apply]` | Create/re-attach an engagement (idempotent; diff+confirm on material changes) |
| `doo engagement status <id>` | Print an engagement's properties + Scope hash |
| `doo engagement keepalive <id>` | Run the external kill-switch lease keeper |
| `doo ingest har --engagement <id> <har>` | L1: upload the HAR + queue an envelope |
| `doo worker run [--once] [--batch N]` | L2+L3: drain the streams into the graph |

## 6. Troubleshooting

- **`AuthError … unauthorized`** — wrong/absent Neo4j password. The CLI default
  is `password`; compose uses `doo-dev-password`. Set `DOO_NEO4J_PASSWORD` (or
  `cp .env.example .env`). `echo $DOO_NEO4J_PASSWORD` to check.
- **`Cannot reach Neo4j …`** — the stack isn't up: `docker compose up -d --wait`.
- **A HAR ingested but no Host/Endpoint appeared** — `doo ingest har` only does
  L1; run `doo worker run --once` to build the graph.
- **`worker run` reports parse failures / `decode_error`** — the HAR isn't valid
  JSON (often a truncated export). Confirm with `python -m json.tool your.har >
  /dev/null`, then re-export. Malformed *entries* become `ParseFailure` nodes;
  the rest still ingest.
- **Large HARs are slow** — re-templating currently re-scans the per-`(engagement,
  method)` observation cohort on each commit, so a HAR with thousands of requests
  on one host takes a while to drain. Let `worker run` keep going; it's
  resumable.

## 7. Teardown

```bash
docker compose down -v     # -v also wipes the Neo4j graph + MinIO blobs
```

## Running the tests

The full suite uses testcontainers (it starts its own throwaway Neo4j/Redis/MinIO,
so the compose stack isn't required) and an `opa` binary for the dual-path Scope
test. See [`docs/contributing-testing.md`](contributing-testing.md).

```bash
.venv/bin/pytest -q
```
