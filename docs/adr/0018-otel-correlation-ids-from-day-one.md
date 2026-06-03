# OpenTelemetry correlation IDs from day one; SDK deferred

Every L1 `IngestionEnvelope`, every `L2Event`, and every `l3-events` payload carries a `trace_id` (16-byte W3C trace-context format) and a `span_id` (8-byte). Structured-log lines include the same IDs. The OpenTelemetry SDK and its exporter (Jaeger / Tempo / OTLP) are **not** added in slice 1. The correlation IDs and structured-log conventions are designed so that adding the SDK later is a configuration change, not a data migration.

This is a deliberate "wire it for OTel; don't run OTel yet" stance. The grill-queue lists full OTel as deferred; this ADR refines that to "defer the SDK, not the conventions" because the conventions are nearly-free now and expensive to retrofit later.

## Mechanism

- `IngestionEnvelope` generates a `trace_id` at intake (one trace per arrival — per HAR file, per Logger++ stream connection, per agent batch).
- The intake handler creates a root span (`span_id`), records it in the envelope, and emits structured log lines including both IDs.
- L2 consumes an envelope, derives child spans (`parent_span_id = envelope.span_id`, new `span_id` per L2 phase), and propagates `trace_id` unchanged into every emitted `L2Event`.
- L3 commit derives child spans similarly; `l3-events` payloads carry the trace.
- All structured-log lines across L1/L2/L3 include `trace_id`, `span_id`, and `parent_span_id` fields. Logging library: `structlog` with an OTel-friendly processor, or stdlib `logging` with an OTel-flavored formatter — either way, the processor stays in stub mode (writes IDs into log records but does not export spans) until the SDK is enabled.
- IDs are W3C trace-context format from day one so a future SDK enablement reads them without translation.

## Why both halves of the split

**Why correlation now.** Adding `trace_id` to the envelope after producers and consumers exist is a coordinated migration: every producer must start emitting it, every consumer must start expecting it, historical events lack it. Doing this work to instrument a bug six months in is the wrong moment. Adding the field now costs three small struct changes and a logging-config decision.

**Why no SDK yet.** The SDK adds: async context-var propagation rough edges (asyncio.create_task + OTel context is a known irritation), an exporter that needs a collector to be running, sampling-policy decisions, and dependency surface area. Slice 1 is a HAR → graph pipeline runnable in a single process by a single user; distributed tracing infrastructure for that is overkill. The benefit kicks in once there are multiple services, queue-buffered async paths, and operational debugging across them — slice 2-3 territory.

## Considered Options

- **Full OTel SDK + collector from day 1** (rejected): adds dependency surface and operational overhead disproportionate to slice-1 value. Slice 1 is single-process; the collector buys us nothing yet.
- **Pure-defer; no correlation IDs until SDK ships** (rejected): when the SDK lands in slice 2-3, existing envelopes/events/logs lack `trace_id`. Historical observability becomes a blind spot for the lifetime of slice 1's data — exactly the data we'd want to reason about first when debugging the first dispatcher.
- **Custom correlation IDs (not OTel-shaped)** (rejected): saves nothing — generating a UUID and W3C-format trace_id is the same code path — and incurs a translation step when the SDK lands. W3C format is the lingua franca; pick it now.

## Consequences

- The L1 → L2 → L3 contracts in `ARCHITECTURE.md` carry `trace_id` and `span_id` fields from slice 1. Pydantic models include them as required fields.
- Structured logging configuration is locked to an OTel-friendly library (`structlog` recommended). Swapping later is a non-trivial migration; deciding once now is cheap.
- The SDK enablement, when it lands, is a configuration change: instantiate the `TracerProvider`, configure the exporter, register processors. No envelope or log-line changes required.
- Cross-process tracing (when the Burp-shim, the engagement-keepalive, the auth helper, and the agent process all run simultaneously) works because every process emits the same trace IDs in its logs and events. Aggregating across them is purely an exporter-side concern.
- The "OTel-ready, OTel-not-yet" state is itself worth documenting in audit logs: each envelope's `trace_id` is real and recoverable even before any UI shows traces.
