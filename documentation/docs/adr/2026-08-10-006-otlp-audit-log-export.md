---
title: "ADR-0006: OTLP Log Record Export for Audit Events"
status: "Accepted"
date: "2026-08-10"
authors: "contributors, security operations engineers, platform engineers"
tags: ["architecture", "decision", "audit", "siem", "otlp", "opentelemetry", "observability"]
supersedes: ""
superseded_by: ""
---

# ADR-0006: OTLP Log Record Export for Audit Events

## Status

Accepted

## Context

The KMS already exports metrics and traces via OTLP/gRPC under `[logging] otlp = "…"` —
pushed every 30 seconds to an OpenTelemetry collector and routed to VictoriaMetrics for
Grafana dashboards (see `monitoring/`). This metrics OTLP path is **not** suitable for
audit events: it uses the gRPC protocol, encodes events as spans, and targets a metrics
pipeline.

Compliance audit events (ADR-0003, ADR-0004) are stored as a tamper-evident JSONL file
(ADR-0003) and can be exported as CEF lines (ADR-0005). File tailing (`filebeat`,
`fluent-bit`) is the recommended production ingestion path (see `siems.md`). However,
some deployments require a **native push** model: the KMS server sends audit events
directly to an OTLP backend (Loki, OpenSearch) without an intermediate file-tail agent.

The requirements are:

1. **No change to the authoritative audit file** — OTLP export is a side-car, not a
   replacement for the JSONL store.
2. **Non-blocking** — OTLP network latency must never propagate to the KMIP request
   path.
3. **Structured body** — the LogRecord body carries the full JSONL event so downstream
   backends (Loki, OpenSearch) can index individual fields.
4. **CEF attribute** — a `cef_line` attribute carries the CEF-format line for
   CEF-native consumers (ADR-0005).
5. **Separate from metrics OTLP** — audit logs must use a different config section
   (`[audit.otlp]`) and are conceptually a different OTLP stream. Audit is compliance;
   metrics are operations.

## Decision

Implement `AuditOtlpLogs` — a channel-based side-car exporter that POSTs audit events
as OTLP JSON log records to a collector's `POST /v1/logs` endpoint.

### Architecture

The design mirrors the single-writer pattern from ADR-0003:

```text
KMIP request → AuditMiddleware::call()
                   ├── store.enqueue(drafts)        // file store (ADR-0003)
                   └── otlp_store.enqueue(drafts)   // OTLP export (new)
                        │
                        ▼  mpsc channel (capacity 4096)
                   background tokio task
                        │
                        ▼  POST /v1/logs (JSON, batch of 64)
                   OTel Collector → Loki / OpenSearch
```

- A single background `tokio::spawn` task owns the `reqwest::Client` and the batch
  buffer. No mutex, no blocking.
- `enqueue()` is a non-blocking `try_send` — identical overflow policy to file store.
- Payload is OTLP JSON (`application/json`) — the same dialect the collector's HTTP
  receiver already speaks for trace ingestion.
- Batch size: 64 records per POST. Records accumulate in memory until the threshold
  is reached; no timer-based flush in the initial implementation.

### Payload format

Each LogRecord carries:

| Field | Value |
|-------|-------|
| `body.stringValue` | Full JSONL event (same schema as file store) |
| `severityNumber` | `9` (INFO) for `Success`, `17` (ERROR) for `Failure` |
| `severityText` | `"Success"` or `"Failure"` |
| `cef_line` attribute | CEF v27 line from `to_cef_line()` (ADR-0005) |

The `InstrumentationScope` is `cosmian_kms_audit`, distinct from `cosmian_kms` used for
metrics. This lets operators route audit and metrics to different collector pipelines.

### Configuration

New `[audit.otlp]` section, separate from the existing `[logging] otlp`:

```toml
[audit]
enabled = true

[audit.otlp]
endpoint = "http://localhost:4318"
allow_insecure = true
```

| Setting | CLI flag | Env var | Default |
|---------|----------|---------|---------|
| Endpoint | `--audit-otlp-endpoint` | `KMS_AUDIT_OTLP_ENDPOINT` | _(empty — disabled)_ |
| Allow insecure | `--audit-otlp-allow-insecure` | `KMS_AUDIT_OTLP_ALLOW_INSECURE` | `false` |

When `endpoint` is empty, the OTLP export is disabled and no background task is spawned.

### Why HTTP/JSON, not gRPC

The metrics path uses gRPC because it carries binary protobuf-encoded metrics with
delta aggregation — gRPC's streaming and compression are necessary. Audit log records
are text-heavy JSON payloads sent in batched POSTs; HTTP/1.1 with `reqwest` is simpler,
requires no protobuf dependency, and works with every OTLP collector (gRPC receivers
are optional in some distributions; HTTP receivers are universal).

### Why `reqwest`, not the `opentelemetry` crate

The `opentelemetry` v0.32 `logs` API requires implementing the `LogProcessor` trait
with a `BatchLogProcessor` — additional boilerplate for a use case that is essentially
"POST a batch of JSON objects." Audit log record volume is low (one record per KMIP
operation, not per log statement). The `reqwest`-based approach is simpler, has fewer
dependencies, and is easier to test and debug.

## Consequences

### Positive

- **POS-001**: Native push model — no file-tail agent required for OTLP ingestion.
- **POS-002**: Side-car pattern: OTLP export failure never blocks or corrupts the
  file store. The JSONL file remains the authoritative record.
- **POS-003**: Both JSONL body and CEF attribute in every record — downstream backends
  can index structured fields _and_ forward CEF to SIEMs.
- **POS-004**: Separate config section (`[audit.otlp]`) keeps audit and metrics OTLP
  paths decoupled. Operators can route them to different collectors.
- **POS-005**: Zero additional crate dependencies — uses existing `reqwest` and
  `serde_json`.

### Negative

- **NEG-001**: Batch-only flush: records accumulate until 64 are buffered. If the
  KMS shuts down before the batch is full, the remaining records are lost (the
  background task receives no explicit shutdown signal).
- **NEG-002**: No back-pressure: if the collector is unreachable, batches are silently
  dropped with an `error!` log. There is no retry queue or dead-letter store.
- **NEG-003**: The `ObservedTimestamp` is reported as Unix epoch zero by the collector —
  the current implementation does not set it on the LogRecord.
- **NEG-004**: No TLS client certificate support for mutual TLS to the collector
  (regression from gRPC which supports this via tonic).
- **NEG-005**: The CEF line is rebuilt from `AuditEvent` rather than read from the
  file store — `id`, `prev_hash`, and `row_hash` are zeroed. The CEF line attribute
  is informational only; verification must use the file store.

## Alternatives Considered

### Reuse `opentelemetry` / `opentelemetry_sdk` logs API

- **ALT-001 Description**: Add the `logs` feature to `opentelemetry_sdk`, implement
  `LogProcessor`, and use `BatchLogProcessor` with the OTLP gRPC exporter.
- **ALT-002 Rejection Reason**: The v0.32 logs API requires significant boilerplate
  (`LogProcessor` trait, `SdkLogRecord`, `InstrumentationScope`). Audit log record
  volume is low (not a hot path for batching efficiency). The `reqwest` approach is
  ~150 lines vs. ~400+ for the full OTel integration. Simpler to test, debug, and
  maintain.

### Extend the existing `[logging] otlp` config

- **ALT-003 Description**: Reuse the same OTLP endpoint and `--otlp` flag for audit
  events, mixing audit log records into the metrics/traces pipeline.
- **ALT-004 Rejection Reason**: Audit and metrics are fundamentally different concerns
  with different compliance requirements, retention policies, and backend systems.
  Metrics go to VictoriaMetrics (short retention, used for Grafana); audit goes to
  Loki/OpenSearch (long retention, used for compliance). Mixing them into one pipeline
  forces the operator to run all three backends or drop data. Separate config gives
  operators the choice.

### Add a timer-based flush

- **ALT-005 Description**: Add a `tokio::time::interval` that flushes the batch every
  N seconds even if fewer than 64 records are buffered.
- **ALT-006 Rejection Reason**: Not implemented in the initial version for simplicity.
  Timers add complexity (cancellation, idle wakeups) for a marginal benefit at typical
  audit volumes. Can be added later as a configurable `flush_interval_secs` field
  without changing the LogRecord format.

### CEF-only transport (no JSONL body)

- **ALT-007 Description**: Send only the CEF line as the LogRecord body.
- **ALT-008 Rejection Reason**: CEF is a flat key=value format — Loki and OpenSearch
  cannot index individual fields from it without a parser. Sending the JSONL body
  as well gives structured indexing for free; the CEF attribute is a bonus for
  forwarding.

## Implementation Notes

- **IMP-001**: Core implementation: `crate/server/src/core/audit/otlp_logs.rs`
- **IMP-002**: Config structs: `crate/server/src/config/command_line/audit_config.rs`
  (`AuditOtlpConfig`); resolved params: `crate/server/src/config/params/server_params.rs`
- **IMP-003**: Wiring point: `crate/server/src/core/kms/mod.rs` →
  `create_audit_otlp_store(&server_params)` → `AuditOtlpLogs::start(endpoint, allow_insecure)`
- **IMP-004**: Middleware side-car: `crate/server/src/middlewares/audit.rs` →
  `otlp_store.enqueue(drafts)` after `store.enqueue(drafts)`
- **IMP-005**: OTLP JSON format per [OTLP spec](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding)
- **IMP-006**: Collector must have an OTLP HTTP receiver on port 4318 and a `logs`
  pipeline routing to a backend. See `monitoring/ci-otel-collector-config.yaml` for
  the metrics pipeline; add a `logs` pipeline per `siems.md`.

## References

- **REF-001**: ADR-0003 — Tamper-Evident JSONL Audit Log (file store architecture)
- **REF-002**: ADR-0004 — HTTP-Layer Audit Middleware (side-car injection point)
- **REF-003**: ADR-0005 — CEF v27 as SIEM Export Format (CEF attribute content)
- **REF-004**: `monitoring/docker-compose.yml` — existing OTel stack (VictoriaMetrics, Grafana)
- **REF-005**: `documentation/docs/configuration/siems.md` — SIEM integration guide
- **REF-006**: `documentation/docs/configuration/audit-logs.md` — audit config reference
- **REF-007**: `CHANGELOG/feat_audit_integration.md` — branch change log
