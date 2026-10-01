# Metrics & Traces (OTLP)

The KMS server can export traces and metering events to any
[OpenTelemetry](https://opentelemetry.io/) collector that supports the OTLP protocol.

> **Deploying the monitoring stack**: for a turnkey Docker Compose setup with Grafana,
> VictoriaMetrics, and a pre-configured OTel Collector, see [Monitoring stack setup](./monitoring-setup.md).
>
> **Audit log SIEM integration**: for forwarding compliance audit events to a SIEM,
> use a file-tailing agent (Vector, Filebeat, Fluent Bit) reading `audit.jsonl`.
> See [SIEM integration](./siems.md).

---

## Enabling OTLP

To enable OTLP export, set the collector URL via one of:

- the `otlp` parameter in the TOML configuration file under `[logging]`,
- the `--otlp` command line argument,
- the `KMS_OTLP_URL` environment variable.

```bash
KMS_OTLP_URL="http://localhost:4317"
```

By default, OTLP uses **gRPC on port 4317** with TLS. For local development with a
plaintext HTTP collector, also set `--otlp-allow-insecure`:

```toml
[logging]
otlp = "http://localhost:4317"
otlp_allow_insecure = true
```

### What is exported

**Traces** include:

- The server start configuration
- KMIP request spans (content adjusted by the log level)
- Access-rights management request spans
- Metering spans (when metering is enabled)

**Metrics** push every 30 seconds and cover every category below.

### Enabling metering

Metering events are emitted as OTLP spans and converted to Prometheus metrics downstream.
Enable with:

```toml
[logging]
enable_metering = true
```

| Setting             | CLI flag              | Env var                  |
| ------------------- | --------------------- | ------------------------ |
| Metering            | `--enable-metering`   | _(no env; use TOML)_     |

---

## Metrics Reference

All metrics are pushed via **OTLP/gRPC every 30 seconds** to the configured collector.
No HTTP `/metrics` endpoint is exposed — metrics are always pushed, never scraped.

### KMIP Operations

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.kmip.operations.total` | counter | Total KMIP operations executed | `operation` |
| `kms.kmip.operations.per_user.total` | counter | Total KMIP operations per user | `operation`, `user` |
| `kms.kmip.operation.duration` | histogram (s) | Duration of each KMIP operation | `operation` |

### Users & Permissions

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.active.users` | up-down counter | Unique users who issued at least one request | — |
| `kms.permissions.granted.per_user.total` | counter | Access rights granted, broken down by user | `user`, `permission_type` |
| `kms.permissions.granted.total` | counter | Total access rights granted | — |

### Database

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.database.operations.total` | counter | DB operations by type and result | `operation`, `backend`, `outcome` |
| `kms.database.operation.duration` | histogram (s) | Wall-clock time of each DB call | `operation`, `backend`, `outcome` |

**Label values:**

- `backend`: `sqlite` · `postgresql` · `mysql` · `redis`
- `outcome`: `success` · `error`

### HTTP

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.http.requests.total` | counter | Incoming HTTP requests | `method`, `path`, `status` |
| `kms.http.request.duration` | histogram (s) | HTTP request latency | `method`, `path`, `status` |

`path` is normalised (e.g. `/kmip/2_1`, `/google_cse/...`) to avoid high cardinality from
object identifiers.

### Server Health

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.server.uptime` | counter (monotonic, s) | Seconds elapsed since server start | — |
| `kms.server.start_time` | up-down counter | Server start time as Unix timestamp (s) | — |
| `kms.active.connections` | up-down counter | Current open HTTP connections | — |
| `kms.errors.total` | counter | Errors categorised by type | `error_type` |

### Objects & Keys

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.objects.total` | gauge | Total non-destroyed objects in the KMS | — |
| `kms.keys.active.count` | gauge | Non-destroyed key objects (SymmetricKey, PrivateKey, PublicKey, SplitKey) across all states: PreActive, Active, Deactivated, Compromised | — |

Both metrics are refreshed every 30 s by the metrics cron task and seeded at server startup.

### Cache

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.cache.operations.total` | counter | Unwrap-cache lookups | `operation`, `result` |

### HSM

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.hsm.operations.total` | counter | HSM operations by type and model | `operation`, `hsm_model` |
