# OTLP Metrics Reference

The KMS server pushes metrics to any [OpenTelemetry](https://opentelemetry.io/) collector via
**OTLP/gRPC every 30 seconds**. No HTTP `/metrics` endpoint is exposed — metrics are always
pushed, never scraped.

For deployment instructions and Grafana setup, see [Monitoring Setup](./monitoring-setup.md).
To enable the feature, see [Telemetry & Observability](./logging.md).

## KMIP Operations

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.kmip.operations.total` | counter | Total KMIP operations executed | `operation` |
| `kms.kmip.operations.per_user.total` | counter | Total KMIP operations per user | `operation`, `user` |
| `kms.kmip.operation.duration` | histogram (s) | Duration of each KMIP operation | `operation` |

## Users & Permissions

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.active.users` | up-down counter | Unique users who issued at least one request | — |
| `kms.permissions.granted.per_user.total` | counter | Access rights granted, broken down by user | `user`, `permission_type` |
| `kms.permissions.granted.total` | counter | Total access rights granted | — |

## Database

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.database.operations.total` | counter | DB operations by type and result | `operation`, `backend`, `outcome` |
| `kms.database.operation.duration` | histogram (s) | Wall-clock time of each DB call | `operation`, `backend`, `outcome` |

**Label values:**

- `backend`: `sqlite` · `postgresql` · `mysql` · `redis`
- `outcome`: `success` · `error`

## HTTP

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.http.requests.total` | counter | Incoming HTTP requests | `method`, `path`, `status` |
| `kms.http.request.duration` | histogram (s) | HTTP request latency | `method`, `path` |

`path` is normalised (e.g. `/kmip/2_1`, `/google_cse/...`) to avoid high cardinality from
object identifiers.

## Server Health

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.server.uptime` | counter (monotonic, s) | Seconds elapsed since server start | — |
| `kms.server.start_time` | up-down counter | Server start time as Unix timestamp (s) | — |
| `kms.active.connections` | up-down counter | Current open HTTP connections | — |
| `kms.errors.total` | counter | Errors categorised by type | `error_type` |

## Objects & Keys

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.objects.total` | up-down counter | Total non-destroyed objects in the KMS | — |
| `kms.keys.active.count` | up-down counter | Non-destroyed key objects (SymmetricKey, PrivateKey, PublicKey, SplitKey) across all states: PreActive, Active, Deactivated, Compromised | — |

Both metrics are refreshed every 30 s by the metrics cron task and seeded at server startup.

## Cache

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.cache.operations.total` | counter | Unwrap-cache lookups | `operation`, `result` |

## HSM

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `kms.hsm.operations.total` | counter | HSM operations by type and model | `operation`, `hsm_model` |
