# Telemetry & Observability

By default, the Cosmian KMS server outputs logs to the console with a log level of `INFO`.
Beyond console logging, the server supports OpenTelemetry (OTLP) export, which unlocks a full
observability stack: distributed traces, RED metrics, and long-term dashboards via Grafana.

---

## Adjusting the log level

The log level can be adjusted by setting either:

- the `RUST_LOG` environment variable,
- the `rust_log` setting in the TOML configuration file in the `[logging]` section,
- the `--rust-log` command line argument.

Available levels: `trace`, `debug`, `info`, `warn`, `error`. The default is `info`.

Example:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=info,mysql=info
```

The first `info` sets the default log level for all crates. Individual crates can be overridden:

- To get detailed logs of user requests, set `cosmian_kms_server` to `debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=debug,actix_web=info,mysql=info
```

- To debug HTTP issues, set `actix_web` to `debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=debug,mysql=info
```

> **⚠️ WARNING:** Setting the log level to `debug` or `trace` may leak sensitive information
> in the logs.

---

## Console and syslog logging

Logging to the console is enabled by default. It can be disabled via:

- the `quiet` parameter in the TOML configuration file in the `[logging]` section,
- the `--quiet` command line argument,
- the `KMS_LOG_QUIET` environment variable set to `true`.

On Linux, logs can be redirected to syslog instead of stdout by setting:

- the `log_to_syslog` parameter in the TOML configuration file in the `[logging]` section,
- the `--log-to-syslog` command line argument,
- the `KMS_LOG_TO_SYSLOG` environment variable set to `true`.

---

## Rolling log files

Daily rolling log files can be enabled by specifying the target directory via:

- the `rolling_log_dir` entry of the TOML configuration file,
- the `--rolling-log-dir` command line argument.

Files are named `<name>.YYYY-MM-DD`, where `<name>` defaults to `kms`.
The name can be changed using the `rolling_log_name` TOML entry or `--rolling-log-name` argument.

---

## OTLP telemetry

The KMS server can export traces and metering events to any
[OpenTelemetry](https://opentelemetry.io/) collector that supports the OTLP protocol.

To enable OTLP export, set one of:

- the `otlp` parameter in the TOML configuration file in the `[logging]` section,
- the `--otlp` command line argument,
- the `KMS_OTLP_URL` environment variable.

```bash
KMS_OTLP_URL="http://localhost:4317"
```

### What the traces contain

Traces produced by the KMS include:

- The start configuration of the KMS server
- KMIP requests (content adjusted by the log level)
- Access rights management requests
- Metering events (when `--enable-metering` is active)

### Enabling metering

Metering events are emitted as OTLP spans and converted to Prometheus metrics downstream.
Enable the feature with:

- the `--enable-metering` command line argument,
- or the equivalent TOML key in the `[logging]` section.

---

## Observability stack (OTel Collector + VictoriaMetrics + Grafana)

For production-grade observability, a pre-configured Docker Compose stack is provided.
It replaces the Jaeger quick-test setup with a persistent metrics pipeline and Grafana dashboards.

[Full tutorial available here](./monitoring-setup.md)

### Architecture

```
KMS ──OTLP gRPC──► OTel Collector ──remote_write──► VictoriaMetrics ◄── Grafana
                        │
                        └──prometheus scrape :8888──► VictoriaMetrics
```

| Component | Role |
|---|---|
| **OTel Collector** | Receives OTLP, enriches with metadata, generates RED metrics from traces, exports to VictoriaMetrics |
| **VictoriaMetrics** | Long-term metrics storage (configurable retention) |
| **Grafana** | Dashboard UI — queries VictoriaMetrics via PromQL |

### Quick start

The stack is configured via a single `.env` file. Two deployment modes are available:

**Mode `kms-local` — KMS container included in the stack:**

```bash
# .env
COMPOSE_PROFILES=kms-local
KMS_MODE=local

# Generate a demo TLS certificate (RSA 4096, self-signed, 10 years)
bash generate-demo-cert.sh

# Start everything
docker compose up -d
```

**Mode `external` — existing KMS, stack only:**

```bash
# .env
COMPOSE_PROFILES=
KMS_MODE=external

docker compose up -d
```

In external mode, configure your KMS to send OTLP data to the collector:

```bash
# gRPC (recommended)
KMS_OTLP_URL=http://<collector-host>:4317

# or HTTP
KMS_OTLP_URL=http://<collector-host>:4318
```

### `.env` reference

| Variable | Default | Description |
|---|---|---|
| `COMPOSE_PROFILES` | `kms-local` | `kms-local` to include the KMS container, empty for external mode |
| `KMS_MODE` | `local` | `local` or `external` — propagated as label in all metrics/traces |
| `KMS_CLUSTER` | `cosmian-kms-local` | Logical cluster name — `kms.cluster` label in dashboards |
| `KMS_VERSION` | `latest` | Docker image tag for the KMS |
| `ENVIRONMENT` | `production` | Deployment environment (`production`, `staging`, …) |
| `GRAFANA_ADMIN_PASSWORD` | `password` | Grafana `admin` user password |
| `METRICS_RETENTION_MONTHS` | `12` | VictoriaMetrics retention period (months) |

### OTel Collector pipeline

The collector enriches every span and metric with the following resource attributes:

| Attribute | Source |
|---|---|
| `deployment.environment` | `ENVIRONMENT` from `.env` |
| `service.name` | hardcoded `cosmian-kms` |
| `service.version` | `KMS_VERSION` from `.env` |
| `kms.mode` | `KMS_MODE` from `.env` |
| `kms.cluster` | `KMS_CLUSTER` from `.env` |
| `kms.node` | `host.name` of the KMS container |

**RED metrics from traces** are automatically generated by the `spanmetrics` connector with the
following latency buckets: `10ms, 50ms, 100ms, 250ms, 500ms, 1s, 2s, 5s, 10s, 30s`.

### Exposed ports

| Service | Port | Protocol | Usage |
|---|---|---|---|
| KMS | `9998` | HTTPS | KMS API (local mode only) |
| OTel Collector | `4317` | gRPC | OTLP traces & metrics ingestion |
| OTel Collector | `4318` | HTTP | OTLP traces & metrics ingestion |
| OTel Collector | `8888` | HTTP | Collector self-metrics (Prometheus) |
| OTel Collector | `13133` | HTTP | Health check |
| VictoriaMetrics | `8428` | HTTP | PromQL API + `remote_write` endpoint |
| Grafana | `3000` | HTTP | Dashboard UI |

Access Grafana at [http://localhost:3000](http://localhost:3000) with user `admin`.

---

## Quick test with Jaeger

To quickly validate that OTLP export works without the full stack:

=== "Docker"

  ```bash
  docker run -p 16686:16686 -p 4317:4317 \
    -e COLLECTOR_OTLP_ENABLED=true \
    jaegertracing/all-in-one:latest
  ```

=== "kms.toml"

  ```toml
  [logging]
  otlp = "http://localhost:4317"
  quiet = true
  ```

Then start the KMS locally:

```bash
./cosmian_kms_server --otlp http://localhost:4317 --quiet
```

Open [http://localhost:16686](http://localhost:16686) to browse traces in the Jaeger UI.

> For production use, replace Jaeger with the full OTel Collector + VictoriaMetrics + Grafana
> stack described above.
