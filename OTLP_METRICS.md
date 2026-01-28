# OTLP Metrics Integration

Cosmian KMS exports metrics via OpenTelemetry Protocol (OTLP) over gRPC. This allows you to send metrics directly to any OTLP-compatible backend without exposing an HTTP endpoint.

## Architecture

```text
┌─────────────┐                    ┌──────────────────┐
│  KMS Server │ ──OTLP/gRPC──────> │ OTLP Collector   │
│             │  (port 4317)       │                  │
└─────────────┘                    └──────────────────┘
                                           │
                        ┌──────────────────┼──────────────────┐
                        ▼                  ▼                  ▼
                  ┌─────────┐        ┌─────────┐      ┌──────────┐
                  │ Jaeger  │        │ Cloud   │      │ Custom   │
                  │         │        │ Provider│      │ Backend  │
                  └─────────┘        └─────────┘      └──────────┘
```

## Configuration

### Enable OTLP Metrics in KMS

Configure the OTLP endpoint in your `kms.toml`:

```toml
[logging]
# OTLP endpoint for metrics export
otlp = "http://localhost:4317"
```

Or via environment variable:

```bash
export KMS_OTLP_URL="http://localhost:4317"
export KMS_ENABLE_METERING="true"
```

Or via command-line flag:

```bash
cosmian_kms --otlp http://localhost:4317 --enable-metering
```

### Metrics Export Behavior

- **Automatic**: Metrics are automatically sent when `otlp` URL is configured
- **Interval**: Metrics are pushed every 30 seconds
- **Protocol**: gRPC transport (OTLP/gRPC)
- **No HTTP endpoint**: KMS does not expose any HTTP `/metrics` endpoint

## Quick Start with Docker

### 1. Start the OTLP Stack

```bash
# Start OTLP Collector and Jaeger
docker compose --profile otel-test up -d otel-collector jaeger
```

This starts:

- **OTLP Collector** on host ports 14317 (gRPC) and 14318 (HTTP)
- **Collector Prometheus export** on <http://localhost:18889/metrics>
- **Jaeger UI** on <http://localhost:16686>

### 2. Start KMS with OTLP

```bash
# Configure KMS to send metrics to OTLP Collector
cosmian_kms --otlp-url http://localhost:4317 \
            --database-type sqlite \
            --sqlite-path /tmp/kms-data
```

### 3. View Metrics

- **Jaeger UI**: <http://localhost:16686> (metrics and traces)
- **Collector /metrics**: <http://localhost:18889/metrics>

## Available Metrics

The server exposes the following instruments via OTLP, as implemented in `crate/server/src/core/otel_metrics.rs`.

### KMIP Operations

- `kms.kmip.operations.total` — Total KMIP operations executed (counter)
- `kms.kmip.operations.per_user.total` — Total KMIP operations per user (counter)
- `kms.kmip.operation.duration` — Duration of KMIP operations in seconds (histogram)

### Users & Permissions

- `kms.active.users` — Number of unique active users (up-down counter)
- `kms.permissions.granted.per_user.total` — Permissions granted per user (counter)
- `kms.permissions.granted.total` — Total permissions granted (counter)

### Database Metrics

- `kms.database.operations.total` — Total database operations (counter)
- `kms.database.operation.duration` — Database operation duration in seconds (histogram)

### HTTP Metrics

- `kms.http.requests.total` — Total HTTP requests (counter)
- `kms.http.request.duration` — HTTP request duration in seconds (histogram)

### Server Health

- `kms.server.uptime` — Server uptime in seconds (counter)
- `kms.server.start_time` — Server start time as Unix timestamp (up-down counter)
- `kms.active.connections` — Current number of active connections (up-down counter)
- `kms.errors.total` — Total number of errors by type (counter)

### Objects & Keys

- `kms.objects.total` — Total number of objects (up-down counter)
- `kms.keys.active.count` — Number of keys in Active state (up-down counter; absolute count applied via delta)

### Cache

- `kms.cache.operations.total` — Total cache operations (counter)

### HSM

- `kms.hsm.operations.total` — Total HSM operations (counter)

## OTLP Collector Configuration

The `otel-collector-config.yaml` receives metrics from KMS and forwards to backends:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  otlp:
    endpoint: ${env:OTLP_ENDPOINT}  # Forward to Jaeger, etc.

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [otlp, debug]
```

## Cloud Provider Integration

### Send to Datadog

```bash
# Configure OTLP Collector to export to Datadog
export DD_SITE="datadoghq.com"
export DD_API_KEY="your-api-key"

# Update otel-collector-config.yaml
exporters:
  datadog:
    api:
      key: ${env:DD_API_KEY}
      site: ${env:DD_SITE}
```

### Send to New Relic

```bash
export NEW_RELIC_LICENSE_KEY="your-license-key"

# Update otel-collector-config.yaml
exporters:
  otlp:
    endpoint: otlp.nr-data.net:4317
    headers:
      api-key: ${env:NEW_RELIC_LICENSE_KEY}
```

### Send to Grafana Cloud

```bash
export GRAFANA_INSTANCE_ID="your-instance-id"
export GRAFANA_API_KEY="your-api-key"

# Update otel-collector-config.yaml
exporters:
  otlp:
    endpoint: otlp-gateway-${GRAFANA_INSTANCE_ID}.grafana.net:4317
    headers:
      authorization: "Bearer ${GRAFANA_API_KEY}"
```

## Production Deployment

### Security Best Practices

1. **Use TLS for OTLP transport**:

```toml
[logging]
otlp = "https://collector.example.com:4317"
```

1. **Authentication**: Configure API keys in OTLP Collector:

```yaml
exporters:
  otlp:
    headers:
      authorization: "Bearer ${API_TOKEN}"
```

1. **Network isolation**: Run OTLP Collector in private network

### High Availability

Deploy multiple OTLP Collectors with load balancing:

```toml
[logging]
otlp = "https://otlp-lb.example.com:4317"
```

## Troubleshooting

### No metrics appearing

1. **Check KMS logs** for OTLP connection errors:

    ```bash
    cosmian_kms --log-level debug
    ```

2. **Check Collector logs**:

```bash
docker compose --profile otel-test logs -f otel-collector
```

### Metrics export errors

- Ensure `otlp` URL is correct in configuration
- Check network connectivity to OTLP Collector
- Verify Collector has correct exporters configured

## Files Reference

| File | Purpose |
|------|---------|
| `otel-collector-config.yaml` | OTLP Collector configuration |
| `docker-compose.yml` | Local development stack (use profile `otel-test`) |
| `crate/server/src/core/otel_metrics.rs` | Metrics instruments and recording helpers |

## Differences from HTTP /metrics Endpoint

**Previous Architecture** (Removed):

- KMS exposed HTTP `/metrics` endpoint
- External scrapers pulled metrics
- Security concerns with exposed endpoint

**Current Architecture**:

- KMS pushes metrics via OTLP
- No HTTP endpoint exposure
- More secure and flexible
- Cloud-native standard

## Additional Resources

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [OTLP Specification](https://opentelemetry.io/docs/specs/otlp/)
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
