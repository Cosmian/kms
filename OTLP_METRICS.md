# OTLP Metrics Integration

Cosmian KMS exports metrics via OpenTelemetry Protocol (OTLP) over gRPC. This allows you to send metrics directly to any OTLP-compatible backend without exposing an HTTP endpoint.

## Architecture

```
┌─────────────┐                    ┌──────────────────┐
│  KMS Server │──OTLP/gRPC──────>│ OTLP Collector   │
│             │  (port 4317)      │                  │
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
```

Or via command-line flag:

```bash
cosmian_kms --otlp-url http://localhost:4317
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
docker compose -f docker-compose.otel.yml up -d
```

This starts:

- **OTLP Collector** on port 4317 (gRPC) and 4318 (HTTP)
- **Jaeger UI** on <http://localhost:16686>
- **Grafana** on <http://localhost:3000> (admin/admin)

### 2. Start KMS with OTLP

```bash
# Configure KMS to send metrics to OTLP Collector
cosmian_kms --otlp-url http://localhost:4317 \
            --database-type sqlite \
            --sqlite-path /tmp/kms-data
```

### 3. View Metrics

- **Jaeger UI**: <http://localhost:16686> (metrics and traces)
- **Grafana**: <http://localhost:3000> (dashboards)

## Available Metrics

### KMIP Operations

- `kms.kmip.operations` - Total KMIP operations by operation type
- `kms.kmip.operations.user` - Per-user KMIP operation counts
- `kms.kmip.duration` - KMIP operation duration histogram

### Users & Permissions

- `kms.users.active` - Number of active users
- `kms.permissions.granted` - Permission grants by operation

### Server Health

- `kms.server.uptime` - Server uptime in seconds
- `kms.server.start_time` - Server start timestamp
- `kms.active.connections` - Current active connections
- `kms.errors.total` - Error counts by type

### Objects

- `kms.objects.total` - Total objects by type

### Cache (if enabled)

- `kms.cache.operations` - Cache hit/miss statistics

### HSM (if enabled)

- `kms.hsm.operations` - HSM operation counts

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

2. **Authentication**: Configure API keys in OTLP Collector:

```yaml
exporters:
  otlp:
    headers:
      authorization: "Bearer ${API_TOKEN}"
```

3. **Network isolation**: Run OTLP Collector in private network

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

2. **Verify OTLP Collector is running**:

```bash
curl http://localhost:8888/metrics  # Collector's own metrics
```

3. **Check Collector logs**:

```bash
docker compose -f docker-compose.otel.yml logs -f otel-collector
```

### Metrics export errors

- Ensure `otlp` URL is correct in configuration
- Check network connectivity to OTLP Collector
- Verify Collector has correct exporters configured

## Files Reference

| File | Purpose |
|------|---------|
| `otel-collector-config.yaml` | OTLP Collector configuration |
| `docker-compose.otel.yml` | Local development stack |
| `crate/server/src/core/otel_metrics.rs` | Metrics implementation |

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
