# KMS Observability Stack

Complete monitoring and observability stack for Cosmian KMS, with automatic collection of traces and metrics.

> **⚡ Minimal configuration:** Only one `.env` file to edit — all other files are pre-configured.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration `.env`](#configuration-env)
- [Deployment Modes](#deployment-modes)
- [Services and Ports](#services-and-ports)
- [Useful Commands](#useful-commands)
- [Troubleshooting](#troubleshooting)

---

## Architecture

The stack consists of 4 main services:

```
KMS (local or external) → OTel Collector → VictoriaMetrics → Grafana
```

### Services

- **KMS**: Key Management Service (optional in local mode)
- **OTel Collector**: Reception and processing of OTLP traces/metrics
- **VictoriaMetrics**: Time series database (metrics storage)
- **Grafana**: Web interface for dashboard visualization

### Telemetry Pipeline

```
KMS (Traces + Metrics)
    ↓ OTLP (gRPC :4317 / HTTP :4318)
OTel Collector
    • Memory limiter
    • Batch processor
    • Spanmetrics connector (generates RED metrics)
    • Resource processor
    ↓ remote_write + Prometheus scrape
VictoriaMetrics (:8428)
    ↓ PromQL
Grafana (:3000)
```

**RED metrics** (Rate, Errors, Duration) are automatically derived from traces via the `spanmetrics` connector.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 20.10
- [Docker Compose](https://docs.docker.com/compose/) ≥ 2.x
- `openssl` available in `PATH` (for TLS certificate generation in local mode)

Verify installation:

```bash
docker --version
docker compose version
which openssl
```

---

## Configuration `.env`

All variables must be defined in the `.env` file. Here is the complete reference:

| Variable | Type | Default | Description |
|---|---|---|---|
| `COMPOSE_PROFILES` | string | `kms-local` | `kms-local` to include the KMS container, empty for external mode |
| `KMS_MODE` | string | `local` | `local` or `external` |
| `KMS_CLUSTER` | string | `cosmian-kms-local` | Logical cluster name (label in metrics) |
| `KMS_VERSION` | string | `latest` | Docker image tag for KMS |
| `ENVIRONMENT` | string | `production` | Deployment environment (`production`, `staging`, etc.) |
| `GRAFANA_ADMIN_PASSWORD` | string | `password` | Grafana admin password |
| `METRICS_RETENTION_MONTHS` | int | `12` | Metrics retention in months (VictoriaMetrics) |

### Example `.env`

```env
# Mode
COMPOSE_PROFILES=kms-local
KMS_MODE=local

# Telemetry metadata
KMS_CLUSTER=cosmian-kms-local
KMS_VERSION=latest
ENVIRONMENT=production

# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=mySecureGrafanaPassword123

# VictoriaMetrics
METRICS_RETENTION_MONTHS=12

# KMS
KMS_P12_PASSWORD=mySecureKMSPassword123
```

---

## Deployment Modes

### `kms-local` Mode

- ✅ KMS container included in the stack
- ✅ Persistent SQLite database (volume `kms-data`)
- ✅ TLS enabled via self-signed certificate (`.certs/kms.p12`)
- ✅ Automatic OTLP export to `http://otel-collector:4317`
- ✅ Automatic metering enabled

**Required configuration:**
```env
COMPOSE_PROFILES=kms-local
KMS_MODE=local
```

### `external` Mode

- ✅ Only OTel Collector, VictoriaMetrics, and Grafana start
- ✅ Your external KMS must send traces/metrics to `:4317` (gRPC) or `:4318` (HTTP)

**Required configuration:**
```env
COMPOSE_PROFILES=
KMS_MODE=external
```

---

## Quick Start

### Local Mode (KMS included in the stack)

```bash
# 1. Copy or create .env (variables pre-configured by default)
cp .env.example .env 2>/dev/null || true

# 2. Generate the demo TLS certificate
bash generate-demo-cert.sh
# → creates .certs/kms.p12 (RSA 4096, self-signed, valid 10 years)

# 3. Start the stack
docker compose up -d

# 4. Check status
docker compose ps
docker compose logs -f otel-collector  # Follow startup logs

# 5. Access Grafana
open http://localhost:3000
# login: admin
# password: (value of GRAFANA_ADMIN_PASSWORD in .env)
```

### External Mode (existing KMS)

```bash
# 1. Edit .env
# COMPOSE_PROFILES= (leave empty)
# KMS_MODE=external

# 2. Start the stack
docker compose up -d

# 3. Access Grafana
open http://localhost:3000
```

---

## Services and Ports

| Service | Port | Protocol | Description |
|---|---|---|---|
| KMS | `9998` | HTTPS | KMS API (local mode only) |
| OTel Collector | `4317` | gRPC | OTLP traces/metrics reception |
| OTel Collector | `4318` | HTTP | OTLP traces/metrics reception |
| OTel Collector | `8888` | HTTP | Internal metrics (Prometheus exposition) |
| OTel Collector | `13133` | HTTP | Health check endpoint |
| VictoriaMetrics | `8428` | HTTP | PromQL API + `remote_write` endpoint |
| Grafana | `3000` | HTTP | Dashboard web interface |

---

## Useful Commands

```bash
# Start the stack (detached)
docker compose up -d

# Stop the stack (data preserved)
docker compose down

# Stop and remove volumes (full reset)
docker compose down -v

# Display container status
docker compose ps

# Follow logs
docker compose logs -f                    # All services
docker compose logs -f otel-collector     # Specific service
docker compose logs -f kms
docker compose logs -f grafana

# Restart a service
docker compose restart otel-collector

# Regenerate TLS certificate
bash generate-demo-cert.sh

# Access Grafana
open http://localhost:3000

# Check OTel Collector health
curl http://localhost:13133

# Check VictoriaMetrics
curl http://localhost:8428/health
```

---

## Troubleshooting

### Grafana Inaccessible

```bash
# Verify the container is running
docker compose ps grafana

# Check logs
docker compose logs grafana

# Check connectivity
curl http://localhost:3000
```

**Solutions**:
- Wait a few seconds on initial startup
- Verify available disk space
- Verify port 3000 is not in use by another service

---

### No Metrics in Grafana

```bash
# Verify OTel Collector
curl http://localhost:13133

# Verify VictoriaMetrics
curl http://localhost:8428/health

# Display OTel Collector logs
docker compose logs otel-collector -n 50
```

**Solutions**:
- Verify that KMS is sending traces to `:4317` (gRPC) or `:4318` (HTTP)
- Verify network connectivity between services
- Wait a few minutes for initial data to arrive

---

### Local KMS Won't Start (`kms-local` mode)

```bash
# Verify certificate exists
ls -la .certs/kms.p12

# If missing, regenerate
bash generate-demo-cert.sh

# Check KMS logs
docker compose logs kms -n 100
```

**Solutions**:
- Ensure `generate-demo-cert.sh` executed without errors
- Verify the `.certs/` folder exists
- Remove volumes and restart: `docker compose down -v && bash generate-demo-cert.sh && docker compose up -d`

---

### Missing Metrics from External KMS

```bash
# Verify KMS points to correct OTLP endpoint
# (host:4317 in gRPC or host:4318 in HTTP)

# Test connectivity with curl (HTTP)
curl -X POST http://localhost:4318/v1/metrics \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Solutions**:
- Verify external KMS OTLP export configuration
- Ensure KMS can reach the host on port 4317/4318
- Check network firewalls and Docker network configurations

---

### Expired or Missing Data

```bash
# Verify retention in .env
echo $METRICS_RETENTION_MONTHS

# Increase retention if needed
# METRICS_RETENTION_MONTHS=24

# Restart to apply changes
docker compose restart victoria-metrics
```

**Note**: Default retention is 12 months. Increasing this value consumes more disk space.
**Note2**: You can freely edit/adapt the dashboard on grafana

---

## Support

For any questions or issues:
1. Consult the [Troubleshooting](#troubleshooting) section above
2. Check logs: `docker compose logs -f`
3. Verify connectivity: `docker compose ps`

---

**Last updated:** February 2026
