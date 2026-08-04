# cosmian-kms

Helm chart for deploying [Cosmian KMS](https://github.com/Cosmian/kms) — a FIPS 140-3
compliant Key Management System implementing KMIP 2.1/1.4 — on Kubernetes.

## Documentation

Full installation guide, configuration reference, and publishing instructions are
available in the [Kubernetes (Helm) documentation](https://docs.cosmian.com/installation/kubernetes_helm/).

## Quick start

```bash
# Default: FIPS image with sqlite backend
helm install my-kms ./charts/cosmian-kms

# Production: PostgreSQL backend
helm install my-kms ./charts/cosmian-kms \
  --set kms.database.type=postgresql \
  --set kms.database.url="postgresql://kms:kms@postgres:5432/kms"

# Non-FIPS image
helm install my-kms ./charts/cosmian-kms \
  --set image.repository=ghcr.io/cosmian/kms
```

## Source files

- [`values.yaml`](values.yaml) — all configurable parameters and defaults
- [`templates/`](templates/) — Kubernetes resource templates
- [`Chart.yaml`](Chart.yaml) — chart metadata
