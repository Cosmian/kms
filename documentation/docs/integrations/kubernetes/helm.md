# Kubernetes — Helm Chart Deployment

Cosmian KMS can be deployed on Kubernetes using the bundled Helm chart
(`charts/cosmian-kms/`). The chart supports both FIPS and non-FIPS images, multiple
database backends, and production-grade features such as TLS, autoscaling, network
policies, and pod disruption budgets.

Once the KMS server is running on Kubernetes you can enable the other integrations:

- [KMS Provider Plugin](kms-provider-plugin.md) — etcd Secret encryption
- [Secrets Store CSI Driver Provider](csi-provider.md) — pod-mounted secrets
- [Kubernetes Operator](operator.md) — `KMSSecret` CRD sync

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- An external PostgreSQL or MySQL database for production/HA deployments

!!! warning
    The default `sqlite` backend is suitable for **single-replica, non-HA** use only.
    For production and high-availability deployments, use `postgresql` or `mysql` with
    an external database. Refer to the [High Availability guide](../../installation/high_availability_mode.md)
    for architecture details.

## Container images

The KMS container images are published to the GitHub Container Registry (GHCR),
multi-arch (amd64 + arm64), and signed with [Cosign](https://docs.sigstore.dev/):

| Image | Description |
|-------|-------------|
| `ghcr.io/cosmian/kms-fips` | FIPS 140-3 compliant (default) |
| `ghcr.io/cosmian/kms` | Non-FIPS — additional algorithms (Covercrypt, Redis-findex, …) |

## Installing

Add the chart repository and install:

```bash
helm install my-kms ./charts/cosmian-kms \
  --set kms.database.type=postgresql \
  --set kms.database.url="postgresql://kms:kms@postgres:5432/kms"
```

### Choosing the image variant

The chart defaults to the **FIPS** image (`ghcr.io/cosmian/kms-fips`). To use the
non-FIPS image instead:

```bash
helm install my-kms ./charts/cosmian-kms \
  --set image.repository=ghcr.io/cosmian/kms
```

### Database configuration

By default the chart deploys with the `sqlite` backend, backed by a
`PersistentVolumeClaim`. For production, set the database type and connection string:

```bash
# PostgreSQL
helm install my-kms ./charts/cosmian-kms \
  --set kms.database.type=postgresql \
  --set kms.database.url="postgresql://kms:kms@postgres:5432/kms"

# MySQL
helm install my-kms ./charts/cosmian-kms \
  --set kms.database.type=mysql \
  --set kms.database.url="mysql://kms:kms@mysql:3306/kms"
```

!!! warning
    Never use `--set kms.database.clearDatabase=true` in production. It wipes the
    database on every pod restart.

### Referencing an existing Secret

To avoid storing database credentials in `values.yaml`, reference an existing
Kubernetes Secret:

```bash
helm install my-kms ./charts/cosmian-kms \
  --set kms.database.type=postgresql \
  --set kms.database.existingSecret=my-db-secret
```

The Secret must contain a `database-url` key. For `redis-findex` backends, a
`redis-master-password` key is also expected.

## Accessing the web UI

The KMS container serves the bundled web UI on the same port as the KMIP/REST API
(default `9998`), at the application root and its client-side routes (`/login`,
`/sym`, `/rsa`, `/certificates`, etc.). No separate Service or port is required.

The UI is enabled by default (`kms.uiEnabled: true`).

### Local access via port-forward

```bash
kubectl port-forward svc/my-kms-cosmian-kms 9998:9998
# then open http://127.0.0.1:9998
```

### External access

Enable the Ingress or set the Service type to `LoadBalancer`:

```bash
# Ingress
helm install my-kms ./charts/cosmian-kms \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=kms.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix

# LoadBalancer
helm install my-kms ./charts/cosmian-kms \
  --set service.type=LoadBalancer
```

!!! tip
    If the KMS is reachable at a hostname other than `localhost`/`127.0.0.1`, add
    that origin to `kms.corsAllowedOrigins` — the browser sends an `Origin` header
    on every API request, and the server rejects requests from origins not in the
    list.

## Configuration

See [`values.yaml`](https://github.com/Cosmian/kms/tree/feat/helm-chart-k8s-deployment/charts/cosmian-kms/values.yaml)
for the full list of configurable parameters. Key settings:

| Key | Description |
|-----|-------------|
| `image.repository` / `image.tag` | KMS container image; tag defaults to the chart `appVersion` |
| `kms.database.type` | `sqlite`, `postgresql`, `mysql`, or `redis-findex` (non-FIPS only) |
| `kms.database.url` / `kms.database.existingSecret` | Connection string or existing Secret for non-sqlite backends |
| `kms.uiEnabled` | Serve the bundled web UI (default `true`) |
| `kms.tls.enabled` / `kms.tls.existingSecret` | Terminate TLS on the KMS listener using a `kubernetes.io/tls` Secret |
| `kms.corsAllowedOrigins` | Comma-separated CORS allowed origins (required for UI with non-localhost access) |
| `persistence.*` | PVC settings for the `sqlite` backend |
| `ingress.*` | Optional `Ingress` in front of the `Service` |
| `autoscaling.*` | Optional `HorizontalPodAutoscaler` |
| `podDisruptionBudget.*` | Optional `PodDisruptionBudget` |
| `networkPolicy.*` | Optional `NetworkPolicy` restricting ingress to the KMS port |
| `resources` | CPU/memory requests and limits |
| `extraEnv` / `extraEnvFrom` / `extraArgs` | Escape hatches for settings not covered by a dedicated value |

Every `kms.*` value maps to a `KMS_*` environment variable or CLI flag consumed
directly by the `cosmian_kms` binary. See
[`crate/server/src/config/command_line/`](https://github.com/Cosmian/kms/tree/feat/helm-chart-k8s-deployment/crate/server/src/config/command_line)
in the main repository for the authoritative list.

## Upgrading

```bash
helm upgrade my-kms ./charts/cosmian-kms \
  --set kms.database.type=postgresql \
  --set kms.database.url="postgresql://kms:kms@postgres:5432/kms"
```

## Uninstalling

```bash
helm uninstall my-kms
```

Uninstalling does not delete the PVC created for the `sqlite` backend. Delete it
manually if the data is no longer needed:

```bash
kubectl delete pvc my-kms-cosmian-kms
```

## Implementation notes

- The chart always passes explicit `--database-type` / `--hostname` / `--port`
  arguments, because the Docker image's entrypoint script only reads
  `$COSMIAN_KMS_CONF` or environment-only configuration when invoked with **zero**
  arguments.
- The container runs as the image's built-in `kms` user (uid/gid `1000`); this is
  pinned explicitly via `podSecurityContext.runAsUser`/`runAsGroup` because the
  image has no `USER` directive of its own (it defaults to root), which Kubernetes
  rejects when `runAsNonRoot: true` is set without a matching UID.
- `KMS_ROOT_DATA_PATH` is pinned to a dedicated `emptyDir` volume
  (`/var/lib/cosmian-kms/workspace`). Its server-side default is a relative path
  resolved against `$HOME`, which is not writable for the container's non-root user.

---

## Publishing the Helm chart

The chart is currently distributed as source files in the repository. To publish it
to a Helm repository for easier consumption, use one of the following approaches.

### Option A — OCI registry (recommended)

Push the chart to GHCR alongside the container images. This requires no additional
infrastructure and reuses the existing registry authentication.

```bash
# Login to GHCR
echo $GITHUB_TOKEN | helm registry login ghcr.io -u $GITHUB_ACTOR --password-stdin

# Package the chart
helm package charts/cosmian-kms

# Push to GHCR (replace <org> with your GitHub org/user)
helm push cosmian-kms-*.tgz oci://ghcr.io/<org>/charts
```

Users can then install directly from the OCI registry:

```bash
helm install my-kms oci://ghcr.io/<org>/charts/cosmian-kms --version 0.1.0
```

#### Automating with GitHub Actions

Add a workflow to package and push the chart on release:

```yaml
name: Release Helm Chart

on:
  push:
    tags:
      - 'helm-*'

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Login to GHCR
        uses: docker/login-action@v4
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Package and push chart
        run: |
          helm package charts/cosmian-kms
          helm push cosmian-kms-*.tgz oci://ghcr.io/${{ github.repository_owner }}/charts
```

### Option B — GitHub Pages with chart-releaser

This creates a traditional Helm repository hosted on GitHub Pages.

1. Create a `gh-pages` branch in the repository.
2. Add a workflow using [chart-releaser](https://github.com/helm/chart-releaser-action):

```yaml
name: Release Helm Chart (Pages)

on:
  push:
    branches:
      - main
    paths:
      - 'charts/**'

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: helm/chart-releaser-action@v1
        with:
          charts_dir: charts
        env:
          CR_TOKEN: "${{ secrets.GITHUB_TOKEN }}"
```

Users add the repo and install:

```bash
helm repo add cosmian https://<org>.github.io/kms
helm repo update
helm install my-kms cosmian/cosmian-kms
```
