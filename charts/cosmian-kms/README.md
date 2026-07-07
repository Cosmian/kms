# cosmian-kms

Helm chart for deploying [Cosmian KMS](https://github.com/Cosmian/kms) — a FIPS 140-3
compliant Key Management System implementing KMIP 2.1/1.4 — on Kubernetes.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- An external PostgreSQL or MySQL database for production/HA deployments (the default
  `sqlite` backend is suitable for single-replica, non-HA use only)

## Installing

```bash
helm install my-kms ./charts/cosmian-kms \
  --set kms.database.type=postgresql \
  --set kms.database.url="postgresql://kms:kms@postgres:5432/kms"
```

By default the chart deploys with the `sqlite` backend, backed by a `PersistentVolumeClaim`.
For production and HA, use `postgresql` or `mysql` with an external database and set
`kms.database.url`, or reference an existing Secret via `kms.database.existingSecret`
(expected key: `database-url`).

## Upgrading

```bash
helm upgrade my-kms ./charts/cosmian-kms
```

## Uninstalling

```bash
helm uninstall my-kms
```

Uninstalling does not delete the PVC created for the `sqlite` backend. Delete it manually
if the data is no longer needed:

```bash
kubectl delete pvc <release-name>-cosmian-kms
```

## Accessing the web UI

The KMS container serves a bundled web UI on the same port as the KMIP/REST API
(`kms.port`, default `9998`), at the application root and its client-side routes
(`/login`, `/sym`, `/rsa`, `/certificates`, etc.). No separate Service or port is
required. It is enabled by default (`kms.uiEnabled: true`); set it to `false` to disable
it (all `/ui/` and SPA routes then return 404).

```bash
kubectl port-forward svc/<release-name>-cosmian-kms 9998:9998
# then open http://127.0.0.1:9998
```

For external access, enable `ingress.enabled` and set `ingress.hosts`, or set
`service.type: LoadBalancer`.

If the KMS is reachable at a hostname other than `localhost`/`127.0.0.1`, add that origin
to `kms.corsAllowedOrigins` — the browser sends an `Origin` header on every API request
made from the UI, and the server rejects requests from origins not in that list.

## Configuration

See [values.yaml](values.yaml) for the full list of configurable parameters and their
defaults. Key sections:

| Key | Description |
|-----|--------------|
| `image.repository` / `image.tag` | KMS container image; tag defaults to the chart `appVersion` |
| `kms.database.type` | `sqlite`, `postgresql`, `mysql`, or `redis-findex` (non-FIPS builds only) |
| `kms.database.url` / `kms.database.existingSecret` | Connection string for non-sqlite backends |
| `kms.uiEnabled` | Serve the bundled web UI on the same port (default `true`) |
| `kms.tls.enabled` / `kms.tls.existingSecret` | Terminate TLS on the KMS listener itself, using a `kubernetes.io/tls` Secret |
| `persistence.*` | PVC settings for the `sqlite` backend |
| `ingress.*` | Optional `Ingress` in front of the `Service` |
| `autoscaling.*` | Optional `HorizontalPodAutoscaler` |
| `podDisruptionBudget.*` | Optional `PodDisruptionBudget` |
| `networkPolicy.*` | Optional `NetworkPolicy` restricting ingress to the KMS port |
| `extraEnv` / `extraEnvFrom` / `extraArgs` / `extraVolumes` / `extraVolumeMounts` | Escape hatches for settings not covered by a dedicated value |

## Implementation notes

- Every `kms.*` value maps to a `KMS_*` environment variable or CLI flag consumed
  directly by the `cosmian_kms` binary. See `crate/server/src/config/command_line/` in
  the main repository for the authoritative list.
- The chart always passes explicit `--database-type` / `--hostname` / `--port` arguments,
  because the Docker image's entrypoint script only reads `$COSMIAN_KMS_CONF` or
  environment-only configuration when invoked with **zero** arguments.
- The container runs as the image's built-in `kms` user (uid/gid `1000`); this is pinned
  explicitly via `podSecurityContext.runAsUser`/`runAsGroup` because the image has no
  `USER` directive of its own (it defaults to root), which Kubernetes rejects when
  `runAsNonRoot: true` is set without a matching UID.
- `KMS_ROOT_DATA_PATH` is pinned to a dedicated `emptyDir` volume
  (`/var/lib/cosmian-kms/workspace`). Its server-side default is a relative path resolved
  against `$HOME`, which is not writable for the container's non-root user.
- Never enable `kms.database.clearDatabase` in production; it wipes the database on
  every pod restart.

## Testing

Validated manually against a local Minikube cluster: `helm lint`, `helm template` across
the sqlite/postgresql/full-feature value combinations, `helm install --wait`, `helm test`,
and a live upgrade from the `sqlite` to the `postgresql` backend, confirming the pod
reaches `Ready` and `/health` responds successfully in both cases.
