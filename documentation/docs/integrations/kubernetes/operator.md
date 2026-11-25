# Kubernetes Operator

The Eviden KMS Kubernetes Operator (`cosmian-kms-operator`) manages `KMSSecret` custom
resources. Each `KMSSecret` object tells the operator to fetch a secret from the Cosmian
KMS and materialise it as a native Kubernetes `Secret`, keeping it in sync as the KMS
value changes.

The operator runs two components concurrently:

- **Controller** — reconciles `KMSSecret` CRD instances, creates/updates `Secret` objects,
  and optionally triggers rolling restarts of dependent `Deployment`/`StatefulSet` workloads.
- **Admission webhook** — mutates new `Pod` specs that carry the
  `kms.cosmian.com/inject: "true"` annotation, injecting an init-container that writes
  KMS secrets directly to a shared volume before the application container starts.

```mermaid
flowchart LR
    CRD["KMSSecret CRD"] -->|reconcile| CTL["Controller\n(cosmian-kms-operator)"]
    CTL -->|KMIP Get| KMS["Eviden KMS"]
    KMS -->|secret value| CTL
    CTL -->|create/update| SEC["k8s Secret"]
    SEC -->|volume mount / env var| APP["Application Pod"]
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Eviden KMS ≥ 5.26.0 | Running and reachable from the operator pod |
| Kubernetes ≥ 1.25 | CRD v1 support |
| Helm ≥ 3.8 | Used to install the operator |
| cluster-admin access | Required to install CRDs and ClusterRoleBindings |

---

## Installation

=== "Docker image"

    Pre-built images are published to the GitHub Container Registry on every release:

    ```bash
    docker pull ghcr.io/cosmian/kms-operator:<VERSION>
    ```

    Install the CRD, then run the image as a Deployment that mounts the
    [configuration file](#configuration) from a `ConfigMap`:

    ```bash
    cosmian-kms-operator crd | kubectl apply -f -
    ```

    ```yaml
    containers:
      - name: cosmian-kms-operator
        image: ghcr.io/cosmian/kms-operator:<VERSION>
        args: ["serve", "--config", "/etc/cosmian-kms-operator/config.yaml"]
        volumeMounts:
          - name: config
            mountPath: /etc/cosmian-kms-operator
    ```

    There is no Helm chart for the operator: the `cosmian/kms` chart deploys the KMS server only.

=== "Build from source"

    ```bash
    cargo build --release -p cosmian_kms_k8s_operator
    sudo install -m 755 target/release/cosmian-kms-operator /usr/local/bin/
    ```

---

## Configuration

The configuration file is YAML; unknown keys are rejected.

```yaml
kms:
  server_url: "https://kms.example.com:9998"

  # Optional API token authentication
  api_token: "YOUR_API_KEY"

  # Optional API token injected from a Kubernetes Secret
  # api_token_secret_ref:
  #   name: kms-api-token
  #   key: token

  # Optional mutual TLS
  # tls_client_cert: "/etc/cosmian-kms-operator/client.crt"
  # tls_client_key:  "/etc/cosmian-kms-operator/client.key"
  # tls_ca_cert:     "/etc/cosmian-kms-operator/ca.crt"

# How often each KMSSecret is re-fetched when no individual refreshInterval is set
default_refresh_interval: "1h"

# REQUIRED (fail closed): the KMS UIDs a KMSSecret may fetch, per namespace.
# A namespace or UID that is not listed is refused. An empty map refuses every KMSSecret.
allowed_uids_by_namespace:
  velo-infra:
    - "5f3a1b2c-4d56-7890-abcd-ef1234567890"

webhook:
  # Port for the admission webhook HTTPS server
  port: 9443
  # Image of the init-container injected into annotated pods
  injector_image: "ghcr.io/cosmian/kms-operator:<VERSION>"
  # TLS certificate and key for the webhook server (auto-generated if omitted)
  # tls_cert: "/etc/cosmian-kms-operator/webhook.crt"
  # tls_key:  "/etc/cosmian-kms-operator/webhook.key"
```

### Namespace allowlist

The operator uses a single KMS credential for the whole cluster. Without a policy, anyone who
can create a `KMSSecret` in any namespace could make the operator copy any KMS secret into a
`Secret` they can read (confused deputy). `allowed_uids_by_namespace` binds each namespace to the
KMS UIDs it may reference; the check runs before any call to the KMS and a refused `KMSSecret`
is reported in `status.message`:

```text
KMS UID '<uid>' is not allowed for namespace '<namespace>'
```

At startup the operator logs a warning when the map is empty.

!!! warning "Upgrading"
    Operator configurations written for earlier releases have no `allowed_uids_by_namespace`
    and every `KMSSecret` is refused until the key is added.

### Target `Secret` ownership

Every `Secret` written by the operator carries the label `kms.cosmian.com/kmssecret=<KMSSecret name>`.
Before updating an existing target `Secret`, the operator requires that it:

- carries that label with the name of the reconciled `KMSSecret`; or
- is a legacy operator-managed `Secret` (label `app.kubernetes.io/managed-by=cosmian-kms-operator`
  and no `kms.cosmian.com/kmssecret` label), which is adopted and relabelled.

Any other existing `Secret` (unmanaged, or owned by another `KMSSecret`) is never overwritten; the
reconcile fails with `target Secret '<name>' is not owned by KMSSecret '<name>'`.

---

## `KMSSecret` CRD reference

```yaml
apiVersion: kms.cosmian.com/v1
kind: KMSSecret
metadata:
  name: postgres-credentials
  namespace: velo-infra
spec:
  # UID of the KMS object to fetch
  secretId: "5f3a1b2c-4d56-7890-abcd-ef1234567890"

  # Name of the Kubernetes Secret to create/update (same namespace)
  targetSecret: "postgres-credentials"

  # Key inside Secret.data (default: "value")
  key: "password"

  # Re-fetch interval (overrides default_refresh_interval)
  refreshInterval: "30m"

  # Extra labels added to the managed Secret
  labels:
    app: postgres

  # Deployments to rolling-restart when the value changes
  restartDeployments:
    - postgres

  # StatefulSets to rolling-restart when the value changes
  restartStatefulSets: []
```

### Status fields

```yaml
status:
  ready: "True"           # "True" | "False"
  message: "synced"       # human-readable last result
```

---

## Using the admission webhook (inject mode)

The webhook mutates pods annotated with `kms.cosmian.com/inject: "true"`. It injects an
init-container (`cosmian-kms-operator inject`) that:

1. Fetches the requested KMS objects by UID.
2. Writes each secret value as a file inside a shared `emptyDir` volume.
3. The main container finds the files at the configured mount path on startup.

### Example Pod annotation

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
  annotations:
    kms.cosmian.com/inject: "true"
    kms.cosmian.com/secrets: |
      - name: db-password
        uid: "5f3a1b2c-4d56-7890-abcd-ef1234567890"
        path: /mnt/secrets/db-password
spec:
  containers:
    - name: app
      image: myapp:latest
      volumeMounts:
        - name: kms-secrets
          mountPath: /mnt/secrets
          readOnly: true
  volumes:
    - name: kms-secrets
      emptyDir:
        medium: Memory   # tmpfs — never written to disk
```

After the init-container completes, `/mnt/secrets/db-password` contains the plaintext
secret value.

---

## Security considerations

- Grant the operator only the RBAC permissions it needs: `get/list/watch` on `KMSSecret`
  CRDs, `create/update/delete` on `Secret` in the target namespaces.
- Keep `allowed_uids_by_namespace` as small as possible: it is the only barrier between a
  namespace's `KMSSecret` objects and the operator's KMS credential.
- Use `api_token_secret_ref` to inject the KMS API key from a Kubernetes `Secret` rather
  than embedding it in the operator configuration file.
- The managed `Secret` objects are standard Kubernetes Secrets; apply
  [RBAC restrictions](https://kubernetes.io/docs/concepts/security/secrets-good-practices/)
  to limit which pods can read them.
- For etcd-at-rest encryption of the created Secrets, combine the operator with the
  [KMS Provider Plugin](kms-provider-plugin.md).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `KMSSecret` stuck in `ready: "False"` | KMS unreachable, wrong `secretId`, UID not in `allowed_uids_by_namespace`, or target `Secret` owned by something else | Check `status.message` and the operator logs; verify the UID with `ckms objects get <uid>` |
| Managed `Secret` not updated after rotation | `refreshInterval` not elapsed | Set a shorter `refreshInterval` or force reconcile by annotating the CRD |
| Webhook rejecting pods | Webhook TLS mismatch | Rotate the webhook certificate and update the `MutatingWebhookConfiguration` |
| Init-container crashloops | Invalid KMS URL or missing API key | Check init-container logs with `kubectl logs <pod> -c cosmian-kms-inject` |

### Inspect operator logs

```bash
kubectl logs -n cosmian-kms-operator \
  -l app=cosmian-kms-operator -f
```
