# Secrets Store CSI Driver Provider

The Eviden KMS CSI provider (`cosmian-kms-csi-provider`) implements the
[Kubernetes Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) provider
interface. It allows pods to **mount KMS-managed secrets as files** in their filesystem
without ever storing those secrets in a Kubernetes `Secret` object.

!!! note "Worker-node DaemonSet"
    Unlike the [KMS Provider Plugin](kms-provider-plugin.md), this component runs as a gRPC
    server on **worker nodes** (as a DaemonSet), not on control-plane nodes. It is called by
    the CSI driver whenever a pod is scheduled that references a `SecretProviderClass`.

```mermaid
sequenceDiagram
    participant K as kubelet
    participant D as secrets-store-csi-driver<br/>(DaemonSet)
    participant P as cosmian-kms-csi-provider<br/>(DaemonSet, Unix socket)
    participant M as Eviden KMS

    Note over K,M: Pod scheduled with CSI volume
    K->>D: MountRequest (SecretProviderClass)
    D->>P: gRPC Mount (objects list)
    P->>M: KMIP Get (object UID)
    M-->>P: plaintext secret value
    P-->>D: MountResponse (files + metadata)
    D-->>K: tmpfs volume mounted at /mnt/secrets-store/
    Note over K,M: Secret available as a file inside the pod
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Eviden KMS ≥ 5.26.0 | Running and reachable from every worker node |
| Kubernetes ≥ 1.25 | Secrets Store CSI Driver stable API |
| Helm ≥ 3.8 | Used to install the CSI driver and the provider |
| Secrets Store CSI Driver | Installed via Helm (see below) |

### Install the Secrets Store CSI Driver

```bash
helm repo add secrets-store-csi-driver \
  https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts

helm install csi-secrets-store \
  secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=false \
  --set enableSecretRotation=true \
  --set rotationPollInterval=1m
```

Enable `enableSecretRotation` if you want in-place file updates when a secret is rotated
in the KMS.

The provider identifies the requesting namespace from the pod information the driver passes
on each mount: the `CSIDriver` object must have `podInfoOnMount: true` (the default of the
upstream Helm chart). Without it every mount is refused with
`pod namespace missing: enable podInfoOnMount on the CSIDriver`.

---

## Installation

=== "Helm (recommended)"

    The CSI provider is packaged together with the Eviden KMS Helm chart.
    Install the provider DaemonSet alongside the KMS server:

    ```bash
    helm repo add cosmian https://cosmian.github.io/kms
    helm repo update

    helm install cosmian-kms cosmian/kms \
      --namespace cosmian-kms --create-namespace \
      --set csiProvider.enabled=true \
      --set kms.insecureAllowUnauthenticated=true   # development only: configure authentication in production
    ```

    To install **only** the provider (KMS server is deployed elsewhere):

    ```bash
    helm install cosmian-kms-csi cosmian/kms \
      --namespace cosmian-kms --create-namespace \
      --set server.enabled=false \
      --set csiProvider.enabled=true \
      --set csiProvider.kmsUrl=https://kms.example.com:9998
    ```

=== "Docker image"

    Pre-built images are published to the GitHub Container Registry on every release:

    ```bash
    docker pull ghcr.io/cosmian/kms-csi-provider:<VERSION>
    ```

    Reference the image in your DaemonSet manifest or override it in the Helm chart:

    ```yaml
    # Helm override
    csiProvider:
      image:
        repository: ghcr.io/cosmian/kms-csi-provider
        tag: <VERSION>
    ```

=== "Build from source"

    ```bash
    cargo build --release -p cosmian_kms_csi_provider
    sudo install -m 755 target/release/cosmian-kms-csi-provider /usr/local/bin/
    ```

    Then deploy the `DaemonSet` YAML from
    `crate/clients/k8s/csi_provider/deploy/daemonset.yaml` in the KMS repository.

---

## Configuration

Create the configuration file at `/etc/cosmian-kms-csi/config.yaml` on every worker node
(or mount it via a `ConfigMap` in the DaemonSet):

```yaml
cosmian_kms:
  # URL of the Eviden KMS server
  server_url: "https://kms.example.com:9998"

  # Optional: API key authentication
  # api_key: "YOUR_API_KEY"

  # Optional: mutual TLS
  # tls_cert: "/etc/cosmian-kms-csi/client.crt"
  # tls_key:  "/etc/cosmian-kms-csi/client.key"
  # ca_cert:  "/etc/cosmian-kms-csi/ca.crt"

  # Unix socket path (must match the DaemonSet hostPath)
  socket_path: "/var/run/cosmian-kms-provider.sock"

  # REQUIRED (fail closed): the KMS UIDs a pod may mount, per pod namespace.
  allowed_uids_by_namespace:
    default:
      - "5f3a1b2c-4d56-7890-abcd-ef1234567890"
```

`server_url` and `allowed_uids_by_namespace` are required in practice. `socket_path` defaults to
`/var/run/cosmian-kms-provider.sock`.

### Namespace allowlist and path rules

A `SecretProviderClass` is writable by anyone with access to its namespace, so it must not be
trusted to choose which KMS object is mounted. Before any KMS call, each `Mount` is checked:

| Check | Refusal |
|---|---|
| The CSI driver sent the pod namespace (`podInfoOnMount: true`) | `PermissionDenied`: `pod namespace missing: enable podInfoOnMount on the CSIDriver` |
| `kmsUID` is listed for that namespace in `allowed_uids_by_namespace` (a UID starting with `[`, a KMS tag list, is never allowed) | `PermissionDenied`: `KMS UID '<uid>' is not allowed for namespace '<ns>'` |
| `objectName` is a relative path, does not start with `..` and has no `..` component | `InvalidArgument`: `objectName '<name>' must be a relative path, must not contain '..', and must not start with '..'` |

An empty `allowed_uids_by_namespace` refuses every mount.

!!! warning "Upgrading"
    Provider configurations written for earlier releases must add `allowed_uids_by_namespace`,
    and the `CSIDriver` must enable `podInfoOnMount`, or every mount fails.

---

## Usage

### 1. Pre-create a secret in the KMS

```bash
# Create a symmetric key (or any KMS object)
ckms sym keys create \
  --algorithm aes \
  --number-of-bits 256 \
  --tag db-password
# Note the UID returned — e.g. "5f3a1b2c-4d56-..."
```

You can also create arbitrary secret data (e.g. passwords, API keys) using the `ckms`
CLI or the KMS web UI.

### 2. Create a `SecretProviderClass`

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: db-password
  namespace: default
spec:
  provider: cosmian-kms
  parameters:
    objects: |
      - objectName: "db-password"
        kmsUID: "5f3a1b2c-4d56-..."   # UID of the KMS object
```

The `objects` list can reference multiple KMS objects. Each produces a separate file
inside the pod at `<mountPath>/<objectName>`.

#### Pinning an object version

Each object entry accepts an optional `objectVersion`. When it is empty or absent, the provider always serves the current content of the KMS object. When it is set, it **must** be the version of the object's current content, that is the lower-case hexadecimal SHA-256 digest of the bytes the provider returns; otherwise the mount fails with a `FailedPrecondition` error (`object '<uid>' has version <actual> but the SecretProviderClass pins objectVersion <expected>`).

```yaml
    objects: |
      - objectName: "db-password"
        kmsUID: "5f3a1b2c-4d56-..."
        objectVersion: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

A pinned `objectVersion` makes pods refuse to start (or to re-mount on rotation) when the secret was changed in the KMS, so only pin versions you intend to freeze. Releases before this behavior ignored the field: any `objectVersion` value that is not a content digest must be removed (or emptied) before upgrading.

### 3. Mount the `SecretProviderClass` in a Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
spec:
  containers:
    - name: app
      image: nginx
      volumeMounts:
        - name: secrets
          mountPath: /mnt/secrets
          readOnly: true
  volumes:
    - name: secrets
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: db-password
```

The secret value is available inside the container at `/mnt/secrets/db-password`.

---

## Secret rotation

When `enableSecretRotation=true` is set on the CSI driver, it re-calls the provider at
the configured `rotationPollInterval`. If the KMS object value has changed (the provider
detects this via a SHA-256 hash of the returned bytes), the CSI driver updates the
in-memory `tmpfs` mount atomically. The pod sees the new file content without a restart.

To rotate a secret:

1. In the KMS, update the object (e.g. replace the key material or secret value).
2. Wait for `rotationPollInterval` — the file inside the running pod will be updated
   automatically.

---

## Security considerations

- The Unix socket (`/var/run/cosmian-kms-provider.sock`) must only be accessible by the
  CSI driver. Kubernetes `hostPath` volumes enforce this via file permissions.
- The configuration file containing the `api_key` or TLS key must be mode `0600` and
  owned by the provider process user.
- Secret data is held in a `tmpfs` (in-memory) volume in the pod — it is never written
  to the node's disk.
- Keep `allowed_uids_by_namespace` minimal: it is what stops a pod in one namespace from
  mounting another namespace's secrets through a crafted `SecretProviderClass`.
- Use mutual TLS (`tls_cert`, `tls_key`, `ca_cert`) in production to authenticate the
  provider to the KMS server.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `pod has unbound immediate PersistentVolumeClaims` | CSI driver not installed | Install `secrets-store-csi-driver` via Helm |
| `provider not found: cosmian-kms` | Provider DaemonSet not running on the node | Check `kubectl get pods -n kube-system -l app=cosmian-kms-csi-provider` |
| `connection refused` to KMS | Wrong `server_url` or KMS unreachable | Verify `server_url` from inside the node |
| `KMS UID '…' is not allowed for namespace '…'` | UID missing from `allowed_uids_by_namespace` | Add the UID under the pod's namespace and restart the provider |
| `pod namespace missing` | `podInfoOnMount` disabled on the `CSIDriver` | Enable `podInfoOnMount: true` |
| `object not found` in mount | Wrong `kmsUID` in `SecretProviderClass` | Verify the UID with `ckms objects get <uid>` |
| File not updating on rotation | `enableSecretRotation` not enabled | Reinstall CSI driver with `--set enableSecretRotation=true` |

### Inspect provider logs

```bash
# Find the provider pod on the same node as your failing pod
kubectl get pods -n kube-system -l app=cosmian-kms-csi-provider -o wide

# Tail provider logs
kubectl logs -n kube-system <provider-pod> -f
```
