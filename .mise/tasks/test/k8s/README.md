# Cosmian KMS — Kubernetes E2E Tests

Six mise tasks live under `test:k8s:`.
All tests require a running Minikube cluster (`minikube start --driver=docker`).

---

## 1. Task overview

```mermaid
graph TB
    D["<b>test:k8s</b><br/>(default — runs all three)"]

    P["<b>test:k8s:plugin</b><br/>KMS Provider Plugin<br/>etcd encryption KMS v2"]
    PM["  ↳ --mtls variant"]

    O["<b>test:k8s:operator</b><br/>KMS Operator<br/>Docker image · K8s Job inject"]

    C["<b>test:k8s:csi-provider</b><br/>KMS CSI Provider<br/>Docker image · DaemonSet"]

    OI["<b>test:k8s:operator-image</b><br/>Operator image smoke test<br/>(--help via K8s Pod)"]

    CI["<b>test:k8s:csi-provider-image</b><br/>CSI provider image smoke test<br/>(--help via K8s Pod)"]

    KMS["<b>test:k8s:kms-image</b><br/>KMS server image smoke test<br/>(/etc validation + Helm deploy + HTTP health)"]

    D --> P
    D --> O
    D --> C
    P --> PM
```

> **Constraint**: `test:k8s:operator` and `test:k8s:csi-provider` use **only the published
> Docker images** (built by Nix, loaded into Minikube). No raw binaries are executed for
> those two components — the image is the artefact that ships to users.

---

## 2. Plugin test (`test:k8s:plugin`)

The plugin is the only component installed as a raw binary (it runs as a
**systemd unit on the Kubernetes control-plane node**, which has no container runtime
interface for plugins at the KMS v2 gRPC layer).

```mermaid
sequenceDiagram
    autonumber
    participant R  as Test runner
    participant K  as Cosmian KMS<br/>(Helm, kms-plugin-e2e ns)
    participant PF as port-forward :9998
    participant ck as ckms (local bin)
    participant N  as Minikube node
    participant P  as kubernetes-kms-plugin<br/>(systemd service)
    participant A  as kube-apiserver
    participant E  as etcd

    R->>K: helm upgrade --install (SQLite, emptyDir)
    R->>PF: kubectl port-forward svc/…-cosmian-kms 9998
    ck->>K: sym keys create AES-256 → kek-uid
    R->>N: minikube cp plugin binary → /usr/local/bin/
    R->>N: write /etc/kubernetes-kms-plugin/config.yaml<br/>(server_url, wrapping_key_uid, socket_path)
    R->>N: systemd enable+start kubernetes-kms-plugin.service
    P-->>N: Unix socket created: /var/run/kubernetes-kms-plugin/kms.sock
    R->>N: write /etc/kubernetes/enc/config.yaml (KMS v2 EncryptionConfiguration)
    R->>N: python3 patch-kube-apiserver.py (adds --encryption-provider-config flag)
    A->>P: Status() gRPC → healthz/kms-providers = ok
    Note over R: Create K8s Secret "cosmian-test-secret"
    A->>P: GenerateDataEncryptionKey()
    P->>K: Encrypt(DEK) via sym/encrypt
    K-->>P: wrapped-DEK
    P-->>A: { ciphertext, annotations }
    A->>E: store k8s:enc:kms:v2:cosmian-kms:… blob
    Note over R,E: ASSERT etcd value contains "k8s:enc:kms:v2:cosmian-kms:" prefix
    Note over R,E: ASSERT kubectl get secret decrypts to exact plaintext
    Note over R,P: Restart plugin → ASSERT decryption still works (no plaintext DEK cache)
    Note over R,P: Stop plugin → ASSERT healthz/kms-providers ≠ ok
    Note over R,P: Restart plugin → ASSERT healthz/kms-providers recovers
```

---

## 3. Operator test (`test:k8s:operator`)

The operator runs as a **Kubernetes Job** using the published Docker image.
`ckms` (a local binary) is only used as a test fixture helper to pre-populate
the KMS; the operator itself always runs inside the cluster via its image.

```mermaid
sequenceDiagram
    autonumber
    participant Nix as Nix build<br/>(result-k8s-operator-image)
    participant M   as Minikube
    participant R   as Test runner
    participant K   as Cosmian KMS<br/>(Helm, kms-operator-e2e ns)
    participant PF  as port-forward :9998
    participant ck  as ckms (local bin)
    participant J   as K8s Job<br/>(initContainer: inject<br/> main: verify)

    Nix-->>M: minikube image load tarball → cosmian-kms-operator:TAG
    R->>K: helm upgrade --install (SQLite, emptyDir)
    R->>PF: kubectl port-forward svc/…-cosmian-kms 9998
    ck->>K: secret-data create --value "operator-injected-…" → secret-uid
    R->>PF: close (Job uses ClusterIP directly)

    R->>J: kubectl apply Job
    Note over J: initContainer (inject)<br/>image: cosmian-kms-operator:TAG<br/>imagePullPolicy: Never<br/>args: inject --server-url http://CLUSTER_IP:9998<br/>       --secret-uids secret-uid:injected-secret<br/>       --output-dir /output
    J->>K: GetObject(secret-uid) via KMIP/HTTP → secret bytes
    K-->>J: secret bytes
    J->>J: write /output/injected-secret (emptyDir)
    Note over J: main container (verify)<br/>image: busybox:1.36<br/>command: cat /output/injected-secret → stdout
    R->>J: kubectl wait --for=condition=complete
    R->>J: kubectl logs POD -c verify → WRITTEN
    Note over R: ASSERT WRITTEN == "operator-injected-…"
```

---

## 4. CSI Provider test (`test:k8s:csi-provider`)

The CSI provider runs as a **Kubernetes DaemonSet** using the published Docker
image. It exposes a Unix socket to the Secrets Store CSI Driver via a `hostPath`
volume — the same topology used in production.

```mermaid
sequenceDiagram
    autonumber
    participant Nix as Nix build<br/>(result-k8s-csi-provider-image)
    participant M   as Minikube
    participant R   as Test runner
    participant K   as Cosmian KMS<br/>(Helm, kms-csi-e2e ns)
    participant PF  as port-forward :9998
    participant ck  as ckms (local bin)
    participant DS  as CSI Provider DaemonSet<br/>(kube-system ns)<br/>image: cosmian-kms-csi-provider:TAG
    participant CSI as Secrets Store<br/>CSI Driver (Helm)
    participant Pod as Test Pod

    Nix-->>M: minikube image load tarball → cosmian-kms-csi-provider:TAG
    R->>K: helm upgrade --install (SQLite, emptyDir)
    R->>CSI: helm upgrade --install csi-secrets-store<br/>(enableSecretRotation=true, pollInterval=30s)
    R->>PF: kubectl port-forward svc/…-cosmian-kms 9998

    ck->>K: secret-data create "csi-secret-value-…" → secret-uid
    ck->>K: sym keys create AES-256 → rotate-uid-v1
    ck->>K: sym keys create AES-256 → rotate-uid-v2
    ck->>K: secret-data create "revoke-me-…" → revoke-uid
    ck->>K: secret-data revoke + destroy revoke-uid
    R->>PF: close

    R->>M: kubectl apply ConfigMap (server_url, socket_path)
    R->>M: kubectl apply DaemonSet<br/>hostPath: /etc/kubernetes/secrets-store-csi-providers<br/>imagePullPolicy: Never · securityContext.privileged: true
    DS-->>M: /etc/kubernetes/secrets-store-csi-providers/cosmian-kms.sock created on host

    Note over R,DS: TEST 1 — exact content mount
    R->>M: apply SecretProviderClass(cosmian-known, kmsUID=secret-uid)
    R->>Pod: apply Pod(csi-known-pod) with CSI volume
    CSI->>DS: Mount(objectName=known-secret, kmsUID=secret-uid)
    DS->>K: GetObject(secret-uid) → "csi-secret-value-…"
    K-->>DS: bytes + objectVersion=SHA256
    DS-->>CSI: file content
    CSI-->>Pod: /mnt/secrets/known-secret
    Note over R,Pod: ASSERT cat /mnt/secrets/known-secret == "csi-secret-value-…"

    Note over R,DS: TEST 2 — live rotation (SPC re-pointed to new UID)
    R->>M: update SecretProviderClass(cosmian-rotate, kmsUID=rotate-uid-v2)
    Note over CSI: rotation reconciler wakes (30s poll)
    CSI->>DS: Mount(…, kmsUID=rotate-uid-v2)
    DS->>K: GetObject(rotate-uid-v2) → new bytes
    DS-->>CSI: new content + new objectVersion
    CSI-->>Pod: overwrite /mnt/secrets/rotate-key in-place
    Note over R,Pod: ASSERT file hex changed (live update in running pod)

    Note over R,DS: TEST 3 — graceful failure (revoked object)
    R->>M: apply SecretProviderClass(cosmian-revoked, kmsUID=revoke-uid)
    R->>Pod: apply Pod(csi-revoked-pod) with CSI volume
    CSI->>DS: Mount(…, kmsUID=revoke-uid)
    DS->>K: GetObject(revoke-uid) → 404 / not found
    DS-->>CSI: error
    Note over R,Pod: ASSERT csi-revoked-pod stays NotReady (Mount failed)
```

---

## 5. CI pipeline (`packaging-kubernetes.yml`)

```mermaid
graph LR
    subgraph Build
        BB["<b>build-k8s-bins</b><br/>Nix: k8s-plugin-bin<br/>+ kms-cli (ckms)<br/>→ artifact: k8s-e2e-bins"]
        BI["<b>build-k8s-images</b><br/>Nix: k8s-operator-image<br/>+ k8s-csi-provider-image<br/>→ artifact: k8s-docker-images"]
    end

    subgraph "E2E: plugin (binary on Minikube node)"
        EP1["test:k8s:plugin<br/>(plain HTTP)"]
        EP2["test:k8s:plugin --mtls<br/>(mutual TLS)"]
    end

    subgraph "E2E: images (Docker image in Minikube cluster)"
        EI1["test:k8s:operator<br/>(K8s Job)"]
        EI2["test:k8s:csi-provider<br/>(DaemonSet)"]
        EI3["test:k8s:operator-image<br/>(smoke: --help)"]
        EI4["test:k8s:csi-provider-image<br/>(smoke: --help)"]
    end

    BB -->|k8s-e2e-bins| EP1
    BB -->|k8s-e2e-bins| EP2
    BB -->|ckms binary| EI1
    BB -->|ckms binary| EI2
    BI -->|k8s-docker-images| EI1
    BI -->|k8s-docker-images| EI2
    BI -->|k8s-docker-images| EI3
    BI -->|k8s-docker-images| EI4
```

---

## Key design decisions

| Decision | Rationale |
|----------|-----------|
| Operator uses K8s **Job** (not raw binary) | The Job runs the same image that ships to users; tests the published artifact |
| CSI provider uses K8s **DaemonSet** (not systemd) | Mirrors production topology; image + hostPath socket — exactly what users deploy |
| `imagePullPolicy: Never` on all test pods/jobs | Forces Minikube to use the locally-loaded Nix image; prevents accidental registry pulls |
| `ckms` stays a local binary in both tests | It is a test *fixture helper* (pre-populates KMS), not the component under test |
| Plugin stays a binary on the node | KMS v2 gRPC runs as a privileged systemd service on the control-plane; no K8s container runtime involvement at that layer |

---

## `test:k8s:kms-image` — KMS server image smoke test

Tests the main KMS server Docker image (`ghcr.io/cosmian/kms` or `ghcr.io/cosmian/kms-fips`)
in a Kubernetes pod. This is the regression test for **issue #1132** where required `/etc`
files were missing from the 5.26 image after busybox was removed.

**Checks performed:**

1. **`/etc` validation pod** — a one-shot pod that asserts all of the following are present:
   - `/etc/passwd` — UID resolution (`runAsNonRoot: true`, `getpwuid()`)
   - `/etc/group` — GID resolution
   - `/etc/nsswitch.conf` — DNS / hostname resolution
   - `/etc/ssl/certs/ca-bundle.crt` — outbound TLS certificate verification (OIDC, etc.)
   - `/etc/cosmian` — bind-mount target for `COSMIAN_KMS_CONF` config files

2. **Helm deploy** — full KMS deployment via `charts/cosmian-kms` with the Helm chart's
   production security context (`runAsNonRoot`, `readOnlyRootFilesystem`, etc.).

3. **HTTP health check** — verifies `/version` responds over a `kubectl port-forward`.

**In CI:** triggered by `packaging-docker.yml` (`test-k8s-kms-pod` job) on every build,
for all four combinations of `{fips, non-fips} × {ubuntu-24.04 (amd64), ubuntu-24.04-arm (arm64)}`,
after the arch-specific images are pushed to GHCR.

```bash
# Run locally (requires minikube + helm):
DOCKER_IMAGE_NAME=ghcr.io/cosmian/kms:develop-amd64 mise run test:k8s:kms-image
```
