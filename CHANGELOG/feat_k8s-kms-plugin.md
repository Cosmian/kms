## Features

### Kubernetes integrations

- Add Kubernetes **KMS Provider Plugin** (`crate/clients/k8s/plugin/`) implementing the KMS v2 gRPC API so `kube-apiserver` can encrypt Kubernetes Secrets at rest in etcd via the Cosmian KMS ([#861](https://github.com/Cosmian/kms/issues/861))
- Add Kubernetes **Secrets Store CSI Driver Provider** (`crate/clients/k8s/csi_provider/`) so pods can mount KMS-managed secrets as files, with content-addressed rotation detection ([#862](https://github.com/Cosmian/kms/issues/862))
- Add Kubernetes **operator** (`crate/clients/k8s/operator/`) with controller, admission webhook, and init-container `inject` mode

### Testing

- Add reusable MISE E2E tasks driving a live Minikube cluster: `test:k8s-plugin` (etcd encryption, incl. `--mtls`), `test:csi-provider`, and `test:k8s-operator`, backed by a shared `.mise/lib/k8s.sh` helper library. Coverage includes exact-content assertions, plugin-restart durability, `Status()` degraded-health reporting, mutual TLS, CSI key rotation, and graceful failure on secret revocation

## Changed

### Dependencies

- Align all new Kubernetes crate dependencies to workspace (`prost`, `serde_yaml`, `tonic`, `tokio-stream`, `kube`, `k8s-openapi`, `axum`, `rcgen`, and others added to `[workspace.dependencies]`; k8s crates updated to `{ workspace = true }`)

### Documentation

- Split `documentation/docs/integrations/kubernetes/index.md` (621 lines) into four pages: overview (`index.md`), [KMS Provider Plugin](../documentation/docs/integrations/kubernetes/kms-provider-plugin.md), [Secrets Store CSI Driver Provider](../documentation/docs/integrations/kubernetes/csi-provider.md), and [Kubernetes Operator](../documentation/docs/integrations/kubernetes/operator.md)

### CI

- Rework the `k8s_plugin_e2e.yml` workflow to build the k8s binaries once (shared artifact) and delegate all cluster orchestration to the MISE tasks; remove the duplicated `cargo build` / `cargo test` / `helm lint` steps already covered by the nix test jobs and `test:helm`
