## Breaking Changes

### Kubernetes operator, CSI provider and KMS plugin

- The Kubernetes operator, the Secrets Store CSI provider and the KMS v2 plugin now fail closed and refuse to serve until their configuration lists who may use the KMS credential ([#1496](https://github.com/Cosmian/kms/issues/1496)). Existing configuration files must add the new keys:
  - operator and CSI provider: `allowed_uids_by_namespace` (namespace → list of KMS UIDs). An absent or empty map refuses every `KMSSecret` / mount. The CSI driver must also run with `podInfoOnMount: true`.
  - KMS plugin: `allowed_peer_uids` (list of UIDs, normally the kube-apiserver UID). The plugin does not start with an empty list.

## Bug Fixes

### Kubernetes

- Operator: refuse to overwrite a target `Secret` that is not owned by the reconciled `KMSSecret`. Every managed `Secret` carries the label `kms.cosmian.com/kmssecret=<name>`; legacy operator-managed `Secret` objects are adopted.
- CSI provider: take the pod namespace from the CSI driver (`csi.storage.k8s.io/pod.namespace`), refuse KMS UIDs not allowlisted for it (KMS tag lists included), and reject `objectName` values that are absolute or contain `..`.
- KMS plugin: check the kernel peer credentials of every connection on the Unix socket and drop peers whose UID is not in `allowed_peer_uids`.

## Documentation

- Kubernetes operator page: document the allowlist and ownership rules, correct the configuration keys, and remove the Helm installation instructions (the chart has no operator values). CSI provider and KMS plugin pages document the new keys.

---

Closes #1496
