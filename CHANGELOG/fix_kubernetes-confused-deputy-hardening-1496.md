## Bug Fixes

### Kubernetes
- Restrict the KMS plugin `Decrypt` to the configured KEK and the older KEKs explicitly listed in `allowed_decryption_key_ids` ([#1496](https://github.com/Cosmian/kms/issues/1496)).
- Avoid echoing malformed secret UID annotations into operator logs.

## Security

- Enforce `allowed_uids_by_namespace` in the operator admission webhook: Pod injection with a KMS UID outside the namespace allowlist is denied, and webhook errors no longer admit the Pod (COSMIAN-2026-084).
