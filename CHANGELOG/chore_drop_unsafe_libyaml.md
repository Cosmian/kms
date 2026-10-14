# Remove the unmaintained `unsafe-libyaml` dependency (RUSTSEC-2024-0449)

## Security

- Replace `serde_yaml` (deprecated, depends on the archived `unsafe-libyaml`) with the safe-Rust
  `serde-saphyr` in the Kubernetes KMS plugin, CSI provider, and operator.
- Upgrade `kube` 0.99 → 4.2, `k8s-openapi` 0.24 → 0.28 (feature `v1_30` → `v1_32`, the oldest
  supported by the new release) and `schemars` 0.8 → 1, which `kube` 4 requires. The generated
  `KMSSecret` CRD is structurally unchanged (only description whitespace differs).
- Build `clap-config-fallback` without its `yaml` feature: the server no longer accepts `.yaml` /
  `.yml` configuration files (TOML and JSON remain supported).
- `cargo deny check` passes again without ignoring the advisory.
