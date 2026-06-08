# Regorus for in-process Rego policy evaluation

We use [Regorus](https://github.com/microsoft/regorus) (a pure-Rust Rego engine) as the sole
policy evaluation engine. OPA WASM and external OPA service are not supported.

Regorus eliminates the need for a WASM runtime (wasmtime), an `opa build -t wasm` compilation
step, or a network round-trip per authorization decision. It evaluates `.rego` files natively
in the same process as the KMS server, keeping latency in the microsecond range and removing
all runtime binary dependencies beyond the KMS binary itself.

## Considered Options

- **OPA WASM + wasmtime**: requires `opa build -t wasm` in the policy pipeline, adds ~8MB of
  wasmtime to the binary, and is harder to debug. Rejected.
- **External OPA service (HTTP REST)**: requires a sidecar or remote OPA deployment, adds
  network latency per KMIP request, and complicates failover. Rejected.

## Consequences

Policy authors write standard OPA Rego. Policies must be validated against Regorus's Rego
compatibility surface (a small subset of built-ins may differ from OPA). Test policy bundles
against Regorus directly, not the OPA CLI.
