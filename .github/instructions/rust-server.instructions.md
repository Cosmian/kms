---
name: 'Rust Server'
description: 'KMS server architecture rules (KMIP operations, routes, middleware)'
applyTo: 'crate/server/**/*.rs'
---

# KMS server rules

## KMIP operation pattern

- One file per operation in `src/core/operations/` (e.g., `create.rs`, `get.rs`, `destroy.rs`).
- Dispatcher in `src/core/operations/dispatch.rs` maps TTLV tag → operation function.
- Every operation receives the `KMS` struct (database + crypto_oracles + HSM).
- Authorization check is **mandatory** before every operation executes.

## HTTP route pattern

- Handler function in `src/routes/<module>.rs`.
- Register route in `src/routes/mod.rs`.
- Add middleware in `src/start_kms_server.rs` — middleware order is **LIFO** (last registered = first executed).
- OpenAPI spec must be updated for new endpoints.

## KMS struct (`src/core/kms/mod.rs`)

- Central state: `params`, `database`, `crypto_oracles`, `hsm`.
- Do not clone the KMS struct — pass `&self` references.

## Enterprise integrations

- AWS XKS: `src/routes/aws_xks/`
- Azure EKM: `src/routes/azure_ekm/`
- Google CSE: `src/routes/google_cse/`
- Microsoft DKE: `src/routes/ms_dke/`

## Configuration

- Server config lives in `src/config/`.
- CLI flags map to `clap` derive structs.
- Configuration templates in `resources/`.

## Testing

```bash
cargo test -p cosmian_kms_server             # FIPS mode
cargo test -p cosmian_kms_server --features non-fips  # non-FIPS
```

> For KMIP operation compliance, run `/kmip-compliance`. For new endpoints, run `/openapi-endpoint`.
