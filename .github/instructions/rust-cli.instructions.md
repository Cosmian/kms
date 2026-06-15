---
name: 'Rust CLI Clients'
description: 'CLI actions, binary entry point, WASM bindings, and PKCS#11 rules'
applyTo: 'crate/clients/**/*.rs'
---

# CLI client rules

## Directory structure

- **CLI actions** (clap subcommands): `crate/clients/clap/src/` — one module per feature area.
- **CLI binary** entry point: `crate/clients/ckms/src/` — dispatches to actions.
- **HTTP client library**: `crate/clients/client/` — shared between CLI and WASM.
- **WASM bindings**: `crate/clients/wasm/src/` — browser client used by the Web UI.
- **PKCS#11 provider**: `crate/clients/pkcs11/` — HSM-compatible interface.

## Sync rule: CLI ↔ Web UI

Every new CLI command or flag **must** be mirrored to the Web UI in `ui/src/actions/`.
The UI mirrors the `ckms` CLI tool feature-for-feature.

## Clap conventions

- Use `#[derive(Parser)]` for top-level commands, `#[derive(Subcommand)]` for subcommands.
- `#[derive(Args)]` for reusable argument groups.
- Help text (`/// doc comments`) becomes the CLI `--help` output — keep it user-facing.

## WASM considerations

- WASM builds cannot use `std::fs`, `std::net`, or `tokio::runtime`.
- Shared code in `crate/clients/client_utils/` — must compile for both native and `wasm32-unknown-unknown`.
- Test WASM builds with: `bash .github/scripts/nix.sh --variant fips test wasm`

## Testing

```bash
cargo test -p cosmian_kms_cli_actions
cargo test -p ckms
```
