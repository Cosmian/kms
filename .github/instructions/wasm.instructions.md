---
name: 'WASM Bindings'
description: 'Keep WASM exports, regenerated TypeScript types, and UI consumers in sync'
applyTo: 'crate/clients/wasm/**/*.rs'
---

# WASM bindings sync

A WASM binding change must be rebuilt and its generated types committed.

## Checklist

- [ ] `crate/clients/wasm/src/wasm.rs` — `#[wasm_bindgen]` exported function added
- [ ] Rebuild WASM: `wasm-pack build --target web` (from `crate/clients/wasm/`)
- [ ] `ui/src/wasm/pkg/` — regenerated TS types committed
- [ ] UI component imports and calls the new WASM function

> Rule 4.5 of `/kms-sync-rules`. For WASM target constraints (no `std::fs`, `std::net`, `tokio::runtime`), see `rust-cli.instructions.md`.
