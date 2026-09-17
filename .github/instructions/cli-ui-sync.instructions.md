---
name: 'CLI ⇔ Web UI Parity'
description: 'Mirror every CLI command/flag to the Web UI and regenerate the CLI documentation'
applyTo: 'crate/clients/clap/**/*.rs, crate/clients/ckms/**/*.rs, ui/src/actions/**/*.ts, ui/src/actions/**/*.tsx'
---

# CLI ⇔ Web UI parity

The Web UI mirrors the `ckms` CLI feature-for-feature. Every CLI command or flag must be
reflected in `ui/src/actions/`.

## Checklist

- [ ] `crate/clients/clap/src/actions/<module>/` — CLI action implemented
- [ ] `crate/clients/ckms/src/commands.rs` — subcommand registered in the `CliCommands` enum
- [ ] `ui/src/actions/<Module>/` — React component(s) created
- [ ] `ui/src/App.tsx` — `<Route>` entry added
- [ ] `ui/src/menuItems.tsx` — menu item added
- [ ] `crate/server/src/start_kms_server.rs` — SPA route added if a new top-level path
- [ ] `crate/clients/ckms/src/tests.rs` — tests added for the new subcommand
- [ ] Regenerate CLI docs: `cargo run --bin ckms -- markdown documentation/docs/kms_clients/cli/main_commands.md` and commit the result (manual edits are overwritten)

> Rules 4.4 + 4.15 of `/kms-sync-rules`. For clap/WASM conventions, see `rust-cli.instructions.md`.
