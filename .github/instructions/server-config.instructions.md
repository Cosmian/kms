---
name: 'Server Configuration'
description: 'Keep clap flags, the wizard, and TOML templates in sync when changing server configuration'
applyTo: 'crate/server/src/config/**/*.rs'
---

# Server configuration sync

A configuration change must propagate to the clap struct, the wizard, and the TOML templates.

## Checklist

- [ ] `crate/server/src/config/command_line/clap_config.rs` — struct field with `#[clap(...)]`
- [ ] `crate/server/src/config/wizard/<*>_wizard.rs` — interactive step added/updated
- [ ] `resources/kms.toml` — reference config updated
- [ ] `crate/server/kms_template.toml` — tarball template updated
- [ ] `pkg/kms.toml` — service deployment config updated
- [ ] `crate/clients/client/src/config.rs` — client config struct kept consistent (server ↔ client wizard parity)

> Rules 4.6 + 4.7 of `/kms-sync-rules`.
