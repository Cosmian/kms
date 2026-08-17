---
name: 'Cloud Provider Integrations'
description: 'Keep provider routes, config, wizard, CLI, and UI in sync when adding a cloud provider integration'
applyTo: 'crate/server/src/routes/aws_xks/**, crate/server/src/routes/azure_ekm/**, crate/server/src/routes/google_cse/**, crate/server/src/routes/ms_dke/**'
---

# Cloud provider integration sync

A cloud provider integration spans the config, the wizard, the routes, the OpenAPI spec, the CLI,
and the UI.

## Checklist

- [ ] Config struct in `crate/server/src/config/`
- [ ] Wizard step in `crate/server/src/config/wizard/advanced_wizard.rs`
- [ ] Routes module in `crate/server/src/routes/<provider>/`, declared in `routes/mod.rs`
- [ ] Scope registered in `start_kms_server.rs` with correct auth middleware
- [ ] `crate/server/documentation/openapi.yaml` updated
- [ ] CLI actions in `crate/clients/clap/src/actions/<provider>/`
- [ ] UI actions in `ui/src/actions/CloudProviders/`

> Rule 4.12 of `/kms-sync-rules`.
