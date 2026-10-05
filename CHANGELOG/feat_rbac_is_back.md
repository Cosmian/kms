# Changelog — feat_rbac_is_back

## Features

- **deploy/opa**: add Cosmian KMS service to `deploy/opa/docker-compose.yml` — SQLite backend, embedded Regorus RBAC enabled, shares the same Rego policy bundle as the OPA sidecar container; disable OPA anonymous telemetry (`--disable-telemetry`).
