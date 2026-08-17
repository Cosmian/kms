---
name: 'Auth Middleware'
description: 'Keep auth config, the wizard, the middleware, and scope wiring in sync'
applyTo: 'crate/server/src/middlewares/**/*.rs'
---

# Auth middleware sync

An authentication change must be reflected in the config, the wizard, the middleware, and the
scope wiring.

## Checklist

- [ ] Config struct updated in `crate/server/src/config/`
- [ ] Wizard step added/updated in `crate/server/src/config/wizard/auth_wizard.rs`
- [ ] Middleware implemented in `crate/server/src/middlewares/`
- [ ] Every authenticated scope in `start_kms_server.rs` wraps the middleware with `Condition::new(use_<auth>, <Middleware>)`
- [ ] `EnsureAuth::new` boolean: `use_jwt_auth || use_cert_auth || use_api_token_auth` (every scope except mTLS-only)

> Rule 4.9 of `/kms-sync-rules`.
