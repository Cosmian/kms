---
name: 'REST Routes & OpenAPI'
description: 'Keep handlers, route registration, middleware, and the OpenAPI spec in sync when adding a REST endpoint'
applyTo: 'crate/server/src/routes/**/*.rs'
---

# REST endpoint sync

A new HTTP endpoint is registered in four places. All must stay consistent.

## Checklist

- [ ] Handler implemented in `crate/server/src/routes/<module>/`
- [ ] `crate/server/src/routes/mod.rs` — `pub mod <module>;` declared
- [ ] `crate/server/src/start_kms_server.rs` — `web::scope(...)` or `.service(...)` registered
    - Middleware order: Cors → auth extractors → EnsureAuth (LIFO: wrap inner-first)
- [ ] `crate/server/documentation/openapi.yaml` — path, request/response schemas, tags added
- [ ] Run `crate/test_kms_server/src/openapi_validation.rs` tests to validate

> Rule 4.2 of `/kms-sync-rules`. Run `/openapi-endpoint` for the guided end-to-end flow.
