# Changelog — branch `rbac_design`

## Features

- Add `RbacConfig` and `RbacParams` configuration structs for RBAC/OPA authorization
- Add `tenant_id` column to `objects` table (schema migration for SQLite/PostgreSQL/MySQL)
- Add startup cross-validation: RBAC mode requires IdP auth, bundle path/URL, and non-empty claim paths
- Implement Policy Bundle Manager: load, validate (strict Regorus compilation), and hash `.rego` bundles
- Implement Policy Evaluator: `ArcSwap`-backed Regorus engine with atomic hot-reload and fail-closed semantics
- Implement Policy Input Builder: `PolicyInput` struct matching OPA input contract
- Implement RBAC Audit Logger: structured `tracing::info!` events with typed fields
- Ship default policy bundles: algorithm-only (non-RBAC) and full RBAC (super-admin/admin/operator/auditor)
- Wire `PolicyEvaluator` into the `KMS` struct with automatic initialization at startup
- Add `ckms server migrate-tenants` CLI command for tenant_id backfill before RBAC enablement
- Add `regorus`, `arc-swap`, `notify` workspace dependencies
- Implement three-tier RBAC enforcement:
  - Tier 1: `dispatch.rs` pre-dispatch hook for non-object operations
  - Tier 2: `retrieve_object_utils.rs` object-level authorization via policy
  - Tier 3: `/access/grant` and `/access/revoke` inline enforcement
- Extend JWT `UserClaim` with dynamic claim extraction (dot-notation paths for roles/tenant)
- Bypass legacy `algorithm_policy.rs` when Rego evaluator is active
- Implement hot-reload file watcher (notify crate, cross-platform)
- Implement remote bundle polling with JSON manifest support
- Add `POST /admin/migrate-tenants` server-side REST endpoint
- Add RBAC step to interactive configuration wizard

## Documentation

- Update `CONTEXT.md` with 16 resolved design decisions from grilling session
- Add ADR 0003: Always-Rego algorithm enforcement
- Add ADR 0004: Super-admin role for cross-tenant access
- Add `documentation/docs/configuration/rbac.md` RBAC documentation page
- Register RBAC page in `documentation/mkdocs.yml`
- Add `test_data/vectors/rbac/README.md` documenting planned integration test vectors
