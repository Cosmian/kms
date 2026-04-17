## Features

### NIST Core RBAC (Role-Based Access Control)

- Add RBAC types (`Role`, `UserRole`, `RolePermission`, `EffectivePermission`) in `cosmian_kms_access::rbac`
- Add `RoleStore` trait with 12 async methods for role CRUD, permission assignment, and user-role management
- Implement `RoleStore` for SQLite, PostgreSQL, and MySQL backends with 3 new tables (`roles`, `role_permissions`, `user_roles`)
- Add `NoOpRoleStore` for Redis-findex backend (non-FIPS only)
- Extend `user_has_permission()` to merge role-based permissions with direct grants (union model, fully backward compatible)
- Add 13 REST API endpoints under `/roles/*` for role management, permission assignment, user-role assignment, and effective permission queries
- Add 5 built-in roles seeded on startup: `admin`, `operator`, `crypto-user`, `auditor`, `key-custodian`
- Add `ckms roles` CLI subcommands: `create`, `list`, `get`, `delete`, `add-permission`, `remove-permission`, `list-permissions`, `assign`, `revoke`, `members`
- Add shared DTO types for role REST API (request/response types in `cosmian_kms_access::rbac`)
- Add `put_no_ttlv` and `delete_no_ttlv_no_body` HTTP methods to `KmsClient`
- Add RBAC Web UI module (`ui/src/actions/RBAC/`) with 7 components: list, create, update, add permission, view permissions, assign users, role members
- Add RBAC menu section and route registration in Web UI

### NIST Hierarchical RBAC (Phase 2)

- Add role hierarchy support (general DAG) — senior roles inherit all permissions of junior roles
- Add `RoleHierarchyEdge` and `RoleTreeNode` types, hierarchy REST DTOs
- Extend `RoleStore` trait with 6 hierarchy methods: add/remove edges, list juniors/seniors, get tree, list all edges
- Add `role_hierarchy` table to SQLite, PostgreSQL, and MySQL backends
- Replace `select-role-operations-for-user-object` query with recursive CTE that walks the hierarchy for transitive permission inheritance
- Add cycle detection (BFS) on hierarchy edge insertion to prevent circular inheritance
- Seed default hierarchy on startup: `admin` → `operator` → `crypto-user`, `admin` → `key-custodian`
- Add 6 REST API hierarchy endpoints: `POST/DELETE /roles/{id}/juniors/{junior_id}`, `GET /roles/{id}/juniors`, `GET /roles/{id}/seniors`, `GET /roles/{id}/hierarchy`, `GET /roles-hierarchy`
- Add 6 `KmsClient` hierarchy methods and 4 CLI subcommands: `add-junior`, `remove-junior`, `juniors`, `hierarchy`
- Add hierarchy Web UI: tree visualization (`RoleHierarchy.tsx`) and add junior role form (`RoleAddJunior.tsx`)
- Add 8 hierarchy integration tests: default seeding, add/remove edges, self-loop rejection, cycle detection, transitive inheritance, tree view, delete cascade

### RBAC Enforcement Hardening (Phase 3A)

- Add `RbacEnforcementMode` enum (`Additive` / `Restrictive`) to control how role permissions interact with direct grants ([#651](https://github.com/Cosmian/kms/issues/651))
- Add configurable `strict_get_privilege` option — when enabled, `Get` only grants the `Get` operation itself (removes the Get-implies-all super-privilege) ([#651](https://github.com/Cosmian/kms/issues/651))
- Add `restrict_grant_to_roles` option — when enabled, only users with `admin`/`operator` roles (or object owners) can call grant/revoke ([#651](https://github.com/Cosmian/kms/issues/651))
- Add `[rbac]` configuration section to `kms.toml` with `strict_get_privilege`, `enforcement_mode`, and `restrict_grant_to_roles` settings
- Update `user_has_permission()` to respect enforcement mode and strict Get privilege
- Update `grant_access()` and `revoke_access()` to enforce role-based grant restrictions
- Update effective-permissions REST endpoint to respect enforcement mode
- Add 4 enforcement integration tests: strict Get privilege, restrictive mode, additive mode, config serialization roundtrip

## Bug Fixes

- Fix cycle detection BFS direction in all 3 backends — was starting from wrong node (junior instead of senior)
- Fix SQLite `delete_role` passing wrong parameter count to `delete-hierarchy-edges-for-role` query
