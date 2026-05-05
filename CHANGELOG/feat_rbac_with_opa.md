## Features

### KMIP RBAC (Role-Based Access Control)

- Add RBAC support following NIST SP 800-162 using OPA/Rego policy language
- New `cosmian_kms_rbac` crate with embedded Rego evaluation via Microsoft `regorus` crate
- Optional external OPA server support via `--opa-url` configuration flag
- Server configuration: `--rbac-policy-path` to enable RBAC with custom Rego policies
- Default Rego policy with 4 built-in roles: Administrator, Operator, Auditor, ReadOnly
- `RoleStore` trait with implementations for SQLite, PostgreSQL, MySQL, and Redis
- RBAC works alongside existing per-object ACL (OR logic: either RBAC or ACL allowing grants access)
- REST API endpoints: `POST/DELETE/GET /rbac/roles`, `GET /rbac/status`
- CLI subcommands: `ckms rbac assign-role`, `remove-role`, `list`, `list-all`, `status`
- Web UI: RBAC role management page and status page under new "RBAC" menu section
