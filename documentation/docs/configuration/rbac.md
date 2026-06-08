# RBAC / OPA Authorization

The Cosmian KMS supports an opt-in **Role-Based Access Control (RBAC)** mode that evaluates
all authorization decisions through an in-process [OPA/Rego](https://www.openpolicyagent.org/)
policy engine ([Regorus](https://github.com/microsoft/regorus)).

## Overview

When RBAC is enabled:

- The Regorus policy engine becomes the **single authorization gatekeeper**
- Legacy database-level ACL enforcement is bypassed
- Roles are extracted from JWT claims (IdP)
- Tenant isolation is enforced at the database level
- Every authorization decision is audited via structured tracing events

When RBAC is disabled (default):

- Legacy ownership + ACL grant model is active
- Algorithm enforcement (if configured) is still delegated to Rego via an embedded policy

## Role Hierarchy

```
super-admin > admin > operator > auditor
```

| Role | Permissions |
|------|-------------|
| **super-admin** | All operations, cross-tenant access. Granted via server config only. |
| **admin** | All KMIP operations within their tenant. Can delegate Create grants. |
| **operator** | Create, Import, Encrypt, Decrypt, Sign, Destroy, Revoke, etc. Requires object access. |
| **auditor** | Locate, GetAttributes, GetAttributeList only. No key material access. |

## Configuration

Add the following to `kms.toml`:

```toml
[rbac]
rbac_enabled = true
rbac_bundle_path = "/etc/cosmian/rbac/policies/"
rbac_role_claim = "roles"
rbac_tenant_claim = "tenant_id"
rbac_bundle_poll_interval_secs = 300
```

Or via CLI flags:

```bash
cosmian_kms \
  --rbac-enabled \
  --rbac-bundle-path /etc/cosmian/rbac/policies/ \
  --rbac-role-claim roles \
  --rbac-tenant-claim tenant_id
```

### Super-admins (cross-tenant access)

```toml
[rbac]
rbac_super_admins = ["ops@cosmian.com"]
```

### Prerequisites

Before enabling RBAC:

1. **IdP authentication** must be configured (`--jwt-auth-provider`)
2. **Policy bundle** must exist at the configured path
3. **All objects must have `tenant_id`** — run the migration tool first:

```bash
ckms server migrate-tenants --mapping-file owners-to-tenants.json
```

## Policy Bundle Format

A policy bundle is a directory containing `.rego` files with an `authz.rego` entry point:

```
/etc/cosmian/rbac/policies/
├── authz.rego          # Must define data.kms.authz.allow
├── helpers.rego        # Optional helper rules
└── custom_rules.rego   # Optional additional rules
```

### Required decision paths

- `data.kms.authz.allow` → `boolean` (true = allow, false/undefined = deny)
- `data.kms.authz.reason` → `string` (optional, logged only)

### Hot-reload

Local bundles are watched for changes via the `notify` crate. When a file changes:

1. A new engine is built and validated
2. If valid, it atomically replaces the active engine
3. In-flight evaluations finish against the old policy

## OPA Input Contract

Every authorization evaluation receives this input document:

```json
{
  "subject": {
    "user_id": "alice@example.com",
    "roles": ["operator"],
    "tenant_id": "acme-corp",
    "is_privileged": false
  },
  "request": {
    "ip": "192.168.1.1",
    "tls_subject": "CN=alice,O=Acme",
    "user_agent": "ckms/1.0"
  },
  "operation": {
    "kmip_op": "Get",
    "algorithm": "AES"
  },
  "resource": {
    "id": "3fa85f64-...",
    "owner": "bob@example.com",
    "type": "SymmetricKey",
    "state": "Active",
    "tags": ["env:prod"],
    "tenant_id": "acme-corp"
  },
  "acl": {
    "is_owner": false,
    "granted_ops": ["Get", "Encrypt"]
  }
}
```

## Algorithm Enforcement

Algorithm allowlists from `kms.toml` are loaded as static OPA data at
`data.kms.config.allowlists`. The policy can reference them:

```rego
algorithm_allowed if {
    input.operation.algorithm in data.kms.config.allowlists.algorithms
}
```

## Audit

Every RBAC decision (allow and deny) is emitted as a structured tracing event:

```
INFO kms::rbac::audit: RBAC authorization decision
  user=alice@example.com
  operation=Encrypt
  resource_id=key-123
  tenant_id=acme-corp
  decision=allow
  reason="allowed by default RBAC policy"
  bundle_hash=a3f2b1...
```

These events are exported via the existing OpenTelemetry pipeline.
