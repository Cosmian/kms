# Full RBAC authorization policy (default bundle)
#
# Implements NIST-compatible hierarchical RBAC:
#   super-admin > admin > operator > auditor
#
# Features:
# - Role hierarchy with transitive inheritance
# - Tenant boundary enforcement
# - Algorithm allowlist checks via static data
# - Owner + explicit ACL grant handling
# - Create-grant privilege invariant (only admins can delegate Create)
# - Privileged users (break-glass via server config)

package kms.authz

import rego.v1

default allow := false

# Operation sets per role
auditor_ops := {"Locate", "GetAttributes", "GetAttributeList"}

operator_ops := auditor_ops | {
    "Create", "CreateKeyPair", "Import", "Register",
    "Encrypt", "Decrypt", "Sign", "SignatureVerify",
    "MAC", "MACVerify", "Hash",
    "Destroy", "Revoke", "Activate", "DeriveKey", "ReKey", "ReKeyKeyPair",
    "Certify", "Validate",
    "Get", "Export",
    "SetAttribute", "ModifyAttribute", "AddAttribute", "DeleteAttribute",
}

admin_ops := operator_ops | {"Grant", "RevokeAccess"}

# Helper: check if user has a specific effective role (includes hierarchy)
has_role(r) if {
    r in input.subject.roles
}

has_role("admin") if {
    "super-admin" in input.subject.roles
}

has_role("operator") if {
    has_role("admin")
}

has_role("auditor") if {
    has_role("operator")
}

# Algorithm allowlist check
algorithm_allowed if {
    input.operation.algorithm == null
}

algorithm_allowed if {
    not data.kms.config.allowlists.algorithms
}

algorithm_allowed if {
    input.operation.algorithm in data.kms.config.allowlists.algorithms
}

# Tenant boundary: resource and subject must share tenant
same_tenant if { input.resource == null }
same_tenant if { input.resource.tenant_id == null }
same_tenant if { input.resource.tenant_id == input.subject.tenant_id }

# Object accessibility: user must own or have explicit grant
object_accessible if { input.resource == null }
object_accessible if { input.acl == null }
object_accessible if { input.acl.is_owner }
object_accessible if { input.operation.kmip_op in input.acl.granted_ops }

# === Allow rules ===

# Super-admin: all operations, no tenant boundary
allow if {
    "super-admin" in input.subject.roles
    algorithm_allowed
}

# Admin: all operations, tenant-scoped
allow if {
    has_role("admin")
    same_tenant
    algorithm_allowed
}

# Operator: provisioning + crypto + lifecycle ops on accessible objects
allow if {
    has_role("operator")
    input.operation.kmip_op in operator_ops
    same_tenant
    algorithm_allowed
    object_accessible
}

# Auditor: metadata-only (no key material, no Export)
allow if {
    has_role("auditor")
    input.operation.kmip_op in auditor_ops
    same_tenant
}

# Privileged users: treated as admin by default policy
allow if {
    input.subject.is_privileged
    same_tenant
    algorithm_allowed
}

# Create-grant privilege: only admins can delegate Create
allow if {
    input.operation.kmip_op == "Grant"
    some op in input.operation.grant_ops
    op == "Create"
    has_role("admin")
    same_tenant
}

# Self-access: users can view their own access lists
allow if {
    input.operation.kmip_op in {"ListAccessOwned", "ListAccessObtained", "CheckPermissions"}
}

reason := "allowed by default RBAC policy" if { allow }
reason := "denied by default RBAC policy" if { not allow }
