# Cosmian KMS — Default RBAC Policy
#
# This policy implements role-based access control aligned with NIST SP 800-162.
# It defines four default roles: administrator, operator, auditor, and readonly.
#
# Input schema (NIST SP 800-162 attributes):
#   input.subject.user_id       — authenticated user identifier
#   input.subject.roles         — list of assigned roles
#   input.subject.is_owner      — true if user owns the target object
#   input.subject.is_privileged — true if user is in the privileged_users list
#   input.action.operation      — KMIP operation (lowercase)
#   input.resource.*            — target object attributes
#   input.environment.*         — contextual attributes (reserved)
#
# Decision: data.cosmian.kms.rbac.allow = true | false

package cosmian.kms.rbac

import rego.v1

default allow := false

# ── Administrator ────────────────────────────────────────────────────────
# Full access to all operations.
allow if {
    some role in input.subject.roles
    role == "administrator"
}

# ── Operator ─────────────────────────────────────────────────────────────
# All key management and cryptographic operations.
allow if {
    some role in input.subject.roles
    role == "operator"
    input.action.operation in operator_operations
}

operator_operations := {
    "create",
    "certify",
    "decrypt",
    "derive_key",
    "destroy",
    "encrypt",
    "export",
    "get",
    "get_attributes",
    "hash",
    "import",
    "locate",
    "mac",
    "revoke",
    "rekey",
    "sign",
    "signature_verify",
    "validate",
}

# ── Auditor ──────────────────────────────────────────────────────────────
# Read-only access for inspection and compliance auditing.
allow if {
    some role in input.subject.roles
    role == "auditor"
    input.action.operation in auditor_operations
}

auditor_operations := {
    "get",
    "get_attributes",
    "locate",
    "validate",
}

# ── Read-Only ────────────────────────────────────────────────────────────
# Minimal access: can only list and inspect metadata.
allow if {
    some role in input.subject.roles
    role == "readonly"
    input.action.operation in readonly_operations
}

readonly_operations := {
    "get_attributes",
    "locate",
}
