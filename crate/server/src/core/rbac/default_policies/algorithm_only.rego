# Algorithm-only policy (embedded, used when RBAC is disabled)
#
# This minimal policy enforces only the algorithm allowlist configured in kms.toml.
# No role, tenant, or ACL checks are performed.
# Loaded via include_str! when no external bundle is configured.

package kms.authz

import rego.v1

default allow := false

# Allow if no algorithm is specified (non-crypto operations)
allow if {
    input.operation.algorithm == null
}

# Allow if algorithm is in the configured allowlist
allow if {
    input.operation.algorithm in data.kms.config.allowlists.algorithms
}

# Allow if no algorithm allowlist is configured (unrestricted mode)
allow if {
    not data.kms.config.allowlists.algorithms
}

reason := "algorithm policy"
