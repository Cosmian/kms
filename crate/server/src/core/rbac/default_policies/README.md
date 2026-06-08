# Default Policies

This directory contains the default Rego policy bundles embedded into the KMS binary.

- `algorithm_only.rego` — Minimal policy for non-RBAC mode. Only enforces algorithm allowlists.
- `authz.rego` — Full RBAC policy with role hierarchy, tenant boundary, and ACL handling.
