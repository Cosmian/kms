# OPA is sole gatekeeper in RBAC mode; DB ACL checks are bypassed

When RBAC mode is active, Regorus/OPA is the single authorization gatekeeper. The existing
DB-level ACL enforcement (ownership checks, per-object operation grants in
`retrieve_object_utils.rs`) is bypassed, and ACL state (owner flag, granted operations) is
passed as input fields to the policy instead.

This means a DENY from the Rego policy overrides object ownership — an owner can be denied
by policy. When RBAC mode is disabled, legacy DB ACL enforcement is unchanged.

## Why not run both checks independently?

Running OPA and DB ACL checks in parallel (both must allow) creates two enforcement systems
that can contradict each other. Adding an algorithm to a Rego allowlist would still be blocked
by the DB allowlist unless both are updated in sync. Centralised enforcement in OPA is the
entire point of RBAC mode.

## Consequences

The default policy bundle must explicitly re-encode the invariants that the DB ACL layer
currently enforces implicitly — in particular, that only admins can delegate `Create` grants
and that object owners retain their permissions unless policy explicitly denies them. Test
vectors verify these invariants are not silently dropped.
