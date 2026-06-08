# Algorithm enforcement always via Rego, even without full RBAC

The legacy Rust-level `enforce_kmip_algorithm_policy_for_operation` check is removed. Algorithm
allowlist enforcement is always delegated to the Regorus engine — including when full RBAC
(roles, tenants, ACL bypass) is disabled. In non-RBAC mode, an embedded algorithm-only policy
is compiled into the binary and loaded automatically; no external bundle is required.

This ensures a single source of truth for algorithm policy and eliminates the dual-enforcement
path where both Rust code and Rego could disagree on what's allowed.

## Considered Options

- **Keep both checks (defense-in-depth)**: Rust check as a fast-fail backstop, Rego as the
  authoritative policy. Rejected because two enforcement points for the same concern creates
  confusion about which is canonical, and operators cannot tell which one denied a request.
- **Skip when RBAC active**: Wrap the Rust check in `if !rbac_enabled`. Rejected because it
  preserves two code paths that must be kept in sync — algorithm allowlist changes would need
  to be reflected in both `KmipAllowlistsConfig` Rust validation and Rego `data.kms.config.allowlists`.
- **Always Rego (chosen)**: Single enforcement path regardless of mode. The Rust struct
  `KmipAllowlistsConfig` becomes purely a config source serialized into OPA data, not an
  enforcement mechanism.

## Consequences

- Regorus is always initialized at server startup, even without RBAC. Binary size and startup
  time increase marginally.
- The embedded default policy must be kept in sync with the FIPS/non-FIPS build variant
  (separate embedded policies per feature flag).
- Policy authors have a single, well-documented surface for algorithm restrictions regardless
  of deployment mode.
