# Threat Model Assessment — KMS Authentication Subsystem (Spire Branch)

**Date**: 2026-08-03
**Scope**: Authentication middleware stack — spire branch delta (SPIRE token validation, Auth Verifier JWT, session auth, auth proxy, JWKS manager changes)
**Overall Risk Posture**: **MEDIUM** (with conditional HIGH risks)

## Key Findings

- **🔴 CRITICAL**: The `insecure` feature flag disables all JWT and Auth Verifier signature validation. If a production binary is accidentally compiled with this flag, complete authentication bypass is possible. No runtime guard exists.
- **🟠 HIGH**: The `accept_invalid_certs` configuration flags disable TLS verification for auth-verifier and JWKS connections. Defaults are safe (`false`), but no runtime warning or health indicator exists to catch accidental production enablement.
- **🟠 HIGH**: The unauthenticated auth proxy (`/v1/auth/*`) has no rate limiting and can be used as a DoS amplifier against the auth-verifier. The global rate limiter is disabled by default.
- **🟠 HIGH**: SPIRE identities share the same namespace as native KMS usernames. When `vault_token_optional_middleware` is active, a SPIRE entity named "alice" has the same permissions as native "alice". Only `default_username` collision is prevented.
- **🟡 MEDIUM**: No audit trail distinguishes which authentication method was used for a request. The `AuthenticatedUser` struct carries only a username, not the auth method.

## Risk Summary

| Category | Risk Level | Notes |
|----------|------------|-------|
| Authentication & Authorization | **HIGH** | Strong algorithm controls (asymmetric-only allowlist); undermined by `insecure` flag and `accept_invalid_certs` config risk |
| SPIRE/Vault Integration | **HIGH** | Well-designed token cache and entity validation; identity collision with native users is the primary gap |
| Auth Proxy (SSRF/DoS) | **MEDIUM** | Path traversal comprehensively mitigated; DoS amplification and potential SSRF via header forwarding remain |
| Session Management | **MEDIUM** | Depends on actix-session encryption; salt entropy not validated at startup |
| JWKS Management | **MEDIUM** | Redirect policy prevents SSRF; `force_refresh()` lacks cooldown; key material leaked in error messages |
| Audit & Repudiation | **MEDIUM** | No per-auth-method logging; operators cannot distinguish SPIRE from native auth in audit trails |
| Supply Chain / Build | **LOW** | `insecure` flag is the primary build-time risk; no runtime detection of insecure builds |

## Recommended Actions (Priority Order)

1. **Add startup guard for `insecure` feature** — Log a prominent ERROR or panic when `insecure` is compiled in. Consider a `/health` field reporting signature validation status. *(F-001)*
2. **Namespace-separate SPIRE identities** — Prefix SPIRE entity IDs with `spire:` to prevent collision with native KMS usernames. *(F-004)*
3. **Add rate limiting to auth proxy scope** — Dedicated per-IP rate limit for `/v1/auth/*`; consider a circuit breaker for auth-verifier calls. *(F-003)*
4. **Runtime warning for `accept_invalid_certs`** — Log ERROR at startup when either flag is true; add to `/health` response. *(F-002)*
5. **Add `auth_method` to `AuthenticatedUser`** — Enable audit trails to distinguish SPIRE, JWT, API token, mTLS, and session auth. *(F-006)*
6. **Remove JWKS debug output from error messages** — Prevent public key leakage in error responses. *(F-005)*
7. **Add cooldown to `force_refresh()`** — Prevent unthrottled JWKS endpoint hammering. *(F-007)*
8. **Validate `ui_session_salt` entropy at startup** — Reject weak or known-default salts. *(F-008)*

## Scope Limitations

- **Not analyzed**: HSM trust boundary, KMIP operation-level access control, database encryption at rest, TLS configuration (cipher suites, certificate validation).
- **Not analyzed**: Cloud provider routes (AWS XKS, Azure EKM, Google CSE, MS DKE) — these have separate authentication mechanisms.
- **Assumption**: The auth-verifier server is trusted and correctly validates SPIRE AppRole credentials before issuing tokens.
- **Assumption**: The `insecure` feature is not enabled in production builds (verified: it is not a default feature).
- **Assumption**: actix-session's encrypted cookie backend uses AES-256-GCM or equivalent with the `ui_session_salt` as the key derivation input.

## Positive Security Controls Observed

| Control | Location | Assessment |
|---------|----------|------------|
| Asymmetric-only JWT algorithm allowlist | `jwt_config.rs`, `auth_verifier/token.rs` | ✅ Correct — prevents algorithm confusion |
| SHA-256 token hashing in cache | `spire_token.rs` | ✅ Correct — raw tokens never in memory |
| Path traversal check (dot segments + backslash + percent-encoding) | `auth_proxy.rs` | ✅ Comprehensive — covers all known encoding variants |
| `redirect::Policy::none()` on JWKS fetch | `jwks.rs` | ✅ Prevents SSRF via 3xx |
| `validated_entity()` rejects empty + default_username collision | `spire_token.rs` | ✅ Prevents most identity collision |
| Cache bounded to 100K entries with opportunistic eviction | `spire_token.rs` | ✅ Prevents unbounded memory growth |
| Optional middleware fails closed on invalid token | `spire_token.rs` | ✅ Invalid tokens return 403, not passthrough |
| `extract_bearer_token()` shared across middlewares | `mod.rs` | ✅ Single parsing logic, consistent validation |

---
*Generated by AI Threat Model Analyst. All findings require human review before remediation.*
