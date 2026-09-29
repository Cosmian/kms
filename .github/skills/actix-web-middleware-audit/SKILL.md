---
name: actix-web-middleware-audit
description: 'Audit actix-web middleware ordering, LIFO `.wrap()` evaluation, Condition guard correctness, and request-extension injection. Use when adding or reordering middleware in start_kms_server.rs.'
---

# Actix-Web Middleware Audit

Audit actix-web middleware stacks for correctness. The KMS server has 10+
`.wrap()` calls with complex `Condition` guards — ordering mistakes cause
auth bypass, double-injection, or silently skipped middleware.

## Step 1 — Scope

Default to `crate/server/src/start_kms_server.rs`. If a specific scope
(transit, PKI, KMIP, tokenize, MS-DKE) was mentioned, restrict to that
section.

## Step 2 — LIFO evaluation check

Actix-web evaluates `.wrap()` in **LIFO** order: the last `.wrap()` runs
**first** on the incoming request, and **last** on the outgoing response.

```text
// Request flow (top-to-bottom):
//   .wrap(Cors::permissive())          ← runs LAST  (outermost for response)
//   .wrap(auth_extractor())            ← runs SECOND
//   .wrap(ensure_auth_middleware(...)) ← runs FIRST  (innermost, closest to handler)
//   .service(handler)
```

**Critical rule**: Auth extractors that inject `AuthenticatedUser` must
run **before** `ensure_auth_middleware` in request-processing order.
Since actix-web is LIFO, this means auth extractors must appear **after**
`ensure_auth_middleware` in the `.wrap()` chain.

### Check each scope for

| Scope | Auth extractors (run first) | Gate (runs second) |
|-------|---------------------------|-------------------|
| kmip | `tls_auth_fn` → `jwt_auth_middleware` → `api_token_middleware` → `vault_token_optional_middleware` | `ensure_auth_middleware` |
| ms_dke | `vault_token_optional_middleware` → `tls_auth_fn` → `jwt_auth_middleware` → `api_token_middleware` | `ensure_auth_middleware` |
| tokenize | `vault_token_optional_middleware` → `tls_auth_fn` → `jwt_auth_middleware` → `api_token_middleware` | `ensure_auth_middleware` |
| crypto | `vault_token_optional_middleware` → `tls_auth_fn` → `jwt_auth_middleware` → `api_token_middleware` | `ensure_auth_middleware` |
| transit/PKI | `spire_token_middleware` (strict — mandates `X-Vault-Token`) | (none — handled inside middleware) |

### Verify

- [ ] `vault_token_optional_middleware` is the **outermost** `.wrap()` on every scope (LIFO: runs first, injects user before native auth)
- [ ] `spire_token_middleware` (strict) is only on transit/PKI scopes — never on scopes that accept native auth
- [ ] `ensure_auth_middleware` is always the innermost auth-related wrap
- [ ] Each `Condition` guard's boolean matches the auth method actually configured

## Step 3 — Extension injection check

Every auth extractor must inject **both**:

1. `AuthenticatedUser { username }` — read by `get_user()` and `ensure_auth_middleware`
2. Domain-specific user type (e.g. `SpireAuthenticatedUser`) — for downstream consumption

Verify that:

```rust
req.extensions_mut().insert(AuthenticatedUser { username: user.entity.clone() });
```

Is present in every auth path, not just the happy path.

## Step 4 — CORS placement

`Cors::permissive()` must be the **innermost** wrap (runs last on ingress,
first on egress). Verify it's the first `.wrap()` in the chain (closest
to `.service()`).

## Step 5 — Report

Flag any of:

- 🔴 Auth extractor running **after** `ensure_auth_middleware` (auth bypass)
- 🔴 Missing `AuthenticatedUser` injection in one auth path
- 🟠 `spire_token_middleware` (strict) on a native-auth scope (double-auth required)
- 🟡 `vault_token_optional_middleware` missing from a scope that should accept vault tokens
- 🟢 CORS ordering suboptimal (not innermost)
