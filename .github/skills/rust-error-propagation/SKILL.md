---
name: rust-error-propagation
description: 'Analyze Result propagation chains: find missed ? opportunities, .map_err(|e| e.to_string()) anti-patterns, lost error context, and suggest KmsError enrichment. Use before PR for error-handling hygiene.'
---

# Rust Error Propagation Audit

Audit Rust `Result` propagation chains for correctness, clarity, and
context-preservation. Focus on **conversions that silently discard
information**, **redundant error mapping**, and **missed `?` opportunities**.

## Step 1 — Scope

If a path was provided, restrict to that path. Otherwise default to:

```bash
git diff --name-only origin/develop...HEAD 2>/dev/null || git diff --name-only HEAD~1
```

## Step 2 — Three-pass analysis

### Pass A: Missed `?` (most impactful)

Scan every `match` / `if let` on a `Result`:

```rust
// ❌ verbose — use ?
let uid = match kms.database.retrieve_object(&id).await {
    Ok(Some(owm)) => owm.uid(),
    Ok(None) => return Err(KmsError::ItemNotFound(...)),
    Err(e) => return Err(KmsError::DatabaseError(e.to_string())),
};

// ✅ idiomatic — ? propagates, .ok_or_else enriches
let owm = kms.database.retrieve_object(&id)
    .await?
    .ok_or_else(|| KmsError::ItemNotFound(...))?;
```

Flag every `match result { Ok(x) => ..., Err(e) => return Err(...) }` that
could be `?` + `.map_err(...)`.

### Pass B: `.map_err(|e| e.to_string())` anti-pattern

This strips all type information from the error. In the KMS codebase,
always prefer:

```rust
// ❌ .to_string() loses the error type
.map_err(|e| KmsError::ServerError(e.to_string()))

// ✅ propagate the source error directly when KmsError impls From<SourceErr>
.map_err(KmsError::from)
// or enrich with context using the crate error macro
.map_err(|e| kms_error!("failed to retrieve object {id}: {e}"))
```

### Pass C: Lost error context

Identify call chains where the original error is discarded:

```rust
// ❌ original error swallowed — only a string remains
.map_err(|_| SpireApiError::InternalError("transit key not found".to_owned()))

// ✅ preserve the original error in the message
.map_err(|e| SpireApiError::InternalError(
    format!("transit key not found: {e}")
))
```

## Step 3 — Report

Rank findings by severity:

| Priority | Pattern | Impact |
|----------|---------|--------|
| 🔴 Critical | Silent error discard pattern | Bug-creation in production |
| 🟠 High | `.to_string()` on source error | Loses typed error for matching |
| 🟡 Medium | Missed `?` (verbose match) | Readability, extra LOC |
| 🟢 Low | `map_err` chain that could be a single conversion | Minor |

## Step 4 — KMS-specific rules

- **`KmsError` discriminants**: Prefer the crate's error macro (`kms_error!`) over ad-hoc `format!` + `KmsError::ServerError(...)` — it captures file/line.
- **`SpireApiError`**: Always embed the original error message when converting from `KmsError`; the existing `From<KmsError> for SpireApiError` impl does this for `Unauthorized`/`NotSupported`/`InternalError` variants.
- **External crate errors** (`openssl`, `reqwest`, `base64`): Map to domain errors at the boundary; never let raw external errors leak through the public API.
