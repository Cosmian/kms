---
name: rust-async-refactor
description: 'Detect sequential .await chains that could be parallelized with tokio::join!/try_join!, unnecessary Arc/Box::pin in async contexts, and blocking calls on async paths. Use when performance-tuning transit/PKI or KMIP operation handlers.'
---

# Rust Async Refactor

Find optimization opportunities in async Rust code: parallelizable
sequential `.await` chains, unnecessary heap allocations, and blocking
calls on the async runtime.

## Step 1 — Scope

If a path was provided, restrict to that path. Otherwise default to:

```bash
git diff --name-only origin/develop...HEAD 2>/dev/null || git diff --name-only HEAD~1
```

## Step 2 — Three analysis passes

### Pass A: Parallelizable sequential awaits

Identify pairs (or groups) of independent `.await` calls that could
run concurrently:

```rust
// ❌ sequential — DB query #2 waits for DB query #1
let ca_key = kms.database.find(filter1, ...).await?;
let ca_cert = kms.database.retrieve_object(&uid).await?;

// ✅ parallel — both queries issued simultaneously
let (ca_key, ca_cert) = tokio::try_join!(
    kms.database.find(filter1, ...),
    kms.database.retrieve_object(&uid),
)?;
```

**Rules for safe parallelization:**

- Both futures must be **independent** (neither consumes a value produced by the other)
- Both must use **different resources** or the resource must support concurrent access (e.g. `DashMap`, connection pools)
- Both error types must be compatible with `?` (same `Error` type)
- Never parallelize when one future's output is an argument to the other

**Common KMS patterns to flag:**

```rust
// transit.rs, pki.rs: sequential DB lookups
let filter_result = kms.database.find(...).await?;      // independent
let object = kms.database.retrieve_object(...).await?;  // independent — parallelizable

// sign_intermediate: sequential operations after certify
let certify_resp = kms.certify(req, user).await?;           // must run first
let cert = kms.database.retrieve_object(&cert_uid).await?;  // depends on certify_resp — NOT parallelizable
```

### Pass B: Unnecessary `Arc` in async contexts

```rust
// ❌ Arc for local, single-owner data
let config = Arc::new(load_config());

// ✅ plain struct — no concurrent access
let config = load_config();
```

Flag `Arc::new(...)` where the value is only used within a single async
task and never `clone()`d across tasks. Common in KMS: `Arc<ServerParams>`
is legitimate (shared across workers); `Arc<reqwest::Client>` is
legitimate (cloned per request). But ad-hoc `Arc` wrappers for local data
are noise.

### Pass C: Blocking calls on async runtime

```rust
// ❌ blocks the tokio worker thread
let data = std::fs::read(path)?;

// ✅ spawn_blocking for CPU/IO-heavy work
let data = tokio::task::spawn_blocking(move || std::fs::read(path))
    .await??;
```

Flag:

- `std::fs::read` / `std::fs::write` — use `tokio::fs`
- `std::thread::sleep` — use `tokio::time::sleep`
- Heavy OpenSSL operations (key generation, large cert chains) — consider `spawn_blocking`

## Step 3 — Report

| Priority | Pattern | Example |
|----------|---------|---------|
| 🔴 | Blocking I/O on async runtime | `std::fs::read` in `async fn` |
| 🟠 | Sequential DB calls that could be parallelized | Two independent `.find()` + `.retrieve()` |
| 🟡 | Unnecessary `Arc` allocation | Local config wrapped in `Arc` |
| 🟢 | `Box::pin` for futures that don't need it | Simple `.await` chain manually pinned |

## Step 4 — KMS-specific notes

- **HSM backends**: HSM calls are inherently sequential (single session) — never parallelize HSM operations.
- **Database connection pools**: SQLite is single-writer — parallel reads are safe, writes are not. PostgreSQL/MySQL support concurrent reads within pool limits.
- **`kms.database`** methods are `&self` and use internal synchronization — concurrent calls from the same `KMS` reference are safe.
- **`actix_web::web::Data<Arc<KMS>>`** is already shared across workers — don't re-wrap in `Arc`.
