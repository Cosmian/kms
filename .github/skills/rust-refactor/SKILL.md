---
name: rust-refactor
description: 'Find duplication in Rust code and consolidate it using Traits, Generics, shared functions, and macros. Use when asked to reduce Rust code duplication.'
---

# Rust Refactor

Find opportunities to reduce LOC and consolidate duplicated behavior using Traits, Generics, shared functions, and macros.

## Workflow

### Phase 1 — Discover (always run first)

```bash
# Find clone-heavy code
rg "\.clone\(\)" --stats | tail -5

# Spot copy-paste (identical blocks ≥ 5 lines) across target crate(s)
rg -l "fn create_" crate/server/src/core/operations/
```

Run the **Duplication Scan** checklist:

- [ ] Functions with near-identical signatures/bodies
- [ ] `match` arms that repeat the same multi-line logic
- [ ] `impl` blocks that repeat the same methods on different types
- [ ] Error conversions repeated across files (`From` / `Into` candidates)
- [ ] Struct fields sharing a common subset (candidate for composition or a base trait)
- [ ] Repeated `if cfg!(feature = "...")` guards around the same pattern
- [ ] Repeated access-control check sequences in KMIP operation handlers

### Phase 2 — Classify each finding

For each duplicate, pick the **minimum sufficient** Rust pattern:

| Smell | Pattern |
|-------|---------|
| Same logic on N types | Generic function / `impl<T: Bound>` |
| Same interface, different impls | Trait + `impl Trait for Type` |
| Repetitive `match` / boilerplate impls | Declarative macro (`macro_rules!`) |
| Cross-cutting behaviour (logging, auth) | Blanket `impl` or extension trait |
| Repeated struct field group | Composition / newtype |
| Repeated `From`/`Into` conversions | Derive macro or `impl From<X> for Y` |
| Repeated KMIP operation boilerplate | `macro_rules!` dispatch helpers |

### Phase 3 — Plan

Create a ranked list ordered by: **impact (lines saved) ÷ risk (tests affected)**.
Present it to the user before touching code:

```text
[HIGH] Extract `KeyOperations` trait — saves ~120 LOC, touches 3 files
[MED]  Generic `retrieve<T: KmipObject>` — saves ~60 LOC, touches 2 files
[LOW]  `macro_rules! impl_kmip_response!` — saves ~30 LOC, touches 5 files
```

### Phase 4 — Implement (one finding at a time)

1. Create the trait / generic / helper in its own commit scope.
2. Migrate callers one file at a time; keep the build green after each file.
3. Delete the old code only after all callers compile.
4. After each change: `cargo clippy-all` and `cargo fmt --all`.
5. Run the narrowest test scope that covers the changed code: `cargo test -p <crate>`.

### Phase 5 — Verify

```bash
cargo clippy-all        # zero warnings
cargo fmt --all         # no formatting drift
cargo test -p <crate>   # affected crate(s) only
git diff --stat         # every hunk explainable by the task
```

## Quick Rules

- Prefer **generics** over `dyn Trait` unless the set of types is open at runtime.
- Add `#[allow(clippy::...)]` only with an inline comment explaining why the lint cannot be satisfied.
- Never remove a public function without checking all crates: `rg "fn_name" --type rust`.
- Keep functions under 50 lines after refactoring. Extract helpers rather than growing functions.
- Imports (`use` statements) always go at the top of the file — never inline inside function bodies.
- Feature-flag gating stays at function/module level, not inline: `#[cfg(feature = "non-fips")]` on the `fn`, not inside the body.

## Pattern Cookbook

### Generic function over KMIP objects

```rust
// Before: duplicated retrieve logic in get.rs, export.rs, decrypt.rs
async fn get_object(uid: &str, db: &dyn Database) -> KResult<KmipObject> { ... }
async fn export_object(uid: &str, db: &dyn Database) -> KResult<KmipObject> { ... }

// After: shared generic with trait bound
async fn retrieve_object<P: Permission>(
    uid: &str,
    caller: &str,
    db: &dyn Database,
) -> KResult<KmipObject>
where P: CheckAccess { ... }
```

### Declarative macro for KMIP dispatch boilerplate

```rust
macro_rules! dispatch_operation {
    ($op:expr, $kms:expr, $params:expr) => {
        match $op {
            Operation::Get(req) => get::get($kms, req, $params).await,
            Operation::Locate(req) => locate::locate($kms, req, $params).await,
            // ...
        }
    };
}
```

### Newtype for key identifiers

```rust
// Before: raw String everywhere — easy to mix up key UID and user ID
fn get_key(uid: String, owner: String) -> ...

// After: newtypes prevent accidental parameter swap
struct KeyUid(String);
struct UserId(String);
fn get_key(uid: KeyUid, owner: UserId) -> ...
```
