---
name: 'Rust Conventions'
description: 'Core Rust coding rules for the Eviden KMS workspace'
applyTo: '**/*.rs'
---

# Rust coding conventions

## Error handling

- Never use `.unwrap()` in production code — use `?` propagation with context.
- Use `thiserror`-based error types; each crate defines its own `Error` enum.
- In tests, prefer `.expect("reason")` over `.unwrap()` for better failure messages.

## Panics and brutal exits — FORBIDDEN in production code

The following constructs are **forbidden outside of `#[cfg(test)]` and `fn main()`**:

| Construct | Why forbidden |
|-----------|---------------|
| `panic!(...)` | Aborts the request handler / entire server under `catch_unwind` |
| `todo!()` | Panics at runtime — not acceptable in shipped code |
| `unimplemented!()` | Same as `todo!()` |
| `unreachable!()` | Use `unreachable!` **only** inside `#[cfg(debug_assertions)]` blocks or replace with a `KmsError` variant |
| `.expect("msg")` in production | Replace with `?` or an explicit `KmsError` |
| `std::process::exit(...)` | Hard-kills the process without cleanup |
| `std::process::abort()` | Same — also prevents destructors running |
| Integer overflow via `+`/`*` on primitives | Use `checked_add()` / `saturating_add()` / `wrapping_add()` explicitly |
| Out-of-bounds slice indexing `slice[n]` on untrusted data | Use `.get(n).ok_or_else(...)` |
| `unwrap_or_else(&#124;_&#124; unreachable!())` | Encodes "impossible" assumption — may panic in adversarial input |

**Allowed exceptions** (comment required):

```rust
// PANIC: unreachable by construction — <explain invariant>
unreachable!("variant X is excluded by the type system")
```

Permitted only in `#[cfg(debug_assertions)]` guards, `#[test]` modules, or `fn main()` with a documented rationale.

### Linting for panics

Run the following to catch panic-related issues:

```bash
cargo clippy-all 2>&1 | grep -E "panic|unwrap|expect|todo|unimplemented|unreachable"
grep -rn "\.unwrap()\|\.expect(\|panic!\|todo!\|unimplemented!\|process::exit\|process::abort" \
  --include="*.rs" crate/ | grep -v "#\[cfg(test)\]" | grep -v "^.*//.*"
```

> To automatically audit panic hotspots across the codebase, run `/rust-panic-audit`.

## Feature-flag discipline

- `#[cfg(feature = "non-fips")]` goes at the **function or module level only** — never inside a function body.
- Non-FIPS-only items: Covercrypt, Redis-findex, PQC CLI module, AES-XTS.
- FIPS is the default build mode (no feature flag needed).

## Unsafe code

- Every `unsafe` block requires a `// SAFETY:` comment explaining the invariant.

## Testing

**AI agent mandatory rule: Every new Rust module or feature introduced in a PR MUST include all four test layers below before the PR is considered complete. This rule is non-negotiable and cannot be skipped or deferred.**

### 4 mandatory test layers

| Layer | Location | Runs with | Purpose |
|-------|----------|-----------|---------|
| **Unit** | `#[cfg(test)]` at bottom of same file | `cargo test -p <crate> <module>` | Isolate a single function / algorithm correctness |
| **DB persistence** | `crate/server_database/src/tests/` shared helper called from each backend | `cargo test -p cosmian_kms_server_database` | Verify upsert/read/max/list round-trips for every new DB method |
| **Functional** | `crate/server/src/tests/<feature>_tests.rs` | `cargo test -p cosmian_kms_server <feature>_tests` | End-to-end operation through `KMS::` API; covers happy paths, error cases, format variants |
| **Security/non-regression** | Same file as functional or a dedicated `_security.rs` | Same runner | Replay of every security invariant: enforcement, boundary values, restart monotonicity, invalid inputs |

### Mandatory content per layer

**Unit tests** (file: same file as the code, `#[cfg(test)]` submodule):

- Cover every public function's happy path.
- Cover at least one error case per fallible function.
- For any cryptographic primitive: verify round-trip (encode → decode → compare).
- For any ASN.1 encoding: assert the DER tag byte explicitly (e.g., `0x0A` for ENUMERATED).

**DB persistence tests** (shared helper, called from all backends):

- Empty table → query returns `None` / `[]`.
- Single insert → retrieve returns the exact bytes inserted.
- Multiple inserts → aggregate query (`MAX`, `COUNT`, `LIST`) returns the correct result.
- Upsert replaces previous value (not duplicates).
- Unknown key → returns `None`, no panic.
- Monotonicity invariant: `seed = max(ts, db_max + 1) > db_max` holds.

**Functional tests** (new file `crate/server/src/tests/<feature>_tests.rs`):

- Use `make_kms()` / `test_kms()` for in-process SQLite tests (no network).
- Cover the full lifecycle: create → operate → verify state.
- Test all output formats (DER, PEM, JSON) when applicable.
- Test that the result is persisted and retrievable from cache/DB.
- Test that auto-triggers work (e.g., revoke → CRL auto-refresh).
- Test REST endpoint responses: 200 with correct MIME, 404 when not found.

**Security/non-regression tests** (same file, clearly labeled):

- Every cryptographic invariant the code comments claim must be asserted.
- Every security check that was added (e.g., keyUsage enforcement) must have a test that fires the error path.
- All enumeration values of any KMIP enum must be exercised (e.g., all `RevocationReasonCode` values).
- Restart-invariant properties: simulate what happens after `KMS::instantiate()` is called a second time on the same DB.

### Reference implementation: CRL feature

`crate/server/src/tests/crl_tests.rs` is the canonical reference for this 4-layer pattern:

```text
crl.rs (unit)                  ← test_build_empty_crl, test_build_crl_with_entries,
                                  test_crl_reason_asn1_tag_is_enumerated
permissions_test.rs (DB)       ← crl_persistence() — empty, upsert, max, list, replace
crl_tests.rs (functional)      ← 14 tests covering all paths, endpoints, formats
crl_tests.rs (security)        ← cRLSign enforcement, reason code mapping, restart monotonicity
```

Study this file before implementing tests for any new cryptographic feature.

### Template for new functional test file

```rust
//! Tests for the <FeatureName> feature.
//!
//! | Category | Tests |
//! |----------|-------|
//! | Unit | in `crate/crypto/src/openssl/<module>.rs` |
//! | DB | in `crate/server_database/src/tests/permissions_test.rs` |
//! | Functional | <list tests here> |
//! | Security | <list security tests here> |

#![allow(clippy::unwrap_used, clippy::expect_used)]

// ... imports ...

async fn make_kms() -> KResult<Arc<KMS>> {
    init_openssl_providers_for_tests();
    Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?)
        .map(Ok)  // adjust to project idiom
}

// ── Functional tests ──────────────────────────────────────────────────────────
#[tokio::test]
async fn test_<feature>_happy_path() -> KResult<()> { ... }

// ── Security / non-regression tests ───────────────────────────────────────────
#[tokio::test]
async fn test_<feature>_rejects_invalid_input() -> KResult<()> { ... }
```

### Rules

- Unit tests go in a `#[cfg(test)]` submodule at the bottom of the same file.
- Use `use super::*;` in test modules.
- Run targeted tests: `cargo test -p <crate> <test_name>` — not the full suite.
- **Never mark a test `#[ignore]` to make the suite green.** If a test requires infrastructure (DB, network), annotate it with the reason: `#[ignore = "Requires running PostgreSQL"]`.
- Register every new test module in `crate/server/src/tests/mod.rs`.

## Documentation

- All public items (`pub fn`, `pub struct`, `pub enum`, `pub trait`) require `///` doc comments.

## Clippy and lint suppression — zero new `#[allow]` / `#[expect]` policy

- Zero Clippy warnings required (`cargo clippy-all`).
- **`#[allow(clippy::...)]` is FORBIDDEN on newly written or AI-generated code.** Fix the lint instead.
- **`#[allow(warnings)]` and `#[allow(unused_imports)]` / `#[allow(dead_code)]` and similar** are forbidden on new code. Unused items must be removed, not silenced.
- **`#[expect(clippy::...)]` / `#[expect(dead_code)]`** (Rust 1.81+) is subject to the same rule as `#[allow]` — forbidden on new code.
- **Do not silence any lint to make code compile faster.** Every lint exists for a reason.

### Fully forbidden lint suppressions (no exception, ever)

```rust
#[allow(warnings)]         // forbidden — unconditionally
#[allow(unused_imports)]   // remove the import instead
#[allow(dead_code)]        // remove the dead code instead
#[expect(unused_variables)] // rename to _ or remove instead
```

Any of the above added to **new code** is a blocker that must be fixed before review.

### Decision tree for any lint warning

1. **Fix it** — this is always the correct first option.
2. **Refactor** — if the lint points to genuine complexity, simplify the code.
3. **Narrow exception** — only for a lint that is a confirmed false positive on **pre-existing code** (not code you wrote in this diff). Requires an inline comment with an issue reference:

   ```rust
   #[allow(clippy::too_many_arguments)] // legacy API surface — tracked in #1234
   pub fn existing_function(...) { ... }
   ```

4. **Report** — if none of the above apply, report the exact warning to the reviewer before suppressing.

### Scanning for illegitimate suppressions in the diff

Agents must run the following scan before every commit and after every AI code-generation step:

```bash
# All newly added #[allow(...)] and #[expect(...)] on any lint — not just clippy
git diff origin/develop...HEAD -- '*.rs' \
  | grep '^+' \
  | grep -v '^+++' \
  | grep -E '#\[(allow|expect)\(' \
  | grep -v '//.*tracked\|//.*issue\|//.*#[0-9]\|//.*false.positive\|//.*SAFETY'
```

Any match is a **blocker**: fix the lint or add a `// tracked in #<N>` justification. Report every match to the reviewer.

## Style

- Prefer `impl Trait` in argument position over generic type parameters when the trait bound is used once.
- Keep functions under 60 lines; extract helpers when logic branches.
- Use `Self` to refer to the implementing type inside `impl` blocks.

---

## AI skill triggers — automatically invoke for Rust code

Agents editing Rust files **must** invoke the following skills at the relevant moments:

| Trigger | Skill | When |
|---------|-------|------|
| Any code change | `/rust-panic-audit` | When new `unwrap`/`expect`/`panic!`/`todo!` is added |
| Error handling change | `/rust-error-propagation` | When modifying `Result` chains, adding new error types |
| Async code change | `/rust-async-refactor` | When modifying `.await` chains or `tokio::spawn` calls |
| Code simplification | `/rust-simplify` | When functions grow beyond 60 lines or nesting exceeds 3 levels |
| New pattern / duplication | `/rust-refactor` | When a similar code block already exists elsewhere |
| Before PR | `/rust-review-all` | Full Rust quality gate — runs all review skills sequentially |
| Crypto code | `/cryptography-review` | Any change in `crate/crypto/` |
| Security concern | `/security-review` | Any auth, key handling, or FFI change |
| KMIP operation | `/kmip-compliance` | Any change in `crate/server/src/core/operations/` |
