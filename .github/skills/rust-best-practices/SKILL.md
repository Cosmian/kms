---
name: rust-best-practices
description: 'Idiomatic Rust guidance adapted from BeautifulRust for KMS; use when writing, reviewing or refactoring Rust.'
---

# Rust best practices

Adapted from [BeautifulRust rust-best-practices](https://github.com/morganlinton/BeautifulRust/blob/main/skills/rust-best-practices/SKILL.md), MIT, see `LICENSE`.

This is the generic idiom baseline for Rust in this repository. It never loosens a KMS rule. These stay normative in their own files and win on any conflict:

- Lints, suppressions, panics, tests, feature placement: [`rust.instructions.md`](../../instructions/rust.instructions.md) (§ Clippy and lint suppression, § Feature-flag discipline).
- Secrets, constant-time comparison, log hygiene: [`rust-security.instructions.md`](../../instructions/rust-security.instructions.md).
- Crypto, FIPS gating, randomness (`KmsRng` only): [`rust-crypto.instructions.md`](../../instructions/rust-crypto.instructions.md) and `rust.instructions.md` § Randomness.
- Server, database, KMIP structure: [`rust-server`](../../instructions/rust-server.instructions.md), [`rust-database`](../../instructions/rust-database.instructions.md), [`rust-kmip`](../../instructions/rust-kmip.instructions.md).

KMS-specific design patterns (non-normative): [`references/kms-patterns.md`](references/kms-patterns.md).

Prefer the smallest change that fixes the request. Guidance below is a review lens, not a mandate to rewrite working code: every item is subject to compatibility (wire format, CLI/TOML/env names, REST JSON, public API) and security.

## 1. Mindset

- **Write Rust-shaped code.** Model errors with `Result`, resources with ownership and `Drop`, polymorphism with traits and enums, nullability with `Option`. Inheritance-flavored tricks (`Deref` to a "base" struct, `Manager`/`Factory` types, `throw_if_null` helpers) are smells.
- **Make invalid states unrepresentable.** Push invariants into types: enums instead of bool flags and "must be X if Y" comments, newtypes for units and IDs, fallible constructors that validate once.
- **Application code is not library code.** Code with external users follows the API-design rules below. Code internal to a binary favors simplicity: concrete types, `&str`/`String` parameters, no speculative generality. Keep each crate's existing error type and its `*_error!` / `*_bail!` macros (§5).
- **Let the tools do the work.** rustfmt owns formatting, clippy owns idiom checks, the compiler owns memory safety. Spend attention on design.

## 2. Before you hand back code

Run, scoped to what you touched, and fix everything reported:

```bash
cargo fmt --all
cargo clippy-all
cargo clippy --workspace --all-targets -- -D warnings   # FIPS default
cargo test -p <crate> [<test_name>]
cargo test-fips        # full FIPS workspace suite
cargo test-non-fips    # full non-FIPS workspace suite
```

- Fix a lint rather than silencing it. Suppression rules live in [`rust.instructions.md` § Clippy and lint suppression](../../instructions/rust.instructions.md#clippy-and-lint-suppression--zero-new-allow--expect-policy); do not restate or extend them here.
- Never put `#![deny(warnings)]` / `#![allow(warnings)]` in source. Lint levels live in the root `Cargo.toml` (`[workspace.lints]`) and `clippy.toml`.

## 3. Ownership and borrowing

**Prefer unique ownership.** Reach for `Rc`/`Arc` only when shared ownership is part of the design, and `RefCell`/`Mutex` only when interior mutability is. They move checking from compile time to run time, so use them on purpose. `Arc<Mutex<T>>` around data that is never mutated is a smell.

**Don't clone to make the borrow checker stop complaining.** A clone that exists only to end a borrow produces a silent copy. Try first, roughly in order:

1. Extend a temporary with a named `let`, or shorten a borrow with a block.
2. Split a long expression into typed intermediates so the failing step is visible.
3. Move a field out of `&mut self` with `std::mem::take`, `std::mem::replace`, or `Option::take`.
4. Split a large struct so disjoint fields can be borrowed separately.
5. Clone small, immutable data deliberately, with a comment when not obvious.
6. Indices into an owning `Vec`, or `Rc<RefCell<_>>` with `Weak` back-pointers, as a last resort. Avoid self-referential structs.

```rust
// Move out of a &mut enum without cloning.
fn a_to_b(e: &mut MyEnum) {
    if let MyEnum::A { name, x: 0 } = e {
        *e = MyEnum::B { name: std::mem::take(name) };
    }
}
```

**Accept the most general borrowed type.** `&str` not `&String`, `&[T]` not `&Vec<T>`, `&T` not `&Box<T>`, `Option<&T>` not `&Option<T>`. `impl AsRef<Path>` / `impl AsRef<str>` / `impl AsRef<[u8]>` is fine on parameters that only read (never on struct fields). Code that only iterates may take `impl IntoIterator<Item = T>`.

**Take ownership only when you need it, and then by value.** If a function stores or consumes its argument, take `T`, not `&T` plus an internal `.clone()`. Return multiple values as a tuple or struct, not through `&mut` out-parameters (reusing a caller-owned buffer is the exception).

**Prefer owned data in structs.** A struct holding `&'a T` forces a lifetime onto every container. When a type does carry a lifetime, give it a descriptive name (`'src`, `'conn`).

**Keep `Rc`, `Arc`, `Box` and `RefCell` out of public signatures** where practical: take `&T`, `&mut T` or `T`. A service that must be shared wraps its state in `Arc<Inner>` internally. Boxing a large enum variant (`clippy::large_enum_variant`) is the accepted exception.

## 4. Types and API design

### Naming

| Item | Case |
|---|---|
| Types, traits, enum variants | `UpperCamelCase` (acronyms are one word: `Uuid`, `HttpClient`) |
| Functions, methods, modules, locals | `snake_case` |
| Constants, statics | `SCREAMING_SNAKE_CASE` |

- Conversion prefixes signal cost: `as_` (free borrow), `to_` (expensive), `into_` (consumes `self`). Constructors: `new`, `with_*` variants, `try_new` (fallible), `from_*` (pair important ones with `From`).
- Getter naming (`get_` prefix or not) follows the surrounding module; renaming existing getters is churn, not a fix.
- Avoid weasel suffixes `Manager`, `Factory`, `Helper`, `Util` in new names: name the thing it is. If you implement `len()`, implement `is_empty()`.
- Error type names read verb-object-error: `ParseBoolError`.

### Model the domain with types

- **Newtypes** for semantic distinctions (`struct Miles(f64)`, identifiers) where mixing values is a real risk. A newtype that encodes an invariant validates in a fallible constructor (`TryFrom`, `FromStr`, `try_new`) and offers no infallible `From` from the raw type.
- **No `bool` parameters in public or shared signatures.** `report(true)` is unreadable and cannot grow a third mode: use a two-variant enum or two methods. A private helper whose call sites sit a few lines away is exempt. Several independent flags in one DTO that mirror CLI/TOML/JSON options are governed by `clippy.toml` `max-struct-bools`.
- **Named fields over tuples**, except single-field newtypes and very local code.
- **`Option` for absence, never sentinels** such as `-1` or `""`. **Data-carrying enums** instead of "field X is only meaningful when Y is set".
- **Strongest std type:** `PathBuf`/`&Path` for paths, `Duration` for spans. Keep plain integers at API boundaries.
- A `u32` conversion from a fieldless enum is `u32::from(value)` (generated by `kmip_enum` for KMIP enums), not `value as u32`.

### Standard traits

Derive what every field supports, when it is useful: `Debug`, `Clone`, `Copy` (small plain types only), `PartialEq`/`Eq`, `PartialOrd`/`Ord`, `Hash` (consistent with `Eq`), `Default`. Exceptions: **secrets and key material** are never given a derived `Debug`/`Clone`; hand-write `Debug` to redact them and keep them in `Zeroizing` ([`rust-security.instructions.md`](../../instructions/rust-security.instructions.md)). Implement `From`/`TryFrom`, never `Into`/`TryInto`. Prefer `from`/`into` over `as`, which silently allows lossy casts. Implement `FromStr` rather than an ad-hoc `from_str`. Implement `Deref` only on smart pointers and owning collections. If you hand-write `Ord`, hand-write `PartialEq`, `PartialOrd` and `Hash` to agree with it. Don't put derivable bounds on struct definitions; bounds belong on the `impl` blocks that need them.

### Constructors, builders, defaults

- A constructor with four or more loose arguments groups them into semantic types or a parameter struct (`Deposit::new(account, amount)`); that is how `clippy::too_many_arguments` is fixed here. A builder is one option when construction validates or has many optionals; it is not mandatory.
- If you provide both `new()` and `Default`, make them agree.

### Visibility and evolution

- Private by default; widen to `pub(crate)`/`pub(super)` before `pub`. Every `pub` item is a promise.
- `#[non_exhaustive]` and sealed traits are contextual choices for published API whose evolution you must protect. The KMS crates are not consumed by third parties, so do not add them automatically.
- Expose each public item at one path; do not `pub use` foreign crates' items without a reason; avoid leaking third-party types into new public APIs.
- Mark a function `const` only if it will stay `const`.

### Traits and generics

- Define a trait for generic programming (`T: Trait`, `impl Trait`, `dyn Trait`) or as an extension trait, not to organize code. Put essential functionality in inherent methods.
- Prefer, in order: concrete types; generics; `dyn Trait` (the database/HSM backends are the legitimate `dyn` boundaries). Don't nest generics on service-level types.
- If a function has a clear receiver, make it a method. A computation without a receiver is a free function.
- Closures: use the most general bound that works (`FnOnce`, `FnMut`, then `Fn`); closure parameters go last.
- Reach for a macro only when functions, generics and traits cannot do the job. Prefer `macro_rules!` to proc macros.

### Refactoring someone else's code

- Fix every smell the request is about, not just the cheap ones: clones that only satisfy the borrow checker, `&String`/`&Vec<T>` parameters, `unwrap` on fallible paths, `bool` parameters, `+` string concatenation, nondeterministic `HashMap` iteration in output.
- Keep public behavior identical unless changing it is the point: same operations, same success and failure semantics, same output bytes. Turning a panic into an `Err` is the change callers want; dropping an error variant or changing a constructor's inputs is not.
- Preserve quirks you don't understand and flag them rather than silently "fixing" them.
- When the code has no tests, pin the current behavior with a few before you touch it (unit tests live in a same-file `#[cfg(test)]` submodule).

## 5. Errors and panics

| Situation | Use |
|---|---|
| Absence is normal (`first()`, `checked_add`) | `Option<T>` |
| The caller may need to know what went wrong | `Result<T, E>` with the crate's error type |
| A bug or violated invariant inside your code | a typed error; **not** a production panic |

**Production code never panics.** No `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!` (outside `debug_assertions`), `process::exit`, unchecked arithmetic/indexing on untrusted data: the full list and allowed exceptions are in [`rust.instructions.md` § Panics and brutal exits](../../instructions/rust.instructions.md#panics-and-brutal-exits--forbidden-in-production-code). An invariant that "cannot happen" is still returned as an error variant. Tests may use a meaningful `.expect("<why this cannot fail>")`.

**Pattern-match instead of check-then-unwrap:** `if let Some(v) = opt { .. }` or `let Some(v) = opt else { return .. };`.

**Lock poisoning** is mapped to the crate's existing error (e.g. a `KmsError`/`DbError` variant) with `?`/`map_err`. Neither `.expect("lock poisoned")` nor silent recovery with `into_inner`.

**Error types:** keep each crate's existing `thiserror` error type and its `*_error!` / `*_bail!` macros (`kms_error!`/`kms_bail!`, `db_error!`/`db_bail!`, …). Do not introduce `anyhow`/`eyre`, a second error type per crate, or `Box<dyn Error>`/`String` as a public error type. Error types implement `std::error::Error + Send + Sync + 'static`; `Display` messages are concise; implement `From<Upstream>` so `?` converts and use `map_err` only for foreign errors or to add context. Error messages never contain secrets.

**Destructors never fail, panic, or block.** Provide `close(self) -> Result<()>` for fallible teardown.

**Document failure modes:** public items document applicable `# Errors`, `# Panics` and `# Safety`.

## 6. Everyday idioms

- **Iterators over hand loops** when the pipeline is short and reads top-down; collect fallible steps into `Result<Vec<_>, E>` and apply `?`. Keep an explicit `for` loop when the body is large or needs awkward early returns.
- **Option/Result combinators** (`map`, `and_then`, `ok_or_else`, `as_deref`) when clearer than `match`; `match` when they're not. Use guard clauses, `let-else` and `?` to flatten nesting.
- **`format!`/`write!`** with inline args (`format!("{name}: {count}")`), not chained `+`.
- **Explicit types where inference obscures intent:** `.into()`, `.parse()`, `.collect()`.
- **Drop guards:** bind to a name (`let _guard = ..`); `let _ = ..` drops immediately.
- **Imports:** one `use` per module path, at the top of the file (never inside function bodies); no globs except `use super::*` in tests and `use Enum::*` in a function that matches on it.
- **Magic numbers** become named `const`s with a doc comment.
- **Logging:** structured events through `tracing`, not `println!`/`dbg!`, except a CLI's own stdout output. Never log secrets.
- Use `Self` inside `impl` blocks; prefer `impl Trait` in argument position when the bound is used once.
- Functions over 60 lines or nesting of five or more levels are readability-review candidates, not failures; do not extract helpers automatically.

## 7. Concurrency and async

- Public types, and the futures they return, should be `Send`. Holding an `Rc` or a `RefCell` borrow across an `.await` makes a future `!Send`.
- Prefer message passing to shared state. When sharing: keep data with linked invariants under one lock, keep lock scopes to a few lines, never call user closures while holding a lock, never return a `MutexGuard` from a public method, never hold a lock across `.await` unless it is an async lock by design.
- Write `async fn` rather than `fn -> impl Future`, except in traits or when setup must run outside the async block.
- CPU-bound or blocking work inside async moves to `spawn_blocking` (see `/rust-async-refactor`).
- Library code does not spawn raw threads or assume a runtime.

## 8. Unsafe and FFI

- Write `unsafe` only for FFI/platform calls, a benchmarked performance need, or an abstraction safe code cannot express. Reach for std and well-reviewed crates first.
- Every `unsafe` block or impl gets a `// SAFETY:` comment stating why the invariants hold; every `unsafe fn` gets a `# Safety` doc section. The `unsafe_code` lint exception is `#[expect(unsafe_code, reason = "…")]` per [`rust.instructions.md`](../../instructions/rust.instructions.md).
- Keep `unsafe` in the smallest module that can uphold its invariant behind a safe API. A safe function that can cause UB through any sequence of safe calls is unsound and never acceptable.
- No `transmute` to cast enums or dodge lifetimes, no `unsafe impl Send` to silence the compiler.
- FFI: `#[repr(C)]` on shared structs, sized integer types, `CString`/`CStr` for strings, allocate and free on the same side, wrap C-owned pointers in an RAII type, check for null and return `Result`, stop panics at the boundary.

## 9. Crates, modules, features

- Share versions and lints through `[workspace.dependencies]` and `[workspace.lints]`. Do not add or bump dependencies without following [`dependencies.instructions.md`](../../instructions/dependencies.instructions.md). Do not restructure crates or modules unless the task asks for it.
- Non-leaf modules contain `mod` declarations and re-exports; re-export individually, not with globs. Group by use case rather than by kind (`traits`, `errors`).
- **Feature placement:** `#[cfg(feature = "non-fips")]` goes on an item, `impl`, field, variant or match arm, never on statements or blocks inside a function body and never as runtime `cfg!`. FIPS builds never compile non-FIPS algorithms. Canonical rule: `rust.instructions.md` § Feature-flag discipline.
- Features are additive and bare-named. Don't feature-gate struct fields or trait methods unless the existing code already does.
- Don't run code before `main()`; don't use unstable features on a stable toolchain.

## 10. Documentation and comments

- `///` on every public item; `//!` at the top of every module. The first sentence is a single line.
- Sections, as applicable and in order: `# Examples`, `# Errors`, `# Panics`, `# Safety`. Examples use `?`, never `unwrap()`.
- Document what the signature can't say: preconditions, side effects, ownership transfer, why. Don't restate the type or the name.
- `//` comments explain why, not what (`// SAFETY:`, non-obvious magic values, workarounds with a link). No design journals or rule-compliance tables in code docs: document the end state.

## 11. Behavioral tests

- Unit tests in a same-file `#[cfg(test)]` submodule; integration tests in `tests/` for anything reachable through the public API. The mandatory four layers, the test-server helpers and the no-`sleep`/no-fixed-port rules are in [`rust.instructions.md` § Testing](../../instructions/rust.instructions.md#testing).
- Test observable behavior and properties (round-trips, idempotence, monotonicity), not restated constants or mirrored branches. Assert an error kind or message, not just "an error occurred".
- Write a failing test before fixing a bug.
- Anything doing I/O, time, randomness or network must be controllable from the test. Randomness in tests still comes from `KmsRng`.
- Fuzz parsers of untrusted input where a harness exists; run Miri over new `unsafe` where practical.
- Assertions carry context: `assert_eq!(got, want, "input {input:?}")`.

## 12. Performance

Design for correctness and clarity first, optimize after measuring. When you do: `Vec::with_capacity` or `collect()` over push loops, reuse caller-owned buffers in hot APIs, `Box<[T]>`/`Box<str>`/`Arc<str>` for long-lived immutable sequences, batch work instead of per-item locking, avoid avoidable allocation and copying in compiled hot paths. Allocator and hasher swaps are contextual choices needing a measurement and, for hashers, trusted keys only.

## 13. Final checklist

Before returning Rust code, confirm:

- `cargo fmt --all` and the scoped clippy/test commands of §2 are clean; no new `#[allow]`/`#[expect]` outside the policy.
- No production `unwrap`/`expect`/panics; lock poisoning and "impossible" states are crate errors.
- Public functions take `&str`, `&[T]`, `impl AsRef<_>` or `impl IntoIterator`, not `&String`/`&Vec<T>`.
- No `bool` parameters in public signatures; no `.clone()` whose only job is to satisfy the borrow checker.
- Secrets are not logged, not compared with `==`, not given derived `Debug`/`Clone`.
- Every `unsafe` block has a `// SAFETY:` comment; every `unsafe fn` has `# Safety` docs.
- Public items have docs with a one-line summary and `# Errors`/`# Panics` where relevant.
- Compatibility surfaces (wire format, CLI/TOML/env names, REST JSON) are unchanged unless the task changes them.

## Upstream references

Condensed upstream digests, read when you need the reasoning behind a rule:

- [Rust API Guidelines digest](https://github.com/morganlinton/BeautifulRust/blob/main/skills/rust-best-practices/references/rust-api-guidelines.md)
- [Effective Rust digest](https://github.com/morganlinton/BeautifulRust/blob/main/skills/rust-best-practices/references/effective-rust.md)
- [Rust Design Patterns digest](https://github.com/morganlinton/BeautifulRust/blob/main/skills/rust-best-practices/references/rust-design-patterns.md)
- [Microsoft Pragmatic Rust Guidelines digest](https://github.com/morganlinton/BeautifulRust/blob/main/skills/rust-best-practices/references/microsoft-rust-guidelines.md)
- [Google Rust Style Guide digest](https://github.com/morganlinton/BeautifulRust/blob/main/skills/rust-best-practices/references/google-rust-style-guide.md)
