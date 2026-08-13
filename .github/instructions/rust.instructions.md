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

- Unit tests go in a `#[cfg(test)]` submodule at the bottom of the same file.
- Use `use super::*;` in test modules.
- Run targeted tests: `cargo test -p <crate> <test_name>` — not the full suite.

## Documentation

- All public items (`pub fn`, `pub struct`, `pub enum`, `pub trait`) require `///` doc comments.

## Clippy — zero `#[allow]` policy

- Zero Clippy warnings required (`cargo clippy-all`).
- **`#[allow(clippy::...)]` is FORBIDDEN on newly written or AI-generated code.** Fix the lint instead.
- `#[allow(warnings)]` is **unconditionally forbidden** — never add it under any circumstances.
- **Do not silence Clippy to make code compile faster.** Every lint exists for a reason.

### Decision tree for a Clippy warning

1. **Fix it** — this is always the correct first option.
2. **Refactor** — if the lint points to genuine complexity, simplify the code.
3. **Narrow exception** — if the lint is a false positive on pre-existing code (not code you wrote), document with a precise inline comment:

   ```rust
   #[allow(clippy::too_many_arguments)] // legacy API surface — tracked in #1234
   pub fn existing_function(...) { ... }
   ```

4. **Report** — if none of the above apply, report the exact warning to the reviewer before suppressing.

### Scanning for illegitimate `#[allow(clippy::...)]` additions

Agents must scan the diff for newly added `#[allow(clippy::...)]` lines:

```bash
# Show only added lines (not pre-existing) that suppress Clippy
git diff origin/develop...HEAD -- '*.rs' \
  | grep '^+' \
  | grep -E '#\[allow\(clippy::' \
  | grep -v '^+++' \
  | grep -v '//.*tracked\|//.*issue\|//.*#[0-9]'
```

Any match that lacks a `// tracked in #<issue>` or `// false positive:` inline comment is a **blocker** — reject the change and fix the lint.

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
