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

## Clippy

- Zero warnings required (`cargo clippy-all`).
- `#[allow(clippy::...)]` is acceptable only with an inline comment explaining why the lint cannot be fixed.
- Never use blanket `#[allow(warnings)]`.

## Style

- Prefer `impl Trait` in argument position over generic type parameters when the trait bound is used once.
- Keep functions under 60 lines; extract helpers when logic branches.
- Use `Self` to refer to the implementing type inside `impl` blocks.

> For deeper guidance on KMS-specific Rust patterns, run `/rust-patterns`.
