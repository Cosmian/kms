---
name: 'TOML Configuration'
description: 'TOML file conventions for Cargo manifests, workspace config, and project configuration in the Eviden KMS project'
applyTo: '**/*.toml'
---

# TOML conventions

## Cargo.toml — workspace manifest

The root `Cargo.toml` is a **workspace manifest**. Members are listed in alphabetical order under `[workspace.members]`.

Key conventions:

- All shared dependencies are declared in `[workspace.dependencies]` with explicit versions — individual crates inherit via `{ workspace = true }`.
- Never duplicate a dependency version across crates; always inherit from the workspace.
- `default-features = false` at the workspace level; enable only what is needed per crate.

## Cargo.toml — crate manifest

Each crate `Cargo.toml` must include:

```toml
[package]
name    = "cosmian_kms_<crate>"
version = { workspace = true }
authors = { workspace = true }
edition = { workspace = true }
license = { workspace = true }
```

Feature flags:

- `non-fips` is the only non-default feature flag in this workspace.
- `interop` and `insecure` are always-on test/dev features gated in the server crate only.
- Never add a `default` feature that enables `non-fips`.

## `.cargo/config.toml`

Cargo aliases are defined here. When adding a new alias:

- Use `kebab-case` names.
- Keep the alias as a simple string (not an array) unless it requires multiple arguments.
- Document the alias purpose with an inline comment.

## TOML formatting

- Use inline tables `{ key = value }` only for short values that fit on one line.
- Prefer multi-line tables for more than two keys.
- Add a blank line between `[sections]`.
- Sort keys alphabetically within each section where order is not semantically significant.

## `mise.toml` / `.mise.toml`

- Task definitions that cannot live in `.mise/tasks/` (e.g., top-level aliases) go in `mise.toml`.
- Always prefer file-based tasks (`.mise/tasks/*.sh`) over inline TOML tasks for anything non-trivial.

## `lychee.toml`, `_typos.toml`

- These are tool configuration files; follow the tool's own schema.
- Document any exclusion with an inline comment explaining why the pattern is excluded.
