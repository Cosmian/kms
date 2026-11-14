---
name: rust-refactor
description: 'Review Rust duplication and structural complexity while preserving behavior; use for Rust refactoring or simplification.'
---

# Rust Refactor

Find duplicated behavior and unnecessary structural complexity in Rust code, then (if asked to implement) consolidate it without changing behavior. Baseline idioms: [`../rust-best-practices/SKILL.md`](../rust-best-practices/SKILL.md); KMS rules: [`../../instructions/rust.instructions.md`](../../instructions/rust.instructions.md).

**Usage**: `/rust-refactor` (current diff) or `/rust-refactor crate/server/src/core/`

## Workflow

One pass: discover → classify → plan → implement → behavior proof. Findings are advisory until the user approves a plan; preserve behavior, errors, authorization checks and serialization.

### 1. Discover

Scope: the supplied path, else the changed Rust files. Read the code; text searches only produce candidates and a negative search proves nothing. Reuse `/kms-caveman` evidence for the same scope and revision instead of re-scanning.

#### Duplication

- Functions with near-identical signatures or bodies.
- `match` arms repeating the same multi-line logic.
- `impl` blocks repeating the same methods on different types.
- Error conversions repeated across files (`From` candidates).
- Struct fields sharing a common subset (composition candidate).
- Repeated access-control check sequences in KMIP operation handlers.

#### Structural review

- Nesting ≥ 3 levels: flatten with guard clauses, `let-else` or `?`.
- Functions over 60 lines: readability-review candidates, not failures; extract a helper only when it names a real concept.
- `bool` parameters (especially several): replace with a two-variant enum, updating every call site first.
- Redundant iterator chains and manual collect loops: replace with the clearer form, keep an explicit loop when the body is large.
- Sentinel values (`-1`, `""`, `0`): `Option` / `Result`.
- `Arc<Mutex<T>>` around data that is never mutated: `Arc<T>`.
- `#[cfg(feature)]` inside a function body: hoist to item level (split into two functions with opposite `#[cfg]`).
- Dead code: report only with workspace-wide evidence accounting for callers, macros and generated uses; delete after checking every crate.

### 2. Classify

Pick the **minimum sufficient** pattern, in this order: reuse an existing helper → a concrete helper function → generics / traits / macros only when the duplication really spans types.

| Smell | Pattern |
|-------|---------|
| Same logic on N types | Generic function / `impl<T: Bound>` |
| Same interface, different impls | Trait + `impl Trait for Type` |
| Repetitive `match` / boilerplate impls | `macro_rules!` only if functions cannot do it |
| Repeated struct field group | Composition / newtype |
| Repeated conversions | `impl From<X> for Y` |

Prefer generics over `dyn Trait` unless the set of types is open at runtime. KMS design shapes: [`../rust-best-practices/references/kms-patterns.md`](../rust-best-practices/references/kms-patterns.md).

### 3. Plan

Rank by impact (lines removed or complexity reduced) ÷ risk (tests and callers affected) and present the list before touching code:

```text
[HIGH] Extract shared access check — removes ~60 LOC, touches 3 files
[MED]  Replace `bool` parameter with enum — touches 4 call sites
[LOW]  Flatten nested match with let-else — one function
```

### 4. Implement (one finding at a time)

1. Add the shared item, migrate callers file by file, delete the old code only after all callers compile.
2. Never remove a public item without checking every crate (`rg "name" --type rust`).
3. Never add `#[allow]` / `#[expect]` to get a refactor through: fix the lint (policy in `rust.instructions.md` § Clippy and lint suppression).

### 5. Behavior proof

Run once after the batch, scoped to what changed, and record the commands actually run:

```bash
cargo fmt --all
cargo clippy-all
cargo test -p <crate>
git diff --stat   # every hunk explainable by the task
```

A refactor that cannot be covered by an existing or new behavioral test is reported as unverified, not as safe.

## Report

If an orchestrator writes reports, use `./review-YYYY-MM-DD/rust-refactor.md` and the schema in [`../shared/orchestrator-contract.md`](../shared/orchestrator-contract.md) §4; otherwise return the ranked list.
