---
mode: 'agent'
description: 'Comprehensive code quality audit: duplication, design patterns, Clippy hygiene, CI efficiency. Use: /code-quality [path]'
---

# Code Quality Audit

Run a full code quality pass on the codebase (or a scoped path). Covers Rust
duplication, design patterns, Clippy hygiene, and CI efficiency.

**Usage**: `/code-quality` (full workspace) or `/code-quality crate/server/src/`

> This skill orchestrates four focused skills in the correct order. Each may
> surface action items; collect them all before implementing anything.

---

## Step 1 — Scope

If a path was provided, restrict all steps below to that path.
If no path, audit the full workspace.

```bash
git diff --name-only origin/develop...HEAD 2>/dev/null || git diff --name-only HEAD~1
```

Note which crates were recently changed — prioritize them in steps 2 and 3.

---

## Step 2 — Duplication and consolidation

Invoke `/rust-refactor` on the scoped path.

This finds:

- Near-identical function bodies or `match` arms
- Repeated access-control sequences in KMIP operation handlers
- Struct fields that belong in a shared trait
- Repeated `cfg(feature = ...)` guards

**Output**: a ranked list of duplication hotspots with LOC estimates and
consolidation proposals (Trait / Generic / macro). Stop at discovery —
do not implement.

---

## Step 3 — Design pattern review

Invoke `/rust-patterns` as a reference and evaluate the scoped code against it.

Check for violations of the 8 KMS-specific patterns:

- [ ] Newtype wrappers (`KeyUid`, `UserId`) — are raw strings crossing API boundaries?
- [ ] Builder for complex config structs — any multi-parameter constructors > 4 args?
- [ ] Command pattern for KMIP operations — do operations hold their own state correctly?
- [ ] Trait-based abstraction for DB/HSM — are concrete types leaking into callers?
- [ ] Key lifecycle state machine — are state transitions using `can_transition_to()`?
- [ ] Error macro — are errors constructed ad-hoc instead of using the crate macro?
- [ ] Extension traits — repeated utility methods on foreign types?
- [ ] `macro_rules!` for dispatch boilerplate — repeated match arms in dispatch.rs?

**Output**: pattern violations with file + line references, severity (blocking /
advisory), and recommended fix.

---

## Step 4 — Clippy hygiene

```bash
cargo clippy-all 2>&1 | grep -E "^error|^warning" | head -40
```

Categorize warnings by type. Flag any that indicate real quality issues
(not just style): `clippy::cognitive_complexity`, `clippy::too_many_arguments`,
`clippy::clone_on_ref_ptr`, `clippy::unwrap_used`, `clippy::expect_used`,
`clippy::panic`.

For each `clippy::unwrap_used` or `clippy::expect_used` warning: these are
**cardinal rule violations** — list them separately as blocking items.

---

## Step 5 — CI efficiency (full workspace only)

Skip this step if a sub-path was provided (CI audit always covers the full repo).

Invoke `/ci-efficiency`.

This checks:

- Missing caches (Nix store, Cargo registry, pnpm store)
- Over-broad workflow triggers (`on: push` without path filters)
- No concurrency cancellation on PR workflows
- Redundant matrix jobs between `pr.yml` and `test_all.yml`

**Output**: top 3 efficiency improvements ranked by CI-minutes saved.

---

## Step 6 — Consolidated Report

Produce a single report in this format:

```markdown
## Code Quality Report — <scope> — <date>

### Blocking Items
(cardinal rule violations: unwrap_used, pattern violations that break correctness)

| # | Category | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| 1 | Unwrap | `crate/foo/src/bar.rs:42` | `.unwrap()` in production | Replace with `?` |

### High-Impact Improvements
(duplication hotspots, major pattern violations — worth fixing before next release)

| # | Category | Hotspot | LOC saved | Effort |
|---|----------|---------|-----------|--------|
| 1 | Duplication | KMIP op handlers | ~120 | Medium |

### Advisory
(style, minor patterns, informational)

- ...

### CI Efficiency
(top 3 if step 5 ran)

1. ...

### Next Steps
- Fix blocking items first: `cargo clippy-all` must pass with zero warnings
- For duplication: run `/refactor-plan <area>` before implementing consolidations
- For pattern violations: run `/rust-patterns` for full examples
```

---

## Step 7 — Pre-implementation gate

After presenting the report, ask:

> "Which blocking items or high-impact improvements should I address first?
> For any multi-file change, I will run `/refactor-plan` before touching code."

Do **not** implement any changes until the user confirms scope.
