---
name: rust-simplify
description: Scan Rust code for simplification opportunities — nested control flow, long functions, dead code, boolean param traps, redundant iterator chains, and Clippy-flagged complexity. Use when asked to simplify code, reduce cognitive complexity, clean up code, or find over-engineering in Rust.
---

# Rust Simplify

Find and eliminate unnecessary complexity in Rust code. Complements `/rust-refactor` (duplication)
and `/code-quality` (full audit) by targeting **complexity**, not duplication.

**Usage**: `/rust-simplify` (current file / recent diff) or `/rust-simplify crate/server/src/core/`

---

## Phase 1 — Scan

Run against the target path (default: files from `git diff --name-only`).

### 1a Clippy complexity lints

```bash
cargo clippy-all 2>&1 | grep -E "cognitive_complexity|too_many_arguments|too_many_lines|needless_|dead_code|unused_"
```

### 1b Long functions (> 50 lines)

```bash
rg -c "^\s+(pub |pub\(crate\) )?fn " --type rust <path>   # files with many fns
# Then inspect flagged files for individual functions exceeding 50 lines
```

### 1c Deep nesting (≥ 5 levels)

```bash
rg -n "^ {20,}" --type rust <path> | head -30
```

### 1d Boolean param traps

```bash
rg -n "fn [a-z_]+\([^)]*bool[^)]*bool" --type rust <path>
```

### 1e Iterator anti-patterns

```bash
rg -n "for .+ in .+\.(iter|iter_mut)\(\)" --type rust <path> | head -20
```

### 1f Redundant unwraps / sentinel values

```bash
rg -n '\.unwrap\(\)|\.expect\(' --type rust <path>
```

---

## Phase 2 — Classify

| Smell | Pattern |
|-------|---------|
| Nested `if`/`match` (depth ≥ 3) | Early return, `let-else`, `?` |
| Function > 50 lines | Extract named private helper |
| Multiple `bool` params per fn | Replace with `pub(crate) enum` |
| Dead / unused item | Delete; cross-crate check first |
| Manual `for` → collect | Iterator chain (`map`, `filter`, `fold`) |
| Sentinel value (–1, `""`, 0) | `Option<T>` or `Result<T, E>` |
| `#[cfg(feature)]` inside fn body | Hoist to function / module level |
| `Arc<Mutex<T>>` with immutable `T` | `Arc<T>` |

---

## Phase 3 — Prioritize

Present this ranked list to the user **before touching any code**:

```text
[BLOCKING] unwrap_used / expect_used         — cardinal rule violation
[HIGH]     Function > 100 lines              — extract helper(s)
[HIGH]     Nesting depth ≥ 5                 — invert guard clause
[MED]      Bool param trap                   — define enum
[MED]      Dead code                         — delete after cross-crate check
[LOW]      Manual loop → iterator            — cosmetic, improves readability
```

---

## Phase 4 — Implement (one finding at a time)

**Early return / `let-else`**

```rust
// Before
if let Some(x) = opt { use(x) } else { return Err(e) }
// After
let Some(x) = opt else { return Err(e) };
```

**Extract helper** — name it by *what it does*, not by what calls it. Add a `#[cfg(test)]` unit test.

**Bool trap → enum** — replace `bool` parameter with a named enum:

1. Define `pub(crate) enum FlagName { Yes, No }` near the call site.
2. Update every call site before removing the `bool` param.

**Dead code removal** — always run `rg "item_name" --type rust` across all crates before deleting.

After each file: `cargo clippy-all && cargo fmt --all`
After each crate: `cargo test -p <crate>`

---

## Phase 5 — Verify

```bash
cargo clippy-all        # zero warnings
cargo fmt --all         # no drift
cargo test -p <crate>   # narrowest scope covering the change
git diff --stat         # every hunk explainable by the task
```

---

## Quick Rules

- Keep every function ≤ 50 lines after simplification.
- Never remove a `pub` item without `rg "item_name" --type rust` across all crates.
- One logical simplification per commit; never mix with feature work.
- Add a `//` comment when a non-obvious simplification changes observable behaviour.
