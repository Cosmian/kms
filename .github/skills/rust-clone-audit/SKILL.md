---
name: rust-clone-audit
description: 'Detect and eliminate abusive cloning in Rust: treat every `.clone()`, `.to_owned()`, `.to_vec()`, `Cow::into_owned()`, and equivalent owned-duplication call as a potential ownership-design defect, not a free fix for a borrow-checker error. Use when writing, reviewing, or refactoring Rust code, especially when a `.clone()` is added to make code compile.'
---

# Rust Clone Audit

Companion to [`rust-signature-design`](../rust-signature-design/SKILL.md) (parameter identity/count)
and [`rust-refactor`](../rust-refactor/SKILL.md) (duplicated code blocks): this skill targets a
different axis — the **owned-vs-borrowed decision for a single value** at the call site where a
clone-equivalent call appears. It does not scan for duplicated logic or judge parameter lists.

Goal: identify and aggressively eliminate unnecessary cloning. Must not introduce `.clone()`
merely to satisfy the borrow checker without first exhausting borrowing, lifetime, and
ownership-transfer alternatives — the same rule the lint-suppression decision tree in
[`rust.instructions.md`](../../instructions/rust.instructions.md) already applies to
`clippy::redundant_clone` and `clippy::clone_on_copy`.

## Step 1 — Classify every clone-equivalent call

| Kind | Call shape | Legitimate when | KMS example |
| --- | --- | --- | --- |
| Handle clone | `Arc::clone(&x)`, `Rc::clone(&x)`, `x.clone()` on `Arc`/`Rc` | Always — O(1) ref-count bump, not a data copy | `Arc::clone(&recorder.calls)` (`database_objects.rs:1131`), `Arc::clone(&barrier)` (`audit/pgsql.rs:2070`) |
| Thread/task move clone | `x.clone()` right before `tokio::spawn`/`thread::spawn(move \|\| ...)` | The spawned task outlives the current scope and needs its own owned copy | — |
| Copy-type clone | `.clone()` on a `Copy` type (`u32`, `bool`, small enum) | Never needed — use the value directly or `.copied()`/`.cloned()` on an `Option`/`Iterator` | — |
| Borrow-checker-dodge clone | `.clone()` added only to make an error disappear, with no owned-value requirement downstream | Never — restructure the borrow instead (see rust-unofficial/patterns, "Clone to satisfy the borrow checker") | — |
| Field-extraction clone | `self.field.clone()` returned as an owned value from `&self` | The caller genuinely needs ownership (stores it, moves it across an `await`/thread boundary); otherwise return `&T`/`&str` | — |
| API-forced clone | Function signature takes `T` but the body only reads it — every caller must `.clone()` to call it | Never by itself — change the parameter to `&T` (one signature change fixes every call site) | — |
| Cow-eligible clone | `.to_string()`/`.to_owned()` used because *some* code paths modify the value and others don't | Only on the paths that actually modify; otherwise return `Cow<'_, str>` or the borrow | — |

## Step 2 — Discover

```bash
# Clone-equivalent call density per file, worst-first
rg -c '\.clone\(\)|\.to_owned\(\)|\.to_vec\(\)|Cow::into_owned\(\)' --type rust <path> | sort -t: -k2 -rn | head -20

# Clones immediately preceding a borrow-checker-shaped error pattern: same binding re-read right after
rg -n '(\w+)\.clone\(\)' --type rust <path> -B1 | rg -B1 'let \w+ = &?\1\b'

# Clones on Copy-eligible primitives (near-certain waste)
rg -n '\.(u8|u16|u32|u64|usize|i8|i16|i32|i64|isize|bool|f32|f64)\(\)\.clone\(\)|: *(u8|u16|u32|u64|usize|bool)\b.*\.clone\(\)' --type rust <path>

# Functions that take an owned T but only read it (API-forced clone candidates)
rg -n 'fn \w+\([^)]*: (String|Vec<\w+>|HashMap<[^)]+>)[^)]*\)' --type rust <path>
```

## Step 3 — Pick the narrowest fix (checklist, in order)

1. **Can the parameter/field be borrowed instead?** Change `T` → `&T` (or `&str`/`&[T]` for
   `String`/`Vec<T>`); update every caller — this is often the single-signature fix that removes
   N call-site clones at once.
2. **Is this `Arc::clone`/`Rc::clone`?** Stop — it is already correct, leave it.
3. **Is the value moving into a spawned task/thread/`'static` closure?** Clone is necessary;
   leave it, optionally add a `// moved into spawned task` comment if the reason isn't obvious
   from context.
4. **Does only some code paths need an owned value?** Return `Cow<'_, T>` instead of
   unconditionally cloning or unconditionally borrowing.
5. **Is the clone on a `Copy` type?** Remove `.clone()` entirely; use `.copied()`/`.cloned()`
   for `Option<&T>`/`Iterator<Item = &T>` conversions.
6. **Is the clone structurally required** (stored in a new owner, e.g. a struct field or a
   `HashMap` key/value, with no shared-ownership type in use)? Keep it — this is legitimate
   duplication, not abuse. Do not force `Arc`/`Rc` onto a type with no concurrent/shared
   ownership need just to avoid a single clone.

## Before / after (illustrative)

```rust
// Before — caller forced to clone because the function takes ownership it never needs.
fn log_message(msg: String) {
    println!("[LOG] {msg}");
}
log_message(message.clone());
log_message(message);

// After — borrow; zero allocation, callable repeatedly.
fn log_message(msg: &str) {
    println!("[LOG] {msg}");
}
log_message(&message);
log_message(&message);
```

## Do not

- Do not remove a clone that is structurally required (the value is stored in a new owner, or
  moved into a spawned task/thread) just to reduce a clone count.
- Do not replace a single clone with `Arc`/`Rc`/`RefCell` wrapping across a type with no
  concurrent or shared-ownership requirement — that trades one allocation for a bigger runtime
  cost (atomic ops, interior-mutability panics) and a wider API change.
- Do not silence `clippy::redundant_clone` / `clippy::clone_on_copy` with a bare `#[allow]`
  instead of fixing the call site — forbidden on new code per `rust.instructions.md`.
- Do not change a `crate/kmip` wire struct's field from owned to borrowed — KMIP structs are
  spec-bound value types serialized independently of caller lifetimes.
- Do not flag `Arc::clone`/`Rc::clone` as defects — they are O(1) ref-count bumps, never a data
  copy (see Step 1).

## References

- rust-unofficial/patterns, ["Clone to satisfy the borrow checker"](https://github.com/rust-unofficial/patterns/blob/main/src/anti_patterns/borrow_clone.md)
- Microsoft, ["Avoiding Excessive clone()"](https://microsoft.github.io/RustTraining/c-cpp-book/ch17-1-avoiding-excessive-clone.html) — source of the Step 1 "legitimate when" column and the before/after example
- Rust Project Goals, ["Ergonomic ref-counting"](https://goals.rust-lang.org/2024h2/ergonomic-rc.html)
