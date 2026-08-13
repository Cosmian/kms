---
name: rust-panic-audit
description: 'Scan Rust code for every form of panic or brutal process exit: panic!, todo!, unimplemented!, unreachable!, .unwrap(), .expect() in production, process::exit/abort, integer overflow, and out-of-bounds indexing. Produces a ranked report with patches. Use when reviewing Rust code quality, before any PR, or when adding new Rust code.'
---

# Rust Panic & Brutal-Exit Audit

Detect every construct in Rust code that can cause a panic, abort, or brutal process exit
outside of `#[cfg(test)]` blocks. Produces a report in `./review/rust-panic-audit.md`.

**Usage**: `/rust-panic-audit` (diff scope) or `/rust-panic-audit crate/server/src/`

---

## Step 0 — Create output directory

```bash
mkdir -p ./review
REPORT="./review/rust-panic-audit.md"
echo "# Rust Panic & Brutal-Exit Audit" > "${REPORT}"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${REPORT}"
echo "" >> "${REPORT}"
```

---

## Step 1 — Determine scope

If a path was provided, scan only that path.
Otherwise default to recently changed Rust files:

```bash
SCOPE=$(git diff --name-only origin/develop...HEAD 2>/dev/null || git diff --name-only HEAD~1)
# Fall back to full codebase if diff is empty
[ -z "${SCOPE}" ] && SCOPE="crate/"
```

---

## Step 2 — Mechanical scan (ripgrep passes)

Run each grep pass; collect file + line number + snippet.

### Pass A — Direct panic macros

```bash
rg -n '(^|[^/])\bpanic!\s*(' --type rust ${SCOPE}
```

### Pass B — Placeholder macros (always panic at runtime)

```bash
rg -n '\b(todo!|unimplemented!)\s*(' --type rust ${SCOPE}
```

### Pass C — `.unwrap()` in production code

```bash
rg -n '\.unwrap\(\)' --type rust ${SCOPE}
```

Filter out lines inside `#[cfg(test)]` modules (manual review for context).

### Pass D — `.expect(...)` in production code

```bash
rg -n '\.expect\(' --type rust ${SCOPE}
```

### Pass E — `unreachable!` outside debug-only guards

```bash
rg -n '\bunreachable!\s*(' --type rust ${SCOPE}
```

Flag each hit unless it is inside `#[cfg(debug_assertions)]` or `#[cfg(test)]`.

### Pass F — Process exit / abort

```bash
rg -n '\bstd::process::(exit|abort)\b|\bprocess::(exit|abort)\b' --type rust ${SCOPE}
```

### Pass G — Integer arithmetic without overflow protection on untrusted data

```bash
# Look for direct + / * on integer types in path-handling, length, or index contexts
rg -n '\b(len|index|offset|size|count)\s*[+\*]\s' --type rust ${SCOPE}
```

### Pass H — Direct slice indexing on non-literal indices

```bash
rg -n '\[\s*[a-z_][a-zA-Z0-9_]*\s*\]' --type rust ${SCOPE} \
  | grep -v 'cfg\|macro\|derive\|//\|test'
```

---

## Step 3 — Classify findings

For each finding, assign a severity:

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | `panic!`, `process::exit`, `process::abort`, `todo!`, `unimplemented!` in hot paths |
| **HIGH** | `.unwrap()` or `.expect()` on `Result`/`Option` in request handler, DB, or crypto code |
| **MEDIUM** | `unreachable!` outside debug guards, unchecked slice indexing on untrusted input |
| **LOW** | `.unwrap()` in one-time initialisation (`OnceLock`, `lazy_static`, known-safe) |
| **INFO** | `.expect()` in test code (allowed but must have a meaningful message) |

---

## Step 4 — Filter allowed occurrences

The following are **allowed** and should be marked `[OK]`:

- Any line inside a `#[cfg(test)]` module.
- `OnceLock::set(...).expect("OnceLock already set")` — deterministic.
- `unreachable!()` inside a `#[cfg(debug_assertions)]` block with a `// PANIC:` comment.
- `process::exit(0)` inside `fn main()` only, with a `// PANIC:` comment.

---

## Step 5b — Scan for Clippy suppressions on added code

```bash
git diff origin/develop...HEAD -- '*.rs' \
  | grep '^+' \
  | grep -E '#\[allow\(clippy::' \
  | grep -v '^+++' \
  | grep -v '//.*tracked\|//.*issue\|//.*#[0-9]\|//.*false.positive'
```

Any hit is a **CRITICAL blocker**: the lint must be fixed, not suppressed.
Also scan for blanket suppressions (always CRITICAL):

```bash
git diff origin/develop...HEAD -- '*.rs' \
  | grep '^+' \
  | grep -E '#\[allow\(warnings\)\]' \
  | grep -v '^+++ '
```

Append findings to `./review/rust-panic-audit.md` under a `## Clippy Suppressions` section.

---

## Step 6 — Generate patches for CRITICAL and HIGH findings

For each CRITICAL/HIGH finding, produce a concrete patch:

**`.unwrap()` on `Result`:**
```rust
// ❌ Before
let key = kms.get_key(id).await.unwrap();

// ✅ After
let key = kms.get_key(id).await
    .map_err(|e| KmsError::InvalidRequest(format!("Failed to get key {id}: {e}")))?;
```

**`.expect()` on `Option`:**
```rust
// ❌ Before
let val = map.get(&key).expect("key must exist");

// ✅ After
let val = map.get(&key)
    .ok_or_else(|| KmsError::ItemNotFound(key.clone()))?;
```

**`panic!` with static message:**
```rust
// ❌ Before
panic!("unexpected state");

// ✅ After
return Err(KmsError::InvalidRequest("unexpected state".to_owned()));
```

---

## Step 6 — Write report

Append to `./review/rust-panic-audit.md`:

```markdown
## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | N |
| HIGH     | N |
| MEDIUM   | N |
| LOW      | N |
| INFO     | N |
| OK       | N |

## Findings

### [CRITICAL] panic! in request handler
- **File**: `crate/server/src/core/operations/get.rs:42`
- **Code**: `panic!("key not found")`
- **Impact**: Aborts the Actix-web worker thread; potential DoS via crafted request.
- **Fix**: Replace with `return Err(KmsError::ItemNotFound(...))`.

...
```

---

## Step 7 — Summary verdict

Print to chat:

```
Rust Panic Audit complete.
CRITICAL: N  HIGH: N  MEDIUM: N  LOW: N
Report: ./review/rust-panic-audit.md
```

If CRITICAL or HIGH count > 0, recommend running `/rust-review-all` for a full quality gate
before the PR is submitted.
