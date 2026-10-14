---
name: code-quality
description: 'Scoped code-quality audit orchestrator: runs 8 phases per .github/skills/shared/orchestrator-contract.md (KMS Caveman first, then MISE, error-prop, simplify, refactor, patterns, async, Clippy). Each phase is a task sub-agent routed by Jev delegation. One ranked report deduplicating overlapping findings. Use before PRs or when improving code quality.'
---

# Code Quality Audit

Orchestrates six Rust-focused audit skills, MISE Bash checks, Clippy, and CI efficiency in one ranked report. The read-only KMS Caveman pass runs first; findings from deeper reviews are deduplicated.

**Usage**: `/code-quality` (full workspace) or `/code-quality crate/server/src/`
> **Canonical Reference**: This orchestrator's phase ordering, skip gates, and deduplication rules follow `.github/skills/shared/orchestrator-contract.md`. Each phase runs as a task sub-agent and is automatically routed by Jev to `smol` (mechanical phases) or `slow` (reasoning phases) based on phase type.

## Orchestration rationale

The Rust review skills overlap; this orchestrator orders them and deduplicates findings.

1. **Orders for efficiency** — cheap, high-signal scans first; expensive
   analysis later; skips irrelevant skills.
2. **Deduplicates findings** — when two skills flag the same issue (e.g. a long
   function), it appears once under the highest-severity category.
3. **Conditions execution** — KMS Caveman runs once first. `mise` runs only when `.mise/` changed.
   Async review runs only when changed code or call paths are relevant; CI review runs only for full-workspace audits.

### Skill overlap map

| Finding                        | Clippy | rust-refactor | rust-simplify | rust-patterns | rust-err-prop | rust-async |
| ------------------------------ | :----: | :-----------: | :-----------: | :-----------: | :-----------: | :--------: |
| `.unwrap()` / `.expect()`      |   ✓    |               |       ✓       |               |               |            |
| Long functions (> 50 lines)    |   ✓    |       ✓       |       ✓       |               |               |            |
| Deep nesting                   |   ✓    |               |       ✓       |               |               |            |
| Bool parameter traps           |        |               |       ✓       |               |               |            |
| Duplicate code blocks          |        |       ✓       |               |               |               |            |
| Repeated `match` arms          |        |       ✓       |               |       ✓       |               |            |
| Missed `?` propagation         |        |               |               |               |       ✓       |            |
| `.to_string()` on errors       |        |               |               |               |       ✓       |            |
| Pattern violations             |        |               |               |       ✓       |               |            |
| Sequential independent awaits  |        |               |               |               |               |     ✓      |
| Blocking I/O on async runtime  |        |               |               |               |               |     ✓      |
| Unnecessary `Arc`              |        |               |               |               |               |     ✓      |

**Overlap resolution rule**: when the same issue is found by multiple skills,
report it under the *first* skill in pipeline order (Clippy > err-prop > refactor
> simplify > patterns > async). List cross-references in the detail column.

---

## Step 1 — Scope, KMS Caveman First & Eligibility

If a path was provided, restrict all steps to that path. Otherwise use the changed-file scope, including
branch changes, staged and unstaged files, and untracked files. If the base diff is unavailable or the
scope is empty, state that fact; never treat a failed or empty diff command as proof of a clean audit.

If Rust files are in scope, invoke `/kms-caveman` once before the other Rust review skills. Reuse its
verified findings and do not repeat them. KMS Caveman is triage, not a substitute for semantic,
security, crypto, or protocol review; a clean result does not prove those areas are clean.

Determine eligibility from the actual changed code and relevant callers, not merely from whether a
whole path contains a matching token. Full-workspace audits run every applicable skill. For focused
diffs, use these conservative gates and state every skip in the report:

|Skill|Run when|Skip only when|
|---|---|---|
|`/mise`|`.mise/` files in scope|No `.mise/` files changed|
|`/rust-async-refactor`|Changed code/callers async or may block runtime|Inspected changes and callers have no async/blocking relevance|
|`/rust-error-propagation`|Changed code affects fallible operations/errors|Inspected changes cannot affect error paths|
|`/rust-simplify`|Full audit or focused structural change|Inspected changes do not affect complexity|
|`/rust-refactor`|Full audit or focused code has repeated behavior|Inspected code unrelated to duplication; regex misses are insufficient|
|`/ci-efficiency`|Full-workspace audit|Focused sub-path is the complete requested scope|

This skill does not replace security, cryptographic, or standards reviews. Run those when their
dedicated scope rules apply; a clean mechanical pass is never evidence to skip them.

---

## Step 2 — MISE script audit (conditional)

**Only run if** Step 1 detected `.mise/` files in scope. Fast scan (~2 s).

Invoke `/mise` conventions as reference. Run three passes:

### Pass A — shellcheck (correctness)

```bash
# Lint changed MISE task files
git diff --name-only origin/develop...HEAD 2>/dev/null | grep '^\.mise/tasks/' | while read -r f; do
  [ -f "$f" ] && shellcheck "$f"
done
```

### Pass B — Convention compliance

```bash
# Tasks missing set -euo pipefail
rg -L "set -euo pipefail" .mise/tasks/ <path> 2>/dev/null

# Tasks missing print_success at end
for f in .mise/tasks/*/*; do
  [ -f "$f" ] && ! tail -3 "$f" | grep -q "print_success" && echo "Missing print_success: $f"
done

# Wrong sourcing path (not using MISE_CONFIG_ROOT)
rg -n 'source.*\.mise/lib' <path> 2>/dev/null | grep -v 'MISE_CONFIG_ROOT'

# Missing kms_init_env when FEATURES_FLAG is used
for f in .mise/tasks/*/*; do
  [ -f "$f" ] && rg -q 'FEATURES_FLAG' "$f" && ! rg -q 'kms_init_env' "$f" && echo "Missing kms_init_env: $f"
done
```

### Pass C — LOC minimization opportunities

Checklist against `/mise` conventions:

- [ ] Wrapper tasks using `bash ... && exit $?` → replace with `exec bash ... "$@"`
- [ ] Inline `run_step` / `FAILED=()` aggregator missing where ≥ 3 sub-steps exist
- [ ] Inline server startup → should use `kms_server.sh` helpers (`kms_pick_free_port`, `kms_start`, etc.)
- [ ] Inline connection-string assembly → should use `check_and_test_db` / `run_db_tests`
- [ ] Reinvented functions that exist in `.mise/lib/` (`wait_for_port`, `compute_sha256`, `kms_pick_free_port`, etc.)
- [ ] Task files with `.sh` extension → must have no extension
- [ ] Library files using wrong naming (not `snake_case.sh`)

### Output

| Category | File:Line | Issue | Severity |
|----------|-----------|-------|----------|
| shellcheck | `.mise/tasks/test/foo:12` | SC2086: Double quote to prevent globbing | HIGH |
| Convention | `.mise/tasks/test/bar` | Missing `set -euo pipefail` | BLOCKING |
| LOC | `.mise/tasks/test/baz:15` | Use `run_step` aggregator (3 inline steps) | MEDIUM |
| Reinvented | `.mise/tasks/test/qux:8` | Reimplements `wait_for_port` — use common.sh | HIGH |

---

## Step 3 — Clippy hygiene (after KMS Caveman)

Run Clippy after the KMS Caveman pass. Use `cargo clippy-all` for a full-workspace audit; for a focused
Rust change, run Clippy on the affected crate rather than compiling the whole workspace.

```bash
# Full workspace
cargo clippy-all

# Focused crate
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
```

Categorize every warning:

| Category | Lint examples | Severity |
|----------|--------------|----------|
| **Blocking** | `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` | BLOCKING |
| **Structural** | `clippy::cognitive_complexity`, `clippy::too_many_arguments`, `clippy::too_many_lines` | HIGH |
| **Correctness** | `clippy::clone_on_ref_ptr`, `clippy::needless_pass_by_ref_mut` | HIGH |
| **Style** | `clippy::needless_return`, `clippy::redundant_closure` | ADVISORY |

> Cardinal rule: every `unwrap_used` / `expect_used` in production code is
> **BLOCKING**. List each with file:line and suggested replacement (`?` or
> `.ok_or_else(|| kms_error!(...))?`).

**Flags to save for dedup**: unwrap/expect, cognitive_complexity, too_many_lines,
too_many_arguments.

---

## Step 4 — Error propagation audit (conditional)

For a full-workspace audit, run `/rust-error-propagation`. For a focused diff, run it when the
changed code or affected callers modify fallible operations, `Result` propagation, error conversion,
or error context. Skip only after inspecting the changes and confirming none of those paths are
affected; record the reason. Do not infer irrelevance from the absence of the word `Result` in a
search of the entire containing file.

### Pass A — Missed `?`

```bash
# Find verbose match on Result that could be ?
rg -n "match .*\\b(Ok|Err)\\b" --type rust <path> | head -30
```

### Pass B — `.to_string()` anti-pattern

```bash
rg -n '\.to_string\(\)' --type rust <path> | grep -i "err\|map_err" | head -20
```

### Pass C — Silent error discard

```bash
rg -n 'map_err\(\s*\|_\|' --type rust <path> | head -20
```

**Output**: ranked list (🔴 Critical → 🟢 Low) per the rust-error-propagation
severity scale. Merge with Clippy findings — if Clippy already flagged the same
line, append "(also flagged by Clippy)" instead of duplicating.

---

## Step 5 — Structural analysis: duplication + simplification

For a full-workspace audit, run both skills. For a focused diff, use the scope gate in Step 1;
`/kms-caveman` can identify literal duplicate candidates but cannot rule out semantically duplicated
behavior. Do not skip `/rust-refactor` based only on a negative regex/search result.

### 4a — Duplication scan (rust-refactor)

```bash
# Find clone-heavy code
rg "\.clone\(\)" --type rust <path> --stats 2>/dev/null | tail -5

# Spot repeated function patterns across KMIP operations
rg -l "fn (create|get|locate|activate|revoke|destroy)_" <path> 2>/dev/null | head -10
```

Checklist:
- [ ] Functions with near-identical signatures/bodies
- [ ] `match` arms repeating the same multi-line logic
- [ ] `impl` blocks repeating methods on different types
- [ ] Repeated `#[cfg(feature = "...")]` guards
- [ ] Repeated access-control check sequences in KMIP operation handlers

### 4b — Complexity scan (rust-simplify)

```bash
# Long functions (> 50 lines) — approximate via indented fn bodies
rg -c "^\\s+(pub |pub\\(crate\\) )?fn " --type rust <path>

# Deep nesting (≥ 5 levels = 20 spaces)
rg -n "^ {20,}" --type rust <path> | head -30

# Bool param traps
rg -n "fn [a-z_]+\\([^)]*bool[^)]*bool" --type rust <path>

# Iterator anti-patterns
rg -n "for .+ in .+\.(iter|iter_mut)\(\)" --type rust <path> | head -20
```

### 4c — Classify & dedup

Merge 4a + 4b findings. When both flag the same function (e.g. long + duplicated),
list once with both tags.

| Smell | Pattern | Severity |
|-------|---------|----------|
| Duplicate function bodies | Generic / Trait / macro | HIGH |
| Near-identical KMIP handlers | `macro_rules!` dispatch helper | HIGH |
| Repeated access-control blocks | Shared `check_access` helper | HIGH |
| Function > 100 lines | Extract named helper(s) | HIGH |
| Nesting depth ≥ 5 | Early return / `let-else` / `?` | HIGH |
| Multiple `bool` params | Replace with `pub(crate) enum` | MEDIUM |
| Dead / unused item | Delete (cross-crate check first) | MEDIUM |
| Manual `for` → iterator chain | `map` / `filter` / `fold` | LOW |
| `#[cfg(feature)]` inside fn body | Hoist to fn/module level | LOW |

---

## Step 6 — Design pattern compliance (always run)

Invoke `/rust-patterns` as a reference. Evaluate the scoped code against the
8 KMS-specific patterns:

- [ ] **Newtype wrappers** — raw strings crossing API boundaries? (`KeyUid`, `UserId`, `UniqueIdentifier`)
- [ ] **Builder for complex config** — any constructor with > 4 args?
- [ ] **Command pattern for KMIP ops** — operations hold their own state correctly?
- [ ] **Trait-based abstraction for DB/HSM** — concrete types leaking into callers?
- [ ] **Key lifecycle state machine** — state transitions using `can_transition_to()`?
- [ ] **Error macro** — errors constructed ad-hoc instead of `kms_error!`?
- [ ] **Extension traits** — repeated utility methods on foreign types?
- [ ] **`macro_rules!` for dispatch** — repeated match arms in dispatch.rs?

**Output**: pattern violations with file:line, severity (BLOCKING / HIGH / ADVISORY),
and the pattern reference. Cross-reference with Step 5 findings — a "repeated
match arms" finding in Step 5 is likely a Pattern 8 violation.

---

## Step 7 — Async optimization (conditional)

**Only run if** Step 1 detected async code in scope.

Invoke `/rust-async-refactor` logic:

### Pass A — Sequential independent awaits

```bash
rg -n "let .+ = .+\.await;" --type rust <path> | head -40
```

For each file with ≥ 3 consecutive independent `.await` calls, flag as
candidate for `tokio::try_join!`.

### Pass B — Unnecessary Arc

```bash
rg -n "Arc::new" --type rust <path> | head -20
```

Flag `Arc::new(...)` where the value is only used within a single async task.
Exempt: `Arc<ServerParams>`, `Arc<reqwest::Client>`, `web::Data<Arc<KMS>>`.

### Pass C — Blocking calls on async runtime

```bash
rg -n "std::fs::(read|write)|std::thread::sleep" --type rust <path> | head -20
```

### Output

| Priority | Pattern | Example |
|----------|---------|---------|
| 🔴 Critical | Blocking I/O on async runtime | `std::fs::read` in `async fn` |
| 🟠 High | Sequential DB calls that could be parallelized | Two independent `.find()` + `.retrieve()` |
| 🟡 Medium | Unnecessary `Arc` allocation | Local config wrapped in `Arc` |

**KMS safety notes**:
- HSM calls are inherently sequential — never flag for parallelization.
- SQLite is single-writer — parallel reads safe, writes not.
- PostgreSQL/MySQL support concurrent reads within pool limits.
- `kms.database` methods use internal sync — concurrent calls from same `KMS` reference are safe.

---

## Step 8 — CI efficiency (full workspace only)

**Skip** if a sub-path was provided (CI audit always covers the full repo).

Invoke `/ci-efficiency`. Check:

- Missing caches (Nix store, Cargo registry, pnpm store)
- Over-broad workflow triggers (`on: push` without path filters)
- No concurrency cancellation on PR workflows
- Redundant matrix jobs between `pr.yml` and `test_all.yml`

**Output**: top 3 efficiency improvements ranked by CI-minutes saved.

---

## Step 9 — Consolidated report

Produce a single detailed report. **All findings from all skills merged and
deduplicated:**

```markdown
## Code Quality Report — <scope> — <date>

> Skills run: KMS Caveman, Clippy, rust-error-propagation, rust-refactor, rust-simplify,
> rust-patterns[, mise][, rust-async-refactor][, ci-efficiency]
> Scope: <path or "full workspace">
> KMS Caveman: [PASS / BLOCK / NOT APPLICABLE / INCOMPLETE]; verified findings are not repeated below
> Async / MISE / CI eligibility: [run or skipped, with reason]

### BLOCKING — Must fix before merge

| # | Category | File:Line | Issue | Fix | Cross-ref |
|---|----------|-----------|-------|-----|-----------|
| 1 | Unwrap   | `crate/foo/src/bar.rs:42` | `.unwrap()` in production | Replace with `?` | Clippy |
| 2 | Pattern  | `crate/server/src/ops/create.rs:18` | Raw String for UID | Wrap in `UniqueIdentifier` | rust-patterns #1 |

### HIGH — Fix before next release

| # | Category | File:Line | Issue | LOC impact | Fix |
|---|----------|-----------|-------|------------|-----|
| 1 | Duplication | `crate/server/src/core/operations/` (×12 files) | Repeated access-control preamble | ~140 LOC saved | Extract `check_access_and_resolve` |
| 2 | Complexity | `crate/server/src/core/operations/export.rs:200` | 147-line function | Extract 3 helpers | Split into `validate_request`, `retrieve_key`, `build_response` |
| 3 | ErrProp    | `crate/clients/client/src/rest.rs:89` | `.map_err(\|e\| e.to_string())` | — | Use `map_err(KmsError::from)` |
| 4 | Async      | `crate/server/src/core/operations/transit.rs:34-35` | Sequential independent DB queries | — | `tokio::try_join!` |

### MEDIUM — Worth addressing

| # | Category | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| 1 | BoolTrap | `crate/server/src/config/mod.rs:67` | `fn enable(force: bool, dry_run: bool)` | Replace with `enum Mode { Force, DryRun }` |
| 2 | DeadCode | `crate/crypto/src/legacy.rs:120` | Unused `fn pad_pkcs7` | Delete after `rg --type rust` cross-crate check |

### ADVISORY — Style & polish

- `crate/server/src/routes/kmip.rs:30`: `needless_return` — remove explicit `return`
- `crate/kmip/src/types.rs:215`: iterator `.iter().map().collect()` → direct `.into_iter()`

### MISE Scripts (if Step 2 ran)

| # | Category | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| 1 | Convention | `.mise/tasks/test/foo` | Missing `set -euo pipefail` | Add after `#USAGE` block |
| 2 | LOC | `.mise/tasks/test/bar:15` | Use `run_step` aggregator | Replace 3 inline calls |
| 3 | shellcheck | `.mise/tasks/test/baz:12` | SC2086: unquoted expansion | Double-quote `$var` |

### Async Optimization (if Step 7 ran)

| Priority | File:Line | Issue | Recommendation |
|----------|-----------|-------|----------------|
| 🟠 | ... | ... | ... |

### CI Efficiency (if Step 8 ran)

1. **Top saving**: [recommendation] — saves ~X CI-minutes/month
2. ...
3. ...

### Pattern Compliance Summary

| Pattern | Status | Violations |
|---------|--------|------------|
| #1 Newtype | ✅ / ⚠️ / ❌ | ... |
| #2 Builder | ✅ / ⚠️ / ❌ | ... |
| #3 Command | ✅ / ⚠️ / ❌ | ... |
| #4 Trait abstraction | ✅ / ⚠️ / ❌ | ... |
| #5 Key lifecycle SM | ✅ / ⚠️ / ❌ | ... |
| #6 Error macro | ✅ / ⚠️ / ❌ | ... |
| #7 Extension traits | ✅ / ⚠️ / ❌ | ... |
| #8 Macro dispatch | ✅ / ⚠️ / ❌ | ... |

### Next Steps

1. Fix all **BLOCKING** items — `cargo clippy-all` must pass with zero warnings,
   and MISE tasks must pass `shellcheck`.
2. For HIGH duplication: run `/refactor-plan <area>` before implementing consolidations.
3. For HIGH complexity (long functions): run `/rust-simplify <file>` for detailed refactoring.
4. For pattern violations: run `/rust-patterns` for full examples.
5. For error propagation fixes: run `/rust-error-propagation <file>` for detailed rewrite.
6. For MISE convention/LOC issues: run `/mise` for full conventions reference.
7. For async optimization: run `/rust-async-refactor <file>` for detailed analysis.
```

---

## Step 10 — Pre-implementation gate

After presenting the report, ask:

> "**BLOCKING** items must be fixed before merge. Which HIGH or MEDIUM items
> should I address first? For any multi-file change, I will run `/refactor-plan`
> before touching code."

Do **not** implement any changes until the user confirms scope.

---

## Execution rules

1. **Never skip a skill silently.** State the evidence-based scope reason in the report; do not use
   a negative mechanical scan as proof that a semantic audit is unnecessary.
2. **Dedup always.** Before adding a finding to the report, check if the same
   file:line already appears. If yes, merge under the more severe category and
   add a cross-reference.
3. **Estimate LOC impact** for duplication findings. Count the duplicated lines
   across all occurrences, not just one instance.
4. **Respect cardinal rules.** `unwrap_used` and `expect_used` in production
   code are always BLOCKING — never downgrade to HIGH or ADVISORY.
   Missing `set -euo pipefail` in MISE tasks is always BLOCKING.
5. **Cross-crate safety.** Before flagging any `pub` item as dead code, run
   `rg "item_name" --type rust` across the full workspace.
6. **Shellcheck is authoritative.** Never disable a shellcheck warning without
   an inline `# shellcheck disable=SCxxxx` comment explaining why.
