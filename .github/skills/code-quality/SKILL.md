---
name: code-quality
description: 'Scoped code-quality audit orchestrator: runs 8 phases per .github/skills/shared/orchestrator-contract.md (KMS Caveman first, then MISE, Clippy, error-prop, refactor, best practices, async, CI efficiency). One ranked report with one owner per finding. Use before PRs or when improving code quality.'
---

# Code Quality Audit

Orchestrates the Rust-focused audit skills, MISE Bash checks, Clippy, and CI efficiency in one ranked report. The read-only KMS Caveman pass runs first; each finding has one owner.

**Usage**: `/code-quality` (full workspace) or `/code-quality crate/server/src/`
> **Canonical Reference**: This orchestrator's phase ordering, skip gates, finding ownership and report schema follow `.github/skills/shared/orchestrator-contract.md` (§1 Code Quality Order, §3, §4). Delegate only genuinely independent phases via the harness's supported mechanism; otherwise run inline (contract §6). Baseline: [`rust-best-practices`](../rust-best-practices/SKILL.md).

## Orchestration rationale

1. **Orders for efficiency** — cheap, high-signal scans first; expensive analysis later; skips irrelevant skills.
2. **One owner per finding** — when two phases flag the same issue it appears once, at the maximum confirmed severity, with cross-references.
3. **Conditions execution** — KMS Caveman runs once first. `mise` runs only when `.mise/` changed. Async review runs only when changed code or call paths are relevant; CI review runs only for full-workspace audits.

Phase 1 is the single owner of mechanical findings; later phases add evidence and cross-references rather than re-reporting (contract §3).

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
|`/rust-refactor`|Full audit, or focused code with repeated behavior or structural change|Inspected code unrelated to duplication and complexity; regex misses are insufficient|
|`/rust-best-practices`|Rust files in scope|Never for Rust scope; not applicable when no Rust is in scope|
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

**Suppressions**: reuse the Phase 1 `#[allow]` / `#[expect]` evidence and classify it against `rust.instructions.md` § Clippy and lint suppression (zero clippy suppressions outside tests; tests use `expect` with `reason`); do not re-scan. Clippy findings seed finding ownership for the later phases (contract §3).

---

## Step 4 — Error propagation (conditional)

**Invoke**: `/rust-error-propagation [path]`. **Eligibility**: full-workspace audit, or a focused diff whose changed code or affected callers modify fallible operations, `Result` propagation, error conversion, or error context. Skip only after inspecting the changes and confirming none of those paths are affected; record the reason. Do not infer irrelevance from the absence of the word `Result` in a search of the whole containing file.

**Input scope**: the Step 1 scope. **Report**: `./review-YYYY-MM-DD/rust-error-propagation.md` when persisted. If Clippy already flagged the same line, add a cross-reference (contract §3).

---

## Step 5 — Structural and duplication review

**Invoke**: `/rust-refactor [path]` once; it covers duplication and structural complexity in one review. **Eligibility**: full-workspace audit, or focused code with repeated behavior or structural change. `/kms-caveman` can identify literal duplicate candidates but cannot rule out semantically duplicated behavior; do not skip based on a negative regex result.

**Input scope**: the Step 1 scope. **Report**: `./review-YYYY-MM-DD/rust-refactor.md` when persisted.

---

## Step 6 — Best practices and KMS patterns

**Invoke**: `/rust-best-practices`, with [`references/kms-patterns.md`](../rust-best-practices/references/kms-patterns.md) as a non-normative reference. **Eligibility**: always when Rust is in scope. Evaluate the scoped code semantically against the baseline; KMS instruction files win on any conflict.

**Input scope**: the Step 1 scope. **Report**: `./review-YYYY-MM-DD/rust-best-practices.md` when persisted.

---

## Step 7 — Async optimization (conditional)

**Invoke**: `/rust-async-refactor [path]`. **Eligibility**: Step 1 found changed code or affected callers on async paths or that may block the runtime; otherwise record the inspected skip reason.

**Input scope**: the Step 1 scope. **Report**: `./review-YYYY-MM-DD/rust-async-refactor.md` when persisted.

---

## Step 8 — CI efficiency (full workspace only)

**Skip** if a sub-path was provided (CI audit always covers the full repo).

**Invoke**: `/ci-efficiency`. Check:

- Missing caches (Nix store, Cargo registry, pnpm store)
- Over-broad workflow triggers (`on: push` without path filters)
- No concurrency cancellation on PR workflows
- Redundant matrix jobs between `main.yml` and `test_all.yml`

**Output**: top 3 efficiency improvements ranked by CI-minutes saved.

---

## Step 9 — Consolidated report

Produce a single detailed report. **All findings from all skills merged under one owner per finding (contract §3):**

```markdown
## Code Quality Report — <scope> — <date>

> Skills run: KMS Caveman, Clippy, rust-error-propagation, rust-refactor,
> rust-best-practices[, mise][, rust-async-refactor][, ci-efficiency]
> Scope: <path or "full workspace">
> KMS Caveman: [PASS / BLOCK / NOT APPLICABLE / INCOMPLETE]; verified findings are not repeated below
> Async / MISE / CI eligibility: [run or skipped, with reason]
> Per-phase status: PASS | FAIL | SKIPPED | INCOMPLETE with evidence (contract §4)

### BLOCKING — Must fix before merge

| # | Category | File:Line | Issue | Fix | Cross-ref |
|---|----------|-----------|-------|-----|-----------|
| 1 | Unwrap   | `crate/foo/src/bar.rs:42` | `.unwrap()` in production | Replace with `?` | Clippy |

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

### Verification performed

Commands actually run with outcome, behavior exercised, and unverified surfaces (contract §4).

### Next Steps

1. Fix all **BLOCKING** items — `cargo clippy-all` must pass with zero warnings,
   and MISE tasks must pass `shellcheck`.
2. For HIGH duplication or complexity: run `/refactor-plan <area>` before multi-file consolidations; `/rust-refactor <file>` for the detailed review.
3. For idiom/API findings: run `/rust-best-practices`.
4. For error propagation fixes: run `/rust-error-propagation <file>` for detailed rewrite.
5. For MISE convention/LOC issues: run `/mise` for full conventions reference.
6. For async optimization: run `/rust-async-refactor <file>` for detailed analysis.
```

---

## Step 10 — Pre-implementation gate

After presenting the report, ask:

> "**BLOCKING** items must be fixed before merge. Which HIGH or MEDIUM items
> should I address first? For any multi-file change, I will run `/refactor-plan`
> before touching code."

Do **not** implement any changes until the user confirms scope. An already-approved implementation does not stop for this prompt; it proceeds with the approved scope and records the findings.

---

## Execution rules

1. **Never skip a skill silently.** State the evidence-based scope reason in the report; do not use
   a negative mechanical scan as proof that a semantic audit is unnecessary.
2. **One owner per finding.** Follow contract §3: the first executed phase owns a finding, severity is
   the maximum confirmed severity, later detections add cross-references. Findings are advisory;
   preserve behavior, errors, authorization and serialization when acting on them.
3. **Estimate LOC impact** for duplication findings. Count the duplicated lines
   across all occurrences, not just one instance.
4. **Respect cardinal rules.** `unwrap_used` and `expect_used` in production
   code are always BLOCKING — never downgrade to HIGH or ADVISORY.
   Missing `set -euo pipefail` in MISE tasks is always BLOCKING.
5. **Cross-crate safety.** Before flagging any `pub` item as dead code, run
   `rg "item_name" --type rust` across the full workspace.
6. **Shellcheck is authoritative.** Never disable a shellcheck warning without
   an inline `# shellcheck disable=SCxxxx` comment explaining why.
7. **Report schema.** Status per phase, evidence and the verification-performed section follow
   [`orchestrator-contract.md` §4](../shared/orchestrator-contract.md). A phase that could not run is
   `INCOMPLETE`, never `PASS`.
