---
name: rust-review-all
description: 'Hardcore Rust code review gate per .github/skills/shared/orchestrator-contract.md: runs 9 review phases. Each phase writes to ./review-YYYY-MM-DD/. Use before significant Rust PRs or large code generation.'
---

# Rust Review All — Full Rust Quality Gate

Runs KMS Caveman (Phase 1) through Clippy/format/suppression classification (Phase 9) in order. Collects all findings into `./review-YYYY-MM-DD/`. Produces a unified `./review-YYYY-MM-DD/SUMMARY.md` with a go/no-go verdict.

**Orchestration**: See `.github/skills/shared/orchestrator-contract.md` for canonical phase order, skip gates, finding ownership (§3), and the report schema and status rules (§4: `PASS | FAIL | SKIPPED | INCOMPLETE`, evidence, verification performed). Delegate only genuinely independent phases via the harness's supported mechanism; otherwise run them inline (contract §6).

**Baseline**: [`rust-best-practices`](../rust-best-practices/SKILL.md) and [`rust.instructions.md`](../../instructions/rust.instructions.md).

**Usage**: `/rust-review-all` (full diff) or `/rust-review-all crate/server/src/core/`

> This is the **hardcore review gate**. Run it before any significant PR that touches Rust.
> For a quick single-concern audit, invoke the individual skills directly.

---

## Orchestrator Contract Reference

This skill implements the 9-phase **Full Audit Order** defined in `.github/skills/shared/orchestrator-contract.md`. Report format and status semantics are in contract §4. A required phase that could not run is `INCOMPLETE`, never `PASS`.

---

## Prerequisite — Create output directory

```bash
mkdir -p ./review-$(date +%F)
SUMMARY="./review-$(date +%F)/SUMMARY.md"
echo "# Rust Review All — Unified Report" > "${SUMMARY}"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${SUMMARY}"
echo "" >> "${SUMMARY}"
```

---

## Phase 1 — KMS Caveman

**Invoke**: `/kms-caveman [path]`

- Scans the scoped Rust changes once for confirmed panic hazards, unchecked arithmetic/indexing, new lint suppressions, observed compiler diagnostics, and structural candidates.
- Report: `./review-YYYY-MM-DD/kms-caveman.md`
- **BLOCKER** for confirmed CRITICAL or HIGH findings. Reuse these findings in later phases; do not scan again in this orchestrator. `/kms-caveman [path]` is also the standalone panic audit.

---

## Phase 2 — Error Propagation Audit

**Invoke**: `/rust-error-propagation [path]`

- Finds missed `?` opportunities, `.map_err(|e| e.to_string())` anti-patterns, lost error context, silently discarded errors.
- Report: `./review-YYYY-MM-DD/rust-error-propagation.md`
- **BLOCKER** if error context is silently dropped in any crypto, DB, or auth path.

---

## Phase 3 — Duplication & Structural Review

**Invoke**: `/rust-refactor [path]`

- One review covering duplicated bodies and repeated access-control sequences, and structural complexity: nesting, long functions, dead code, bool traps, redundant iterator chains.
- Report: `./review-YYYY-MM-DD/rust-refactor.md`
- **WARNING** level (non-blocking but must be addressed before merge if count > 5).

---

## Phase 4 — Async Correctness (conditional)

**Invoke**: `/rust-async-refactor [path]` when changed code or affected callers are on async paths or may block an async runtime.

- If the inspected focused diff has no async/blocking relevance, mark the phase **SKIPPED** with that evidence; do not infer this from a search miss alone.
- Report: `./review-YYYY-MM-DD/rust-async-refactor.md` when run.
- **WARNING** for parallelism; **BLOCKER** for blocking calls inside an async task.

---

## Phase 5 — Best Practices (semantic idiom and API review)

**Invoke**: `/rust-best-practices`, using [`references/kms-patterns.md`](../rust-best-practices/references/kms-patterns.md) as a non-normative reference, then evaluate the scoped code.

- Reads the changed code against the baseline: ownership and borrowing, API and type design, error and panic policy, async, unsafe, docs, tests. KMS instruction files win on any conflict.
- Report: `./review-YYYY-MM-DD/rust-best-practices.md`
- **WARNING** level.

---

## Phase 6 — Security Review (Rust scope)

**Invoke**: `/security-review [path]`

- Covers: OWASP Top 10, CWE Top 25, KMIP authorization, FIPS gating, memory safety (FFI, `unsafe`), side-channel resistance, supply chain.
- Report: `./review-YYYY-MM-DD/security-review.md`
- **BLOCKER** if any HIGH or CRITICAL security findings.

---

## Phase 7 — Cryptographic Review (conditional)

**Invoke**: `/cryptography-review [path]` when crypto primitives, algorithm selection, key lifecycle or policy, provider initialization, or FIPS feature gates are affected.

- Skip only for a confirmed focused diff that affects none of those areas; file-path checks alone are insufficient. Full/release gates must follow their own no-skip rules.
- Report: `./review-YYYY-MM-DD/cryptography-review.md` when run.
- **BLOCKER** if any non-FIPS-approved algorithm is used in the default build.

---

## Phase 8 — Standards Compliance (conditional)

**Invoke**: `/standards-review [path]` when a governing protocol or standards requirement may be affected.

- For a focused diff, skip only after confirming no protocol/standards semantics changed; full/release gates follow their own applicability rules.
- Report: `./review-YYYY-MM-DD/standards-review.md` when run.
- **BLOCKER** if any spec-violating protocol behaviour.

---

## Phase 9 — Clippy, Format & Suppression Classification (mechanical)

### 9a — Run Clippy and fmt

```bash
cargo clippy-all 2>&1 | tee ./review-$(date +%F)/clippy.txt
cargo fmt --all -- --check 2>&1 | tee ./review-$(date +%F)/fmt.txt
```

- **BLOCKER** if Clippy emits any warnings.
- **BLOCKER** if `cargo fmt --check` exits non-zero.
- If a command cannot run (toolchain, platform, build failure for environmental reasons), the phase is **INCOMPLETE**, not PASS.

### 9b — Classify KMS Caveman lint-suppression findings

Reuse the changed-diff `#[allow(...)]` and `#[expect(...)]` findings from Phase 1; do not repeat the scan. Classify each observed finding against [`rust.instructions.md` § Clippy and lint suppression](../../instructions/rust.instructions.md) and append evidence to `./review-YYYY-MM-DD/clippy.txt`.

| Pattern | Verdict |
|---------|---------|
| `#[allow(warnings)]`, source `#![deny(warnings)]` / `#![allow(warnings)]` | **BLOCKER** — unconditionally forbidden |
| `#[allow(dead_code)]` / `#[expect(dead_code)]`, `unused_*` | **BLOCKER** — remove the dead/unused item |
| `#[allow(deprecated)]` / `#[expect(deprecated)]` in production | **BLOCKER** — migrate off the deprecated API |
| `#[allow(clippy::*)]` or `#[expect(clippy::*)]` in non-test source | **BLOCKER** — fix the lint (generated `*_proto` crates are configured in their `Cargo.toml`) |
| `#[allow(...)]` in test code | **BLOCKER** — tests use `#[expect(<lint>, reason = "…")]` |
| `#[expect(clippy::*)]` in test code without `reason` or for a lint that does not fire | **BLOCKER** — add the reason or delete it |
| Non-clippy rustc `#[allow]` (`unsafe_code`, `non_camel_case_types`, …) | **BLOCKER** — use `#[expect(lint, reason = "…")]`; sole documented exception: `kmip_enum` expansion in `crate/kmip-derive` |

A BLOCKER that cannot be fixed immediately is reported to the reviewer with the exact warning and the blocked recipe; it is never suppressed.

---

## Final — Unified Summary

Append to `./review-YYYY-MM-DD/SUMMARY.md` (header fields, per-phase evidence and the **Verification performed** section follow contract §4):

```markdown
## Results

| Phase | Skill | Status | Blockers | Warnings |
|-------|-------|--------|----------|----------|
| 1 | kms-caveman | PASS/FAIL/INCOMPLETE | N | N |
| 2 | rust-error-propagation | PASS/FAIL/INCOMPLETE | N | N |
| 3 | rust-refactor | PASS/FAIL/INCOMPLETE | 0 | N |
| 4 | rust-async-refactor | PASS/FAIL/SKIPPED/INCOMPLETE | N | N |
| 5 | rust-best-practices | PASS/FAIL/INCOMPLETE | 0 | N |
| 6 | security-review | PASS/FAIL/INCOMPLETE | N | N |
| 7 | cryptography-review | PASS/FAIL/SKIPPED/INCOMPLETE | N | N |
| 8 | standards-review | PASS/FAIL/SKIPPED/INCOMPLETE | N | N |
| 9 | clippy + fmt + suppressions | PASS/FAIL/INCOMPLETE | N | 0 |

## Verdict

**GO** — All blockers resolved and no required phase is INCOMPLETE. PR may proceed.

or

**NO-GO** — N blocker(s) or incomplete required phase(s) must be resolved before merge:
- [ ] <blocker description with file:line>
```

Print the verdict to chat with the count of total blockers and a link to `./review-YYYY-MM-DD/SUMMARY.md`.

---

## Report files produced

| File | Source skill |
|------|-------------|
| `./review-YYYY-MM-DD/kms-caveman.md` | `/kms-caveman` |
| `./review-YYYY-MM-DD/rust-error-propagation.md` | `/rust-error-propagation` |
| `./review-YYYY-MM-DD/rust-refactor.md` | `/rust-refactor` |
| `./review-YYYY-MM-DD/rust-async-refactor.md` | `/rust-async-refactor` |
| `./review-YYYY-MM-DD/rust-best-practices.md` | `/rust-best-practices` |
| `./review-YYYY-MM-DD/security-review.md` | `/security-review` |
| `./review-YYYY-MM-DD/cryptography-review.md` | `/cryptography-review` (if in scope) |
| `./review-YYYY-MM-DD/standards-review.md` | `/standards-review` (if in scope) |
| `./review-YYYY-MM-DD/clippy.txt` | `cargo clippy-all` |
| `./review-YYYY-MM-DD/fmt.txt` | `cargo fmt --check` |
| `./review-YYYY-MM-DD/SUMMARY.md` | This skill |
