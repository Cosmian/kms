---
name: rust-review-all
description: 'Hardcore Rust code review gate: runs one KMS Caveman pass first, then error propagation, simplify, async, refactor, patterns, security, cryptography, and standards reviews as applicable, plus Clippy. Each phase writes to ./review/. Use before significant Rust PRs or large code generation.'
---

# Rust Review All — Full Rust Quality Gate

Runs KMS Caveman once, then the applicable Rust review phases in order, and collects all findings into `./review/`. Produces a unified `./review/SUMMARY.md` with a go/no-go verdict.

**Usage**: `/rust-review-all` (full diff) or `/rust-review-all crate/server/src/core/`

> This is the **hardcore review gate**. Run it before any significant PR that touches Rust.
> For a quick single-concern audit, invoke the individual skills directly.

---

## Prerequisite — Create output directory

```bash
mkdir -p ./review
SUMMARY="./review/SUMMARY.md"
echo "# Rust Review All — Unified Report" > "${SUMMARY}"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${SUMMARY}"
echo "" >> "${SUMMARY}"
```

---

## Phase 1 — KMS Caveman

**Invoke**: `/kms-caveman [path]`

- Scans the scoped Rust changes once for confirmed panic hazards, new lint suppressions, observed compiler diagnostics, and structural candidates.
- Report: `./review/kms-caveman.md`
- **BLOCKER** for confirmed CRITICAL or HIGH findings. Reuse these findings in later phases; do not invoke `/rust-panic-audit` again in this orchestrator. The standalone skill remains available for a dedicated panic audit.

---

## Phase 2 — Error Propagation Audit

**Invoke**: `/rust-error-propagation [path]`

- Finds missed `?` opportunities, `.map_err(|e| e.to_string())` anti-patterns, lost error context, silently discarded errors.
- Report: `./review/rust-error-propagation.md`
- **BLOCKER** if error context is silently dropped in any crypto, DB, or auth path.

---

## Phase 3 — Code Simplification

**Invoke**: `/rust-simplify [path]`

- Detects nested control flow (depth > 3), functions over 60 lines, dead code, boolean param traps, redundant iterator chains.
- Report: `./review/rust-simplify.md`
- **WARNING** level (non-blocking but must be addressed before merge if count > 5).

---

## Phase 4 — Async Correctness (conditional)

**Invoke**: `/rust-async-refactor [path]` when changed code or affected callers are on async paths or may block an async runtime.

- If the inspected focused diff has no async/blocking relevance, mark the phase **SKIPPED** with that evidence; do not infer this from a search miss alone.
- Report: `./review/rust-async-refactor.md` when run.
- **WARNING** for parallelism; **BLOCKER** for blocking calls inside an async task.

---

## Phase 5 — Duplication & Refactor

**Invoke**: `/rust-refactor [path]`

- Identifies near-identical function bodies, repeated access-control sequences, struct fields that belong in shared traits.
- Report: `./review/rust-refactor.md`
- **WARNING** level.

---

## Phase 6 — Design Patterns

**Invoke**: `/rust-patterns` as a reference, then evaluate the scoped code against it.

- Checks: newtype wrappers, builder config, command pattern for KMIP ops, trait-based HSM/DB abstraction.
- Findings appended to `./review/rust-patterns.md`
- **WARNING** level.

---

## Phase 7 — Security Review (Rust scope)

**Invoke**: `/security-review [path]`

- Covers: OWASP Top 10, CWE Top 25, KMIP authorization, FIPS gating, memory safety (FFI, `unsafe`), side-channel resistance, supply chain.
- Report: `./review/security-review.md`
- **BLOCKER** if any HIGH or CRITICAL security findings.

---

## Phase 8 — Cryptographic Review (conditional)

**Invoke**: `/cryptography-review [path]` when crypto primitives, algorithm selection, key lifecycle or policy, provider initialization, or FIPS feature gates are affected.

- Skip only for a confirmed focused diff that affects none of those areas; file-path checks alone are insufficient. Full/release gates must follow their own no-skip rules.
- Report: `./review/cryptography-review.md` when run.
- **BLOCKER** if any non-FIPS-approved algorithm is used in the default build.

---

## Phase 9 — Standards Compliance (conditional)

**Invoke**: `/standards-review [path]` when a governing protocol or standards requirement may be affected.

- For a focused diff, skip only after confirming no protocol/standards semantics changed; full/release gates follow their own applicability rules.
- Report: `./review/standards-review.md` when run.
- **BLOCKER** if any spec-violating protocol behaviour.

---

## Phase 10 — Clippy, Format & Forbidden Suppressions (mechanical)

### 10a — Run Clippy and fmt

```bash
cargo clippy-all 2>&1 | tee ./review/clippy.txt
cargo fmt --all -- --check 2>&1 | tee ./review/fmt.txt
```

- **BLOCKER** if Clippy emits any warnings.
- **BLOCKER** if `cargo fmt --check` exits non-zero.

### 10b — Classify KMS Caveman lint-suppression findings

Reuse the changed-diff `#[allow(...)]` and `#[expect(...)]` findings from Phase 1; do not repeat the scan. Classify each observed finding using the severity rules below and append evidence to `./review/clippy.txt`.

Severity classification:

| Pattern | Verdict |
|---------|---------|
| `#[allow(warnings)]` | **BLOCKER** — unconditionally forbidden |
| `#[allow(unused_imports)]`, `#[allow(dead_code)]`, `#[expect(dead_code)]` | **BLOCKER** — remove the dead/unused item |
| `#[allow(unused_*)]`, `#[expect(unused_*)]` | **BLOCKER** — rename to `_` or remove |
| `#[allow(deprecated)]`, `#[expect(deprecated)]` | **BLOCKER** — migrate off the deprecated API |
| `#[allow(clippy::*)]`, `#[expect(clippy::*)]` without justification | **BLOCKER** — fix the lint |
| `#[allow(clippy::*)]` with `// tracked in #N` on pre-existing code | Logged, non-blocking |

Any BLOCKER that cannot be fixed immediately must be reported to the reviewer with a `// tracked in #<N>` reference before merge.

---

## Final — Unified Summary

Append to `./review/SUMMARY.md`:

```markdown
## Results

| Phase | Skill | Status | Blockers | Warnings |
|-------|-------|--------|----------|----------|
| 1 | kms-caveman | ✅/❌/— | N | N |
| 2 | rust-error-propagation | ✅/❌ | N | N |
| 3 | rust-simplify | ✅/⚠️ | 0 | N |
| 4 | rust-async-refactor | ✅/⚠️/— | N | N |
| 5 | rust-refactor | ✅/⚠️ | 0 | N |
| 6 | rust-patterns | ✅/⚠️ | 0 | N |
| 7 | security-review | ✅/❌ | N | N |
| 8 | cryptography-review | ✅/❌/— | N | N |
| 9 | standards-review | ✅/❌/— | N | N |
| 10 | clippy + fmt | ✅/❌ | N | 0 |

## Verdict

**GO** — All blockers resolved. PR may proceed.

or

**NO-GO** — N blocker(s) must be fixed before merge:
- [ ] <blocker description with file:line>
```

Print the verdict to chat with the count of total blockers and a link to `./review/SUMMARY.md`.

---

## Report files produced

| File | Source skill |
|------|-------------|
| `./review/kms-caveman.md` | `/kms-caveman` |
| `./review/rust-error-propagation.md` | `/rust-error-propagation` |
| `./review/rust-simplify.md` | `/rust-simplify` |
| `./review/rust-async-refactor.md` | `/rust-async-refactor` |
| `./review/rust-refactor.md` | `/rust-refactor` |
| `./review/rust-patterns.md` | `/rust-patterns` |
| `./review/security-review.md` | `/security-review` |
| `./review/cryptography-review.md` | `/cryptography-review` (if in scope) |
| `./review/standards-review.md` | `/standards-review` (if in scope) |
| `./review/clippy.txt` | `cargo clippy-all` |
| `./review/fmt.txt` | `cargo fmt --check` |
| `./review/SUMMARY.md` | This skill |
