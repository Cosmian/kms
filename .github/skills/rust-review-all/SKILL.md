---
name: rust-review-all
description: 'Hardcore Rust code review gate: orchestrates ALL Rust review skills in sequence (panic audit, error propagation, async refactor, simplify, refactor, patterns, security, cryptography). Each skill writes its report to ./review/. Produces a unified go/no-go verdict. Use before submitting any significant Rust PR or after large code generation.'
---

# Rust Review All — Full Rust Quality Gate

Runs every Rust-focused review skill in the correct order and collects all findings
into `./review/`. Produces a unified `./review/SUMMARY.md` with a go/no-go verdict.

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

## Phase 1 — Panic & Brutal-Exit Audit

**Invoke**: `/rust-panic-audit [path]`

- Detects all `panic!`, `.unwrap()`, `.expect()`, `todo!`, `unimplemented!`, `unreachable!`, `process::exit/abort`, unchecked indexing.
- Report: `./review/rust-panic-audit.md`
- **BLOCKER** if any CRITICAL or HIGH findings remain unpatched.

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

## Phase 4 — Async Correctness

**Invoke**: `/rust-async-refactor [path]`

- Detects sequential `.await` chains that could be parallelized with `tokio::join!`, blocking calls on async paths, unnecessary `Arc/Box::pin`.
- Report: `./review/rust-async-refactor.md`
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

## Phase 8 — Cryptographic Review (if `crate/crypto/` in scope)

**Invoke**: `/cryptography-review [path]`  ← only if the path includes `crate/crypto/` or algorithm selection code.

- Checks: FIPS 140-3, BSI TR-02102, ANSSI, NIST SP 800-series algorithm allow-list, key sizes, OpenSSL provider init, key lifecycle.
- Report: `./review/cryptography-review.md`
- **BLOCKER** if any non-FIPS-approved algorithm used in default build.

---

## Phase 9 — Standards Compliance (if KMIP/protocol code in scope)

**Invoke**: `/standards-review [path]`  ← only if the path includes `crate/kmip/` or `crate/server/src/core/operations/`.

- Verifies code against KMIP 2.1 spec, FIPS, NIST SP, RFC citations.
- Report: `./review/standards-review.md`
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

### 10b — Scan for all new lint suppressions (`#[allow]` / `#[expect]`)

Covers every lint — not just Clippy. Uses a single diff-based pass:

```bash
# Detect all newly added #[allow(...)] and #[expect(...)] on any lint
git diff origin/develop...HEAD -- '*.rs' \
  | grep '^+' \
  | grep -v '^+++' \
  | grep -E '#\[(allow|expect)\(' \
  | grep -v '//.*tracked\|//.*issue\|//.*#[0-9]\|//.*false.positive' \
  | tee -a ./review/clippy.txt
```

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
| 1 | rust-panic-audit | ✅/❌ | N | N |
| 2 | rust-error-propagation | ✅/❌ | N | N |
| 3 | rust-simplify | ✅/⚠️ | 0 | N |
| 4 | rust-async-refactor | ✅/⚠️ | N | N |
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
| `./review/rust-panic-audit.md` | `/rust-panic-audit` |
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
