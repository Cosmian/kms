---
name: meta-security
description: 'Full security-audit orchestrator that runs /security-review, /cryptography-review, /threat-model, and /standards-review. Use before release or after significant changes; use incremental skip gates only when explicitly requested for a follow-up.'
---

# Meta-Security — Comprehensive Security Audit

Orchestrates all four security-focused skills in the correct order and produces a
single unified go/no-go report. This is the most thorough security review available.

> **When to use**: before a release (in addition to `/pre-release`), after a major
> feature addition, when onboarding a new cloud provider integration, or when a
> comprehensive security posture assessment is requested.

## Step 0 — Load Anti-Hallucination Discipline

Read `.github/skills/shared/anti-hallucination.md` **before any analysis**. All rules in
that file are mandatory for every sub-skill invoked below. Do not proceed until you have read it.

## Step 1 — Determine Scope

Collect the union of branch changes, staged and unstaged changes, and untracked files. For example:

```bash
git diff --name-only origin/develop...HEAD
git diff --name-only HEAD
git diff --name-only --cached
git ls-files --others --exclude-standard
```

If `origin/develop` is unavailable, state that and use a known base or the supplied path; never treat an empty or failed diff as a clean scope.

If a path was provided (e.g. `/meta-security crate/server/`), restrict all sub-skills to that path.
Otherwise, use the full workspace.

### Full and incremental gates

- Full/comprehensive or release-oriented requests run all four sub-skills. A supplied path narrows their scope; it does not itself authorize skipping a review.
- Apply relevance skips only when the user explicitly requests an incremental follow-up. If scope or applicability is uncertain, run the review.
- In incremental mode, run `/security-review` for changed attack surfaces, user-controlled flows, auth/session, FFI, or security-sensitive code.
  Skip only verified documentation/format-only changes or static UI with no dynamic data, auth/session, API, or sensitive-data behavior.
  A clean mechanical scan is not a security skip condition.
- Run `/cryptography-review` when crypto primitives/call sites, algorithm selection, key lifecycle/policy, provider setup, or FIPS gates changed.
  In incremental mode only, skip when the diff and affected callers are confirmed unrelated to all of them.
- Run `/threat-model` when a trust boundary or security-relevant data flow changed (auth, routes, middleware, config/TLS, DB/HSM, crypto, external integrations).
  In incremental mode only, skip after confirming none changed.
- Run `/standards-review` when protocol or standards-constrained behavior changed. In incremental mode only, skip after confirming no such behavior changed.
- Full or release gates never skip a sub-skill based on mechanical scan results. Record every incremental skip and its evidence.

Record which areas changed:

- [ ] `crate/crypto/` — crypto primitives
- [ ] `crate/server/src/core/operations/` — KMIP operations
- [ ] `crate/server/src/routes/` — HTTP routes
- [ ] `crate/server/src/middlewares/` — auth/middleware
- [ ] `crate/server/src/config/` — server config
- [ ] `crate/server_database/` — database backends
- [ ] `crate/hsm/` — HSM integrations
- [ ] `crate/kmip/` — KMIP types
- [ ] `crate/clients/` — CLI / WASM / client
- [ ] `ui/` — Web UI
- [ ] `.github/` — CI / scripts

## Step 2 — Security Review

In full/comprehensive mode, always invoke `/security-review` on the scoped path. In an explicitly incremental review, apply the gate above and record any skip.

This covers:

- OWASP Top 10 / CWE Top 25 vulnerability families
- Memory & type safety (FFI, `unsafe` blocks)
- Deserialization & protocol parsing (TTLV, JSON, HTTP smuggling)
- Race conditions / TOCTOU
- Denial of service (ReDoS, resource exhaustion)
- Side-channel attacks (timing, Marvin, Lucky13)
- OAuth/OIDC & token-based auth attacks
- HTTP-level & web security (CSRF, clickjacking, CORS)
- Supply chain & dependency integrity
- Security logging & monitoring
- Business logic & KMIP-specific attacks
- Injection flaws, secrets exposure, data handling
- FIPS feature flag consistency
- KMIP protocol authorization

Collect all findings. Record the severity summary.

## Step 3 — Cryptographic Review

In full/comprehensive mode, invoke `/cryptography-review` on the scoped path. In incremental mode, invoke it for crypto primitives/call sites,
algorithm selection, key lifecycle/policy, provider initialization, or FIPS gates. Skip only after confirming none apply.

This covers:

- Algorithm inventory and FIPS/BSI/ANSSI compliance
- Feature flag gating audit
- Key size enforcement (multi-standard minimums)
- OpenSSL provider initialization
- Entropy / RNG audit
- CBOM / SBOM currency
- Key management lifecycle (SP 800-57)
- Multi-standard compliance matrix
- Academic research flags (known cryptanalytic attacks)

Collect all findings. If skipped in incremental mode, record the checked areas and reason.

## Step 4 — Threat Model

In full/comprehensive mode, invoke `/threat-model`. If a prior threat model exists, use incremental mode; otherwise use single analysis mode.
For an explicitly incremental review, skip only after confirming no trust boundary or security-relevant data flow changed.
Relevant boundaries include authentication, routes, middleware, config/TLS, DB/HSM, crypto, and external integrations.

Collect all findings or record the evidence for an incremental skip.

## Step 5 — Standards Compliance Review

In full/comprehensive mode, invoke `/standards-review` on the scoped path. In an explicitly incremental review, run it when protocol or standards-constrained behavior changed; otherwise record why it is not applicable.

This covers:

- KMIP 2.1 spec conformance (local HTML verification)
- RFC conformance (URL-verified section citations)
- FIPS / NIST SP conformance
- BSI / ANSSI guideline conformance
- Per-algorithm compliance checklist cross-reference

Collect all findings. Record applicability and conformance gaps.

## Step 6 — Unified Report

Produce this exact report structure:

```markdown
## Meta-Security Audit Report — [scope] — [date]

### Consolidated Status

| Skill | Status | Critical | High | Medium | Low |
|-------|--------|----------|------|--------|-----|
| Security Review | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | N | N | N | N |
| Cryptographic Review | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | N | N | N | N |
| Threat Model | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | N | N | N | N |
| Standards Review | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | N | N | N | N |

### Blocking Findings (CRITICAL + HIGH)

| # | Source Skill | Category | File:Line | Title | Severity |
|---|-------------|----------|-----------|-------|----------|
| 1 | security-review | Side-Channel | `crate/crypto/src/rsa.rs:42` | Non-constant-time MAC comparison | 🔴 CRITICAL |
| 2 | ... | ... | ... | ... | ... |

### Multi-Standard Compliance Matrix
[From cryptography-review Step 9 — only rows with divergences]

### Standards Conformance Gaps
[From standards-review — only violations and deviations]

### New/Changed Threats
[From threat-model — only new or severity-changed threats since baseline]

### Full Findings by Skill
[Complete findings from each skill, grouped]

### Unverified Items
[All items marked REQUIRES MANUAL VERIFICATION across all skills]

### Verdict

**PASS** — no CRITICAL or HIGH findings across all required reviews; full-mode reviews all ran, or incremental skips were confirmed and reported.

— or —

**BLOCK** — N blocking findings must be resolved before proceeding.
[List each blocking finding with its source skill and recommended fix]
```

### Blocking criteria

- Any 🔴 CRITICAL finding from any skill → **BLOCK**
- Any 🟠 HIGH finding from security-review or cryptography-review → **BLOCK**
- Any 🔴 Violation from standards-review → **BLOCK**
- Unmitigated CRITICAL/HIGH threats from threat-model → **BLOCK**
- ⏭ SKIPPED is acceptable only in an explicitly requested incremental review with confirmed inapplicability; never skip in full/comprehensive or release mode.

## Output Rules

- **Never** auto-apply fixes — present the unified report for human review
- **Always** attribute each finding to its source skill
- **Always** deduplicate findings that appear in multiple skills (keep the most detailed version, note the overlap)
- **Group** blocking findings at the top for immediate visibility
- If all skills pass cleanly, say so clearly with a summary of what was scanned

An incremental PASS is not a release go/no-go; use the full `/pre-release` gate before release.
