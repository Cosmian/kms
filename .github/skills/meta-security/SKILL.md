---
name: meta-security
description: 'Comprehensive security audit orchestrator: invokes /security-review, /cryptography-review, /threat-model, and /standards-review in sequence. Produces a unified go/no-go report. Use for full security audit before release or after significant changes.'
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

```bash
git diff --name-only origin/develop...HEAD 2>/dev/null || git diff --name-only HEAD~5
```

If a path was provided (e.g. `/meta-security crate/server/`), restrict all sub-skills to that path.
Otherwise, use the full workspace.

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

Invoke `/security-review` on the scoped path.

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

Invoke `/cryptography-review` on the scoped path.

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

Collect all findings. Record the compliance matrix.

## Step 4 — Threat Model

Invoke `/threat-model`:

- If a prior threat model exists (`threat-model-*/` directory): use **incremental mode**
- If no prior threat model exists: use **single analysis mode**

Focus on areas identified in Step 1 that affect trust boundaries:

- New or modified authentication methods
- New or modified endpoints (especially unauthenticated ones)
- New outbound calls (cloud provider integrations)
- New HSM / database backend integrations
- Changes to TLS configuration

Collect all findings. Record new/changed threats.

## Step 5 — Standards Compliance Review

Invoke `/standards-review` on the scoped path.

This covers:

- KMIP 2.1 spec conformance (local HTML verification)
- RFC conformance (URL-verified section citations)
- FIPS / NIST SP conformance
- BSI / ANSSI guideline conformance
- Per-algorithm compliance checklist cross-reference

Collect all findings. Record the applicability matrix and conformance gaps.

## Step 6 — Unified Report

Produce this exact report structure:

```markdown
## Meta-Security Audit Report — [scope] — [date]

### Consolidated Status

| Skill | Status | Critical | High | Medium | Low |
|-------|--------|----------|------|--------|-----|
| Security Review | ✅ PASS / ❌ BLOCK | N | N | N | N |
| Cryptographic Review | ✅ PASS / ❌ BLOCK | N | N | N | N |
| Threat Model | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | N | N | N | N |
| Standards Review | ✅ PASS / ❌ BLOCK | N | N | N | N |

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

**PASS** — no CRITICAL or HIGH findings across all four skills.
Proceed with release / merge.

— or —

**BLOCK** — N blocking findings must be resolved before proceeding.
[List each blocking finding with its source skill and recommended fix]
```

### Blocking criteria

- Any 🔴 CRITICAL finding from any skill → **BLOCK**
- Any 🟠 HIGH finding from security-review or cryptography-review → **BLOCK**
- Any 🔴 Violation from standards-review → **BLOCK**
- Unmitigated CRITICAL/HIGH threats from threat-model → **BLOCK**
- ⏭ SKIPPED skills are acceptable when skip condition is confirmed

## Output Rules

- **Never** auto-apply fixes — present the unified report for human review
- **Always** attribute each finding to its source skill
- **Always** deduplicate findings that appear in multiple skills (keep the most detailed version, note the overlap)
- **Group** blocking findings at the top for immediate visibility
- If all skills pass cleanly, say so clearly with a summary of what was scanned
