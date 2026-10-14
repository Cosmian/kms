---
name: meta-security
description: 'Full security-audit orchestrator running /security-review, /cryptography-review, /threat-model, and /standards-review in canonical order per .github/skills/shared/orchestrator-contract.md. Each phase is a task sub-agent (routed by Jev delegation when enabled). Use before release or major changes; incremental skips only when explicitly requested for follow-ups.'
---

# Meta-Security — Comprehensive Security Audit

Orchestrates all four security-focused skills in the correct order and produces a
single unified go/no-go report. This is the most thorough security review available.

> **When to use**: before a release (in addition to `/pre-release`), after a major
> feature addition, when onboarding a new cloud provider integration, or when a
> comprehensive security posture assessment is requested.

---

## Step 0 — Load Anti-Hallucination Discipline

Read `.github/skills/shared/anti-hallucination.md` **before any analysis**. All rules in
that file are mandatory for every sub-skill invoked below. Do not proceed until you have read it.

### Jev Delegation Routing

When phases are task sub-agents (Jev delegation enabled), the orchestrator contract in
`.github/skills/shared/orchestrator-contract.md` sections 1 and 6 control:

- **Phase ordering** (Section 1: security audit phases 1–4)
- **Sub-agent routing** (Section 6: `slow` model for judgment/reasoning phases)
- **Overlap deduplication** (Section 3: report overlaps once under earliest phase)
- **Unified report schema** (Section 4: SUMMARY.md structure)
- **Blocking criteria** (Section 5: go/no-go gates)

This skill's manual steps below align with that contract. For orchestration rules and
report format details, see the shared contract.

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

### Full and Incremental Gates (per Orchestrator Contract Section 2)

- **Full/comprehensive or release-oriented** requests run all four sub-skills. A supplied path narrows their scope; it does not itself authorize skipping a review.
- **Incremental mode** applies relevance skips *only when the user explicitly requests* a follow-up. If scope or applicability is uncertain, run the review.
- Record which areas changed and apply the conservative skip rules from the shared contract (Section 2).

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

---

## Step 2 — Security Review

In full/comprehensive mode, always invoke `/security-review` on the scoped path. In an explicitly incremental review, apply the gate from Step 1 and record any skip.

See `.github/skills/shared/orchestrator-contract.md` Section 2 (Skip Gates) for conservative skip rules.

This phase covers (per `security-review` skill):

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

Collect all findings. Record the severity summary. If skipped in incremental mode, record the evidence and checked areas.

## Step 3 — Cryptographic Review

In full/comprehensive mode, invoke `/cryptography-review` on the scoped path. In incremental mode, invoke it for crypto primitives/call sites,
algorithm selection, key lifecycle/policy, provider initialization, or FIPS gates. Skip only after confirming none apply.

See `.github/skills/shared/orchestrator-contract.md` Section 2 (Skip Gates) for conservative skip rules.

This phase covers (per `cryptography-review` skill):

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

For an explicitly incremental review, skip only after confirming no trust boundary or security-relevant data flow changed (authentication, routes, middleware, config/TLS, DB/HSM, crypto, external integrations).

See `.github/skills/shared/orchestrator-contract.md` Section 2 (Skip Gates) for conservative skip rules.

Collect all findings or record the evidence for an incremental skip.

## Step 5 — Standards Compliance Review

In full/comprehensive mode, invoke `/standards-review` on the scoped path. In an explicitly incremental review, run it when protocol or standards-constrained behavior changed; otherwise record why it is not applicable.

See `.github/skills/shared/orchestrator-contract.md` Section 2 (Skip Gates) for conservative skip rules.

This phase covers (per `standards-review` skill):

- KMIP 2.1 spec conformance (local HTML verification)
- RFC conformance (URL-verified section citations)
- FIPS / NIST SP conformance
- BSI / ANSSI guideline conformance
- Per-algorithm compliance checklist cross-reference

Collect all findings. Record applicability and conformance gaps.

---

## Step 6 — Unified Report

Produce a report using the unified schema from `.github/skills/shared/orchestrator-contract.md` Section 4 (Unified Report Schema).

**Report structure** (adapted for security audit):

```markdown
# Meta-Security — <Scope> Report

**Generated**: <ISO 8601 timestamp>
**Scope**: <full workspace | path | specific changed files>
**Mode**: <full | incremental>

## Summary

- **Total Findings**: N
- **Critical**: N
- **High**: N
- **Medium**: N
- **Low**: N
- **Skipped Phases**: <list with evidence>

## Verdict

**GO** / **NO-GO** (with reason)

## Findings (ordered by phase)

### Phase 1: Security Review [PASS | FAIL | SKIPPED]
...

### Phase 2: Cryptography Review [PASS | FAIL | SKIPPED]
...

### Phase 3: Threat Model [PASS | FAIL | SKIPPED]
...

### Phase 4: Standards Review [PASS | FAIL | SKIPPED]
...
```

## Step 7 — Blocking Criteria (per Orchestrator Contract Section 5)

Determine go/no-go using this order:

### BLOCKER (GO → NO-GO)

- Any 🔴 **CRITICAL** finding from any phase
- Any 🟠 **HIGH** finding from security-review or cryptography-review
- Any 🔴 **Violation** from standards-review
- Unmitigated **CRITICAL/HIGH** threats from threat-model
- ⏭ **SKIPPED** phases are acceptable only in an explicitly requested incremental review with confirmed inapplicability; never skip in full/comprehensive or release mode

### WARNING (recorded but non-blocking)

- **MEDIUM** findings; must be addressed before merge if count > 5
- **LOW** findings

## Step 8 — Output Rules

- **Never** auto-apply fixes — present the unified report for human review
- **Always** attribute each finding to its source phase (per deduplication rules in shared contract Section 3)
- **Always** deduplicate findings that appear in multiple phases (keep the most detailed version, note the overlap)
- **Group** blocking findings at the top for immediate visibility
- If all phases pass cleanly, say so clearly with a summary of what was scanned

> **Note**: An incremental PASS is not a release go/no-go; use the full `/pre-release` gate before release.
