# Copilot Skills — Eviden KMS

Team-wide GitHub Copilot skills for the KMS repository.

## Where skills live

| Surface | Location | How to invoke |
|---------|----------|---------------|
| **VS Code Copilot Chat** | `.github/skills/<name>/SKILL.md` | Type `/skill-name` in Chat |
| **Copilot CLI** (`copilot` terminal) | `.github/skills/<name>/SKILL.md` | `/skill-name` in CLI session or auto-invoked by description match |
| **Copilot Cloud Agent** | `.github/skills/<name>/SKILL.md` | Auto-invoked by description match |

**Single source**: all skill content lives in `.github/skills/`. Skills are an [open standard](https://agentskills.io/) that works across VS Code, Copilot CLI, and cloud agents — no wrapper files needed.

---

## Skill Index

### Security

| Skill | Command | Description |
|-------|---------|-------------|
| **Meta-Security** | `/meta-security [path]` | **Comprehensive security audit orchestrator.** Invokes `/security-review`, `/cryptography-review`, `/threat-model`, and `/standards-review` in sequence. Produces a unified go/no-go report. |
| Security Review | `/security-review [path]` | OWASP Top 10, CWE Top 25, 20 vulnerability families (injection, memory safety, side-channel, supply chain, business logic, etc.), KMIP authorization, FIPS gating. Full data-flow analysis with patches. |
| Cryptographic Review | `/cryptography-review [path]` | Multi-standard cryptographic audit: FIPS 140-3, BSI TR-02102, ANSSI, NIST SP 800-series. Algorithm allow-list, key sizes, feature-flag gating, OpenSSL provider init, key lifecycle (SP 800-57), multi-standard compliance matrix, academic cryptanalysis cross-check. |
| Standards Review | `/standards-review [path]` | Verify code against exact text of applicable standards (FIPS, NIST SP, RFC, KMIP, PKCS, BSI, ANSSI, OWASP). Every citation is URL-verified — no hallucinated section numbers. Includes per-algorithm compliance checklist. |
| Threat Model | `/threat-model` | STRIDE-A full threat model or incremental update. Pre-seeded with KMS trust boundaries (client → KMIP → HSM/DB). |

### KMIP / Protocol

| Skill | Command | Description |
|-------|---------|-------------|
| KMIP Compliance | `/kmip-compliance [operation]` | Validate a KMIP operation against the spec HTML, dispatch table, type definitions, and access control requirements. |

### Release

| Skill | Command | Description |
|-------|---------|-------------|
| **Pre-Release Gate** | `/pre-release` | **Run before every release.** Orchestrates all AI audit skills (security, FIPS, KMIP, threat model, sync rules, changelog, release notes) and produces a go/no-go report. |
| KMS Release Notes | `/kms-release-notes <version>` | Aggregate all `CHANGELOG/*.md` files into a single compact release note grouped by section and component. Writes `CHANGELOG/RELEASE_<version>.md`. |

### Workflow Automation

| Skill | Command | Description |
|-------|---------|-------------|
| **CI Fix Loop** | `/ci-fix` | **Monitor CI, fix all failures, push, repeat until green.** Polls GitHub workflow runs, fetches logs, categorizes failures (fmt / clippy / compile / test / Nix hash / deps), applies fixes, and loops. Aborts after 3 identical failures. |
| **KMS Sync Rules** | `/kms-sync-rules` | **Run after every code change.** Auto-detects changed files via `git diff` and maps them to the applicable sync rule numbers (4.1–4.18), pointing to the normative checklist in `.github/instructions/*.instructions.md` for each (auto-applied via `applyTo` when editing a matching file). Only rule 4.8 (non-FIPS gating) has no instruction file and is checked in full by this skill. |
| KMS Test Vector | `/kms-test-vector` | Walk through the full test vector workflow: directory, `manifest.toml`, TTLV steps, `vector_runner.rs` registration, README count update. |
| KMS Changelog | `/kms-changelog` | Create or update `CHANGELOG/<branch>.md` with correct sections, component grouping, and PR/issue links. |
| OpenAPI Endpoint | `/openapi-endpoint` | Implement a new REST endpoint: handler → `routes/mod.rs` → `start_kms_server.rs` (LIFO middleware) → `openapi.yaml` → validation tests. |
| **ckms Subcommand Tests** | `/ckms-subcommand-test` | **Run after adding any new `ckms` subcommand or flag.** Generates the test file, writes helper functions, covers happy path + error cases + CO-gating, registers the module in `mod.rs`, and runs `cargo test -p ckms`. |

### Code Quality

| Skill | Command | Description |
|-------|---------|-------------|
| **Code Quality** | `/code-quality [path]` | **Orchestrates** `/rust-refactor`, `/rust-patterns`, Clippy hygiene, and `/ci-efficiency`. Produces a ranked report of blocking items and high-impact improvements. |
| **Rust Review All** | `/rust-review-all [path]` | **Hardcore Rust quality gate.** Runs all 10 review phases (panic audit, error propagation, async, simplify, refactor, patterns, security, crypto, standards, Clippy). Each phase writes to `./review/`. Produces `./review/SUMMARY.md` with a go/no-go verdict. |
| **Rust Panic Audit** | `/rust-panic-audit [path]` | Scan for every panic/brutal-exit: `panic!`, `todo!`, `unimplemented!`, `unreachable!`, `.unwrap()`, `.expect()`, `process::exit/abort`, unchecked indexing, integer overflow. Ranked findings with patches. Report: `./review/rust-panic-audit.md`. |
| Refactor Plan | `/refactor-plan` | Investigate a refactor, produce a phased plan with cargo verification steps. Wait for confirmation before implementing. |
| Rust Refactor | `/rust-refactor` | Find duplication in Rust code and consolidate with Traits, Generics, macros. Ranked impact/risk plan before touching code. |
| Rust Simplify | `/rust-simplify [path]` | Find simplification opportunities: nested control flow, long functions, dead code, bool param traps, iterator anti-patterns, and Clippy-flagged complexity. Ranked list before touching code. |
| Rust Patterns | `/rust-patterns` | KMS-specific Rust design patterns: newtype, builder, command, trait abstraction, key lifecycle state machine. |
| Rust Error Propagation | `/rust-error-propagation [path]` | Analyze `Result` propagation chains: find missed `?` opportunities, `.map_err(|e| e.to_string())` anti-patterns, lost error context. Report: `./review/rust-error-propagation.md`. |
| Rust Async Refactor | `/rust-async-refactor [path]` | Detect sequential `.await` chains parallelizable with `tokio::join!`, blocking calls on async paths, unnecessary `Arc/Box::pin`. Report: `./review/rust-async-refactor.md`. |
| CI Efficiency | `/ci-efficiency` | Audit GitHub Actions workflows for waste (missing caches, over-broad triggers, no concurrency cancellation). |

### Documentation

| Skill | Command | Description |
|-------|---------|-------------|
| Docs Writer | `/docs-writer` | Diátaxis expert: Tutorial / How-To / Reference / Explanation. Adapted to `documentation/docs/` + mdBook nav (`SUMMARY.md` + `nav.yml`). |
| ADR | `/adr` | Create an Architectural Decision Record under `documentation/docs/adr/`. |

### UI / Frontend

| Skill | Command | Description |
|-------|---------|-------------|
| Playwright KMS | `/playwright-kms` | Create E2E tests: `data-testid`, Ant Design Select portal helpers, regex assertions, FIPS skip pattern. |
| React/Ant Patterns | `/react-ant-patterns` | React 19 + Ant Design 5 + Tailwind 4 + Vite 7 patterns: WASM integration, FIPS guard, TypeScript strict mode. |

---

## Quick Start

```bash
# After any code change — always run this first:
# /kms-sync-rules

# New KMIP operation workflow:
# 1. /kmip-compliance <OperationName>   ← spec validation
# 2. /kms-test-vector                   ← create test vectors
# 3. /kms-sync-rules                    ← check what else needs updating
# 4. /kms-changelog                     ← write the changelog entry

# Full Rust quality gate before any significant PR (writes all reports to ./review/):
# /rust-review-all

# Quick panic/brutal-exit scan only:
# /rust-panic-audit crate/server/src/core/

# Error propagation audit:
# /rust-error-propagation crate/server/src/

# Security review before PR:
# /security-review crate/server/src/core/operations/
# /cryptography-review crate/crypto/src/

# Full security audit (orchestrates all 4 security skills):
# /meta-security

# Standards compliance check:
# /standards-review crate/server/src/core/operations/create.rs

# UI feature workflow:
# /react-ant-patterns    ← coding conventions
# /playwright-kms        ← write E2E tests
# /kms-sync-rules        ← UI sync checklist (rules 4.1, 4.4, 4.5)
```

---

## Skill Reference Files

Several skills load detailed guidance from `references/` subdirectories:

### `/threat-model` references

| File | Purpose |
|------|---------|
| `references/threat-model-orchestrator.md` | 10-step workflow, 10 mandatory rules |
| `references/threat-model-output-formats.md` | Templates for all output files |
| `references/threat-model-diagrams.md` | Mermaid DFD shape/color/arrow conventions |
| `references/threat-model-analysis-principles.md` | STRIDE-A, OWASP Top 10, exploitability tiers, false-positive avoidance |

### `/standards-review` references

| File | Purpose |
|------|---------|
| `references/standards-index.md` | Curated index of ~50 standards (FIPS, NIST SP, RFC, KMIP, BSI, ANSSI, OWASP) with canonical URLs |
| `references/citation-rules.md` | 8-rule anti-hallucination citation discipline |
| `references/compliance-checklist.md` | Per-algorithm cross-standard compliance matrix |

### Shared references

| File | Purpose |
|------|---------|
| `shared/anti-hallucination.md` | 8-rule anti-hallucination discipline loaded by every security skill before analysis |

---

## Adding a New Skill

1. Create `.github/skills/<skill-name>/SKILL.md`
2. Add YAML frontmatter: `name: '<skill-name>'` and `description: '...'`
3. Optionally add resources (scripts, templates, examples) in the same directory
4. Add a row to this README's index table
5. The skill appears immediately as `/<skill-name>` in VS Code Chat, Copilot CLI, and cloud agent
