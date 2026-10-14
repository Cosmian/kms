---
name: kms-pr-review
description: 'Two-pass PR/diff review per .github/skills/shared/orchestrator-contract.md: structural scan (with conditional domain-skill escalation for crypto, security, KMIP), then semantic verification that disposes of every structural finding. Self-review mode (local branch) auto-applies confirmed fixes for up to 2 fix cycles; PR mode (PR number/URL) is report-only. Use before marking non-trivial work done, before opening a PR, or to review a PR.'
---

# KMS PR Review — two-pass diff gate

Diff-scoped review gate, following `.github/skills/shared/orchestrator-contract.md` (phase order, report schema, sub-agent routing). It is lighter than `/rust-review-all` and `/meta-security` and **does not replace them** for release or security-audit requests.

## Step 0 — Anti-hallucination

Read `.github/skills/shared/anti-hallucination.md` before analysing anything.

## Step 1 — Mode and scope

- Argument is a PR number or URL → **PR mode** (report-only). Scope: `gh pr diff <N> --repo Cosmian/kms`.
- No argument → **self-review mode**. Scope is the union of:
  - `git diff --name-only origin/develop...HEAD`
  - `git diff --name-only HEAD`
  - `git diff --name-only --cached`
  - `git ls-files --others --exclude-standard`

Never treat an empty or failed diff as clean: report it and stop.

## Step 2 — Phase 1: Structural Scan

Run a `task` sub-agent with `smol` routing (contract §6). Scan file scope, imports, naming, obvious anti-patterns, hardcoded values, missing error handling, surface risks.

If `/kms-caveman` already ran this session on overlapping scope, feed its findings in instead of re-scanning.

Run a domain skill only when the diff touches its area; skip it otherwise (token cost). They are report-only. Add their findings to `review/01-structural.md` as `S<n>` claims tagged with the source skill, so Phase 2 still disposes of each one:

| Diff touches | Run |
|---|---|
| `crate/crypto/`, `openssl_providers.rs`, algorithm or key-size choice | `/cryptography-review <paths>` |
| `crate/server/src/middlewares/`, `routes/`, `core/operations/`, `crate/access/`, cloud-provider routes, parsing of untrusted input | `/security-review <paths>` |
| `crate/kmip/`, `crate/server/src/core/operations/` | `/kmip-compliance <operation>` |

Do not run `/kms-sync-rules` here (`AGENTS.md` §5 step 4 already ran it) and do not run `/meta-security` (an audit orchestrator, not a diff gate).

Write `review/01-structural.md`. Each claim has an ID `S<n>`, file:line, evidence, and a recommended fix.

## Step 3 — Phase 2: Semantic Verification

Run a `task` sub-agent with `slow` routing. Inputs: `review/01-structural.md`, the live diff and source, `AGENTS.md`, and the applicable `.github/instructions/*.instructions.md`.

- Give every `S<n>` exactly one disposition: `confirmed`, `rejected` (with reason), `adjusted` (with corrected severity/line/fix), `[UNVERIFIED]`, or `needs-human`.
  Use `needs-human` when the fix needs a design decision, changes public API or behavior outside the task, or needs external access.
- Add missed findings as `M<n>` with the same fields (correctness, concurrency, edge cases, cross-file impact, contract compliance).
- Write `review/02-semantic.md` with the disposition table, the findings, and a **GO / NO-GO** verdict.

If the disposition table is missing, the report is invalid: redo Step 3.

## Step 4 — Final report

Write `review/final.md` using the Unified Report Schema (contract §4). It adds no new findings, links `review/01-structural.md` and `review/02-semantic.md`, and records `Cycle: <k>` (0 = first review).

## Step 5 — Auto-fix loop (self-review mode only)

1. Verdict GO and no `confirmed`/`adjusted` findings left unapplied → done.
2. Apply the recommended fix of every `confirmed` and `adjusted` finding, at any severity. Never apply `rejected`, `[UNVERIFIED]`, or `needs-human` findings.
3. When Rust files changed, re-run `AGENTS.md` §5 step 1 (targeted tests for the touched code) and step 3 (`cargo clippy-all`, `cargo fmt --all`). A newly failing test or warning is a `confirmed` finding of the next cycle.
4. Re-run Steps 1–4 with `Cycle: k+1`, overwriting the `review/*.md` files.
5. Stop after **2 fix cycles**: the review at `Cycle: 2` is the last. If it is NO-GO, or any `needs-human`, `confirmed` or `adjusted` finding is still unapplied, stop, report those findings from `review/final.md` to the user, and do not start another cycle.

## Step 6 — Output rules

- PR mode: never edit files.
- Never post to GitHub, push, or resolve review threads.
- Attribute each finding to its phase; list blockers first.

`/kms-adversarial-test` is the complementary live adversarial test against a running KMS.
