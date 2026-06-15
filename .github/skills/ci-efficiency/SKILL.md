---
name: ci-efficiency
description: Audit GitHub Actions workflows for efficiency and recommend fixes to reduce CI minutes and costs. Use when asked to improve CI performance.
---

# CI Efficiency Audit

Inspect the repository's GitHub Actions workflows, identify waste sources, and recommend targeted fixes to reduce CI minutes and cost.

## This Codebase's CI Structure

The CI entry point is `.github/scripts/nix.sh`. All builds and tests go through it:

```bash
bash .github/scripts/nix.sh [--variant fips|non-fips] [--link static|dynamic] COMMAND [args]
```

Key workflows:

- `.github/workflows/pr.yml` — pull request CI
- `.github/workflows/main.yml` + `main_base.yml` — push CI
- `.github/workflows/test_all.yml` — full test matrix
- `.github/workflows/release.yml` — release automation
- `.github/workflows/packaging.yml`, `packaging-docker.yml`, `packaging-tests.yml` — packaging

Test matrix variants: `sqlite`, `psql`, `mariadb`, `percona`, `wasm`, `google_cse`, `gcp_cmek`, `otel_export`, `hsm`, `redis` (non-fips), `aws_xks` (non-fips), `azure_ekm` (non-fips), `ui` (non-fips).

## Step 1 — Measure First

```bash
# Scan for efficiency signals
rg -n "on:|concurrency:|paths:|paths-ignore:|strategy:|matrix:|cache:" .github/workflows

# Check recent run history (if gh CLI available)
GH_PAGER=cat gh run list --limit 10 --repo Cosmian/kms
run_id=$(GH_PAGER=cat gh run list --limit 1 --json databaseId --jq '.[0].databaseId' --repo Cosmian/kms)
GH_PAGER=cat gh run view "$run_id" --log-failed --repo Cosmian/kms
```

Look for:

- Missing dependency caches (Rust `~/.cargo`, `target/`, nix store, pnpm store)
- Missing `concurrency` groups to cancel stale runs on the same PR
- Over-broad triggers (full matrix on every push to any branch)
- Duplicate workflow coverage (same job in both `pr.yml` and `main.yml`)
- Expensive jobs running regardless of what changed (e.g. UI E2E triggered by Rust-only changes)

## Step 2 — Apply Guardrails

Before recommending any fix, verify it passes all guardrails:

1. Does not hide required validation — do not remove FIPS/non-FIPS test matrix legs that have explicit version commitments.
2. Does not reduce parallelism without justification.
3. Preserves security-critical checks — secret scanning, Dependabot, SBOM generation must not be gated behind path filters.
4. Write-back jobs (auto-formatting, CLI doc regeneration) must use opt-in triggers, not run on every PR.
5. Nix hash update jobs must not be silently skipped.

## Step 3 — Select Top 3 Fixes

From these candidates, keep only those supported by audit evidence AND passing all guardrails. Rank by estimated daily CI minutes saved:

1. **Dependency caching** — Cache the Nix store, Rust `~/.cargo/registry`, and pnpm store with lockfile-based keys
2. **Concurrency cancellation** — Add `concurrency: { group: "${{ github.ref }}", cancel-in-progress: true }` to PR workflows
3. **Path-based triggers** — Use `paths:` filters so Rust-only changes don't trigger the full UI E2E suite and vice versa
4. **Matrix reduction** — Run expensive test variants (hsm, cloud providers) only on push to `develop`/`main`, not on every PR
5. **Job parallelism** — Identify jobs currently running sequentially that could run in parallel
6. **Duplicate workflow removal** — Merge overlapping jobs between `pr.yml` and `main.yml`
7. **Redundant test detection** — Identify tests that exercise the same or near-identical code paths under different names (e.g. two test-vector tests that execute similar flows). Redundancy is not limited to textual repetition — look for semantic overlap in test logic

## Step 4 — Verify

If `gh` CLI is available, validate path-gating and concurrency cancellation with a dry-run check.
If live validation is not possible, state that explicitly.

## Required Output

1. **Waste sources** — top cost/latency drivers found in step 1
2. **Proposed fixes** — top 3 (or all remaining) with supporting audit evidence
3. **Validation** — what was proven live vs. checked statically, and any remaining risk
4. **Impact** — expected savings (separate PR wall-clock time from total runner time)

**If shell or `gh` CLI access is unavailable:** request the user paste `.github/workflows/` contents and `gh run list --limit 10` output. Begin static-only responses with: "**Static-only analysis** (not confirmed with live runs)."
