---
name: pre-release
description: Release readiness gate: runs all AI audit skills in sequence and produces a go/no-go report. Use before triggering the release workflow.
---

# Pre-Release Readiness Gate

Run this skill **before triggering `release.yml`**. It orchestrates all AI audit skills
in the correct order and produces a structured go/no-go report.

> **The `release.yml` workflow handles the deterministic part** (version bump, doc generation,
> Nix hash recompute, packaging CI, SBOM, git-flow finalization). This skill handles the
> judgment-based part that cannot be automated in CI.

## Step 0 — Determine release scope

```bash
git log --oneline $(git describe --tags --abbrev=0)..HEAD
git diff --stat $(git describe --tags --abbrev=0)..HEAD
```

Record: which crates changed, whether crypto/KMIP/auth/UI was touched, whether any
`non-fips` feature gate was added or removed.

## Step 1 — Sync rules audit

Invoke `/kms-sync-rules` with the full diff since the last tag.

Verify every applicable sub-rule (4.1–4.17) is satisfied. Block on any open item.

## Step 2 — Security review

Invoke `/security-review` on each changed area:

- `crate/server/src/core/operations/` if any KMIP operation changed
- `crate/server/src/middlewares/` if auth changed
- `crate/server/src/routes/` if any endpoint changed
- `crate/crypto/src/` if any crypto primitive changed

Block on any HIGH or CRITICAL finding.

## Step 3 — FIPS audit (if crypto or algorithm selection changed)

Invoke `/fips-audit` on `crate/crypto/src/`.

Skip if no file under `crate/crypto/` or `crate/server/src/openssl_providers.rs` changed.

Block on: disallowed algorithm added, missing `#[cfg(feature = "non-fips")]` gate,
incorrect key size, OpenSSL provider init bypassed.

## Step 4 — KMIP compliance (if any KMIP operation added or modified)

Invoke `/kmip-compliance` for each changed operation.

Skip if no file under `crate/kmip/`, `crate/server/src/core/operations/`, or
`crate/server/src/core/operations/dispatch.rs` changed.

Block on: spec deviation, missing dispatch arm, missing access control check.

## Step 5 — Threat model update (if trust boundary or auth flow changed)

Invoke `/threat-model` in incremental mode if any of these changed:

- `crate/server/src/middlewares/`
- `crate/server/src/routes/`
- `crate/server/src/config/`
- Any HSM crate under `crate/hsm/`

Skip if only internal refactoring or test changes.

## Step 6 — Deterministic checks

Run locally to confirm CI will pass:

```bash
cargo clippy-all          # zero warnings required
cargo fmt --all           # no formatting drift
cargo test-fips           # full FIPS suite
cargo test-non-fips       # full non-FIPS suite
```

## Step 7 — CHANGELOG completeness

Invoke `/kms-changelog`.

Verify `CHANGELOG/<branch>.md` covers every user-visible change:
public API signatures, CLI flags/output, config keys, default behavior,
supported algorithms, operator-visible error messages.

## Step 8 — Generate release notes

Invoke `/kms-release-notes <version>` (substitute the actual semver).

This aggregates all `CHANGELOG/*.md` files into a single human-readable release
note at `CHANGELOG/RELEASE_<version>.md`. Review it before proceeding:

- All Breaking Changes are documented with a migration guide.
- Security section is present if any security fix was merged.
- No operator-visible change is missing.

## Step 9 — Go / No-Go Report

Produce this exact report:

```markdown
## Pre-Release Readiness Report — v<X.Y.Z>

| Check | Status | Blocking findings |
|-------|--------|-------------------|
| Sync rules (4.1–4.17) | ✅ PASS / ❌ BLOCK | [list open items] |
| Security review | ✅ PASS / ❌ BLOCK | [HIGH/CRITICAL findings] |
| FIPS audit | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | [violations] |
| KMIP compliance | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | [spec deviations] |
| Threat model | ✅ PASS / ⏭ SKIPPED / ❌ BLOCK | [new unmitigated threats] |
| Clippy | ✅ PASS / ❌ BLOCK | [warning count] |
| Test suite (FIPS) | ✅ PASS / ❌ BLOCK | [failing tests] |
| Test suite (non-FIPS) | ✅ PASS / ❌ BLOCK | [failing tests] |
| CHANGELOG | ✅ PASS / ❌ BLOCK | [missing entries] || Release notes | ✅ PASS / ❌ BLOCK | [missing sections] |
### Verdict
**GO** — all checks pass. Trigger `release.yml` with inputs:
  - `new_version`: <X.Y.Z>
  - `base`: develop

**NO-GO** — resolve blocking findings before release.
```

All ❌ BLOCK items must be resolved before triggering `release.yml`.
⏭ SKIPPED items are acceptable when the skip condition is confirmed.
