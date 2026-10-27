---
name: kms-changelog
description: 'Create or update the branch CHANGELOG entry, or consolidate all CHANGELOG/*.md branch files into the root CHANGELOG.md release entry and delete them. Use when writing a changelog entry for this branch or when preparing a release.'
---

# KMS Changelog

Two modes:

| Mode | Command | Output |
|------|---------|--------|
| **Branch entry** (default) | `/kms-changelog` | Create or append to `CHANGELOG/<branch>.md` |
| **Consolidate** (release time) | `/kms-changelog consolidate <X.Y.Z>` | Merge every `CHANGELOG/*.md` into the `## [X.Y.Z]` entry of the root `CHANGELOG.md`, then delete the branch files |

## Important Notes

- Branch changelogs live in `CHANGELOG/<branch-name>.md` (replace `/` with `_`). They are **ephemeral working
  documents**: every one is consumed and deleted by the consolidate mode at release time.
- The root `CHANGELOG.md` is **hand-maintained at release time by the consolidate mode** (or `/kms-release-notes`,
  which delegates to it). Outside a release, never edit it.
- **Security entries describe issues present in the previous release only.** `CHANGELOG/*.md` files and the root
  `CHANGELOG.md` must not list a security fix, hardening or "Setup action" for an issue that was introduced and fixed
  within the same release (new feature, new endpoint, new package, code added since the last tag). Describe such
  behaviour in the feature's own Features entry instead, and fix it silently. Verify with
  `git grep <symbol> <previous-tag>`: if the code or feature does not exist there, the entry does not belong in
  `## Security`.
- **Every bullet of a `Security` section carries a `COSMIAN-YYYY-NNN` id** that exists in `SECURITY.md` with
  `Fixed in` equal to the release. A hardening or fix without a `SECURITY.md` entry is not listed under Security: put
  it in Bug Fixes (theme `Hardening`), Build or Features. Never create the `SECURITY.md` entry yourself; report that
  one is missing when the issue looks like a real vulnerability.

# Mode 1 — Branch entry

## Step 1 — Determine the Branch

```bash
git branch --show-current
```

Never guess the branch name. Always run this command.

The changelog file path is: `CHANGELOG/<branch-name-with-slashes-replaced-by-underscores>.md`

Example: branch `fix/kmip-auth-bypass` → `CHANGELOG/fix_kmip-auth-bypass.md`

## Step 2 — Assess Whether an Entry Is Warranted

Write a changelog entry for **any** of the following (when in doubt, write one):

- Bug fix (any user- or operator-observable error, crash, or wrong behaviour)
- New feature (user-visible or operator-visible)
- Security hardening or vulnerability fix
- Behavioral change (default behaviour, error messages, CLI output)
- Breaking change from a customer's point of view (see "Breaking Changes" below)
- Significant refactor that materially affects operators or contributors

**Skip** for: routine internal implementation, formatting, test-only changes with no observable behaviour difference, CI pipeline adjustments.

## Step 3 — Gather Information

Ask the user (or infer from git diff and context):

1. What changed? (one-sentence summary)
2. Which category: Features / Bug Fixes / Security / Refactor / Build / CI / Documentation / Testing
3. Which component: `kmip`, `api`, `cli`, `ui`, `crypto`, `db`, `hsm`, `config`, `wasm`, `docs`, `nix`, `ci`
4. Is there a related GitHub PR or issue number? (optional)
5. Are there any linked issues to close? (optional)

## Step 4 — Write the Entry

Create or append to `CHANGELOG/<branch>.md` using this structure:

```markdown
## Features

### KMIP / Crypto
- Add `ReKey` operation with AES-256-GCM support for symmetric key rotation ([#42](https://github.com/Cosmian/kms/issues/42))

### CLI
- Add `ckms keys rekey` subcommand with `--uid` and `--wrapping-key-uid` flags

## Bug Fixes

### API
- Return HTTP 403 (not 500) when key access is denied in `Get` operation ([#38](https://github.com/Cosmian/kms/issues/38))

## Security

- Enforce access control check in `Wrap` operation before returning wrapped key material (COSMIAN-2026-001)

## Build

- Upgrade OpenSSL from 3.5.0 to 3.6.0 (FIPS provider updated)

---

Closes #38
Closes #42
```

Section names: `Breaking Changes`, `Features`, `Bug Fixes`, `Security`, `Refactor`, `Documentation`, `Testing`, `CI`, `Build`

Sub-group by component when multiple entries share the same area (e.g. multiple KMIP changes under `### KMIP`).

## Step 5 — Create the File if Needed

If `CHANGELOG/<branch>.md` does not exist yet:

```bash
mkdir -p CHANGELOG && ls CHANGELOG/
```

Create it with just the new entry. Do not copy content from other CHANGELOG files.

## Step 6 — Breaking Changes

Add a `## Breaking Changes` section at the top (with a migration action) **if and only if** the change is breaking
from a customer's point of view, compared with the previous release:

- a breaking change in the **SQL schema or the Redis schema** (a migration is needed, or existing data stops working);
- a breaking change on a **server endpoint** (KMIP over HTTP/TLS or the socket server, REST/JOSE, Azure EKM, AWS XKS,
  Google CSE, EST/SCEP, …): changed request or response layout, status or error codes, required headers, limits or
  access rules that make a previously valid call fail.

The KMS crates are not meant to be consumed by third parties, so internal breaking changes (Rust function or type
signatures, traits, crate layout, CLI flags, benchmarks, build requirements) are **not** breaking changes: describe
them as normal entries. A feature introduced since the previous release cannot break anything, so its restrictions are
described in its Features entry.

A change that corrects wrong, non-compliant or unsafe behaviour is **not** a breaking change, even when some clients
must adapt: a KMIP-compliance fix (stricter validation, error code or response layout aligned with the spec), a
rejected input that should never have been accepted, or a response-format fix goes to Bug Fixes (state the client
action in the bullet), and anything with a `COSMIAN-YYYY-NNN` id goes to Security. Reserve Breaking Changes for a
deliberate contract change that has no bug-fix or security justification; a release may have none.

```markdown
## Breaking Changes

### REST endpoints
- Rename the `kid` field of the `/v1/crypto/keys` response to `key_id` (hypothetical example). Clients must read
  `key_id`; `kid` is no longer returned.
```

## PR/Issue Link Format

- PR link: `([#N](https://github.com/Cosmian/kms/pull/N))`
- Issue link: `([#N](https://github.com/Cosmian/kms/issues/N))`
- Auto-close syntax at end of file: `Closes #N`

# Mode 2 — Consolidate (`/kms-changelog consolidate <X.Y.Z>`)

Run at release time, on the release or develop branch. The version defaults to the workspace version in the root
`Cargo.toml` (`.mise/scripts/release/get_version.sh`); the date is today's.

## Step C1 — Collect

```bash
ls CHANGELOG/*.md
git log --oneline $(git describe --tags --abbrev=0)..HEAD
```

Read **every** `CHANGELOG/*.md` file in full, plus the `## [Unreleased]` content and any existing `## [X.Y.Z]` entry
of the root `CHANGELOG.md`. Keep a checklist of the source files; each must be accounted for before deleting anything.
Use the `git log` PR numbers to link items and to spot merged work that has no branch file (add a bullet from the
commit title only, and say so in the final report).

## Step C2 — Summarize and regroup

- Sections, in this order: `### ⚠️ Breaking Changes`, `### 🔒 Security`, `### 🚀 Features`, `### 🐛 Bug Fixes`,
  `### ♻️ Refactor`, `### 🧪 Testing`, `### ⚙️ Build`, `### ⚙️ CI`, `### 📚 Documentation`.
- Regroup by theme (`####`, ≥ 2 bullets; reuse the same theme name across sections): `HSM`, `PKCS#11`, `Audit Logging`,
  `EST & SCEP Enrollment`, `OpenPGP`, `Hybrid KEM`, `Database`, `CLI`, …. Branch files use different or overlapping
  category names (`Fixed`, `Improvements`, `Tests`, …): map them to the sections above.
- **A theme that is new in this release lives in one place.** Every item about a feature introduced since the previous
  release (`Audit Logging`, `EST & SCEP Enrollment`, `OpenPGP`, …) goes under that feature's single `####`
  subsection of Features: its follow-up fixes, refactors, tests and docs included, not scattered over Bug Fixes,
  Refactor, Testing and Documentation. Only themes that already existed in the previous release (`HSM`, `Database`,
  `CLI`, …) are split across sections.
- Merge duplicates so each item appears exactly once. A bug fix and a feature describing the same change stay under
  Features. A breaking change appears under Breaking Changes only, with its migration action, and only when it meets
  the customer-facing criteria of Step 6 (SQL/Redis schema or server endpoint); demote every other "breaking" item to a
  regular bullet in the matching section.
- Summarize: one bullet per user- or operator-observable change, imperative verb, type/flag/crate names, PR/issue link.
  Drop benchmark numbers, per-test names, step-by-step investigation notes and internal file paths that do not affect
  observable behaviour. Compress Refactor to one sentence per area and Testing to categories.
- Do not invent facts: every claim must come from a branch file, the Unreleased section or a commit; mark anything
  unverified in the final report.

## Step C3 — Security cross-check

For each `COSMIAN-YYYY-NNN` id in the Security section, verify `SECURITY.md` lists it with `Fixed in` equal to
`X.Y.Z` and an affected range that includes the previous release. If one is missing, **stop and report**; do not
create the SECURITY.md entry.

Also check the reverse direction: list every advisory of the `SECURITY.md` summary table whose `Fixed in` equals
`X.Y.Z` (`grep "| X.Y.Z " SECURITY.md`, not just a guessed id range). Each one must appear exactly once in the Security
section.

Then check **every** Security bullet against the previous tag, as defined in Important Notes: `git grep` the symbol,
endpoint, config key or package it concerns in the previous tag. If it does not exist there (new feature, new package,
new endpoint), move the content to Features (keep any operator "Setup action") and delete it from Security. Finally,
every Security bullet must contain an id; move each bullet without one to Bug Fixes (`Hardening`), Build or Features
and list in the final report the ones that look like real vulnerabilities, so that a `SECURITY.md` entry can be written.

## Step C4 — Write the root entry

In `CHANGELOG.md`, replace the content between `## [Unreleased]` and the previous `## [A.B.C]` heading with an empty
`## [Unreleased]` line followed by the `## [X.Y.Z] - YYYY-MM-DD` entry. If an `## [X.Y.Z]` entry already exists, merge
into it instead of adding a second heading. Do not touch older entries.

## Step C5 — Verify coverage, then delete

1. Walk the checklist from Step C1: every source file's breaking changes, security items, features and fixes appear in
   the new entry. If a file has content that does not fit, add it before continuing.
2. Find references to the files about to be deleted and repoint them to the root entry (`CHANGELOG.md`, heading
   `[X.Y.Z]`):

   ```bash
   grep -rn "CHANGELOG/" --include=*.md --include=*.toml --include=*.yml . | grep -v "^./CHANGELOG"
   ```

   Keep generic mentions of the `CHANGELOG/<branch>.md` convention (CONTRIBUTING.md, skills, instructions).
3. Delete the consolidated branch files (`CHANGELOG/.gitignore` is tracked and keeps the directory):

   ```bash
   rm CHANGELOG/*.md
   ```

   Never delete when step 1 found a gap, when the Security cross-check failed, or when the user has not run the
   consolidation on the branch that will be released. Deleted files stay in git history.

## Step C6 — Report

List: source files merged, items taken from commit titles only, ADR/doc references repointed, and any claim left
unverified.
