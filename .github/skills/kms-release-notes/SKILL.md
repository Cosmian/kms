---
name: kms-release-notes
description: 'Write the next version entry at the top of CHANGELOG.md by summarizing all changes since the last tagged release. Use when preparing release notes.'
---

# KMS Release Notes Generator

Write a new `## [X.Y.Z] - YYYY-MM-DD` entry at the **top** of `CHANGELOG.md`
by summarizing all changes since the previous release tag.

**Usage**: `/kms-release-notes <version>` — e.g. `/kms-release-notes 5.24.0`

## Step 1 — Determine the diff scope

```bash
git log --oneline $(git describe --tags --abbrev=0)..HEAD
git diff --stat $(git describe --tags --abbrev=0)..HEAD
```

Identify all commits and changed files since the last release tag.

## Step 2 — Parse and deduplicate entries

Group changes by their natural theme (feature area, integration, component).

**Deduplication rules:**

- If two commits describe the same logical change, keep the more complete one.
- If a bug fix and a feature entry describe the same item, keep under Features.
- Merge related items under the same themed subsection.

## Step 3 — Write the entry with themed subsections

Insert a new `## [X.Y.Z] - YYYY-MM-DD` section at the **top** of `CHANGELOG.md`
(before the previous version entry).

Use this structure with **themed subsections** under each top-level category:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### 🔒 Security

- <entry> ([#N](...))

### 🚀 Features

#### <Theme Name>
- <entry>
- <entry>

#### <Another Theme>
- <entry>

### 🐛 Bug Fixes

#### <Theme Name>
- <entry>

#### <Another Theme>
- <entry>

### ♻️ Refactor

- <summary per area>

### 🧪 Testing

- <new test categories, not individual function names>

### ⚙️ Build

- <entry>

### 📚 Documentation

- <entry>
```

**Theme examples** (derive from the actual changes — not a fixed list):
`FPE & Anonymization`, `JOSE / REST Crypto API`, `OpenTelemetry Metrics`,
`Windows / CNG KSP / Intune`, `CKMS CLI`, `PKCS#11 / VeraCrypt`,
`EDB PostgreSQL TDE`, `VAST Data / KMIP 1.4`, `Server Configuration`,
`HSM`, `KMIP / XML`, etc.

**Section ordering**: Security → Features → Bug Fixes → Refactor → Testing → Build → Documentation.

**Rules for themed subsections (`####`):**

- Use `####` headings only when a theme has ≥2 bullet points.
- Single-bullet themes can stay as flat bullets without a subsection.
- Every theme name should be short, descriptive, and reusable across sections
  (e.g. if "JOSE / REST Crypto API" appears in Features, use the same name in Bug Fixes).

## Step 4 — Compress internal-facing sections

- **Refactor**: one summary sentence per crate or area.
- **Testing**: list new test categories or coverage areas, not individual test names.

## Step 5 — Cross-check SECURITY.md

If the entry contains a `### 🔒 Security` section:

1. Read `SECURITY.md`.
2. For each `COSMIAN-YYYY-NNN` entry, verify it exists in `SECURITY.md` with matching
   `Fixed in` version.
3. If missing, **block and report** — do not create the entry yourself.
4. Remove from `### 🔒 Security` any item whose issue was introduced in this same release (the feature, endpoint or
   package does not exist in the previous tag): describe it under Features instead.
5. Every bullet under `### 🔒 Security` must contain its `COSMIAN-YYYY-NNN` id; move any bullet without one to Bug
   Fixes, Build or Features and report it.
6. Every advisory of the `SECURITY.md` table with `Fixed in` equal to this release appears exactly once under Security.

## Step 6 — Tone and formatting rules

- Start each bullet with an imperative verb: "Add", "Fix", "Remove", "Upgrade", etc.
- Be specific: type names, flag names, algorithm names, crate names.
- Omit internal implementation details unless they affect observable behavior.
- Include PR/issue links: `([#N](https://github.com/Cosmian/kms/pull/N))`.
- No line-count limit, but be concise — compress where possible.

## Step 7 — Write the output

Edit `CHANGELOG.md` in-place. Insert the new version entry before the previous
`## [X.Y.Z]` heading, under an empty `## [Unreleased]` line. Do **not** edit any
other entry, and do **not** create files in `CHANGELOG/`.

The root `CHANGELOG.md` is hand-maintained at release time.

## Step 8 — Consolidate and clean up branch CHANGELOGs

Run `/kms-changelog consolidate <version>`. It reads every `CHANGELOG/*.md`
branch file, summarizes and regroups them into the themed subsections of the
entry written above (each item exactly once), cross-checks `SECURITY.md`, and
deletes the branch files. Do not duplicate that procedure here.
