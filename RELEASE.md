# Release

[TOC]

## Automated release (recommended)

The `.github/workflows/release.yml` workflow automates the entire release
flow. Trigger it from the GitHub Actions UI or via the GitHub CLI:

```sh
gh workflow run release.yml \
  --repo Cosmian/kms \
  --field old_version=5.19.0 \
  --field new_version=5.20.0
```

### What the workflow does — in order

1. **Validates** inputs (semver format, `old_version` matches `Cargo.toml`,
   branch/tag do not already exist).
2. **Creates** `release/<new_version>` from `develop`.
3. **Bumps** all version references via `.github/scripts/release/release.sh --ci`
   (sed-based substitutions across all `Cargo.toml` files and versioned docs)
   and regenerates `Cargo.lock`.  Commits and pushes.
4. **Updates Nix vendor hashes** by running `nix_build_update_hash.sh` on a
   Linux runner (builds all derivations in order, auto-fixes hash mismatches).
   Commits and pushes the updated `nix/expected-hashes/` files.
5. **Triggers a packaging CI run** (`pr.yml` via `workflow_dispatch`) on the
   release branch, then polls until it completes.  This run publishes packages
   and SBOMs to `package.cosmian.com`.
6. **Retrieves SBOMs** from `package.cosmian.com` and commits them.
7. **Pushes the annotated Git tag** `<new_version>`.  This triggers `pr.yml`
   (`on:push:tags`) which builds the final packages and creates the GitHub
   Release.
8. **Git-flow finalisation**: merges `release/<new_version>` into `main` (no-ff),
   merges `release/<new_version>` back into `develop` (syncs the version bump),
   then deletes the release branch.

### Prerequisites

- Repository secret `PAT_TOKEN` must have `repo` + `workflow` scopes so that
  commits and tag pushes made by the workflow can re-trigger other workflows
  (pushes made with `GITHUB_TOKEN` do not trigger them).

### Remaining manual step

Once the tag-triggered packaging pipeline completes, update the GitHub Release
notes at `https://github.com/Cosmian/kms/releases/tag/<new_version>` (copy
paste from `CHANGELOG.md`).

---

## Manual release (legacy)

Follow these steps only if the automated workflow is unavailable or needs to be
debugged.

### Pre-requisites

1. Install git-flow: <https://skoch.github.io/Git-Workflow/\>
2. Install git-cliff:

```sh
cargo install git-cliff
```

### Step by step

1. Create new release branch with git-flow:

   ```sh
   git checkout main
   git pull
   git checkout develop
   git pull
   git flow init
   git flow release start X.Y.Z
   ```

2. Update the version X.Y.Z almost everywhere:

   ```sh
   bash .github/scripts/release/release.sh <old_version> <new_version>
   ```

3. Commit the changes:

   ```sh
   git commit -m "build: release X.Y.Z"
   git push
   ```

   Make sure the CI pipeline is green.

4. Finish the release with git-flow:

   ```sh
   git flow release finish X.Y.Z --push
   ```

5. Do not forget to update GitHub CHANGELOG at
   <https://github.com/Cosmian/kms/releases/tag/X.Y.Z> (copy paste from CHANGELOG.md)
