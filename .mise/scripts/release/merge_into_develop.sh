#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root; leave genuine merge failures for manual recovery.
RELEASE_REF="${1:?Usage: merge_into_develop.sh <release-ref>}"
MERGE_STATUS=0
git merge --no-ff --no-commit "${RELEASE_REF}" \
  -m "build: merge ${RELEASE_REF#origin/} into develop" || MERGE_STATUS=$?

if [[ "${MERGE_STATUS}" -ne 0 ]]; then
  CONFLICTS="$(git diff --name-only --diff-filter=U)"
  [[ -n "${CONFLICTS}" ]] || exit "${MERGE_STATUS}"

  while IFS= read -r path; do
    if [[ ! "${path}" =~ ^nix/expected-hashes/[A-Za-z0-9.-]+\.sha256$ ]]; then
      echo "ERROR: refusing to resolve non-generated conflict: ${path}" >&2
      exit "${MERGE_STATUS}"
    fi
  done <<<"${CONFLICTS}"

  # Lockfiles alone are insufficient: manifests, versions and Nix tooling matter.
  # Conservatively require the entire merged tree, except hashes, to match release.
  if ! git diff --cached --quiet "${RELEASE_REF}" -- . \
    ':(exclude,glob)nix/expected-hashes/*.sha256'; then
    echo 'ERROR: merged inputs differ from release; merge manually and regenerate Nix hashes.' >&2
    exit "${MERGE_STATUS}"
  fi

  RELEASE_HASH_FILES="$(git ls-tree -r --name-only "${RELEASE_REF}" -- nix/expected-hashes)"
  while IFS= read -r path; do
    [[ "${path}" == *.sha256 ]] || continue
    if ! hash="$(git show "${RELEASE_REF}:${path}")" ||
      [[ ! "${hash}" =~ ^sha256-[A-Za-z0-9+/]{43}=$ ]]; then
      echo "ERROR: no valid release hash for ${path}" >&2
      exit "${MERGE_STATUS}"
    fi
  done <<<"${RELEASE_HASH_FILES}"

  # Keep the release hash set together, including files that merged without conflict.
  git restore --source="${RELEASE_REF}" --staged --worktree -- \
    ':(glob)nix/expected-hashes/*.sha256'
fi

# An already-merged release has no MERGE_HEAD and needs no new commit.
if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
  git commit --no-edit
fi
