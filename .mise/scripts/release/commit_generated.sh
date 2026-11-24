#!/usr/bin/env bash
# Apply a generated-files patch (data only) onto the checked-out base commit and commit it locally.
#
# Runs with NO credential, in a checkout of BASE_SHA made without persisted credentials. Nothing from the
# patch is executed: it is applied with `git apply`, hooks and signing are off, and only changes that
# validate_generated_changes.py accepts for the caller's exact path list survive.
#
# Environment: BASE_SHA, ARTIFACT_DIR (holds changes.patch and base-sha.txt), ALLOWED_FILE (path list),
#              VALIDATOR (trusted copy of validate_generated_changes.py), MESSAGE, GITHUB_OUTPUT (optional).
# Output: changed=true|false.
set -euo pipefail

: "${BASE_SHA:?}" "${ARTIFACT_DIR:?}" "${ALLOWED_FILE:?}" "${VALIDATOR:?}" "${MESSAGE:?}"
fail() {
  echo "::error::$*" >&2
  exit 1
}

[[ "${BASE_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "base-sha is not a full commit SHA"
[ -f "${ARTIFACT_DIR}/changes.patch" ] || fail "generated artifact has no changes.patch"
[ -f "${ARTIFACT_DIR}/base-sha.txt" ] || fail "generated artifact has no base-sha.txt"
[ "$(tr -d '[:space:]' <"${ARTIFACT_DIR}/base-sha.txt")" = "${BASE_SHA}" ] ||
  fail "artifact was generated from a different commit than ${BASE_SHA}"
[ "$(git rev-parse HEAD)" = "${BASE_SHA}" ] || fail "checkout is not at ${BASE_SHA}"
git diff --quiet HEAD && [ -z "$(git status --porcelain)" ] || fail "checkout is not clean"

emit() { if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "changed=$1" >>"${GITHUB_OUTPUT}"; fi; }

# An empty patch is the valid "nothing to regenerate" result (a missing artifact failed above).
if [ ! -s "${ARTIFACT_DIR}/changes.patch" ]; then
  echo "Generated files are already up to date."
  emit false
  exit 0
fi

git -c core.hooksPath=/dev/null apply --index --whitespace=nowarn -- "${ARTIFACT_DIR}/changes.patch"
python3 "${VALIDATOR}" "${ALLOWED_FILE}"
git diff --cached --quiet HEAD && {
  echo "Patch applied to no net change."
  emit false
  exit 0
}
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
git -c core.hooksPath=/dev/null -c commit.gpgsign=false commit --quiet -m "${MESSAGE}"
echo "Committed: ${MESSAGE}"
emit true
