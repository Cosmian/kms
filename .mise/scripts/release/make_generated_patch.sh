#!/usr/bin/env bash
# Capture what a generation step changed as a data-only artifact for commit-generated.yml.
#
# Writes OUT_DIR/changes.patch (git diff --binary HEAD over the exact PATHS) and OUT_DIR/base-sha.txt.
# An empty patch means "nothing changed"; the artifact upload must still fail when this script did not run.
#
# Environment: PATHS (newline-separated repository-relative paths), OUT_DIR, BASE_SHA (HEAD before generation).
set -euo pipefail

: "${PATHS:?}" "${OUT_DIR:?}" "${BASE_SHA:?}"
[ "$(git rev-parse HEAD)" = "${BASE_SHA}" ] || {
  echo "::error::HEAD moved during generation" >&2
  exit 1
}
paths=()
existing=()
while IFS= read -r p; do
  [ -z "${p}" ] && continue
  paths+=("${p}")
  if [ -e "${p}" ] || [ -L "${p}" ]; then existing+=("${p}"); fi
done <<<"${PATHS}"
[ "${#paths[@]}" -gt 0 ] || {
  echo "::error::no path to capture" >&2
  exit 1
}
# Make files created by the generator (optional outputs) visible to `git diff HEAD`.
if [ "${#existing[@]}" -gt 0 ]; then git add --intent-to-add -- "${existing[@]}"; fi
mkdir -p "${OUT_DIR}"
git diff --binary HEAD -- "${paths[@]}" >"${OUT_DIR}/changes.patch"
printf '%s\n' "${BASE_SHA}" >"${OUT_DIR}/base-sha.txt"
echo "Captured $(wc -c <"${OUT_DIR}/changes.patch") bytes of generated changes."
