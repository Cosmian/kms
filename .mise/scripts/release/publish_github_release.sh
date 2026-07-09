#!/usr/bin/env bash
# .mise/scripts/release/publish_github_release.sh
#
# Extract the changelog entry for TAG and create (or update) the matching
# GitHub Release with those notes.
# When the release already exists (e.g. created by packaging.yml uploading
# the first asset) it is updated via `gh release edit`; otherwise it is
# created via `gh release create` so that downstream asset-upload steps have
# a release to attach to.
#
# Usage: publish_github_release.sh <tag>
#   tag — e.g. 5.24.0
#
# Required env: GH_TOKEN
# Optional env: KMS_GITHUB_REPO  (default: Cosmian/kms)

set -euo pipefail

TAG="${1:?Usage: publish_github_release.sh <tag>}"
REPO="${KMS_GITHUB_REPO:-Cosmian/kms}"
NOTES_FILE="/tmp/release_notes.md"

: "${GH_TOKEN:?GH_TOKEN must be set}"
export GH_PAGER=cat

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "${SCRIPT_DIR}/extract_changelog.sh" "${TAG}" "CHANGELOG.md" "${NOTES_FILE}"

if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  gh release edit "$TAG" \
    --repo "$REPO" \
    --notes-file "$NOTES_FILE"
  echo "[INFO] Updated existing GitHub Release '$TAG' on $REPO with changelog notes."
else
  gh release create "$TAG" \
    --repo "$REPO" \
    --title "Release $TAG" \
    --notes-file "$NOTES_FILE"
  echo "[INFO] Created GitHub Release '$TAG' on $REPO with changelog notes."
fi
