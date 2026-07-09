#!/usr/bin/env bash
# .mise/scripts/release/extract_changelog.sh
#
# Extract the changelog entry for VERSION from CHANGELOG_FILE and write to
# OUTPUT_FILE.
#
# Usage: extract_changelog.sh <version> [changelog_file] [output_file]
#   version        — e.g. 5.24.0
#   changelog_file — path to CHANGELOG.md  (default: CHANGELOG.md)
#   output_file    — destination file path  (default: /tmp/release_notes.md)
#
# The extracted block starts at the line *after* "## [VERSION]" and ends just
# before the next "## [" heading.  Leading and trailing blank lines are kept
# so the caller can choose how to present the content.

set -euo pipefail

VERSION="${1:?Usage: extract_changelog.sh <version> [changelog_file] [output_file]}"
CHANGELOG="${2:-CHANGELOG.md}"
OUTPUT="${3:-/tmp/release_notes.md}"

NOTES=$(awk \
  "/^## \[$VERSION\]/{found=1; next} found && /^## \[/{exit} found{print}" \
  "$CHANGELOG")

if [ -z "$NOTES" ]; then
  echo "[WARN] No changelog entry found for version $VERSION in $CHANGELOG." >&2
  NOTES="See the full history at https://github.com/Cosmian/kms/releases/tag/$VERSION"
fi

printf '%s\n' "$NOTES" >"$OUTPUT"
echo "[INFO] Extracted $(wc -l <"$OUTPUT") lines for version $VERSION → $OUTPUT"
