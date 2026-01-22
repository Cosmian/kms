#!/usr/bin/env bash
set -euo pipefail

# Clean top-level result* folders safely.
# Usage: bash .github/scripts/clean_result.sh

# Determine repo root (script is under .github/scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v git >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
else
  # Fallback: two levels up from .github/scripts
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
fi

cd "${REPO_ROOT}"

# Sanity check: warn if Cargo.toml missing, but continue (some CI contexts)
if [[ ! -f "Cargo.toml" ]]; then
  echo "Warning: Cargo.toml not found at repo root; proceeding anyway." >&2
fi

# Find top-level directories starting with result and delete them
mapfile -t TARGETS < <(find "${REPO_ROOT}" -maxdepth 1 -name 'result*')

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  echo "No result* folders found at top level."
  exit 0
fi

echo "Cleaning the following result* entries:" >&2
for d in "${TARGETS[@]}"; do
  echo " - ${d}" >&2
  rm -rf -- "${d}"
done

echo "Cleanup completed."
