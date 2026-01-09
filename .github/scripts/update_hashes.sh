#!/usr/bin/env bash
# Update expected hashes by reading the last packaging pipeline from GitHub Actions
# and extracting hash mismatches with pattern: specified: sha256-XXX / got: sha256-YYY
#
# Usage:
#   update_hashes.sh [RUN_ID]
#
# If RUN_ID is not provided, the latest packaging workflow run will be used.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXPECTED_DIR="$REPO_ROOT/nix/expected-hashes"
LOG_DIR="${TMPDIR:-/tmp}/kms-update-hashes"
mkdir -p "$LOG_DIR"

# Check if gh CLI is available
if ! command -v gh &> /dev/null; then
  echo "Error: gh CLI is not installed. Please install it from https://cli.github.com/" >&2
  exit 1
fi

# Get the run ID from argument or fetch the latest
if [ $# -ge 1 ]; then
  RUN_ID="$1"
  echo "Using provided workflow run: $RUN_ID"
else
  echo "Fetching latest packaging workflow run..."
  RUN_ID=$(gh api repos/Cosmian/kms/actions/workflows/pr.yml/runs \
    --jq '.workflow_runs[0].id' 2>/dev/null || echo "")

  if [ -z "$RUN_ID" ]; then
    echo "Error: Could not fetch latest workflow run. Make sure you're authenticated with 'gh auth login'." >&2
    exit 1
  fi
  echo "Found workflow run: $RUN_ID"
fi

echo "Fetching failed jobs..."

# Get all failed jobs from this run
FAILED_JOBS=$(gh api "repos/Cosmian/kms/actions/runs/$RUN_ID/jobs" \
  --jq '.jobs[] | select(.conclusion == "failure") | .id' 2>/dev/null || echo "")

if [ -z "$FAILED_JOBS" ]; then
  echo "No failed jobs found in run $RUN_ID. Nothing to update."
  exit 0
fi

# Declare associative array to store hash updates
declare -A FILE_TO_HASH

# Process each failed job
while IFS= read -r JOB_ID; do
  [ -z "$JOB_ID" ] && continue

  echo "Processing job $JOB_ID..."
  LOG_FILE="$LOG_DIR/job_${JOB_ID}.log"

  # Download job logs
  gh api "repos/Cosmian/kms/actions/jobs/$JOB_ID/logs" > "$LOG_FILE" 2>&1 || {
    echo "Warning: Could not fetch logs for job $JOB_ID, skipping..."
    continue
  }

  # Parse logs for hash mismatches
  # Pattern:
  #   error: hash mismatch in fixed-output derivation '/nix/store/...-name.drv':
  #            specified: sha256-XXXX
  #               got:    sha256-YYYY

  last_drv_name=""
  while IFS= read -r line; do
    # Capture derivation name from error line
    if echo "$line" | grep -q "hash mismatch in fixed-output derivation"; then
      drv_path=$(echo "$line" | grep -Eo "'/nix/store/[^']+'" | tr -d "'" || echo "")
      if [ -n "$drv_path" ]; then
        # Extract the package name from the derivation path
        # e.g., /nix/store/xxx-cosmian-kms-ui-deps-fips-5.14.1-npm-deps.drv -> cosmian-kms-ui-deps-fips-5.14.1-npm-deps
        last_drv_name=$(basename "$drv_path" | sed 's/\.drv$//')
      fi
    fi

    # Capture the "got" hash
    if echo "$line" | grep -q "got:"; then
      got_hash=$(echo "$line" | grep -Eo "sha256-[A-Za-z0-9+/=]+" | head -n1 || echo "")

      if [ -n "$got_hash" ] && [ -n "$last_drv_name" ]; then
        # Map derivation name to expected hash file
        target_file=""

        # UI npm deps (both fips and non-fips share the same npm deps)
        if echo "$last_drv_name" | grep -qE "ui-deps-(fips|non-fips).*-npm-deps"; then
          target_file="$EXPECTED_DIR/ui.npm.sha256"
        # UI wasm vendor - fips
        elif echo "$last_drv_name" | grep -qE "ui-wasm-fips.*-vendor"; then
          target_file="$EXPECTED_DIR/ui.vendor.fips.sha256"
        # UI wasm vendor - non-fips
        elif echo "$last_drv_name" | grep -qE "ui-wasm-non-fips.*-vendor"; then
          target_file="$EXPECTED_DIR/ui.vendor.non-fips.sha256"
        # Server vendor - need to determine platform from job name or derivation
        elif echo "$last_drv_name" | grep -qE "server.*-vendor"; then
          # Try to infer from the derivation or use default for Linux
          if echo "$last_drv_name" | grep -qE "darwin"; then
            if echo "$last_drv_name" | grep -qE "static"; then
              target_file="$EXPECTED_DIR/server.vendor.static.darwin.sha256"
            else
              target_file="$EXPECTED_DIR/server.vendor.dynamic.darwin.sha256"
            fi
          else
            # Default to Linux (most common in CI)
            target_file="$EXPECTED_DIR/server.vendor.linux.sha256"
          fi
        fi

        if [ -n "$target_file" ]; then
          FILE_TO_HASH["$target_file"]="$got_hash"
          echo "  Found hash for $target_file: $got_hash"
        fi

        last_drv_name=""
      fi
    fi
  done < "$LOG_FILE"
done <<< "$FAILED_JOBS"

# Apply updates
updated_count=0
for file in "${!FILE_TO_HASH[@]}"; do
  hash="${FILE_TO_HASH[$file]}"
  echo "$hash" >"$file"
  echo "Updated $file -> $hash"
  updated_count=$((updated_count + 1))
done

if [ "$updated_count" -eq 0 ]; then
  echo "No hashes found to update." >&2
  echo "This could mean:" >&2
  echo "  - No hash mismatches were found in the workflow run" >&2
  echo "  - The workflow run is still in progress" >&2
  echo "  - The failed jobs don't contain hash mismatch errors" >&2
  exit 1
fi

echo "Done. Updated $updated_count expected-hash file(s)."
