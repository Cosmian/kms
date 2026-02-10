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
if ! command -v gh &>/dev/null; then
  echo "Error: gh CLI is not installed. Please install it from https://cli.github.com/" >&2
  exit 1
fi

# Get the run ID from argument or fetch the latest
if [ $# -ge 1 ]; then
  RUN_ID="$1"
  echo "Using provided workflow run: $RUN_ID"
else
  # Get current git branch
  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if [ -z "$CURRENT_BRANCH" ]; then
    echo "Error: Could not determine current git branch" >&2
    exit 1
  fi
  
  echo "Fetching latest packaging workflow run for branch: $CURRENT_BRANCH..."
  
  # Fetch recent workflow runs and filter by current branch
  # Prioritize failed runs (which likely have hash mismatches), then fall back to any completed run
  RUN_ID=$(gh run list --limit 50 --json databaseId,status,conclusion,headBranch,name | \
    jq -r --arg branch "$CURRENT_BRANCH" \
    '.[] | select(.headBranch == $branch and .name == "Packaging" and .status == "completed") | 
     {databaseId, conclusion, priority: (if .conclusion == "failure" then 0 elif .conclusion == "success" then 1 else 2 end)} | 
     select(.conclusion != "cancelled")' | \
    jq -s 'sort_by(.priority) | .[0].databaseId' || echo "")

  if [ -z "$RUN_ID" ]; then
    echo "Error: Could not fetch latest workflow run for branch '$CURRENT_BRANCH'." >&2
    echo "Make sure you're authenticated with 'gh auth login' and the branch has CI runs." >&2
    exit 1
  fi
  echo "Found workflow run: $RUN_ID (branch: $CURRENT_BRANCH)"
fi

echo "Fetching failed jobs..."

# Get all failed jobs from this run (id + name)
# We rely on the job name to infer platform/linkage for server vendor hashes.
FAILED_JOBS=$(gh api "repos/Cosmian/kms/actions/runs/$RUN_ID/jobs" \
  --jq '.jobs[] | select(.conclusion == "failure") | [.id, .name] | @tsv' 2>/dev/null || echo "")

if [ -z "$FAILED_JOBS" ]; then
  echo "No failed jobs found in run $RUN_ID. Nothing to update."
  exit 0
fi

# Declare associative array to store hash updates
declare -A FILE_TO_HASH

# Process each failed job
while IFS=$'\t' read -r JOB_ID JOB_NAME; do
  [ -z "${JOB_ID:-}" ] && continue
  JOB_NAME=${JOB_NAME:-""}

  echo "Processing job $JOB_ID${JOB_NAME:+ ($JOB_NAME)}..."
  LOG_FILE="$LOG_DIR/job_${JOB_ID}.log"

  # Download job logs
  gh api "repos/Cosmian/kms/actions/jobs/$JOB_ID/logs" >"$LOG_FILE" 2>&1 || {
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
        # e.g., /nix/store/xxx-cosmian-kms-ui-deps-fips-X.Y.Z-npm-deps.drv -> cosmian-kms-ui-deps-fips-X.Y.Z-npm-deps
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
        # Server vendor (Cargo vendoring). Derivation names do not reliably include platform/linkage;
        # infer those from the GitHub Actions job name.
        elif echo "$last_drv_name" | grep -qiE "(kms-server|server).*vendor|(^|-)vendor($|-)"; then
          if echo "$JOB_NAME" | grep -qiE "macos|darwin"; then
            if echo "$JOB_NAME" | grep -qiE "static"; then
              target_file="$EXPECTED_DIR/server.vendor.static.darwin.sha256"
            elif echo "$JOB_NAME" | grep -qiE "dynamic"; then
              target_file="$EXPECTED_DIR/server.vendor.dynamic.darwin.sha256"
            else
              # Default for macOS packaging jobs: update both (some job names don't include link)
              FILE_TO_HASH["$EXPECTED_DIR/server.vendor.static.darwin.sha256"]="$got_hash"
              FILE_TO_HASH["$EXPECTED_DIR/server.vendor.dynamic.darwin.sha256"]="$got_hash"
              echo "  Found hash for $EXPECTED_DIR/server.vendor.static.darwin.sha256: $got_hash"
              echo "  Found hash for $EXPECTED_DIR/server.vendor.dynamic.darwin.sha256: $got_hash"
              target_file=""
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
  done <"$LOG_FILE"
done <<<"$FAILED_JOBS"

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
