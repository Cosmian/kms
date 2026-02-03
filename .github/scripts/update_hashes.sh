#!/usr/bin/env bash
# Update expected hashes by reading the last packaging pipeline from GitHub Actions
# and extracting hash mismatches with pattern: specified: sha256-XXX / got: sha256-YYY
#
# To keep this fast, we only parse the failed step output for the
# "Package with GPG signature" step via `gh run view --log-failed`.
#
# Usage:
#   update_hashes.sh
#
# This script takes no arguments.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXPECTED_DIR="$REPO_ROOT/nix/expected-hashes"
shopt -s nocasematch

# Check if gh CLI is available
if ! command -v gh &>/dev/null; then
  echo "Error: gh CLI is not installed. Please install it from https://cli.github.com/" >&2
  exit 1
fi

if [ $# -ne 0 ]; then
  echo "Error: update_hashes.sh takes no arguments" >&2
  exit 2
fi

# Get current git branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ -z "$CURRENT_BRANCH" ]; then
  echo "Error: Could not determine current git branch" >&2
  exit 1
fi

echo "Fetching latest packaging workflow run for branch: $CURRENT_BRANCH..."

# Fetch recent workflow runs and filter by current branch
# Prioritize failed runs (which likely have hash mismatches), then fall back to any completed run
RUN_ID=$(gh run list --limit 50 --json databaseId,status,conclusion,headBranch,name |
  jq -r --arg branch "$CURRENT_BRANCH" \
    '.[] | select(.headBranch == $branch and .name == "Packaging" and .status == "completed") | 
    {databaseId, conclusion, priority: (if .conclusion == "failure" then 0 elif .conclusion == "success" then 1 else 2 end)} | 
    select(.conclusion != "cancelled")' |
  jq -s 'sort_by(.priority) | .[0].databaseId' || echo "")

if [ -z "$RUN_ID" ]; then
  echo "Error: Could not fetch latest workflow run for branch '$CURRENT_BRANCH'." >&2
  echo "Make sure you're authenticated with 'gh auth login' and the branch has CI runs." >&2
  exit 1
fi
echo "Found workflow run: $RUN_ID (branch: $CURRENT_BRANCH)"

echo "Fetching failed jobs..."

# Get all failed jobs from this run (id + name)
# We rely on the job name to infer platform/linkage for server vendor hashes.
# Filter out ARM and Docker builds to speed up the process (keep Ubuntu x86_64 and macOS only)
FAILED_JOBS=$(gh api "repos/Cosmian/kms/actions/runs/$RUN_ID/jobs" \
  --jq '.jobs[] | select(.conclusion == "failure") | select(.name | test("arm|docker"; "i") | not) | [.id, .name] | @tsv' 2>/dev/null || echo "")

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

  # Fast path: only scan packaging matrix jobs (both fips + non-fips, static + dynamic).
  # Packaging jobs are named like: ubuntu-24.04-fips-static, macos-15-non-fips-dynamic, ...
  if ! echo "$JOB_NAME" | grep -qE '^(ubuntu-|macos-).+-(fips|non-fips)-(static|dynamic)$'; then
    continue
  fi

  echo "Processing job $JOB_ID${JOB_NAME:+ ($JOB_NAME)}..."

  # Parse logs for hash mismatches
  # Pattern:
  #   error: hash mismatch in fixed-output derivation '/nix/store/...-name.drv':
  #            specified: sha256-XXXX
  #               got:    sha256-YYYY

  # Stream only failed-step logs for this job (much smaller than full job log archives).
  # Output format is typically: "<STEP NAME> | <log line>".
  last_drv_name=""
  while IFS= read -r raw_line; do
    line="$raw_line"

    # If `gh` associates log lines with steps, filter to the packaging step.
    # If not (e.g., UNKNOWN STEP), keep the line (still only failed steps).
    if [[ "$line" == *"|"* ]]; then
      step_name=${line%%|*}
      step_name=${step_name%" "}
      msg=${line#*|}
      msg=${msg#" "}
      if [[ "$step_name" != *"Package with GPG signature"* ]] && [[ "$step_name" != *"UNKNOWN STEP"* ]]; then
        continue
      fi
      line="$msg"
    fi

    # Capture derivation name from error line
    if [[ "$line" =~ hash\ mismatch\ in\ fixed-output\ derivation.*\'(/nix/store/[^\']+)\' ]]; then
      drv_path="${BASH_REMATCH[1]}"
      drv_name="${drv_path##*/}"
      last_drv_name="${drv_name%.drv}"
      continue
    fi

    # Capture the "got" hash
    if [[ "$line" == *"got:"* ]] && [[ "$line" =~ (sha256-[A-Za-z0-9+/=]+) ]]; then
      got_hash="${BASH_REMATCH[1]}"

      if [ -n "$got_hash" ] && [ -n "$last_drv_name" ]; then
        target_file=""

        # UI npm deps (both fips and non-fips share the same npm deps)
        if [[ "$last_drv_name" =~ ui-deps-(fips|non-fips).*-npm-deps ]]; then
          target_file="$EXPECTED_DIR/ui.npm.sha256"
        # UI wasm vendor - fips
        elif [[ "$last_drv_name" =~ ui-wasm-fips.*-vendor ]]; then
          target_file="$EXPECTED_DIR/ui.vendor.fips.sha256"
        # UI wasm vendor - non-fips
        elif [[ "$last_drv_name" =~ ui-wasm-non-fips.*-vendor ]]; then
          target_file="$EXPECTED_DIR/ui.vendor.non-fips.sha256"
        # Server vendor (Cargo vendoring). Derivation names do not reliably include platform/linkage;
        # infer those from the GitHub Actions job name.
        elif [[ "$last_drv_name" =~ (kms-server|server).*vendor|(^|-)vendor($|-) ]]; then
          if [[ "$JOB_NAME" == *"macos"* ]] || [[ "$JOB_NAME" == *"darwin"* ]]; then
            if [[ "$JOB_NAME" == *"static"* ]]; then
              target_file="$EXPECTED_DIR/server.vendor.static.darwin.sha256"
            elif [[ "$JOB_NAME" == *"dynamic"* ]]; then
              target_file="$EXPECTED_DIR/server.vendor.dynamic.darwin.sha256"
            else
              FILE_TO_HASH["$EXPECTED_DIR/server.vendor.static.darwin.sha256"]="$got_hash"
              FILE_TO_HASH["$EXPECTED_DIR/server.vendor.dynamic.darwin.sha256"]="$got_hash"
              echo "  Found hash for $EXPECTED_DIR/server.vendor.static.darwin.sha256: $got_hash"
              echo "  Found hash for $EXPECTED_DIR/server.vendor.dynamic.darwin.sha256: $got_hash"
              target_file=""
            fi
          else
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
  done < <(gh run view "$RUN_ID" --log-failed --job "$JOB_ID" 2>/dev/null || true)
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
