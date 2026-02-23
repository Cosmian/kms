#!/usr/bin/env bash
# Update expected hashes by reading the latest CI workflow run for the current branch
# from GitHub Actions and extracting fixed-output derivation hash mismatches.
#
# It looks for log patterns like:
#   specified: sha256-XXX
#   got:       sha256-YYY
#
# Usage:
#   update_hashes.sh
#   update_hashes.sh <RUN_ID>
#   update_hashes.sh <RUN_ID> <JOB_ID>
#   update_hashes.sh <actions-run-or-job-url>
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXPECTED_DIR="$REPO_ROOT/nix/expected-hashes"
shopt -s nocasematch

# Check if gh CLI is available
if ! command -v gh &>/dev/null; then
  echo "Error: gh CLI is not installed. Please install it from https://cli.github.com/" >&2
  exit 1
fi

DEFAULT_FALLBACK_RUN_ID="22031087521"

RUN_ID=""
JOB_ID=""
ARGS_PROVIDED="false"

parse_args() {
  if [ $# -eq 0 ]; then
    return 0
  fi

  if [ $# -eq 1 ]; then
    local arg="$1"
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      RUN_ID="$arg"
      return 0
    fi

    # Accept a full Actions URL:
    #   https://github.com/<org>/<repo>/actions/runs/<RUN_ID>
    #   https://github.com/<org>/<repo>/actions/runs/<RUN_ID>/job/<JOB_ID>
    # Note: When a URL contains a job id, we still scan the whole run.
    # To force a single-job scan, pass two numeric args: <RUN_ID> <JOB_ID>.
    if [[ "$arg" =~ /actions/runs/([0-9]+)(/job/([0-9]+))? ]]; then
      RUN_ID="${BASH_REMATCH[1]}"
      JOB_ID=""
      return 0
    fi

    echo "Error: Unsupported argument '$arg'" >&2
    echo "Expected: RUN_ID, RUN_ID+JOB_ID URL, or no args" >&2
    exit 2
  fi

  if [ $# -eq 2 ]; then
    if [[ "$1" =~ ^[0-9]+$ ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
      RUN_ID="$1"
      JOB_ID="$2"
      return 0
    fi
    echo "Error: Expected numeric RUN_ID and JOB_ID" >&2
    exit 2
  fi

  echo "Error: Too many arguments" >&2
  exit 2
}

if [ $# -gt 0 ]; then
  ARGS_PROVIDED="true"
fi
parse_args "$@"

# Get current git branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ -z "$CURRENT_BRANCH" ]; then
  echo "Error: Could not determine current git branch" >&2
  exit 1
fi

if [ -z "$RUN_ID" ]; then
  echo "Fetching latest CI workflow run for branch: $CURRENT_BRANCH..."

  # Fetch recent workflow runs on this branch.
  # Prefer failures (likely hash mismatches), then fall back to the newest completed run.
  # shellcheck disable=SC2016  # $runs is a jq variable, not a shell variable
  RUN_ID=$(gh run list --branch "$CURRENT_BRANCH" --limit 50 --json databaseId,status,conclusion \
    --jq 'map(select(.status=="completed" and .conclusion != "cancelled")) as $runs |
          ($runs | map(select(.conclusion=="failure")) | .[0].databaseId) // ($runs | .[0].databaseId)')

  if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
    echo "Warning: Could not auto-detect a workflow run for branch '$CURRENT_BRANCH'." >&2
    echo "Falling back to a known run for now: run=$DEFAULT_FALLBACK_RUN_ID" >&2
    RUN_ID="$DEFAULT_FALLBACK_RUN_ID"
    JOB_ID=""
  fi
fi

echo "Using workflow run: $RUN_ID${JOB_ID:+ (job: $JOB_ID)}"

echo "Fetching jobs..."

FAILED_JOBS=""

if [ -n "$JOB_ID" ]; then
  # If a specific job is requested, process it even if it did not fail.
  JOB_NAME=$(gh api "repos/Cosmian/kms/actions/jobs/$JOB_ID" --jq '.name' 2>/dev/null || echo "")
  FAILED_JOBS=$(printf "%s\t%s\n" "$JOB_ID" "$JOB_NAME")
else
  # Get all failed jobs from this run (id + name).
  # We rely on the job name (when available) to infer platform/linkage for server vendor hashes.
  FAILED_JOBS=$(gh api "repos/Cosmian/kms/actions/runs/$RUN_ID/jobs" \
    --jq '.jobs[]
          | select((.conclusion == "failure") or (.status == "in_progress"))
          | [.id, .name] | @tsv' 2>/dev/null || echo "")

  if [ -z "$FAILED_JOBS" ]; then
    echo "No failed or in-progress jobs found in run $RUN_ID. Nothing to update."
    exit 0
  fi
fi

# Declare associative array to store hash updates
declare -A FILE_TO_HASH

stream_job_logs() {
  local run_id="$1"
  local job_id="$2"
  local tmp
  tmp=$(mktemp -t gha-job-log.XXXXXX)

  # Prefer `gh run view` (nice formatting and smaller for failed steps),
  # but it may refuse logs while the overall run is still in progress.
  if gh run view "$run_id" --log-failed --job "$job_id" >"$tmp" 2>/dev/null; then
    cat "$tmp"
    rm -f "$tmp"
    return 0
  fi

  if gh run view "$run_id" --log --job "$job_id" >"$tmp" 2>/dev/null; then
    cat "$tmp"
    rm -f "$tmp"
    return 0
  fi

  # Fallback: fetch raw job logs directly (works even if run is still running).
  rm -f "$tmp"
  gh api "repos/Cosmian/kms/actions/jobs/$job_id/logs" 2>/dev/null || true
}

# Process each failed job
while IFS=$'\t' read -r JOB_ID JOB_NAME; do
  [ -z "${JOB_ID:-}" ] && continue
  JOB_NAME=${JOB_NAME:-""}

  echo "Processing job $JOB_ID${JOB_NAME:+ ($JOB_NAME)}..."

  # Parse logs for hash mismatches
  # Pattern:
  #   error: hash mismatch in fixed-output derivation '/nix/store/...-name.drv':
  #            specified: sha256-XXXX
  #               got:    sha256-YYYY

  # Stream failed-step logs for this job (much smaller than full job log archives).
  # If a specific job was requested and it didn't fail, fall back to the full job log.
  # Output format is typically: "<STEP NAME> | <log line>".
  last_drv_name=""

  while IFS= read -r raw_line; do
    line="$raw_line"

    # If `gh` associates log lines with steps, strip the step prefix.
    if [[ "$line" == *"|"* ]]; then
      msg=${line#*|}
      msg=${msg#" "}
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
        # infer linkage from the GitHub Actions job name. Linux and Darwin share the same hash files.
        elif [[ "$last_drv_name" =~ (kms-server|server).*vendor|(^|-)vendor($|-) ]]; then
          if [[ "$JOB_NAME" == *"dynamic"* ]]; then
            target_file="$EXPECTED_DIR/server.vendor.dynamic.sha256"
          elif [[ "$JOB_NAME" == *"static"* ]] || [[ "$JOB_NAME" == *"docker"* ]]; then
            target_file="$EXPECTED_DIR/server.vendor.static.sha256"
          else
            # Docker packaging builds are always static-linked.
            FILE_TO_HASH["$EXPECTED_DIR/server.vendor.static.sha256"]="$got_hash"
            FILE_TO_HASH["$EXPECTED_DIR/server.vendor.dynamic.sha256"]="$got_hash"
            echo "  Found hash for $EXPECTED_DIR/server.vendor.static.sha256: $got_hash"
            echo "  Found hash for $EXPECTED_DIR/server.vendor.dynamic.sha256: $got_hash"
            target_file=""
          fi
        fi

        if [ -n "$target_file" ]; then
          FILE_TO_HASH["$target_file"]="$got_hash"
          echo "  Found hash for $target_file: $got_hash"
        fi

        last_drv_name=""
      fi
    fi
  done < <(stream_job_logs "$RUN_ID" "$JOB_ID")
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
  if [ "$ARGS_PROVIDED" = "false" ] && [ "$RUN_ID" != "$DEFAULT_FALLBACK_RUN_ID" ]; then
    echo "No hashes found in auto-selected run ($RUN_ID). Retrying fallback run/job..." >&2
    exec "$0" "$DEFAULT_FALLBACK_RUN_ID"
  fi
  echo "No hashes found to update." >&2
  echo "This could mean:" >&2
  echo "  - No hash mismatches were found in the workflow run" >&2
  echo "  - The workflow run is still in progress" >&2
  echo "  - The failed jobs don't contain hash mismatch errors" >&2
  exit 1
fi

echo "Done. Updated $updated_count expected-hash file(s)."
