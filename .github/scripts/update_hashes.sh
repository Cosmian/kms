#!/usr/bin/env bash
# Update expected hashes for all server/ui variants by parsing build output
# It runs packaging for the four combinations and updates files in nix/expected-hashes
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXPECTED_DIR="$REPO_ROOT/nix/expected-hashes"
LOG_DIR="${TMPDIR:-/tmp}/kms-update-hashes"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/packaging_$(date +%s).log"

run_package() {
  local variant="$1" link="$2"
  echo "### RUN variant=$variant link=$link" | tee -a "$LOG_FILE"
  # Capture both stdout and stderr; do not stop on failure
  bash "$REPO_ROOT/.github/scripts/nix.sh" --variant "$variant" --link "$link" package 2>&1 | tee -a "$LOG_FILE" || true
}

# Run all four combinations (dynamic/static x fips/non-fips)
run_package fips dynamic
run_package fips static
run_package non-fips dynamic
run_package non-fips static

# Parse build log and collect mappings of file -> got sha256
# Expected lines look like:
#   <path>/nix/expected-hashes/<name>.sha256
#   specified: sha256: <hex>
#   got:       sha256: <hex>
# We update <path>.sha256 with the "got" value.

declare -A FILE_TO_HASH
current_run_variant=""
current_run_link=""
last_drv_path=""
while IFS= read -r line; do
  # Track which combination we are in
  if [[ "$line" =~ ^###\ RUN\ variant= ]]; then
    current_run_variant=$(echo "$line" | sed -E 's/^### RUN variant=([^ ]+).*/\1/')
    current_run_link=$(echo "$line" | sed -E 's/^### RUN variant=[^ ]+ link=([^ ]+)/\1/')
    continue
  fi
  # Capture the derivation path from error lines to identify what's failing
  if echo "$line" | grep -q "hash mismatch in fixed-output derivation"; then
    last_drv_path=$(echo "$line" | grep -Eo "'/nix/store/[^']+'" | tr -d "'")
  fi
  # For Nix fixed-output mismatch lines, capture the SRI sha256 after 'got:'
  if echo "$line" | grep -q "got:"; then
    sri=$(echo "$line" | grep -Eo "sha256-[A-Za-z0-9+/=]+" | head -n1 || true)
    if [ -n "${sri:-}" ] && [ -n "$current_run_variant" ] && [ -n "$current_run_link" ]; then
      # Determine which file to update based on the derivation path
      file=""
      # Check if this is a UI vendor hash (wasm vendor derivation)
      if echo "$last_drv_path" | grep -qE "ui-wasm-(fips|non-fips).*-vendor"; then
        if [ "$current_run_variant" = "fips" ]; then
          file="$EXPECTED_DIR/ui.vendor.fips.sha256"
        else
          file="$EXPECTED_DIR/ui.vendor.non-fips.sha256"
        fi
      # Check if this is a UI npm deps hash
      elif echo "$last_drv_path" | grep -qE "ui-deps-(fips|non-fips).*-npm-deps"; then
        file="$EXPECTED_DIR/ui.npm.sha256"
      # Otherwise, map server vendor hashes based on platform
      else
        os=$(uname)
        case "$os" in
        Darwin)
          # server vendor hash
          if [ "$current_run_link" = "dynamic" ]; then
            file="$EXPECTED_DIR/server.vendor.dynamic.darwin.sha256"
          else
            file="$EXPECTED_DIR/server.vendor.static.darwin.sha256"
          fi
          ;;
        Linux)
          # server vendor hash on Linux
          file="$EXPECTED_DIR/server.vendor.linux.sha256"
          ;;
        *)
          file=""
          ;;
        esac
      fi
      if [ -n "$file" ]; then
        FILE_TO_HASH["$file"]="$sri"
      fi
    fi
  fi
done <"$LOG_FILE"

# Apply updates
updated_count=0
for file in "${!FILE_TO_HASH[@]}"; do
  hash="${FILE_TO_HASH[$file]}"
  if [ -f "$file" ]; then
    echo "$hash" >"$file"
    echo "Updated $file -> $hash"
    updated_count=$((updated_count + 1))
  else
    # If file is missing, create it under expected dir using its basename
    base=$(basename "$file")
    out="$EXPECTED_DIR/$base"
    echo "$hash" >"$out"
    echo "Created $out -> $hash"
    updated_count=$((updated_count + 1))
  fi
done

if [ "$updated_count" -eq 0 ]; then
  echo "No hashes found to update. Check $LOG_FILE for details." >&2
  exit 1
fi

echo "Done. Updated $updated_count expected-hash file(s)."
