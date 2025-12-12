#!/usr/bin/env bash
# Update expected hashes for all server/ui variants by parsing build output
# It runs packaging for the four combinations and updates files in nix/expected-hashes
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXPECTED_DIR="$REPO_ROOT/nix/expected-hashes"
LOG_DIR="${TMPDIR:-/tmp}/kms-update-hashes"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/packaging_$(date +%s).log"

# As requested, start by removing all existing expected-hash files
echo "Cleaning existing expected hashes in $EXPECTED_DIR…"
find "$EXPECTED_DIR" -maxdepth 1 -type f -name '*.sha256' -print -delete || true

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
  # Track UI WASM vendor derivations even when there's no mismatch
  if echo "$line" | grep -qE "^building '/nix/store/.*-ui-wasm-(fips|non-fips).*vendor.tar.gz.drv'"; then
    ui_drv=$(echo "$line" | grep -Eo "'/nix/store/[^']+'" | tr -d "'")
    if [ -n "$ui_drv" ] && [ -n "$current_run_variant" ]; then
      # Persist last seen UI vendor drv per variant (sanitize '-' to '_')
      sanitized_variant="${current_run_variant//-/_}"
      eval "UI_VENDOR_DRV_${sanitized_variant}='$ui_drv'"
    fi
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

# Fallback: ensure UI vendor hashes exist by computing from drv outputs
# Adds robust logging, discovery from log, and sanitized variant handling
for variant in fips non-fips; do
  sanitized_variant="${variant//-/_}"
  drv_var="UI_VENDOR_DRV_${sanitized_variant}"
  ui_drv_path="${!drv_var:-}"
  if [ "$variant" = "fips" ]; then
    target_file="$EXPECTED_DIR/ui.vendor.fips.sha256"
  else
    target_file="$EXPECTED_DIR/ui.vendor.non-fips.sha256"
  fi

  if [[ -f "$target_file" ]]; then
    echo "[fallback] $target_file already exists; keeping it"
    continue
  fi

  if [[ -z "$ui_drv_path" ]]; then
    echo "[fallback] No UI vendor drv recorded for variant=$variant; attempting discovery from log"
    discovered=$(grep -E "cosmian-kms-ui-wasm-${variant}.*vendor\\.tar\\.gz\\.drv" "$LOG_FILE" | tail -n1 | sed -E "s/.*'([^']+)'/\1/" | xargs)
    if [[ -n "$discovered" ]]; then
      echo "[fallback] Discovered UI vendor drv for $variant: $discovered"
      ui_drv_path="$discovered"
    else
      echo "[fallback] Could not discover UI vendor drv for $variant; skipping"
      continue
    fi
  fi
  # Normalize/trim any whitespace around the drv path
  ui_drv_path=$(echo "$ui_drv_path" | xargs)

  # First, try to trigger a build of the drv to capture a fixed-output mismatch and parse the 'got:' SRI
  echo "[fallback] Building UI vendor drv to capture SRI (drv=$ui_drv_path, variant=$variant)"
  tmp_log="$LOG_DIR/ui_vendor_${sanitized_variant}_$(date +%s).log"
  nix-store -r "$ui_drv_path" 2>&1 | tee "$tmp_log" || true
  sri=$(grep -Eo "got:\s*sha256-[A-Za-z0-9+/=]+" "$tmp_log" | head -n1 | sed -E 's/.*(sha256-[A-Za-z0-9+/=]+).*/\1/' || true)
  if [[ -n "$sri" ]]; then
    echo "$sri" >"$target_file"
    echo "Created $target_file -> $sri"
    updated_count=$((updated_count + 1))
    continue
  fi

  echo "[fallback] No 'got:' SRI found; resolving output path for hashing (drv=$ui_drv_path)"
  echo "[fallback] Resolving outputs for drv=$ui_drv_path (variant=$variant)"
  # Try deriving actual output path via derivation metadata first
  deriv_json=$(nix show-derivation "$ui_drv_path" 2>/dev/null || nix derivation show "$ui_drv_path" 2>/dev/null || true)
  output_path=""
  if [[ -n "$deriv_json" ]]; then
    if command -v jq >/dev/null 2>&1; then
      output_path=$(echo "$deriv_json" | jq -r 'to_entries[0].value.outputs.out.path // empty')
    fi
  fi
  # Fallback to nix-store outputs
  if [[ -z "$output_path" || ! -e "$output_path" ]]; then
    drv_outputs=$(nix-store -q --outputs "$ui_drv_path" || true)
    output_path=$(echo "$drv_outputs" | head -n1)
  fi
  # If still missing, realize and re-query
  if [[ -z "$output_path" || ! -e "$output_path" ]]; then
    echo "[fallback] Output path missing; realizing $ui_drv_path"
    nix-store -r "$ui_drv_path" >/dev/null 2>&1 || true
    drv_outputs=$(nix-store -q --outputs "$ui_drv_path" || true)
    output_path=$(echo "$drv_outputs" | head -n1)
  fi
  if [[ -z "$output_path" ]]; then
    echo "[fallback] Still no output path for $ui_drv_path; skipping"
    continue
  fi

  sri=$(nix hash path --sri "$output_path" | tr -d '\n')
  if [[ -z "$sri" ]]; then
    echo "[fallback] Failed to compute SRI for $output_path; skipping"
    continue
  fi
  echo "$sri" >"$target_file"
  echo "Created $target_file -> $sri"
  updated_count=$((updated_count + 1))
done

if [ "$updated_count" -eq 0 ]; then
  echo "No hashes found to update. Check $LOG_FILE for details." >&2
  exit 1
fi

echo "Done. Updated $updated_count expected-hash file(s)."
