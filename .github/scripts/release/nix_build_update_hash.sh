#!/usr/bin/env bash
# Build all Nix derivations (ui → kms-cli → kms-server) and automatically fix
# vendor-hash mismatches without user prompts.
#
# When nix-build fails with a fixed-output derivation hash mismatch the script:
#   1. Extracts the correct hash from the error output.
#   2. Writes it to the matching file under nix/expected-hashes/.
#   3. Retries the same derivation (up to MAX_RETRIES times).
#
# Usage:
#   nix_build_update_hash.sh              # build all derivations
#   nix_build_update_hash.sh -A <attr>   # build one specific derivation
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
EXPECTED_DIR="$REPO_ROOT/nix/expected-hashes"
MAX_RETRIES=3

OS="linux"
[[ "$(uname -s)" == "Darwin" ]] && OS="darwin"

# Ordered list of derivations to build, split by platform:
#   Linux  — all derivations (server + cli + ui wasm + ui pnpm)
#   macOS  — only UI (for ui.pnpm.darwin) + CLI (for cli.vendor.*.darwin)
#             server derivations are Linux-only and must NOT run on macOS.
if [[ "$OS" == "darwin" ]]; then
  ALL_ATTRS=(
    ui-fips
    ui-non-fips
    kms-cli-fips-static-openssl
    kms-cli-non-fips-dynamic-openssl
  )
else
  ALL_ATTRS=(
    ui-fips
    ui-non-fips
    kms-cli-fips-static-openssl
    kms-cli-non-fips-dynamic-openssl
    kms-server-fips-static-openssl
    kms-server-non-fips-dynamic-openssl
  )
fi

# ── hash-file mapping ─────────────────────────────────────────────────────────
# Map a Nix derivation name + the -A attribute to the expected-hash file it controls.
# Returns empty string when not recognized.
drv_to_hash_file() {
  local drv_name="$1"
  local attr="$2"

  if [[ "$drv_name" =~ ui-deps.*(fips|non-fips).*pnpm-deps ]]; then
    echo "$EXPECTED_DIR/ui.pnpm.${OS}.sha256"; return
  fi
  if [[ "$drv_name" =~ ui-wasm-non-fips.*vendor ]]; then
    # ui.vendor.*.sha256 are Linux-only; skip on macOS to avoid overwriting them.
    [[ "$OS" != "linux" ]] && echo "" && return
    echo "$EXPECTED_DIR/ui.vendor.non-fips.sha256"; return
  fi
  if [[ "$drv_name" =~ ui-wasm-fips.*vendor ]]; then
    [[ "$OS" != "linux" ]] && echo "" && return
    echo "$EXPECTED_DIR/ui.vendor.fips.sha256"; return
  fi
  if [[ "$drv_name" =~ (cosmian-kms-cli|ckms).*vendor|cli.*vendor ]]; then
    if [[ "$OS" == "linux" ]]; then
      echo "$EXPECTED_DIR/cli.vendor.linux.sha256"; return
    fi
    local link="static"
    [[ "$drv_name" == *dynamic* || "$attr" == *dynamic* ]] && link="dynamic"
    echo "$EXPECTED_DIR/cli.vendor.${link}.darwin.sha256"; return
  fi
  if [[ "$drv_name" =~ (kms-server|server).*vendor ]]; then
    # server.vendor.*.sha256 are Linux-only; skip on macOS.
    [[ "$OS" != "linux" ]] && echo "" && return
    local link="static"
    [[ "$drv_name" == *dynamic* || "$attr" == *dynamic* ]] && link="dynamic"
    echo "$EXPECTED_DIR/server.vendor.${link}.sha256"; return
  fi
  echo ""
}

# ── single derivation build with auto hash fix ───────────────────────────────
build_attr() {
  local attr="$1"
  local attempt=0

  while true; do
    attempt=$((attempt + 1))
    echo ""
    echo "==> nix-build -A ${attr} (attempt ${attempt}/${MAX_RETRIES})"

    local output exit_code=0
    output=$(cd "$REPO_ROOT" && nix-build -A "$attr" 2>&1) || exit_code=$?

    if [[ "$exit_code" -eq 0 ]]; then
      echo "$output"
      echo "==> OK: ${attr}"
      return 0
    fi

    echo "$output"

    # Strip ANSI colour codes so regexes work reliably on both Linux and macOS
    # (macOS Nix may emit colour escapes that confuse bash's =~ operator).
    local output_plain
    output_plain=$(printf '%s\n' "$output" | sed $'s/\033\\[[0-9;]*[A-Za-z]//g')

    # Parse hash mismatches
    local last_drv="" updated=0 skipped=0
    while IFS= read -r line; do
      if [[ "$line" == *"hash mismatch in fixed-output derivation"* ]]; then
        # Extract /nix/store/...drv without relying on specific quote characters
        if [[ "$line" =~ (/nix/store/[A-Za-z0-9.+_-]+\.drv) ]]; then
          last_drv="${BASH_REMATCH[1]##*/}"
          last_drv="${last_drv%.drv}"
        fi
        continue
      fi
      if [[ "$line" == *"got:"* ]] && [[ "$line" =~ (sha256-[A-Za-z0-9+/=]+) ]]; then
        local got_hash="${BASH_REMATCH[1]}"
        if [[ -n "$got_hash" && -n "$last_drv" ]]; then
          local target_file
          target_file=$(drv_to_hash_file "$last_drv" "$attr")
          if [[ -n "$target_file" ]]; then
            echo "    Updating $(basename "$target_file"): $got_hash"
            echo "$got_hash" > "$target_file"
            updated=$((updated + 1))
          else
            echo "    Skipping (managed by peer OS runner): $last_drv"
            skipped=$((skipped + 1))
          fi
          last_drv=""
        fi
      fi
    done <<<"$output_plain"

    if [[ "$updated" -gt 0 && "$attempt" -lt "$MAX_RETRIES" ]]; then
      echo "==> Updated ${updated} hash file(s), retrying..."
      continue
    fi

    # All remaining failures are hash files owned by the peer OS runner (e.g.
    # ui.vendor.*.sha256 on macOS, or ui.pnpm.darwin.sha256 on Linux).  Those
    # will be fixed by the other matrix job; this runner is done.
    if [[ "$updated" -eq 0 && "$skipped" -gt 0 ]]; then
      echo "==> ${skipped} hash mismatch(es) are managed by the peer OS runner — skipping."
      return 0
    fi

    echo "ERROR: nix-build -A ${attr} failed after ${attempt} attempt(s)." >&2
    return 1
  done
}

# ── main ──────────────────────────────────────────────────────────────────────
# If called with -A <attr>, build only that one; otherwise build all in order.
if [[ "$#" -ge 2 && "$1" == "-A" ]]; then
  build_attr "$2"
else
  for attr in "${ALL_ATTRS[@]}"; do
    build_attr "$attr"
  done
  echo ""
  echo "==> All Nix derivations built successfully."
fi
