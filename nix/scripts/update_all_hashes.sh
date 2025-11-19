#!/usr/bin/env bash
# Cosmian KMS - Automated Hash Update Script
#
# This script updates all expected hashes for the current architecture:
# - Cargo vendor hash (cargoHash in kms-server.nix)
# - Binary hashes for FIPS and non-FIPS variants
#
# Usage:
#   bash nix/scripts/update_all_hashes.sh [--vendor-only|--binary-only]
#
# Options:
#   --vendor-only   Only update the Cargo vendor hash
#   --binary-only   Only update binary hashes (skip vendor)
#   --help          Show this help message
#
# Requirements:
#   - Nix package manager installed
#   - Working directory must be repository root
#   - Network access (for vendor hash update)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory and repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NIX_DIR="$REPO_ROOT/nix"

# Detect current platform
CURRENT_SYSTEM="$(nix-instantiate --eval -E 'builtins.currentSystem' | tr -d '"')"

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

usage() {
    cat <<'EOF'
Cosmian KMS - Automated Hash Update Script

Usage:
  bash nix/scripts/update_all_hashes.sh [OPTIONS]

Options:
  --vendor-only   Only update the Cargo vendor hash (cargoHash)
  --binary-only   Only update binary hashes (skip vendor update)
  --help          Show this help message

Examples:
  # Update all hashes for current platform
  bash nix/scripts/update_all_hashes.sh

  # Update only the Cargo vendor hash after dependency changes
  bash nix/scripts/update_all_hashes.sh --vendor-only

  # Update only binary hashes after code changes
  bash nix/scripts/update_all_hashes.sh --binary-only

Platform support:
  - x86_64-linux (Intel/AMD Linux)
  - aarch64-linux (ARM64 Linux)
  - aarch64-darwin (Apple Silicon macOS)

Note: Vendor hash may differ between macOS and Linux due to
platform-specific dependencies.
EOF
}

# Parse command line arguments
UPDATE_VENDOR=true
UPDATE_BINARY=true

for arg in "$@"; do
    case $arg in
    --vendor-only)
        UPDATE_BINARY=false
        ;;
    --binary-only)
        UPDATE_VENDOR=false
        ;;
    --help)
        usage
        exit 0
        ;;
    *)
        error "Unknown option: $arg"
        usage
        exit 1
        ;;
    esac
done

# Change to repository root
cd "$REPO_ROOT"

log "Platform: $CURRENT_SYSTEM"
log "Update vendor hash: $UPDATE_VENDOR"
log "Update binary hashes: $UPDATE_BINARY"
echo ""

# ============================================================================
# Step 1: Update Cargo vendor hash (cargoHash)
# ============================================================================

update_vendor_hash() {
    log "Updating Cargo vendor hash (cargoHash)..."

    # Temporarily set an incorrect hash to trigger the error that reveals the real hash
    local temp_hash="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    # Create a temporary Nix file to get the vendor hash
    local nix_expr
    nix_expr=$(
        cat <<'NIXEXPR'
let
  pkgs = import <nixpkgs> {};
  src = pkgs.lib.cleanSourceWith {
    src = ./.;
    filter = path: type:
      let baseName = baseNameOf path;
      in !(pkgs.lib.hasPrefix "result-" baseName ||
           pkgs.lib.hasPrefix "SBOM-" baseName ||
           baseName == "sbom" ||
           baseName == "sbom-fips" ||
           baseName == "target");
  };
in
pkgs.rustPlatform.buildRustPackage {
  pname = "cosmian-kms-server";
  version = "0.0.0";
  inherit src;
  cargoLock = { lockFile = ./Cargo.lock; };
  cargoDeps = pkgs.rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };
  dontBuild = true;
  installPhase = "mkdir -p $out";
}
NIXEXPR
    )

    log "Attempting Nix build to discover vendor hash..."

    # Try to build and capture the hash from the error message
    local build_output
    local new_vendor_hash

    if build_output=$(nix-build -E "$nix_expr" 2>&1); then
        error "Build succeeded unexpectedly. Cannot determine vendor hash."
        return 1
    fi

    # Extract the "got:" hash from error message
    new_vendor_hash=$(echo "$build_output" | grep -oP 'got:\s+\Ksha256-[A-Za-z0-9+/=]+' || true)

    if [[ -z "$new_vendor_hash" ]]; then
        # Alternative: try using nix-prefetch
        log "Trying alternative method with nix-prefetch..."
        new_vendor_hash=$(nix-shell -p nix-prefetch --run "nix-prefetch '{ sha256 }: (import $NIX_DIR/kms-server.nix { }).cargoDeps.overrideAttrs (_: { outputHash = sha256; })'" 2>/dev/null || true)
    fi

    if [[ -z "$new_vendor_hash" ]]; then
        error "Could not determine vendor hash automatically."
        echo ""
        warn "Manual steps:"
        echo "1. Edit nix/kms-server.nix and set an incorrect cargoHash"
        echo "2. Run: nix-build -A kms-server-fips"
        echo "3. Copy the 'got:' hash from the error message"
        echo "4. Update nix/kms-server.nix with the correct hash"
        return 1
    fi

    log "Discovered vendor hash: $new_vendor_hash"

    # Update kms-server.nix
    local kms_server_nix="$NIX_DIR/kms-server.nix"

    # Find the current hash and replace it
    if grep -q "sha256-" "$kms_server_nix"; then
        # Create a backup
        cp "$kms_server_nix" "$kms_server_nix.backup"

        # Platform-specific update logic
        case "$CURRENT_SYSTEM" in
        x86_64-linux)
            # Update Linux hash on line ~123
            sed -i "s/sha256-[A-Za-z0-9+\/=]\{44\}/$new_vendor_hash/g" "$kms_server_nix"
            ;;
        aarch64-darwin)
            # Update macOS hash on line ~115
            sed -i '' "s/sha256-[A-Za-z0-9+\/=]\{44\}/$new_vendor_hash/g" "$kms_server_nix"
            ;;
        *)
            sed -i "s/sha256-[A-Za-z0-9+\/=]\{44\}/$new_vendor_hash/g" "$kms_server_nix"
            ;;
        esac

        success "Updated cargoHash in $kms_server_nix"
        rm -f "$kms_server_nix.backup"
    else
        error "Could not find existing hash in $kms_server_nix"
        return 1
    fi
}

# ============================================================================
# Step 2: Build binaries and update expected hashes
# ============================================================================

update_binary_hash() {
    local variant="$1" # "fips" or "non-fips"
    local features=""

    if [[ "$variant" == "non-fips" ]]; then
        features="--features non-fips"
    fi

    log "Building $variant variant..."

    # Build using Nix
    local result_link="result-server-$variant"
    if ! nix-build -A "kms-server-$variant" -o "$result_link"; then
        error "Nix build failed for $variant variant"
        return 1
    fi

    # Compute hash
    local binary_path="$result_link/bin/cosmian_kms"
    if [[ ! -f "$binary_path" ]]; then
        error "Binary not found at $binary_path"
        return 1
    fi

    local new_hash
    new_hash=$(sha256sum "$binary_path" | cut -d' ' -f1)

    log "Computed hash for $variant: $new_hash"

    # Update expected hash file
    local hash_file="$NIX_DIR/expected-hashes/${variant}.${CURRENT_SYSTEM}.sha256"

    # Create directory if it doesn't exist
    mkdir -p "$NIX_DIR/expected-hashes"

    # Write new hash
    echo "$new_hash" >"$hash_file"

    success "Updated $hash_file"
}

# ============================================================================
# Main execution
# ============================================================================

main() {
    echo "=================================================="
    echo "  Cosmian KMS - Hash Update Script"
    echo "  Platform: $CURRENT_SYSTEM"
    echo "=================================================="
    echo ""

    # Step 1: Update vendor hash
    if [[ "$UPDATE_VENDOR" == "true" ]]; then
        update_vendor_hash || {
            error "Failed to update vendor hash"
            exit 1
        }
        echo ""
    fi

    # Step 2: Update binary hashes
    if [[ "$UPDATE_BINARY" == "true" ]]; then
        for variant in fips non-fips; do
            update_binary_hash "$variant" || {
                error "Failed to update $variant binary hash"
                exit 1
            }
            echo ""
        done
    fi

    echo "=================================================="
    success "All hashes updated successfully!"
    echo "=================================================="
    echo ""

    # Show summary
    log "Summary of changes:"
    if [[ "$UPDATE_VENDOR" == "true" ]]; then
        echo "  - Cargo vendor hash (cargoHash) in nix/kms-server.nix"
    fi
    if [[ "$UPDATE_BINARY" == "true" ]]; then
        echo "  - Binary hash: nix/expected-hashes/fips.$CURRENT_SYSTEM.sha256"
        echo "  - Binary hash: nix/expected-hashes/non-fips.$CURRENT_SYSTEM.sha256"
    fi
    echo ""

    log "Verify changes with:"
    echo "  git diff nix/"
    echo ""

    log "Test the build:"
    echo "  bash .github/scripts/nix.sh build"
    echo ""

    log "Commit changes:"
    echo "  git add nix/"
    echo "  git commit -m \"Update Nix hashes for $CURRENT_SYSTEM\""
}

main "$@"
