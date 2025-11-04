#!/usr/bin/env bash
# Cosmian KMS - Automated Hash Update Script
#
# This script updates all expected hashes for the current architecture:
# - Cargo vendor hash (cargoHash in kms-server.nix)
# - Binary hashes for FIPS and non-FIPS variants
#
# Usage:
#   bash nix/scripts/update_all_hashes.sh [OPTIONS]
#
# Options:
#   --vendor-only          Only update the Cargo vendor hash
#   --binary-only          Only update binary hashes (skip vendor)
#   --variant <fips|non-fips>  Update specific variant (default: both)
#   --help                 Show this help message
#
# Requirements:
#   - Nix package manager installed
#   - Working directory must be repository root
#   - Network access (for vendor hash update)

set -euo pipefail

# Script directory and repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Helper function to compute SHA256
compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

# Show usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Updates expected hashes for Cosmian KMS Nix builds on current platform.

Options:
  --vendor-only          Only update the Cargo vendor hash (cargoHash)
  --binary-only          Only update binary hashes (skip vendor)
  --variant <fips|non-fips>  Update specific variant (default: both)
  --help                 Show this help message

Examples:
  $0                           # Update all hashes (vendor + binaries)
  $0 --vendor-only             # Update only Cargo vendor hash
  $0 --binary-only             # Update only binary hashes
  $0 --variant fips            # Update only FIPS variant
  $0 --binary-only --variant non-fips  # Update only non-FIPS binary hash

When to use:
  --vendor-only    After updating Cargo.lock (dependency changes)
  --binary-only    After code changes (keeps vendor hash unchanged)
  (no flags)       After both dependency and code changes

Platform support:
  - x86_64-linux (Intel/AMD Linux)
  - aarch64-linux (ARM64 Linux)
  - aarch64-darwin (Apple Silicon macOS)
EOF
    exit 0
}

# Parse command-line arguments
UPDATE_VENDOR=true
UPDATE_BINARY=true
VARIANT=""

while [ $# -gt 0 ]; do
    case "$1" in
    --vendor-only)
        UPDATE_BINARY=false
        shift
        ;;
    --binary-only)
        UPDATE_VENDOR=false
        shift
        ;;
    --variant)
        VARIANT="${2:-}"
        if [ -z "$VARIANT" ]; then
            echo "Error: --variant requires an argument (fips or non-fips)" >&2
            exit 1
        fi
        shift 2
        ;;
    --help | -h)
        usage
        ;;
    *)
        echo "Error: Unknown option: $1" >&2
        echo "Run '$0 --help' for usage information." >&2
        exit 1
        ;;
    esac
done

# Detect current platform
CURRENT_SYSTEM="$(nix-instantiate --eval -E 'builtins.currentSystem' | tr -d '"')"

echo "Updating expected hashes for current platform..."
echo "Platform: $CURRENT_SYSTEM"
echo "Update vendor hash: $UPDATE_VENDOR"
echo "Update binary hashes: $UPDATE_BINARY"
if [ -n "$VARIANT" ]; then
    echo "Variant: $VARIANT"
else
    echo "Variant: both (fips and non-fips)"
fi
echo ""

# Step 1: Update vendor hash (if requested)
if [ "$UPDATE_VENDOR" = "true" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 1: Updating Cargo vendor hash..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Use the variant for build, defaulting to fips
    BUILD_VARIANT="${VARIANT:-fips}"

    # Trigger a Nix build that will fail with the correct hash
    echo "Building to discover vendor hash..."

    if BUILD_OUTPUT=$(nix-build -A "kms-server-$BUILD_VARIANT" -o "result-server-$BUILD_VARIANT" 2>&1); then
        echo "Build succeeded (vendor hash already correct)"
    else
        # Extract the "got:" hash from error message
        # Use sed instead of grep -P for macOS compatibility
        NEW_VENDOR_HASH=$(echo "$BUILD_OUTPUT" | sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' | head -1 || true)

        if [ -n "$NEW_VENDOR_HASH" ]; then
            echo "Discovered vendor hash: $NEW_VENDOR_HASH"

            # Update kms-server.nix
            KMS_SERVER_NIX="$REPO_ROOT/nix/kms-server.nix"

            # Platform-specific sed syntax
            # Use a non-slash delimiter to avoid replacement errors with '/'
            if [ "$(uname)" = "Darwin" ]; then
                sed -i '' "s@sha256-[A-Za-z0-9+/=]\{44\}@$NEW_VENDOR_HASH@g" "$KMS_SERVER_NIX"
            else
                sed -i "s@sha256-[A-Za-z0-9+/=]\{44\}@$NEW_VENDOR_HASH@g" "$KMS_SERVER_NIX"
            fi

            echo "✅ Updated cargoHash in $KMS_SERVER_NIX"
        else
            echo "⚠️  Could not extract vendor hash from build output"
            echo "Vendor hash may already be correct or build failed for another reason"
        fi
    fi
    echo ""
fi

# Step 2: Update binary hashes (if requested)
if [ "$UPDATE_BINARY" = "true" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 2: Updating binary hashes..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Determine which variants to update based on --variant flag
    if [ -n "$VARIANT" ]; then
        VARIANTS_TO_UPDATE="$VARIANT"
    else
        # Default: update both FIPS and non-FIPS
        VARIANTS_TO_UPDATE="fips non-fips"
    fi

    # Update both static and dynamic builds for each variant
    for build_variant in $VARIANTS_TO_UPDATE; do
        for link_mode in static dynamic; do
            echo ""
            echo "Building $build_variant variant ($link_mode linkage)..."

            # Determine Nix attribute name
            # Use -no-openssl suffix for dynamic builds (backward compatibility)
            if [ "$link_mode" = "dynamic" ]; then
                NIX_ATTR="kms-server-${build_variant}-no-openssl"
                VARIANT_SUFFIX="${build_variant}-no-openssl"
            else
                NIX_ATTR="kms-server-${build_variant}"
                VARIANT_SUFFIX="${build_variant}"
            fi

            # Build using Nix with deterministic hash enforcement disabled
            # This allows the build to succeed even if the hash doesn't match yet
            RESULT_LINK="result-server-${VARIANT_SUFFIX}"
            if ! nix-build --arg enforceDeterministicHash false -A "$NIX_ATTR" -o "$RESULT_LINK"; then
                echo "❌ Nix build failed for $build_variant variant ($link_mode)"
                exit 1
            fi

            # Compute hash
            BINARY_PATH="$RESULT_LINK/bin/cosmian_kms"
            if [ ! -f "$BINARY_PATH" ]; then
                echo "❌ Binary not found at $BINARY_PATH"
                exit 1
            fi

            NEW_HASH=$(compute_sha256 "$BINARY_PATH")

            echo "Computed hash for $build_variant ($link_mode): $NEW_HASH"

            # Update expected hash file using new naming convention:
            #   <fips|non-fips>-.<openssl|non-openssl>.<arch>.<os>.sha256
            ARCH="${CURRENT_SYSTEM%%-*}"
            OS="${CURRENT_SYSTEM#*-}"
            IMPL=$([ "$link_mode" = "dynamic" ] && echo non-openssl || echo openssl)
            HASH_FILE="$REPO_ROOT/nix/expected-hashes/${build_variant}-.${IMPL}.${ARCH}.${OS}.sha256"

            # Create directory if it doesn't exist
            mkdir -p "$REPO_ROOT/nix/expected-hashes"

            # Write new hash
            echo "$NEW_HASH" >"$HASH_FILE"

            echo "✅ Updated $HASH_FILE"
        done
    done
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Hash update complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Summary of changes:"
if [ "$UPDATE_VENDOR" = "true" ]; then
    echo "  ✓ Cargo vendor hash (cargoHash) in nix/kms-server.nix"
fi
if [ "$UPDATE_BINARY" = "true" ]; then
    for build_variant in $VARIANTS_TO_UPDATE; do
        ARCH="${CURRENT_SYSTEM%%-*}"
        OS="${CURRENT_SYSTEM#*-}"
        echo "  ✓ Binary hash (static): nix/expected-hashes/${build_variant}-.openssl.${ARCH}.${OS}.sha256"
        echo "  ✓ Binary hash (dynamic): nix/expected-hashes/${build_variant}-.non-openssl.${ARCH}.${OS}.sha256"
    done
fi
echo ""
echo "Next steps:"
echo "  1. Review changes:   git diff nix/"
echo "  2. Test the build:   bash .github/scripts/nix.sh build"
echo "  3. Commit changes:   git add nix/ && git commit -m 'Update Nix hashes for $CURRENT_SYSTEM'"
echo ""
