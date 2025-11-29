#!/usr/bin/env bash
# Cosmian KMS - Automated Hash Update Script
#
# This script updates all expected hashes for the current architecture:
# - KMS Server Cargo vendor hashes (cargoHash in kms-server.nix) - 4 variants
# - UI Cargo vendor hashes (cargoHash in ui.nix and default.nix) - 2 variants
# - NPM dependencies hash (npmDepsHash in ui.nix)
# - Binary hashes for FIPS and non-FIPS variants (static/dynamic)
#
# Note: External tool hashes (cargo-generate-rpm, cargo-packager, wasm-bindgen-cli,
#       OpenSSL source) are intentionally NOT updated by this script as they are
#       pinned to specific versions.
#
# Usage:
#   bash nix/scripts/update_all_hashes.sh [OPTIONS]
#
# Options:
#   --vendor-only          Only update Cargo vendor hashes (server + UI)
#   --binary-only          Only update binary hashes (skip vendor)
#   --npm-only             Only update NPM dependencies hash
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
  --vendor-only          Only update Cargo vendor hashes (server + UI)
  --binary-only          Only update binary hashes (skip vendor)
  --npm-only             Only update NPM dependencies hash
  --variant <fips|non-fips>  Update specific variant (default: both)
  --help                 Show this help message

Examples:
  $0                           # Update all hashes (vendor + npm + binaries)
  $0 --vendor-only             # Update only Cargo vendor hashes (server + UI)
  $0 --npm-only                # Update only NPM dependencies hash
  $0 --binary-only             # Update only binary hashes
  $0 --variant fips            # Update only FIPS variant
  $0 --binary-only --variant non-fips  # Update only non-FIPS binary hash

When to use:
  --vendor-only    After updating Cargo.lock (dependency changes)
  --npm-only       After updating package-lock.json (UI dependency changes)
  --binary-only    After code changes (keeps vendor hashes unchanged)
  (no flags)       After both dependency and code changes

Platform support:
  - x86_64-linux (Intel/AMD Linux)
  - aarch64-linux (ARM64 Linux)
  - aarch64-darwin (Apple Silicon macOS)

Hash types updated:
  1. KMS Server Cargo vendor hashes (4 variants: static/dynamic x Darwin/Linux)
  2. UI Cargo vendor hashes (2 variants: FIPS/non-FIPS)
  3. NPM dependencies hash (UI node_modules)
  4. Binary hashes (FIPS/non-FIPS x static/dynamic)

Note: External tool hashes are NOT updated (cargo-generate-rpm, cargo-packager,
      wasm-bindgen-cli, OpenSSL source) as they are pinned to specific versions.
EOF
    exit 0
}

# Parse command-line arguments
UPDATE_VENDOR=true
UPDATE_BINARY=true
UPDATE_NPM=true
VARIANT=""

while [ $# -gt 0 ]; do
    case "$1" in
    --vendor-only)
        UPDATE_BINARY=false
        UPDATE_NPM=false
        shift
        ;;
    --binary-only)
        UPDATE_VENDOR=false
        UPDATE_NPM=false
        shift
        ;;
    --npm-only)
        UPDATE_VENDOR=false
        UPDATE_BINARY=false
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
echo "Update NPM hash: $UPDATE_NPM"
echo "Update binary hashes: $UPDATE_BINARY"
if [ -n "$VARIANT" ]; then
    echo "Variant: $VARIANT"
else
    echo "Variant: both (fips and non-fips)"
fi
echo ""

# Step 1: Update vendor hashes (if requested)
if [ "$UPDATE_VENDOR" = "true" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 1: Updating Cargo vendor hashes..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Update KMS Server vendor hashes for all 4 combinations
    # (static/dynamic x Darwin/Linux for current platform)
    echo ""
    echo "1.1: Updating KMS Server vendor hashes..."

    KMS_SERVER_NIX="$REPO_ROOT/nix/kms-server.nix"

    # Determine which variants to update
    if [ -n "$VARIANT" ]; then
        BUILD_VARIANTS="$VARIANT"
    else
        BUILD_VARIANTS="fips"  # Use FIPS to discover hash (same for both)
    fi

    for BUILD_VARIANT in $BUILD_VARIANTS; do
        for LINK_MODE in static dynamic; do
            echo ""
            echo "Building KMS server ($BUILD_VARIANT, $LINK_MODE) to discover vendor hash..."

            # Determine Nix attribute name
            if [ "$LINK_MODE" = "dynamic" ]; then
                NIX_ATTR="kms-server-${BUILD_VARIANT}-no-openssl"
            else
                NIX_ATTR="kms-server-${BUILD_VARIANT}"
            fi

            # Trigger a Nix build that will fail with the correct hash
            if BUILD_OUTPUT=$(nix-build -A "$NIX_ATTR" -o "result-server-${BUILD_VARIANT}-${LINK_MODE}-vendor" 2>&1); then
                echo "Build succeeded (vendor hash already correct for $LINK_MODE)"
            else
                # Extract the "got:" hash from error message
                NEW_VENDOR_HASH=$(echo "$BUILD_OUTPUT" | sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' | head -1 || true)

                if [ -n "$NEW_VENDOR_HASH" ]; then
                    echo "Discovered vendor hash for $LINK_MODE: $NEW_VENDOR_HASH"

                    # Determine the old hash to replace based on platform and link mode
                    KMS_SERVER_NIX="$REPO_ROOT/nix/kms-server.nix"

                    # Extract hash using awk (much faster than grep chains)
                    if [ "$(uname)" = "Darwin" ]; then
                        if [ "$LINK_MODE" = "static" ]; then
                            # macOS static hash - line ~322
                            OLD_HASH=$(awk '/# macOS vendor hash/{f=1} f && /static then/{getline; match($0, /sha256-[^"]+/); print substr($0, RSTART, RLENGTH); exit}' "$KMS_SERVER_NIX")
                        else
                            # macOS dynamic hash - line ~324
                            OLD_HASH=$(awk '/# macOS vendor hash/{f=1} f && /else/{getline; match($0, /sha256-[^"]+/); print substr($0, RSTART, RLENGTH); exit}' "$KMS_SERVER_NIX")
                        fi
                    else
                        # Linux
                        if [ "$LINK_MODE" = "static" ]; then
                            # Linux static hash - line ~327
                            OLD_HASH=$(awk '/# Linux vendor hash for SERVER/{f=1} f && /if static then/{getline; match($0, /sha256-[^"]+/); print substr($0, RSTART, RLENGTH); exit}' "$KMS_SERVER_NIX")
                        else
                            # Linux dynamic hash - line ~329
                            OLD_HASH=$(awk '/# Linux vendor hash for SERVER/{f=1} f && /else$/{getline; match($0, /sha256-[^"]+/); print substr($0, RSTART, RLENGTH); exit}' "$KMS_SERVER_NIX")
                        fi
                    fi

                    if [ -n "$OLD_HASH" ] && [ "$OLD_HASH" != "$NEW_VENDOR_HASH" ]; then
                        echo "Replacing $(uname) $LINK_MODE hash:"
                        echo "  Old: $OLD_HASH"
                        echo "  New: $NEW_VENDOR_HASH"

                        # Simple string replacement
                        if [ "$(uname)" = "Darwin" ]; then
                            sed -i '' "s|$OLD_HASH|$NEW_VENDOR_HASH|g" "$KMS_SERVER_NIX"
                        else
                            sed -i "s|$OLD_HASH|$NEW_VENDOR_HASH|g" "$KMS_SERVER_NIX"
                        fi

                        echo "✅ Updated KMS server vendor hash ($(uname), $LINK_MODE)"
                    elif [ "$OLD_HASH" = "$NEW_VENDOR_HASH" ]; then
                        echo "Hash already up-to-date for $(uname) $LINK_MODE"
                    else
                        echo "⚠️  Could not extract old hash from $KMS_SERVER_NIX"
                    fi
                else
                    echo "⚠️  Could not extract vendor hash from build output for $LINK_MODE"
                    echo "Vendor hash may already be correct or build failed for another reason"
                fi
            fi
        done
    done

    # Update UI vendor hashes for FIPS and non-FIPS variants
    echo ""
    echo "1.2: Updating UI vendor hashes..."

    UI_NIX="$REPO_ROOT/nix/ui.nix"
    DEFAULT_NIX="$REPO_ROOT/default.nix"

    # Determine which UI variants to update
    if [ -n "$VARIANT" ]; then
        UI_VARIANTS="$VARIANT"
    else
        UI_VARIANTS="fips non-fips"
    fi

    for UI_VARIANT in $UI_VARIANTS; do
        echo ""
        echo "Building UI ($UI_VARIANT) to discover vendor hash..."

        # Trigger a Nix build that will fail with the correct hash
        if BUILD_OUTPUT=$(nix-build -A "ui-${UI_VARIANT}" -o "result-ui-${UI_VARIANT}-vendor" 2>&1); then
            echo "Build succeeded (vendor hash already correct for $UI_VARIANT)"
        else
            # Extract the "got:" hash from error message
            NEW_UI_HASH=$(echo "$BUILD_OUTPUT" | sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' | head -1 || true)

            if [ -n "$NEW_UI_HASH" ]; then
                echo "Discovered UI vendor hash for $UI_VARIANT: $NEW_UI_HASH"

                # Determine the old hash to replace based on variant
                if [ "$UI_VARIANT" = "fips" ]; then
                    OLD_UI_HASH="sha256-3t531rxDX6syyUCguKax8hv+L7rFTBVeNlypcDZSndg="
                else
                    OLD_UI_HASH="sha256-JzLOE+jQn1qHfJJ9+QZXqCZxH9oS3R5YWchZBFKEctg="
                fi

                if [ "$OLD_UI_HASH" != "$NEW_UI_HASH" ]; then
                    echo "Replacing UI $UI_VARIANT hash: $OLD_UI_HASH -> $NEW_UI_HASH"

                    # Update ui.nix
                    if [ "$(uname)" = "Darwin" ]; then
                        sed -i '' "s|$OLD_UI_HASH|$NEW_UI_HASH|g" "$UI_NIX"
                    else
                        sed -i "s|$OLD_UI_HASH|$NEW_UI_HASH|g" "$UI_NIX"
                    fi

                    # Update default.nix
                    if [ "$(uname)" = "Darwin" ]; then
                        sed -i '' "s|$OLD_UI_HASH|$NEW_UI_HASH|g" "$DEFAULT_NIX"
                    else
                        sed -i "s|$OLD_UI_HASH|$NEW_UI_HASH|g" "$DEFAULT_NIX"
                    fi

                    echo "✅ Updated UI vendor hash ($UI_VARIANT) in $UI_NIX and $DEFAULT_NIX"
                elif [ "$OLD_UI_HASH" = "$NEW_UI_HASH" ]; then
                    echo "UI hash already up-to-date for $UI_VARIANT"
                fi
            else
                echo "⚠️  Could not extract UI vendor hash from build output for $UI_VARIANT"
                echo "Vendor hash may already be correct or build failed for another reason"
            fi
        fi
    done
    echo ""
fi

# Step 2: Update NPM dependencies hash (if requested)
if [ "$UPDATE_NPM" = "true" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 2: Updating NPM dependencies hash..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    UI_NIX="$REPO_ROOT/nix/ui.nix"

    echo ""
    echo "Building UI to discover NPM dependencies hash..."

    # Use FIPS variant for NPM hash discovery (hash is same for both variants)
    if BUILD_OUTPUT=$(nix-build -A "ui-fips" -o "result-ui-fips-npm" 2>&1); then
        echo "Build succeeded (NPM hash already correct)"
    else
        # Extract the "got:" hash from error message - look for npmDepsHash mismatch
        # NPM hash errors typically appear after cargo hash errors, so use tail
        NEW_NPM_HASH=$(echo "$BUILD_OUTPUT" | sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' | tail -1 || true)

        if [ -n "$NEW_NPM_HASH" ]; then
            echo "Discovered NPM dependencies hash: $NEW_NPM_HASH"

            # Extract current NPM hash
            OLD_NPM_HASH=$(sed -n 's/.*npmDepsHash = "\(sha256-[^"]*\)".*/\1/p' "$UI_NIX")

            if [ -n "$OLD_NPM_HASH" ] && [ "$OLD_NPM_HASH" != "$NEW_NPM_HASH" ]; then
                echo "Replacing NPM hash: $OLD_NPM_HASH -> $NEW_NPM_HASH"

                # Update ui.nix npmDepsHash
                if [ "$(uname)" = "Darwin" ]; then
                    sed -i '' "s|npmDepsHash = \"$OLD_NPM_HASH\"|npmDepsHash = \"$NEW_NPM_HASH\"|" "$UI_NIX"
                else
                    sed -i "s|npmDepsHash = \"$OLD_NPM_HASH\"|npmDepsHash = \"$NEW_NPM_HASH\"|" "$UI_NIX"
                fi

                echo "✅ Updated NPM dependencies hash in $UI_NIX"
            elif [ "$OLD_NPM_HASH" = "$NEW_NPM_HASH" ]; then
                echo "NPM hash already up-to-date"
            else
                echo "⚠️  Could not extract old NPM hash from $UI_NIX"
            fi
        else
            echo "⚠️  Could not extract NPM dependencies hash from build output"
            echo "NPM hash may already be correct or build failed for another reason"
        fi
    fi
    echo ""
fi

# Step 3: Update binary hashes (if requested)
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
            HASH_FILE="$REPO_ROOT/nix/expected-hashes/${build_variant}.${IMPL}.${ARCH}.${OS}.sha256"

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
    echo "  ✓ KMS Server Cargo vendor hashes in nix/kms-server.nix"
    echo "    - Static linkage hash (Darwin/Linux)"
    echo "    - Dynamic linkage hash (Darwin/Linux)"
    echo "  ✓ UI Cargo vendor hashes in nix/ui.nix and default.nix"
    echo "    - FIPS variant"
    echo "    - Non-FIPS variant"
fi
if [ "$UPDATE_NPM" = "true" ]; then
    echo "  ✓ NPM dependencies hash (npmDepsHash) in nix/ui.nix"
fi
if [ "$UPDATE_BINARY" = "true" ]; then
    for build_variant in $VARIANTS_TO_UPDATE; do
        ARCH="${CURRENT_SYSTEM%%-*}"
        OS="${CURRENT_SYSTEM#*-}"
        echo "  ✓ Binary hash (static): nix/expected-hashes/${build_variant}.openssl.${ARCH}.${OS}.sha256"
        echo "  ✓ Binary hash (dynamic): nix/expected-hashes/${build_variant}.non-openssl.${ARCH}.${OS}.sha256"
    done
fi
echo ""
echo "Next steps:"
echo "  1. Review changes:   git diff nix/"
echo "  2. Test the build:   bash .github/scripts/nix.sh build"
echo "  3. Commit changes:   git add nix/ && git commit -m 'Update Nix hashes for $CURRENT_SYSTEM'"
echo ""
