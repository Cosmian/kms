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
#   --component <ui|server>       Component to update (default: both)
#   --variant <fips|non-fips>     Crypto feature variant (default: fips)
#   --link <static|dynamic>       Limit to a specific server linkage (default: both)
#   --max-retries N            Convergence attempts (default: 3)
#   --retry-delay-seconds S    Delay between attempts (default: 2)
#   --help                     Show this help message
#
# Requirements:
#   - Nix package manager installed
#   - Working directory must be repository root
#   - Network access (for vendor hash update)
#   - Profile: release (mandatory). If env var PROFILE is set, it must be 'release'

set -euo pipefail

# Maximum retry cycles to converge hashes (can be set via flags)
MAX_RETRIES=${MAX_RETRIES:-3}
RETRY_DELAY_SECONDS=${RETRY_DELAY_SECONDS:-2}

# Track overall convergence status
CONVERGED=false

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

# Validate SRI-style sha256 (must be 'sha256-' followed by base64 chars)
is_valid_sri() {
    local val="$1"
    # Typical Nix SRI hashes are base64 ~44 chars; guard to avoid empty 'sha256-'
    [[ "$val" =~ ^sha256-[A-Za-z0-9+/=]{20,}$ ]]
}

# Show usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Updates expected hashes for Cosmian KMS Nix builds on current platform.

Options:
    --component <ui|server>       Limit to a single component (default: both)
    --variant <fips|non-fips>     Update specific variant (default: fips)
    --link <static|dynamic>       Limit server to a single linkage (default: both)
    --max-retries N               Convergence attempts (default: 3)
    --retry-delay-seconds S       Delay between attempts (default: 2)
    --help                        Show this help message

Examples:
    $0                                   # Update all (server+ui, fips, static+dynamic)
    $0 --variant non-fips                # Update non-FIPS hashes
    $0 --component server --link static  # Only server hashes for static linkage
    bash .github/scripts/nix.sh --variant fips --link dynamic update-hashes

Notes:
    - Profile is release mandatory. If PROFILE is set, it must be 'release'.
    - External tool hashes (cargo-generate-rpm, cargo-packager, wasm-bindgen-cli,
        OpenSSL source) are pinned and not updated here.

Platform support:
  - x86_64-linux (Intel/AMD Linux)
  - aarch64-linux (ARM64 Linux)
  - aarch64-darwin (Apple Silicon macOS)

Hash types updated:
    1. KMS Server Cargo vendor hashes (static/dynamic)
    2. UI Cargo vendor hash
    3. NPM dependencies hash (UI node_modules)
    4. Server binary hashes (static/dynamic)
EOF
    exit 0
}

# Parse command-line arguments (new interface)
COMPONENT=""
VARIANT=""
LINK=""
UPDATE_VENDOR=true
UPDATE_BINARY=true
UPDATE_NPM=true

while [ $# -gt 0 ]; do
    case "$1" in
    --component)
        COMPONENT="${2:-}"
        if [ -z "$COMPONENT" ] || { [ "$COMPONENT" != "ui" ] && [ "$COMPONENT" != "server" ]; }; then
            echo "Error: --component requires 'ui' or 'server'" >&2
            exit 1
        fi
        shift 2
        ;;
    --variant)
        VARIANT="${2:-}"
        if [ -z "$VARIANT" ]; then
            echo "Error: --variant requires an argument (fips or non-fips)" >&2
            exit 1
        fi
        shift 2
        ;;
    --link)
        LINK="${2:-}"
        if [ -z "$LINK" ] || { [ "$LINK" != "static" ] && [ "$LINK" != "dynamic" ]; }; then
            echo "Error: --link requires 'static' or 'dynamic'" >&2
            exit 1
        fi
        shift 2
        ;;
    --max-retries)
        MAX_RETRIES="${2:-}"
        shift 2
        ;;
    --retry-delay-seconds)
        RETRY_DELAY_SECONDS="${2:-}"
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

# Enforce release profile if provided by caller
if [ -n "${PROFILE:-}" ] && [ "${PROFILE}" != "release" ]; then
    echo "Error: PROFILE must be 'release' for hash updates (got '${PROFILE}')" >&2
    exit 1
fi

# Detect current platform
CURRENT_SYSTEM="$(nix-instantiate --eval -E 'builtins.currentSystem' | tr -d '"')"

echo "Updating expected hashes for current platform..."
echo "Platform: $CURRENT_SYSTEM"
echo "Component: ${COMPONENT:-all}"
if [ -n "$VARIANT" ]; then
    echo "Variant: $VARIANT"
else
    echo "Variant: fips (default)"
fi
if [ -n "$LINK" ]; then
    echo "Link: $LINK"
else
    echo "Link: static+dynamic"
fi
echo ""

# Helper: try to build an attr and detect hash mismatch (returns 0 if ok)
build_attr_validates() {
    local attr="$1"
    local outlink="$2"
    if nix-build -A "$attr" -o "$outlink" >/dev/null 2>&1; then
        return 0
    fi
    # Common mismatch messages include 'got:' in fetchers; treat as non-converged
    return 1
}

# One pass to update vendor hashes
update_vendor_hashes() {
    # Step 1: Update vendor hashes (if requested)
    if [ "$UPDATE_VENDOR" != "true" ]; then
        return 0
    fi
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
        BUILD_VARIANTS="fips" # Use FIPS to discover hash (same for both)
    fi

    for BUILD_VARIANT in $BUILD_VARIANTS; do
        # Determine which link modes to process
        if [ -n "$LINK" ]; then
            LINK_MODES="$LINK"
        else
            LINK_MODES="static dynamic"
        fi
        for LINK_MODE in $LINK_MODES; do
            echo ""
            echo "Building KMS server ($BUILD_VARIANT, $LINK_MODE) to discover vendor hash..."

            # Determine Nix attribute name
            if [ "$LINK_MODE" = "dynamic" ]; then
                NIX_ATTR="kms-server-${BUILD_VARIANT}-no-openssl"
            else
                NIX_ATTR="kms-server-${BUILD_VARIANT}"
            fi

            # Precompute hash file path for this variant/linkage
            ARCH="${CURRENT_SYSTEM%%-*}"
            OS="${CURRENT_SYSTEM#*-}"
            # Server vendor hash is shared across variants and linkage modes
            HASH_FILE="$REPO_ROOT/nix/expected-hashes/server.vendor.${ARCH}.${OS}.sha256"
            mkdir -p "$REPO_ROOT/nix/expected-hashes"

            # Ensure the expected-hash file exists to avoid missing-file errors
            if [ ! -f "$HASH_FILE" ]; then
                echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >"$HASH_FILE"
                echo "Created placeholder server vendor hash file: $HASH_FILE"
            fi

            # Trigger a Nix build that will fail early with the correct vendor hash suggestion
            # Disable deterministic binary hash enforcement to avoid masking the vendor error
            if BUILD_OUTPUT=$(nix-build --show-trace --arg enforceDeterministicHash false -A "$NIX_ATTR" -o "result-server-${BUILD_VARIANT}-${LINK_MODE}-vendor" 2>&1); then
                echo "Build succeeded (vendor hash already correct for $LINK_MODE)"
                # Even if build succeeded, make sure the hash file is present
                if [ ! -s "$HASH_FILE" ]; then
                    # Read current vendor hash via a forced fetch failure to capture 'got:'
                    TMP_OUT=$(nix-build --show-trace --arg enforceDeterministicHash false -A "$NIX_ATTR" -o "result-server-${BUILD_VARIANT}-${LINK_MODE}-vendor" 2>&1 || true)
                    CUR_VENDOR_HASH=$(echo "$TMP_OUT" |
                        sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                        head -1 || true)
                    if is_valid_sri "$CUR_VENDOR_HASH"; then
                        echo "$CUR_VENDOR_HASH" >"$HASH_FILE"
                        echo "✅ Ensured $HASH_FILE exists with current hash"
                    else
                        # Leave placeholder; subsequent cycles will correct it if needed
                        echo "⚠️  Could not determine current vendor hash on success; placeholder remains."
                    fi
                fi
            else
                # Extract the suggested hash using multiple patterns
                # Extract the suggested hash using multiple patterns
                NEW_VENDOR_HASH=$(echo "$BUILD_OUTPUT" |
                    sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                    head -1 || true)
                if ! is_valid_sri "$NEW_VENDOR_HASH"; then
                    # Alternative message format
                    NEW_VENDOR_HASH=$(echo "$BUILD_OUTPUT" |
                        sed -n 's/.*hash mismatch.*got is\s*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                        head -1 || true)
                fi

                if is_valid_sri "$NEW_VENDOR_HASH"; then
                    echo "Discovered vendor hash for $LINK_MODE: $NEW_VENDOR_HASH"
                    echo "$NEW_VENDOR_HASH" >"$HASH_FILE"
                    echo "✅ Wrote $HASH_FILE"
                    echo "$HASH_FILE: $NEW_VENDOR_HASH"
                else
                    # Dump a short snippet for debugging
                    echo "⚠️  Could not extract vendor hash from build output for $LINK_MODE (no 'got:' found). Forcing placeholder and retry…"
                    # Force a placeholder to trigger fetcher suggestion on next build
                    echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >"$HASH_FILE"
                    echo "Injected placeholder into $HASH_FILE"
                    BUILD_OUTPUT=$(nix-build --show-trace --arg enforceDeterministicHash false -A "$NIX_ATTR" -o "result-server-${BUILD_VARIANT}-${LINK_MODE}-vendor" 2>&1 || true)
                    NEW_VENDOR_HASH=$(echo "$BUILD_OUTPUT" |
                        sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                        head -1 || true)
                    if ! is_valid_sri "$NEW_VENDOR_HASH"; then
                        NEW_VENDOR_HASH=$(echo "$BUILD_OUTPUT" |
                            sed -n 's/.*hash mismatch.*got is\s*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                            head -1 || true)
                    fi
                    if is_valid_sri "$NEW_VENDOR_HASH"; then
                        echo "Discovered vendor hash on retry for $LINK_MODE: $NEW_VENDOR_HASH"
                        echo "$NEW_VENDOR_HASH" >"$HASH_FILE"
                        echo "✅ Wrote $HASH_FILE"
                        echo "$HASH_FILE: $NEW_VENDOR_HASH"
                    else
                        echo "⚠️  Still could not extract vendor hash."
                        echo "--- build output (tail) ---"
                        echo "$BUILD_OUTPUT" | tail -n 50
                        echo "---------------------------"
                    fi
                fi
            fi
        done
    done

    # Update UI vendor hashes for FIPS and non-FIPS variants
    echo ""
    echo "1.2: Updating UI vendor hashes..."

    # (no longer editing Nix files directly; hashes are written to nix/expected-hashes)

    # Determine which UI variants to update
    if [ -n "$VARIANT" ]; then
        UI_VARIANTS="$VARIANT"
    else
        UI_VARIANTS="fips"
    fi

    for UI_VARIANT in $UI_VARIANTS; do
        echo ""
        echo "Building UI ($UI_VARIANT) to discover vendor hash..."

        # Ensure vendor UI expected-hash file exists with a placeholder
        ARCH="${CURRENT_SYSTEM%%-*}"
        OS="${CURRENT_SYSTEM#*-}"
        UI_VENDOR_FILE="$REPO_ROOT/nix/expected-hashes/ui.vendor.${UI_VARIANT}.${ARCH}.${OS}.sha256"
        # UI WASM vendor hash uses the same file as UI vendor hash
        UI_WASM_VENDOR_FILE="$UI_VENDOR_FILE"
        mkdir -p "$REPO_ROOT/nix/expected-hashes"
        if [ ! -f "$UI_VENDOR_FILE" ]; then
            echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >"$UI_VENDOR_FILE"
            echo "Created placeholder UI vendor hash file: $UI_VENDOR_FILE"
        fi
        # Create placeholder for WASM vendor hash as well (kept in sync with UI vendor)
        if [ ! -f "$UI_WASM_VENDOR_FILE" ]; then
            echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >"$UI_WASM_VENDOR_FILE"
            echo "Created placeholder UI WASM vendor hash file: $UI_WASM_VENDOR_FILE"
        fi

        # Trigger a Nix build that will fail with the correct hash
        if BUILD_OUTPUT=$(nix-build --show-trace --arg enforceDeterministicHash false -A "ui-${UI_VARIANT}" -o "result-ui-${UI_VARIANT}-vendor" 2>&1); then
            echo "Build succeeded (vendor hash already correct for $UI_VARIANT)"
            # Ensure the WASM vendor hash file mirrors the UI vendor hash
            if [ -s "$UI_VENDOR_FILE" ]; then
                CUR_HASH=$(tr -d ' \t\r\n' <"$UI_VENDOR_FILE" || true)
                echo "✅ UI vendor hash is current: $CUR_HASH"
            fi
        else
            # Extract the "got:" hash from error message
            NEW_UI_HASH=$(echo "$BUILD_OUTPUT" |
                sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                head -1 || true)
            if ! is_valid_sri "$NEW_UI_HASH"; then
                NEW_UI_HASH=$(echo "$BUILD_OUTPUT" |
                    sed -n 's/.*hash mismatch.*got is\s*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
                    head -1 || true)
            fi

            if is_valid_sri "$NEW_UI_HASH"; then
                echo "Discovered UI vendor hash for $UI_VARIANT: $NEW_UI_HASH"
                echo "$NEW_UI_HASH" >"$UI_VENDOR_FILE"
                echo "✅ Wrote $UI_VENDOR_FILE"
                echo "$UI_VENDOR_FILE: $NEW_UI_HASH"
            else
                echo "⚠️  Could not extract UI vendor hash from build output for $UI_VARIANT"
                echo "Vendor hash may already be correct or build failed for another reason"
                echo "--- build output (tail) ---"
                echo "$BUILD_OUTPUT" | tail -n 50
                echo "---------------------------"
            fi
        fi
    done
    echo ""
}

# One pass to update NPM deps hash
update_npm_hash() {
    if [ "$UPDATE_NPM" != "true" ]; then
        return 0
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 2: Updating NPM dependencies hash..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # (no longer editing ui.nix directly; hashes are written to nix/expected-hashes)

    echo ""
    echo "Building UI to discover NPM dependencies hash..."

    # NPM hash is shared across variants (content is identical)
    ARCH="${CURRENT_SYSTEM%%-*}"
    OS="${CURRENT_SYSTEM#*-}"
    NPM_HASH_FILE="$REPO_ROOT/nix/expected-hashes/ui.npm.${ARCH}.${OS}.sha256"
    mkdir -p "$REPO_ROOT/nix/expected-hashes"
    if [ ! -f "$NPM_HASH_FILE" ]; then
        echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >"$NPM_HASH_FILE"
        echo "Created placeholder NPM hash file: $NPM_HASH_FILE"
    fi

    if BUILD_OUTPUT=$(nix-build --show-trace -A "ui-fips" -o "result-ui-fips-npm" 2>&1); then
        echo "Build succeeded (NPM hash already correct)"
    else
        # Extract the "got:" hash from error message - look for npmDepsHash mismatch
        NEW_NPM_HASH=$(echo "$BUILD_OUTPUT" |
            sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' |
            tail -1 || true)

        if is_valid_sri "$NEW_NPM_HASH"; then
            echo "Discovered NPM dependencies hash: $NEW_NPM_HASH"
            echo "$NEW_NPM_HASH" >"$NPM_HASH_FILE"
            echo "✅ Wrote $NPM_HASH_FILE"
            echo "$NPM_HASH_FILE: $NEW_NPM_HASH"
        else
            echo "⚠️  Could not extract NPM dependencies hash from build output"
            echo "NPM hash may already be correct or build failed for another reason"
            echo "--- build output (tail) ---"
            echo "$BUILD_OUTPUT" | tail -n 50
            echo "---------------------------"
        fi
    fi
    echo ""
}

# Step 2: Update NPM dependencies hash (if requested)

# Step 3: Update binary hashes (if requested)
update_binary_hashes() {
    if [ "$UPDATE_BINARY" != "true" ]; then
        return 0
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 3: Updating binary hashes..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # If server vendor hashes are unresolved (empty or placeholder), skip binary step to avoid build failure
    KMS_SERVER_NIX="$REPO_ROOT/nix/kms-server.nix"
    unresolved_vendor=false
    # Detect empty cargoHash strings or placeholder AAAAA... in platform-specific sections
    if grep -q 'cargoHash[[:space:]]*=.*""' "$KMS_SERVER_NIX" ||
        grep -q 'cargoHash[[:space:]]*=.*sha256-AAAA' "$KMS_SERVER_NIX"; then
        unresolved_vendor=true
    fi
    if [ "$unresolved_vendor" = true ]; then
        echo "⚠️  Skipping binary hash update: server cargoHash appears unset (\"\")."
        echo "    Run vendor-only update first, then re-run binary hashes."
        echo ""
        return 0
    fi

    # Determine which variants to update based on --variant flag
    if [ -n "$VARIANT" ]; then
        VARIANTS_TO_UPDATE="$VARIANT"
    else
        # Default: update FIPS only
        VARIANTS_TO_UPDATE="fips"
    fi

    # Update both static and dynamic builds for each variant (or limit via --link)
    for build_variant in $VARIANTS_TO_UPDATE; do
        if [ -n "$LINK" ]; then
            LINK_MODES="$LINK"
        else
            LINK_MODES="static dynamic"
        fi
        for link_mode in $LINK_MODES; do
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

            # Binary hash files are variant-specific but not impl-specific
            # Naming convention: server.<variant>.<arch>.<os>.sha256
            ARCH="${CURRENT_SYSTEM%%-*}"
            OS="${CURRENT_SYSTEM#*-}"
            HASH_FILE="$REPO_ROOT/nix/expected-hashes/server.${build_variant}.${ARCH}.${OS}.sha256"

            # Create directory if it doesn't exist
            mkdir -p "$REPO_ROOT/nix/expected-hashes"

            # Write new hash
            echo "$NEW_HASH" >"$HASH_FILE"

            echo "✅ Updated $HASH_FILE: $NEW_HASH"
            echo "$HASH_FILE: $NEW_HASH"
        done
    done
    echo ""
}

# Convergence loop: iterate until all targeted hashes validate or retries exhausted
for attempt in $(seq 1 "$MAX_RETRIES"); do
    echo "========================================================"
    echo "Hash update cycle $attempt/$MAX_RETRIES"
    echo "========================================================"

    if [ -z "$COMPONENT" ] || [ "$COMPONENT" = "ui" ]; then
        update_vendor_hashes
        update_npm_hash
    fi
    if [ -z "$COMPONENT" ] || [ "$COMPONENT" = "server" ]; then
        update_vendor_hashes
        update_binary_hashes
    fi

    echo "Validating builds for convergence…"

    VARIANTS_TO_CHECK="${VARIANT:-fips}"
    ALL_VALID=true
    if [ -z "$COMPONENT" ] || [ "$COMPONENT" = "server" ]; then
        for v in $VARIANTS_TO_CHECK; do
            if [ -z "$LINK" ] || [ "$LINK" = "static" ]; then
                if ! build_attr_validates "kms-server-$v" "result-server-$v-fips-static"; then ALL_VALID=false; fi
            fi
            if [ -z "$LINK" ] || [ "$LINK" = "dynamic" ]; then
                if ! build_attr_validates "kms-server-$v-no-openssl" "result-server-$v-fips-dynamic"; then ALL_VALID=false; fi
            fi
        done
    fi
    if [ -z "$COMPONENT" ] || [ "$COMPONENT" = "ui" ]; then
        if ! build_attr_validates "ui-${VARIANT:-fips}" "result-ui-${VARIANT:-fips}"; then ALL_VALID=false; fi
    fi

    if [ "$ALL_VALID" = true ]; then
        CONVERGED=true
        echo "✅ All builds validate with current hashes."
        break
    else
        echo "Hashes not fully converged yet; retrying after ${RETRY_DELAY_SECONDS}s…"
        sleep "$RETRY_DELAY_SECONDS"
    fi
done

if [ "$CONVERGED" != true ]; then
    echo "⚠️  Hash update did not fully converge after $MAX_RETRIES attempts."
    echo "    You can increase retries via MAX_RETRIES or inspect the logs."
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Hash update complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Summary of changes:"
ARCH="${CURRENT_SYSTEM%%-*}"
OS="${CURRENT_SYSTEM#*-}"
if [ -z "$COMPONENT" ] || [ "$COMPONENT" = "server" ]; then
    echo "  ✓ Server vendor hash: nix/expected-hashes/server.vendor.${ARCH}.${OS}.sha256"
    # Only print binary summary if we updated binaries and know which variants
    if [ "$UPDATE_BINARY" = "true" ]; then
        VARIANTS_SUMMARY="${VARIANT:-fips}"
        for build_variant in $VARIANTS_SUMMARY; do
            echo "  ✓ Binary hash: nix/expected-hashes/server.${build_variant}.${ARCH}.${OS}.sha256"
        done
    fi
fi
if [ -z "$COMPONENT" ] || [ "$COMPONENT" = "ui" ]; then
    UI_VARIANT_SUMMARY="${VARIANT:-fips}"
    echo "  ✓ UI vendor hash: nix/expected-hashes/ui.vendor.${UI_VARIANT_SUMMARY}.${ARCH}.${OS}.sha256"
    echo "  ✓ NPM deps hash:  nix/expected-hashes/ui.npm.${ARCH}.${OS}.sha256"
fi
echo ""
echo "Next steps:"
echo "  1. Review changes:   git diff nix/"
echo "  2. Test the build:   bash .github/scripts/nix.sh --variant '${VARIANT:-fips}' --link '${LINK:-static}' build"
echo "  3. Commit changes:   git add nix/ && git commit -m 'Update Nix hashes for $CURRENT_SYSTEM'"
echo ""
