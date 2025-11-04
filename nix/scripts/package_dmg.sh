#!/usr/bin/env bash
# Build macOS DMG via cargo-packager inside nix-shell (non-pure),
# ensuring access to macOS system tools like hdiutil and osascript.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
# Source unified PIN_URL and helpers
source "$REPO_ROOT/.github/scripts/common.sh"

# Determine variant and link mode from CLI arguments
VARIANT="fips"
LINK="static"
while [ $# -gt 0 ]; do
  case "$1" in
  -v | --variant)
    VARIANT="${2:-}"
    shift 2 || true
    ;;
  -l | --link)
    LINK="${2:-}"
    shift 2 || true
    ;;
  *) shift ;;
  esac
done
case "$VARIANT" in
fips | non-fips) : ;;
*)
  echo "Error: --variant must be 'fips' or 'non-fips'" >&2
  exit 1
  ;;
esac
case "$LINK" in
static | dynamic) : ;;
*)
  echo "Error: --link must be 'static' or 'dynamic'" >&2
  exit 1
  ;;
esac

# Get version from Cargo.toml
VERSION_STR=$("$REPO_ROOT/nix/scripts/get_version.sh")

# Decide if we can reuse an existing built server without triggering a full Nix rebuild.
if [ "$LINK" = "dynamic" ]; then
  ATTR="kms-server-${VARIANT}-no-openssl"
else
  ATTR="kms-server-${VARIANT}"
fi
OUT_LINK="$REPO_ROOT/result-server-${VARIANT}-${LINK}"

reuse_server=false
force_rebuild=${FORCE_REBUILD:-}
if [ -z "$force_rebuild" ] && [ -L "$OUT_LINK" ]; then
  REAL_OUT_EXISTING=$(readlink -f "$OUT_LINK" || true)
  if [ -n "$REAL_OUT_EXISTING" ] && [ -x "$REAL_OUT_EXISTING/bin/cosmian_kms" ]; then
    # Quick variant/health check: --info should contain expected OpenSSL mode marker.
    INFO_OUT=$("$REAL_OUT_EXISTING/bin/cosmian_kms" --info 2>&1 || true)
    if [ "$VARIANT" = "fips" ]; then
      echo "$INFO_OUT" | grep -q "OpenSSL FIPS mode" && reuse_server=true || reuse_server=false
    else
      echo "$INFO_OUT" | grep -q "OpenSSL default mode" && reuse_server=true || reuse_server=false
    fi
    # Extra guard: version string must match repository version from Cargo.toml.
    if ! echo "$INFO_OUT" | grep -q "${VERSION_STR}"; then
      reuse_server=false
    fi
  fi
fi

if [ "$reuse_server" = true ]; then
  echo "Reusing existing server derivation at $OUT_LINK (skip nix-build)"
  REAL_OUT="$REAL_OUT_EXISTING"
else
  echo "Building server derivation (variant: $VARIANT) via nix-build…"
  # Preserve existing link if reuse failed; replace atomically.
  rm -f "$OUT_LINK" 2>/dev/null || true
  nix-build -I "nixpkgs=${PIN_URL}" -A "$ATTR" -o "$OUT_LINK"
  REAL_OUT=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
fi

# Prepare target folders and copy binary where cargo-packager expects it
BIN_OUT="$REAL_OUT/bin/cosmian_kms"
HOST_TRIPLE=$(rustc -vV | awk '/host:/ {print $2}')
mkdir -p "crate/server/target/$HOST_TRIPLE/release" "crate/server/target/release" "target/release"
# Force overwrite in case readonly artifacts already exist from previous runs
cp -f -v "$BIN_OUT" "crate/server/target/$HOST_TRIPLE/release/cosmian_kms"
cp -f -v "$BIN_OUT" "crate/server/target/release/cosmian_kms"
cp -f -v "$BIN_OUT" "target/release/cosmian_kms"

# Writable HOME/CARGO_HOME for cargo metadata
export HOME="${TMPDIR:-/tmp}"
export CARGO_HOME="$HOME/cargo-home"
mkdir -p "$CARGO_HOME"

# Ensure macOS system tools are available
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

APP_PATH_EXISTING="target/release/Cosmian KMS Server.app"
skip_packager=false
if [ -z "${FORCE_REBUILD:-}" ] && [ -d "$APP_PATH_EXISTING" ]; then
  # Validate embedded binary matches expected version & variant.
  BIN_EMBEDDED="$APP_PATH_EXISTING/Contents/MacOS/cosmian_kms"
  if [ -x "$BIN_EMBEDDED" ]; then
    EMBED_INFO=$("$BIN_EMBEDDED" --info 2>&1 || true)
    if echo "$EMBED_INFO" | grep -q "$VERSION_STR"; then
      if { [ "$VARIANT" = "fips" ] && echo "$EMBED_INFO" | grep -q "OpenSSL FIPS mode"; } || { [ "$VARIANT" = "non-fips" ] && echo "$EMBED_INFO" | grep -q "OpenSSL default mode"; }; then
        skip_packager=true
      fi
    fi
  fi
fi

if [ "$skip_packager" = true ]; then
  echo "Reusing existing .app bundle (skip cargo-packager)"
else
  # Package .app with cargo-packager (avoid create-dmg AppleScript in sandbox)
  pushd crate/server >/dev/null
  echo "Building .app bundle via cargo-packager..."
  if ! cargo packager --verbose --formats app --release; then
    echo "Retrying cargo packager without verbose..."
    cargo packager --formats app --release
  fi
  popd >/dev/null
fi

# Collect output DMG into repo-level result link
RESULT_DIR="$REPO_ROOT/result-dmg-${VARIANT}-${LINK}"
mkdir -p "$RESULT_DIR"
# Create a DMG from the generated .app using hdiutil (no AppleScript)
APP_BUNDLE=$(find crate/server/target/release -maxdepth 1 -name '*.app' | head -n1 || true)
if [ -z "$APP_BUNDLE" ]; then
  # cargo-packager may place the .app under the workspace root target/release
  APP_BUNDLE=$(find target/release -maxdepth 1 -name '*.app' | head -n1 || true)
fi
if [ -z "$APP_BUNDLE" ]; then
  echo "Error: .app bundle not found under crate/server/target/release or target/release" >&2
  exit 1
fi
DMG_NAME="Cosmian KMS Server_${VERSION_STR}_$(uname -m).dmg"
echo "Creating DMG $DMG_NAME from $APP_BUNDLE..."
if [ -z "${FORCE_REBUILD:-}" ] && [ -f "$RESULT_DIR/$DMG_NAME" ]; then
  echo "Existing DMG found at $RESULT_DIR/$DMG_NAME (skipping hdiutil create)"
else
  hdiutil create -volname "Cosmian KMS Server" -srcfolder "$APP_BUNDLE" -ov -format UDZO "$RESULT_DIR/$DMG_NAME"
fi

echo "Built dmg (${VARIANT}): $RESULT_DIR/$DMG_NAME"

# Write deterministic checksum for the newly created DMG (avoid stale checksum files)
DMG_SHA256=$(shasum -a 256 "$RESULT_DIR/$DMG_NAME" | awk '{print $1}')
CHECKSUM_FILE="$RESULT_DIR/${DMG_NAME}.sha256"
echo "$DMG_SHA256  $DMG_NAME" >"$CHECKSUM_FILE"
echo "Wrote checksum: $CHECKSUM_FILE ($DMG_SHA256)"

# Source and use the unified sign_packages function from package_common.sh
COMMON_LIB="$REPO_ROOT/nix/scripts/package_common.sh"
if [ -f "$COMMON_LIB" ]; then
  # Extract and execute the sign_packages function
  # shellcheck disable=SC1090
  source <(sed -n '/^sign_packages()/,/^}/p' "$COMMON_LIB")
  # Only sign packages when executing inside GitHub Actions (GITHUB_ACTION is
  # provided by the runner). Avoid attempting signing on developer machines
  # where the signing key/material isn't available.
  if [ -n "${GITHUB_ACTION:-}" ]; then
    sign_packages "$RESULT_DIR/$DMG_NAME"
  else
    echo "Skipping package signing (not running in GitHub Actions)."
  fi
fi

# Copy public key to result directory if it exists
PUBLIC_KEY="$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc"
if [ -f "$PUBLIC_KEY" ]; then
  cp -v "$PUBLIC_KEY" "$RESULT_DIR/"
  echo "Copied public key to $RESULT_DIR/"
fi
