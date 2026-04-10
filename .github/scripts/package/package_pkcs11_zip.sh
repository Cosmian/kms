#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Package the standalone PKCS#11 bundle as a cross-platform ZIP archive.
#
# Artifacts included in the ZIP (flat layout):
#   libcosmian_pkcs11.so   (Linux) or libcosmian_pkcs11.dylib (macOS)
#   cosmian_pkcs11_verify  (binary, any platform)
#   cosmian-kms-public.asc (signing public key)
#
# Both artifacts are taken from the Nix CLI derivation
# (kms-cli-<variant>-<link>-openssl).
#
# Output directory: result-pkcs11-zip-<variant>-<link>/
# Output file:      cosmian-pkcs11-<variant>-<link-suffix>_<version>_<os>-<arch>.zip
# Signature:        <zip-file>.asc  (GPG detached ASCII-armor)
# Checksum:         <zip-file>.sha256
#
# Usage:
#   bash package_pkcs11_zip.sh --variant fips|non-fips --link static|dynamic
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
VARIANT="fips"
LINK="static"
while [[ $# -gt 0 ]]; do
  case "$1" in
  --variant)
    VARIANT="$2"
    shift 2
    ;;
  --link)
    LINK="$2"
    shift 2
    ;;
  *)
    echo "Unknown argument: $1" >&2
    exit 1
    ;;
  esac
done

case "$VARIANT" in
fips | non-fips) ;;
*)
  echo "Error: --variant must be fips or non-fips" >&2
  exit 1
  ;;
esac
case "$LINK" in
static | dynamic) ;;
*)
  echo "Error: --link must be static or dynamic" >&2
  exit 1
  ;;
esac

# ---------------------------------------------------------------------------
# Resolve PIN_URL from common.sh (single source of truth for nixpkgs pin)
# ---------------------------------------------------------------------------
# shellcheck source=../.github/scripts/common.sh
source "$REPO_ROOT/.github/scripts/common.sh"

NIXPKGS_ARG="${NIXPKGS_STORE:-$PIN_URL}"

# ---------------------------------------------------------------------------
# Build / reuse CLI Nix derivation (contains both artifacts)
# ---------------------------------------------------------------------------
if [ "$LINK" = "dynamic" ]; then
  CLI_ATTR="kms-cli-${VARIANT}-dynamic-openssl"
else
  CLI_ATTR="kms-cli-${VARIANT}-static-openssl"
fi

CLI_OUT_LINK="$REPO_ROOT/result-cli-${VARIANT}-${LINK}"
if [ -L "$CLI_OUT_LINK" ] && [ -x "$(readlink -f "$CLI_OUT_LINK")/bin/ckms" ]; then
  echo "Reusing existing CLI derivation at $CLI_OUT_LINK"
else
  echo "Building CLI derivation ($CLI_ATTR)…"
  nix-build -I "nixpkgs=${NIXPKGS_ARG}" --option substituters "" \
    "$REPO_ROOT/default.nix" -A "$CLI_ATTR" -o "$CLI_OUT_LINK"
fi
REAL_CLI=$(readlink -f "$CLI_OUT_LINK")

# ---------------------------------------------------------------------------
# Locate artifacts
# ---------------------------------------------------------------------------
PKCS11_VERIFY_BIN="$REAL_CLI/bin/cosmian_pkcs11_verify"
[ -x "$PKCS11_VERIFY_BIN" ] || {
  echo "ERROR: cosmian_pkcs11_verify not found in $REAL_CLI/bin/" >&2
  exit 1
}

if [ "$(uname)" = "Darwin" ]; then
  PKCS11_LIB="$REAL_CLI/lib/libcosmian_pkcs11.dylib"
  LIB_FILENAME="libcosmian_pkcs11.dylib"
else
  PKCS11_LIB="$REAL_CLI/lib/libcosmian_pkcs11.so"
  LIB_FILENAME="libcosmian_pkcs11.so"
fi
[ -f "$PKCS11_LIB" ] || {
  echo "ERROR: $LIB_FILENAME not found in $REAL_CLI/lib/" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Determine version, arch, OS
# ---------------------------------------------------------------------------
VERSION_STR="$("$REPO_ROOT/.github/scripts/release/get_version.sh")"

RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
x86_64) ZIP_ARCH="amd64" ;;
aarch64 | arm64) ZIP_ARCH="arm64" ;;
*) ZIP_ARCH="$RAW_ARCH" ;;
esac

if [ "$(uname)" = "Darwin" ]; then
  ZIP_OS="macos"
else
  ZIP_OS="linux"
fi

LINK_SUFFIX="$([ "$LINK" = "static" ] && echo "static-openssl" || echo "dynamic-openssl")"
ZIP_NAME="cosmian-pkcs11-${VARIANT}-${LINK_SUFFIX}_${VERSION_STR}_${ZIP_OS}-${ZIP_ARCH}.zip"

# ---------------------------------------------------------------------------
# Assemble ZIP
# ---------------------------------------------------------------------------
RESULT_DIR="$REPO_ROOT/result-pkcs11-zip-${VARIANT}-${LINK}"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cp "$PKCS11_LIB" "$WORK_DIR/$LIB_FILENAME"
cp "$PKCS11_VERIFY_BIN" "$WORK_DIR/cosmian_pkcs11_verify"

PUBLIC_KEY="$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc"
[ -f "$PUBLIC_KEY" ] && cp "$PUBLIC_KEY" "$WORK_DIR/cosmian-kms-public.asc"

echo "Assembling $ZIP_NAME …"
(cd "$WORK_DIR" && zip -j "$RESULT_DIR/$ZIP_NAME" ./*.so ./*.dylib ./cosmian_pkcs11_verify ./cosmian-kms-public.asc 2>/dev/null ||
  zip -j "$RESULT_DIR/$ZIP_NAME" "$LIB_FILENAME" cosmian_pkcs11_verify cosmian-kms-public.asc 2>/dev/null ||
  zip -j "$RESULT_DIR/$ZIP_NAME" "$LIB_FILENAME" cosmian_pkcs11_verify)

[ -f "$RESULT_DIR/$ZIP_NAME" ] || {
  echo "ERROR: zip assembly failed — $ZIP_NAME not created" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Copy public key next to ZIP for easy discovery
# ---------------------------------------------------------------------------
[ -f "$PUBLIC_KEY" ] && cp "$PUBLIC_KEY" "$RESULT_DIR/cosmian-kms-public.asc"

# ---------------------------------------------------------------------------
# Sign the ZIP
# ---------------------------------------------------------------------------
_sign_zip() {
  local pkg="$1"
  local keys_dir="$REPO_ROOT/nix/signing-keys"
  local key_id_file="$keys_dir/key-id.txt"

  local require_signing="0"
  [ "${REQUIRE_SIGNING:-}" = "1" ] || [ -n "${CI:-}" ] && require_signing="1" || true

  if [ ! -f "$key_id_file" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: No signing key-id.txt found at $key_id_file" >&2
      exit 1
    fi
    echo "Signing skipped: no key-id.txt present"
    return 0
  fi

  local key_id
  key_id=$(tr -d ' \t\r\n' <"$key_id_file")

  if [ -z "${GPG_SIGNING_KEY_PASSPHRASE:-}" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: GPG_SIGNING_KEY_PASSPHRASE not set" >&2
      exit 1
    fi
    echo "Signing skipped: GPG_SIGNING_KEY_PASSPHRASE not set"
    return 0
  fi

  local private_key="$keys_dir/cosmian-kms-private.asc"
  if [ -n "${GPG_SIGNING_KEY:-}" ]; then
    printf '%s\n' "$GPG_SIGNING_KEY" >"$private_key"
    gpg --batch --import "$private_key" 2>/dev/null || {
      echo "ERROR: Failed to import GPG key from GPG_SIGNING_KEY" >&2
      exit 1
    }
  elif ! gpg --list-secret-keys "$key_id" >/dev/null 2>&1; then
    [ -f "$private_key" ] || {
      echo "ERROR: No private key available" >&2
      exit 1
    }
    gpg --batch --import "$private_key" 2>/dev/null || {
      echo "ERROR: Failed to import GPG key from $private_key" >&2
      exit 1
    }
  fi

  local sig="${pkg}.asc"
  rm -f "$sig"
  echo "$GPG_SIGNING_KEY_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --armor --detach-sign --local-user "$key_id" "$pkg"
  [ -f "$sig" ] || {
    echo "ERROR: Failed to create signature for $pkg" >&2
    exit 1
  }
  if gpg --verify "$sig" "$pkg" 2>&1 | grep -q "Good signature"; then
    echo "  Signed and verified: $(basename "$pkg")"
  else
    echo "ERROR: Signature verification failed for $(basename "$pkg")" >&2
    exit 1
  fi
}

if [ -n "${GITHUB_ACTION:-}" ]; then
  _sign_zip "$RESULT_DIR/$ZIP_NAME"
else
  echo "Skipping ZIP signing (not in GitHub Actions; set REQUIRE_SIGNING=1 to enforce)"
fi

# ---------------------------------------------------------------------------
# Write SHA-256 checksum
# ---------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM=$(sha256sum "$RESULT_DIR/$ZIP_NAME" | awk '{print $1}')
else
  CHECKSUM=$(shasum -a 256 "$RESULT_DIR/$ZIP_NAME" | awk '{print $1}')
fi
echo "$CHECKSUM  $ZIP_NAME" >"$RESULT_DIR/$ZIP_NAME.sha256"
echo "Wrote checksum: $ZIP_NAME.sha256 ($CHECKSUM)"

echo "====================================================="
echo "PKCS#11 ZIP ($VARIANT-$LINK): $RESULT_DIR/$ZIP_NAME"
ls -lh "$RESULT_DIR/"
echo "====================================================="
