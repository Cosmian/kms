#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Package a musl/Alpine-compatible release tarball for the KMS server or CLI.
#
# Unlike the deb/rpm/dmg packages (glibc-only), these tarballs contain a Linux
# musl build that runs natively on Alpine (and any other musl-based distro)
# with no `gcompat` shim required:
#   - fips     -> dynamically-linked musl (ld-musl-<arch>.so.1 present on Alpine;
#                 keeps dlopen available so the FIPS provider loads normally)
#   - non-fips -> fully static musl (+crt-static, no dynamic linker at all;
#                 the legacy OpenSSL provider is skipped at runtime — see
#                 crate/server/src/openssl_providers.rs)
#
# Artifacts included in the tarball (flat layout):
#   cosmian_kms (server) or ckms (CLI)
#   cosmian-kms-public.asc (signing public key)
#
# Output directory: result-musl-<component>-<variant>/
# Output file:      cosmian-kms-<component>-<variant>-musl-<dynamic|static>_<version>_<musl-triple>.tar.gz
# Signature:        <tar.gz>.asc  (GPG detached ASCII-armor)
# Checksum:         <tar.gz>.sha256
#
# Usage:
#   bash package_musl_tarball.sh --component server|cli --variant fips|non-fips
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
COMPONENT="server"
VARIANT="fips"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --component)
      COMPONENT="$2"
      shift 2
      ;;
    --variant)
      VARIANT="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

case "$COMPONENT" in
  server | cli) ;;
  *)
    echo "Error: --component must be server or cli" >&2
    exit 1
    ;;
esac
case "$VARIANT" in
  fips | non-fips) ;;
  *)
    echo "Error: --variant must be fips or non-fips" >&2
    exit 1
    ;;
esac

# musl libc linking mode is determined by variant, not freely chosen — see
# crate/server/src/openssl_providers.rs / nix/kms-server-musl.nix for why.
if [ "$VARIANT" = "fips" ]; then
  LIBC_TAG="musl-dynamic"
else
  LIBC_TAG="musl-static"
fi

# ---------------------------------------------------------------------------
# Resolve PIN_URL from common.sh (single source of truth for nixpkgs pin)
# ---------------------------------------------------------------------------
# shellcheck source=../.mise/scripts/common.sh
source "${REPO_ROOT}/.mise/scripts/common.sh"

NIXPKGS_ARG="${NIXPKGS_STORE:-$PIN_URL}"

# ---------------------------------------------------------------------------
# Build / reuse Nix derivation
# ---------------------------------------------------------------------------
NIX_ATTR="kms-${COMPONENT}-${VARIANT}-${LIBC_TAG}"
OUT_LINK="$REPO_ROOT/result-musl-${COMPONENT}-${VARIANT}"

if [ -L "$OUT_LINK" ] && [ -n "$(find "$(readlink -f "$OUT_LINK")/bin" -maxdepth 1 -type f 2>/dev/null)" ]; then
  echo "Reusing existing derivation at $OUT_LINK"
else
  echo "Building Nix derivation ($NIX_ATTR)…"
  nix-build -I "nixpkgs=${NIXPKGS_ARG}" --option substituters "" \
    "$REPO_ROOT/default.nix" -A "$NIX_ATTR" -o "$OUT_LINK"
fi
REAL_OUT=$(readlink -f "$OUT_LINK")

if [ "$COMPONENT" = "server" ]; then
  BIN_NAME="cosmian_kms"
else
  BIN_NAME="ckms"
fi
BIN_PATH="$REAL_OUT/bin/$BIN_NAME"
[ -x "$BIN_PATH" ] || {
  echo "ERROR: $BIN_NAME not found or not executable at $BIN_PATH" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Determine version and musl target triple
# ---------------------------------------------------------------------------
VERSION_STR="$("$REPO_ROOT/.mise/scripts/release/get_version.sh")"

RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64) MUSL_TRIPLE="x86_64-unknown-linux-musl" ;;
  aarch64 | arm64) MUSL_TRIPLE="aarch64-unknown-linux-musl" ;;
  *)
    echo "ERROR: unsupported architecture for musl packaging: $RAW_ARCH" >&2
    exit 1
    ;;
esac

TAR_NAME="cosmian-kms-${COMPONENT}-${VARIANT}-${LIBC_TAG}_${VERSION_STR}_${MUSL_TRIPLE}.tar.gz"

# ---------------------------------------------------------------------------
# Assemble tarball
# ---------------------------------------------------------------------------
RESULT_DIR="$REPO_ROOT/result-musl-tarball-${COMPONENT}-${VARIANT}"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"

WORK_DIR="$(mktemp -d)"
# `cp -r` below (usr/local/cosmian/lib/) copies from a Nix store path, whose
# directories are read-only (dr-xr-xr-x) by design — cp -r replicates that
# same permission onto the destination directories once populated. Without
# the chmod, a plain `rm -rf` on cleanup fails ("Permission denied": removing
# an entry needs write access to its *parent* directory), which — being the
# last command the EXIT trap runs — would make the whole task report failure
# even though the tarball (in the separate $RESULT_DIR) was already built
# successfully. `|| true` on both: cleanup is best-effort and must never
# fail a task whose real work is already done.
trap 'chmod -R u+w "$WORK_DIR" 2>/dev/null || true; rm -rf "$WORK_DIR" || true' EXIT

cp "$BIN_PATH" "$WORK_DIR/$BIN_NAME"
chmod 755 "$WORK_DIR/$BIN_NAME"

# FIPS dynamic-musl server builds ship the FIPS provider module and OpenSSL
# config as a separate usr/local/cosmian/lib/ tree (dlopen'd at runtime via
# OPENSSL_MODULES/OPENSSL_CONF — see nix/kms-server-musl.nix's postInstall).
# Without it the server cannot start at all ("Error loading shared library
# .../fips.so: No such file or directory"). Bundle it, preserving the path,
# whenever the Nix derivation produced one (server component only; CLI has
# no such directory, and the fully static non-FIPS server does not either).
if [ -d "$REAL_OUT/usr/local/cosmian/lib" ]; then
  mkdir -p "$WORK_DIR/usr/local/cosmian/lib"
  cp -r "$REAL_OUT/usr/local/cosmian/lib/." "$WORK_DIR/usr/local/cosmian/lib/"
  # The Nix store source is read-only (dr-xr-xr-x) by design; `cp -r`
  # replicates that onto these destination directories. Normalize to normal,
  # writable permissions so (a) the shipped tarball doesn't hand end users
  # oddly read-only config/provider files and (b) this tree can later be
  # cleaned up without the EXIT trap below needing a chmod of its own.
  chmod -R u+w "$WORK_DIR/usr/local/cosmian/lib"
fi

PUBLIC_KEY="$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc"
[ -f "$PUBLIC_KEY" ] && cp "$PUBLIC_KEY" "$WORK_DIR/cosmian-kms-public.asc"

echo "Assembling $TAR_NAME …"
tar -C "$WORK_DIR" -czf "$RESULT_DIR/$TAR_NAME" .

[ -f "$RESULT_DIR/$TAR_NAME" ] || {
  echo "ERROR: tar assembly failed — $TAR_NAME not created" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Sign the tarball (mirrors package_pkcs11_zip.sh's signing convention)
# ---------------------------------------------------------------------------
_sign_tarball() {
  local pkg="$1"
  local keys_dir="$REPO_ROOT/nix/signing-keys"
  local key_id_file="$keys_dir/key-id.txt"

  local require_signing="0"
  if [ "${REQUIRE_SIGNING:-}" = "1" ] || [ -n "${CI:-}" ]; then require_signing="1"; fi

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
  _sign_tarball "$RESULT_DIR/$TAR_NAME"
else
  echo "Skipping tarball signing (not in GitHub Actions; set REQUIRE_SIGNING=1 to enforce)"
fi

# ---------------------------------------------------------------------------
# Write SHA-256 checksum
# ---------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM=$(sha256sum "$RESULT_DIR/$TAR_NAME" | awk '{print $1}')
else
  CHECKSUM=$(shasum -a 256 "$RESULT_DIR/$TAR_NAME" | awk '{print $1}')
fi
echo "$CHECKSUM  $TAR_NAME" >"$RESULT_DIR/$TAR_NAME.sha256"
echo "Wrote checksum: $TAR_NAME.sha256 ($CHECKSUM)"

echo "====================================================="
echo "musl tarball ($COMPONENT-$VARIANT): $RESULT_DIR/$TAR_NAME"
ls -lh "$RESULT_DIR/"
echo "====================================================="
