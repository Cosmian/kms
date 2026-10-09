#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Build an Alpine Linux `.apk` package for the KMS server or CLI.
#
# Unlike the deb/rpm/dmg packages (glibc-only), these packages contain a Linux
# musl build that runs natively on Alpine with no `gcompat` shim required:
#   - fips     -> dynamically-linked musl (ld-musl-<arch>.so.1 present on Alpine;
#                 keeps dlopen available so the FIPS provider loads normally).
#                 The package depends on `libgcc` (rustc always links -lgcc_s).
#   - non-fips -> fully static musl (+crt-static, no dynamic linker at all;
#                 the legacy OpenSSL provider is skipped at runtime — see
#                 crate/server/src/openssl_providers.rs)
#
# The binaries come from the Nix musl derivations (nix/kms-server-musl.nix,
# nix/cli-musl.nix); the .apk itself is assembled with nfpm (provided from the
# pinned nixpkgs via nix-shell when not on PATH).
#
# Package contents:
#   server: /usr/sbin/cosmian_kms, /etc/cosmian/kms.toml (config, noreplace),
#           /etc/init.d/cosmian_kms + /etc/conf.d/cosmian_kms (OpenRC),
#           /usr/local/cosmian/ui/dist/ (web UI),
#           /usr/local/cosmian/lib/ (FIPS provider + openssl.cnf, FIPS only)
#   cli:    /usr/bin/ckms
#
# The server runs as a dedicated, unprivileged "kms" system user/group (OpenRC
# command_user, see cosmian_kms.initd), not root. The user/group is created by
# preinstall.sh — this must happen *before* apk-tools extracts the package
# files, because named file_info owners (e.g. kms.toml's `group: kms`) are
# resolved against /etc/passwd at extraction time with a silent root:root
# fallback if the user doesn't exist yet (verified empirically; postinstall
# would be too late on a fresh install). postinstall.sh then chowns the
# runtime directories (/var/lib/cosmian, /var/log/cosmian) to kms:kms.
#
# Output directory: result-apk-<component>-<variant>/
# Output file:      cosmian-kms-<component>-<variant>_<version>-r0_<apk-arch>.apk
# Signature:        <apk>.asc  (GPG detached ASCII-armor; the .apk itself is
#                   not abuild-signed, so install with `apk add --allow-untrusted`)
# Checksum:         <apk>.sha256
#
# Usage:
#   bash package_apk.sh --component server|cli --variant fips|non-fips
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
  nix-build -I "nixpkgs=${NIXPKGS_ARG}" --option substituters "" --no-build-output \
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
# Determine version and apk architecture
# ---------------------------------------------------------------------------
VERSION_STR="$("$REPO_ROOT/.mise/scripts/release/get_version.sh")"
APK_RELEASE="0"

RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64)
    APK_ARCH="x86_64"
    NFPM_ARCH="amd64"
    ;;
  aarch64 | arm64)
    APK_ARCH="aarch64"
    NFPM_ARCH="arm64"
    ;;
  *)
    echo "ERROR: unsupported architecture for apk packaging: $RAW_ARCH" >&2
    exit 1
    ;;
esac

if [ "$VARIANT" = "fips" ]; then
  OTHER_VARIANT="non-fips"
else
  OTHER_VARIANT="fips"
fi
PKG_NAME="cosmian-kms-${COMPONENT}-${VARIANT}"
APK_NAME="${PKG_NAME}_${VERSION_STR}-r${APK_RELEASE}_${APK_ARCH}.apk"

# ---------------------------------------------------------------------------
# Stage package contents
# ---------------------------------------------------------------------------
RESULT_DIR="$REPO_ROOT/result-apk-${COMPONENT}-${VARIANT}"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"

WORK_DIR="$(mktemp -d)"
# Files copied from the Nix store keep its read-only (dr-xr-xr-x) directory
# permissions; restore write access before removal so cleanup never fails.
trap 'chmod -R u+w "$WORK_DIR" 2>/dev/null || true; rm -rf "$WORK_DIR" || true' EXIT

STAGE="$WORK_DIR/stage"
mkdir -p "$STAGE"
cp "$BIN_PATH" "$STAGE/$BIN_NAME"
chmod 755 "$STAGE/$BIN_NAME"

HAS_COSMIAN_LIB=0
HAS_UI=0
if [ "$COMPONENT" = "server" ]; then
  # FIPS dynamic-musl server builds dlopen the FIPS provider module from this
  # tree at runtime (OPENSSL_MODULES/OPENSSL_CONF set by the OpenRC service).
  if [ -d "$REAL_OUT/usr/local/cosmian/lib" ]; then
    HAS_COSMIAN_LIB=1
    mkdir -p "$STAGE/lib"
    cp -r "$REAL_OUT/usr/local/cosmian/lib/." "$STAGE/lib/"
  fi
  if [ -d "$REAL_OUT/usr/local/cosmian/ui/dist" ]; then
    HAS_UI=1
    mkdir -p "$STAGE/ui"
    cp -r "$REAL_OUT/usr/local/cosmian/ui/dist/." "$STAGE/ui/"
  fi
  chmod -R u+w "$STAGE"
fi

# ---------------------------------------------------------------------------
# Generate nfpm configuration
# ---------------------------------------------------------------------------
# One explicit nfpm entry per file: nfpm's `type: tree` produces .apk files
# that apk-tools rejects ("package file format error"), and `**` globs
# flatten nested paths into collisions.
_emit_tree_entries() {
  local src_root="$1" dst_root="$2" f
  while IFS= read -r f; do
    printf '  - src: %s/%s\n    dst: %s/%s\n    file_info: { mode: 0644 }\n' \
      "$src_root" "$f" "$dst_root" "$f"
  done < <(cd "$src_root" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
}

NFPM_CONF="$WORK_DIR/nfpm.yaml"
{
  cat <<EOF
name: ${PKG_NAME}
arch: ${NFPM_ARCH}
platform: linux
version: ${VERSION_STR}
release: ${APK_RELEASE}
maintainer: Cosmian support team <tech@cosmian.com>
vendor: Cosmian Tech SAS
homepage: https://github.com/Cosmian/kms
license: BUSL-1.1
conflicts:
  - cosmian-kms-${COMPONENT}-${OTHER_VARIANT}
replaces:
  - cosmian-kms-${COMPONENT}-${OTHER_VARIANT}
EOF
  if [ "$VARIANT" = "fips" ]; then
    printf 'depends:\n  - libgcc\n'
  fi
  if [ "$COMPONENT" = "server" ]; then
    cat <<EOF
description: Cosmian KMS server (${VARIANT}, musl) for Alpine Linux
scripts:
  preinstall: ${REPO_ROOT}/pkg/apk/preinstall.sh
  postinstall: ${REPO_ROOT}/pkg/apk/postinstall.sh
  preremove: ${REPO_ROOT}/pkg/apk/preremove.sh
contents:
  - src: ${STAGE}/cosmian_kms
    dst: /usr/sbin/cosmian_kms
    file_info: { mode: 0755 }
  - src: ${REPO_ROOT}/pkg/kms.toml
    dst: /etc/cosmian/kms.toml
    type: config|noreplace
    # Group-readable by the unprivileged "kms" service user (see
    # cosmian_kms.initd's command_user) but only root-writable, so a
    # compromised server process cannot modify its own config. Requires
    # preinstall.sh (not postinstall) to create the "kms" group first —
    # apk-tools resolves named owners at file-extraction time and silently
    # falls back to root:root if the group doesn't exist yet.
    file_info: { owner: root, group: kms, mode: 0640 }
  - src: ${REPO_ROOT}/pkg/apk/cosmian_kms.initd
    dst: /etc/init.d/cosmian_kms
    file_info: { mode: 0755 }
  - src: ${REPO_ROOT}/pkg/apk/cosmian_kms.confd
    dst: /etc/conf.d/cosmian_kms
    type: config|noreplace
    file_info: { mode: 0644 }
  - src: ${REPO_ROOT}/README.md
    dst: /usr/share/doc/cosmian/README.md
    file_info: { mode: 0644 }
EOF
    if [ "$HAS_UI" = "1" ]; then
      _emit_tree_entries "$STAGE/ui" /usr/local/cosmian/ui/dist
    fi
    if [ "$HAS_COSMIAN_LIB" = "1" ]; then
      _emit_tree_entries "$STAGE/lib" /usr/local/cosmian/lib
    fi
  else
    cat <<EOF
description: Cosmian KMS CLI (ckms, ${VARIANT}, musl) for Alpine Linux
contents:
  - src: ${STAGE}/ckms
    dst: /usr/bin/ckms
    file_info: { mode: 0755 }
EOF
  fi
} >"$NFPM_CONF"

# ---------------------------------------------------------------------------
# Build the .apk with nfpm
# ---------------------------------------------------------------------------
echo "Building $APK_NAME …"
if command -v nfpm >/dev/null 2>&1; then
  nfpm package --config "$NFPM_CONF" --packager apk --target "$RESULT_DIR/$APK_NAME"
else
  nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p nfpm --run \
    "nfpm package --config '$NFPM_CONF' --packager apk --target '$RESULT_DIR/$APK_NAME'"
fi

[ -f "$RESULT_DIR/$APK_NAME" ] || {
  echo "ERROR: nfpm failed — $APK_NAME not created" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Sign the package (mirrors package_pkcs11_zip.sh's signing convention)
# ---------------------------------------------------------------------------
_sign_package() {
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
  _sign_package "$RESULT_DIR/$APK_NAME"
else
  echo "Skipping apk signing (not in GitHub Actions; set REQUIRE_SIGNING=1 to enforce)"
fi

# ---------------------------------------------------------------------------
# Write SHA-256 checksum
# ---------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM=$(sha256sum "$RESULT_DIR/$APK_NAME" | awk '{print $1}')
else
  CHECKSUM=$(shasum -a 256 "$RESULT_DIR/$APK_NAME" | awk '{print $1}')
fi
echo "$CHECKSUM  $APK_NAME" >"$RESULT_DIR/$APK_NAME.sha256"
echo "Wrote checksum: $APK_NAME.sha256 ($CHECKSUM)"

echo "====================================================="
echo "apk ($COMPONENT-$VARIANT): $RESULT_DIR/$APK_NAME"
ls -lh "$RESULT_DIR/"
echo "====================================================="
