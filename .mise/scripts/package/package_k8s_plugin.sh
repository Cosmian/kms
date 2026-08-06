#!/usr/bin/env bash
# Build deb/rpm package for the Cosmian KMS Kubernetes Plugin.
#
# Unlike package_common.sh this is intentionally lean: the plugin has no
# UI, no FIPS/non-FIPS variants, and no OpenSSL module files. The flow is:
#   1. Build the binary via Nix (k8s-plugin-bin attribute in default.nix).
#   2. Copy it to the expected cargo-deb/cargo-generate-rpm location.
#   3. Run cargo-deb or cargo-generate-rpm with --no-build.
#   4. Collect and rename the output package.
#
# Usage:
#   package_k8s_plugin.sh --format deb|rpm

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
source "${REPO_ROOT}/.mise/scripts/common.sh"
cd "$REPO_ROOT"

FORMAT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f | --format)
      FORMAT="${2:-}"
      shift 2 || true
      ;;
    -h | --help)
      echo "Usage: $0 --format deb|rpm" >&2
      exit 0
      ;;
    *) shift ;;
  esac
done

case "$FORMAT" in
  deb | rpm) : ;;
  *)
    echo "Error: --format must be 'deb' or 'rpm'" >&2
    exit 1
    ;;
esac

PLUGIN_CRATE="$REPO_ROOT/crate/clients/k8s/plugin"
VERSION=$("$REPO_ROOT/.mise/scripts/release/get_version.sh")

# ── 1. Ensure toolchain helpers are sourced ───────────────────────────────────
ensure_modern_rust() {
  local link="$REPO_ROOT/result-rust-1_97"
  if [ -L "$link" ] && [ -x "$link/bin/cargo" ]; then
    :
  else
    rm -f "$link" 2>/dev/null || true
    nix-build -I "nixpkgs=${PIN_URL}" -A rustToolchain -o "$link"
  fi
  export PATH="$link/bin:$PATH"
}

ensure_cargo_deb() {
  local link="$REPO_ROOT/result-cargo-deb"
  if [ -L "$link" ] && [ -x "$link/bin/cargo-deb" ]; then
    :
  else
    rm -f "$link" 2>/dev/null || true
    nix-build -I "nixpkgs=${PIN_URL}" \
      -E 'with import <nixpkgs> {}; cargo-deb.overrideAttrs (old: { doCheck = false; })' \
      -o "$link"
  fi
  export PATH="$link/bin:$PATH"
}

ensure_cargo_generate_rpm() {
  local link="$REPO_ROOT/result-cargo-generate-rpm"
  if [ -L "$link" ] && [ -x "$link/bin/cargo-generate-rpm" ]; then
    :
  else
    rm -f "$link" 2>/dev/null || true
    nix-build -I "nixpkgs=${PIN_URL}" -A cargoGenerateRpmTool -o "$link"
  fi
  export PATH="$link/bin:$PATH"
}

sign_package() {
  local pkg="$1"
  local keys_dir="$REPO_ROOT/nix/signing-keys"
  local key_id_file="$keys_dir/key-id.txt"

  # Signing is mandatory in CI; can be forced locally with REQUIRE_SIGNING=1
  local require_signing="0"
  if [ "${REQUIRE_SIGNING:-}" = "1" ] || [ -n "${CI:-}" ]; then
    require_signing="1"
  fi

  if [ ! -f "$key_id_file" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: No signing key found at $key_id_file" >&2
      echo "Generate one with: bash nix/scripts/generate_signing_key.sh" >&2
      exit 1
    fi
    echo "Signing skipped: no key-id.txt present (set REQUIRE_SIGNING=1 to enforce)"
    return 0
  fi

  local key_id
  key_id=$(tr -d ' \t\r\n' <"$key_id_file")

  if [ -z "$key_id" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: Empty key ID in $key_id_file" >&2
      exit 1
    fi
    echo "Signing skipped: empty key ID"
    return 0
  fi

  if [ -z "${GPG_SIGNING_KEY_PASSPHRASE:-}" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: GPG_SIGNING_KEY_PASSPHRASE is not set" >&2
      exit 1
    fi
    echo "Signing skipped: GPG_SIGNING_KEY_PASSPHRASE not set (set REQUIRE_SIGNING=1 to enforce)"
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
    if [ -f "$private_key" ]; then
      gpg --batch --import "$private_key" 2>/dev/null || {
        echo "ERROR: Failed to import GPG key from $private_key" >&2
        exit 1
      }
    else
      if [ "$require_signing" = "1" ]; then
        echo "ERROR: Key $key_id not in keyring and no private key file found" >&2
        exit 1
      fi
      echo "Signing skipped: no private key available"
      return 0
    fi
  fi

  echo "Signing $pkg with key $key_id..."
  echo "$GPG_SIGNING_KEY_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --armor --detach-sign --local-user "$key_id" "$pkg"
  echo "Signed: $pkg"
}

# ── 2. Build plugin binary via Nix ────────────────────────────────────────────
OUT_LINK="$REPO_ROOT/result-k8s-plugin-bin"
if [ -L "$OUT_LINK" ] && [ -x "$(readlink -f "$OUT_LINK")/bin/kubernetes-kms-plugin" ]; then
  echo "Reusing cached plugin binary from $OUT_LINK"
else
  echo "Building k8s-plugin-bin via Nix..."
  # Do NOT pass --option substituters "" here: the k8s-plugin derivation uses
  # pkgs228 (glibc 2.28) which requires bootstrapping bash-4.4-p23 from source
  # when the binary cache is disabled. Without the cache, Nix downloads
  # bash-4.4 patches from ftpmirror.gnu.org which returns 502 errors. Using
  # the binary cache avoids this by substituting pre-built packages.
  env -u LD_LIBRARY_PATH -u LD_PRELOAD \
    nix-build -I "nixpkgs=${PIN_URL}" \
    "$REPO_ROOT/default.nix" -A k8s-plugin-bin -o "$OUT_LINK"
fi
PLUGIN_BIN="$(readlink -f "$OUT_LINK")/bin/kubernetes-kms-plugin"
[ -x "$PLUGIN_BIN" ] || {
  echo "ERROR: plugin binary not found at $PLUGIN_BIN" >&2
  exit 1
}

# ── 3. Detect host architecture ───────────────────────────────────────────────
HOST_TRIPLE=$(rustc -vV 2>/dev/null | grep '^host' | awk '{print $2}' || echo "x86_64-unknown-linux-gnu")
DEB_ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
RPM_ARCH=$(uname -m)

# ── 4. Place binary where cargo-deb/cargo-generate-rpm expects it ─────────────
# cargo-deb resolves asset paths via `cargo metadata` which returns the
# WORKSPACE target directory (not the crate-specific one). Copy to all
# locations to cover both cargo-deb and cargo-generate-rpm resolution.
TARGET_DIR="$PLUGIN_CRATE/target/release"
WORKSPACE_TARGET="$REPO_ROOT/target/release"
HOST_TRIPLE=$(rustc -vV 2>/dev/null | awk '/host:/ {print $2}')
for dir in "$TARGET_DIR" "$PLUGIN_CRATE/target/$HOST_TRIPLE/release" \
  "$WORKSPACE_TARGET" "$REPO_ROOT/target/$HOST_TRIPLE/release"; do
  mkdir -p "$dir"
  cp -f "$PLUGIN_BIN" "$dir/kubernetes-kms-plugin"
  chmod 755 "$dir/kubernetes-kms-plugin"
done
echo "Copied plugin binary to target/release/ (crate + workspace)"

# ── 5. Build the package ──────────────────────────────────────────────────────
ensure_modern_rust

RESULT_DIR="$REPO_ROOT/result-k8s-plugin-${FORMAT}"
rm -rf "$RESULT_DIR" 2>/dev/null || true
mkdir -p "$RESULT_DIR"

case "$FORMAT" in
  deb)
    ensure_cargo_deb
    cd "$PLUGIN_CRATE"
    cargo deb --no-build --no-strip 2>&1
    cd "$REPO_ROOT"

    # Collect and rename output
    FOUND=0
    for search_dir in \
      "$PLUGIN_CRATE/target/debian" \
      "$PLUGIN_CRATE/target/$HOST_TRIPLE/debian" \
      "$REPO_ROOT/target/debian"; do
      if [ -d "$search_dir" ]; then
        find "$search_dir" -maxdepth 1 -name "*.deb" -print -exec cp -f {} "$RESULT_DIR/" \;
        FOUND=1
      fi
    done
    [ "$FOUND" -eq 1 ] || {
      echo "ERROR: no .deb produced" >&2
      exit 1
    }

    # Rename to convention: kubernetes-kms-plugin_<version>_<arch>.deb
    for f in "$RESULT_DIR"/*.deb; do
      [ -e "$f" ] || continue
      NEW="$RESULT_DIR/kubernetes-kms-plugin_${VERSION}_${DEB_ARCH}.deb"
      [ "$f" = "$NEW" ] || mv -v "$f" "$NEW"
      sign_package "$NEW"
    done

    # Copy public key
    [ -f "$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc" ] &&
      cp "$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc" "$RESULT_DIR/"

    echo "Built deb package: $RESULT_DIR"
    ;;

  rpm)
    ensure_cargo_generate_rpm
    cd "$PLUGIN_CRATE"
    # cargo-generate-rpm does not have --no-build; it generates RPM from
    # already-built artifacts. Pass --target so it finds the binary.
    cargo generate-rpm --target "$HOST_TRIPLE" 2>&1
    cd "$REPO_ROOT"

    # Collect and rename output
    FOUND=0
    for search_dir in \
      "$PLUGIN_CRATE/target/generate-rpm" \
      "$PLUGIN_CRATE/target/$HOST_TRIPLE/generate-rpm" \
      "$REPO_ROOT/target/generate-rpm" \
      "$REPO_ROOT/target/$HOST_TRIPLE/generate-rpm"; do
      if [ -d "$search_dir" ]; then
        find "$search_dir" -maxdepth 1 -name "*.rpm" -print -exec cp -f {} "$RESULT_DIR/" \;
        FOUND=1
      fi
    done
    [ "$FOUND" -eq 1 ] || {
      echo "ERROR: no .rpm produced" >&2
      exit 1
    }

    # Ensure correct arch suffix and rename
    for f in "$RESULT_DIR"/*.rpm; do
      [ -e "$f" ] || continue
      b=$(basename "$f")
      if ! echo "$b" | grep -Eq "\.(noarch|${RPM_ARCH})\.rpm$"; then
        mv -v "$f" "$RESULT_DIR/${b%.rpm}.${RPM_ARCH}.rpm"
        b="${b%.rpm}.${RPM_ARCH}.rpm"
        f="$RESULT_DIR/$b"
      fi
      NEW="$RESULT_DIR/kubernetes-kms-plugin_${VERSION}_${RPM_ARCH}.rpm"
      [ "$f" = "$NEW" ] || mv -v "$f" "$NEW"
      sign_package "$NEW"
    done

    # Copy public key
    [ -f "$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc" ] &&
      cp "$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc" "$RESULT_DIR/"

    echo "Built rpm package: $RESULT_DIR"
    ;;
esac
