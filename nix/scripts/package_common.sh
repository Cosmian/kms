#!/usr/bin/env bash
# Common packaging logic for Cosmian KMS
# Usage:
#   package_common.sh --format deb|rpm [--variant fips|non-fips]
# Notes:
# - Builds the prebuilt server via Nix (offline), enforces deterministic hash natively in derivation,
#   substitutes OpenSSL paths into Cargo.toml, then invokes cargo-deb or cargo-generate-rpm.
# - Reuses existing result-server-<variant> symlink if present to avoid rebuilds.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

# Defaults
FORMAT=""
VARIANT="fips"

usage() {
  echo "Usage: $0 --format deb|rpm [--variant fips|non-fips]" >&2
  exit 2
}

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
  -f | --format)
    FORMAT="${2:-}"
    shift 2 || true
    ;;
  -v | --variant)
    VARIANT="${2:-}"
    shift 2 || true
    ;;
  -h | --help) usage ;;
  *) shift ;;
  esac
done

case "$FORMAT" in
deb | rpm) : ;;
*)
  echo "Error: --format must be 'deb' or 'rpm'" >&2
  usage
  ;;

esac
case "$VARIANT" in
fips | non-fips) : ;;
*)
  echo "Error: --variant must be 'fips' or 'non-fips'" >&2
  exit 1
  ;;

esac

# Pin nixpkgs to match the dev shell (prefer a pre-resolved store path if provided)
PIN_URL="https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz"
if [ -n "${NIXPKGS_STORE:-}" ] && [ -e "${NIXPKGS_STORE}" ]; then
  PIN_URL="$NIXPKGS_STORE"
fi

# Persistent Cargo cache location used for offline packaging
OFFLINE_CARGO_HOME="$REPO_ROOT/target/cargo-offline-home"

# 0) Ensure OpenSSL tarball exists locally (offline build precondition)
OSSL_TARBALL_REL="resources/tarballs/openssl-3.1.2.tar.gz"
one_shot_fetch_openssl() {
  local tarball="$REPO_ROOT/$OSSL_TARBALL_REL"
  if [ ! -f "$tarball" ]; then
    echo "OpenSSL 3.1.2 tarball missing at $OSSL_TARBALL_REL; downloading once so subsequent steps can run offline…"
    mkdir -p "$(dirname "$tarball")"
    curl -fL --retry 3 -o "$tarball" "https://www.openssl.org/source/old/3.1/openssl-3.1.2.tar.gz" || {
      echo "ERROR: Could not fetch OpenSSL tarball (network/offline?). Place it at $OSSL_TARBALL_REL and retry." >&2
      exit 1
    }
  fi
}

# 0.1) Pre-warm Nix store (may use network) for openssl and server
prewarm_store() {
  if [ -n "${NO_PREWARM:-}" ]; then
    echo "Skipping prewarm (NO_PREWARM set)"
    return
  fi
  local need_openssl=1
  local openssl_link="$REPO_ROOT/result-openssl-312"
  if [ -L "$openssl_link" ] && [ -d "$(readlink -f "$openssl_link")" ]; then need_openssl=0; fi
  local need_server=1
  local server_link="$REPO_ROOT/result-server-${VARIANT}"
  if [ -L "$server_link" ] && [ -x "$(readlink -f "$server_link")/bin/cosmian_kms" ]; then need_server=0; fi
  if [ $need_openssl -eq 0 ] && [ $need_server -eq 0 ]; then
    echo "Prewarm skipped (artifacts already present)"
    return
  fi
  [ $need_openssl -eq 1 ] && nix-build -I "nixpkgs=${PIN_URL}" -A openssl312 --no-out-link >/dev/null || echo "OpenSSL derivation already present"
  [ $need_server -eq 1 ] && nix-build -I "nixpkgs=${PIN_URL}" -A "kms-server-${VARIANT}" --no-out-link >/dev/null || echo "Server derivation already present"
}

# 0.2) Pre-warm Cargo registry/cache so cargo-deb/cargo generate-rpm can operate offline
prewarm_cargo_registry() {
  if [ -n "${NO_PREWARM:-}" ]; then
    echo "Skipping cargo registry prewarm (NO_PREWARM set)"
    return
  fi
  ensure_modern_rust
  mkdir -p "$OFFLINE_CARGO_HOME"
  export CARGO_HOME="$OFFLINE_CARGO_HOME"
  echo "Prewarming Cargo registry for the entire workspace (Cargo.lock)…"
  pushd "$REPO_ROOT" >/dev/null
  cargo fetch --locked || true
  popd >/dev/null
}

# 1) Build/reuse prebuilt server via Nix (offline)
build_or_reuse_server() {
  local attr="kms-server-${VARIANT}"
  OUT_LINK="$REPO_ROOT/result-server-${VARIANT}"
  if [ -L "$OUT_LINK" ] && [ -x "$(readlink -f "$OUT_LINK")/bin/cosmian_kms" ]; then
    echo "Reusing prebuilt server from existing link: $OUT_LINK"
    REAL_SERVER=$(readlink -f "$OUT_LINK")
  else
    nix-build -I "nixpkgs=${PIN_URL}" --option substituters "" -A "$attr" -o "$OUT_LINK"
    REAL_SERVER=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
  fi
  BIN_OUT="$REAL_SERVER/bin/cosmian_kms"
}

# Enforce expected deterministic hash even on reuse path.
resolve_expected_hash_file() {
  # Strict resolution: only <base>.<system>.sha256 is accepted.
  # No OS-level or global fallbacks are permitted.
  local base="$1"
  local dir="$REPO_ROOT/nix/expected-hashes"
  local sys
  # Prefer Nix to compute the exact system string
  if sys=$(nix eval --raw --expr 'builtins.currentSystem' 2>/dev/null); then
    :
  else
    # Minimal mapping from uname to Nix system string
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) sys="x86_64-linux" ;;
    Linux-aarch64 | Linux-arm64) sys="aarch64-linux" ;;
    Darwin-x86_64) sys="x86_64-darwin" ;;
    Darwin-arm64) sys="aarch64-darwin" ;;
    *) sys="$(uname -m)-$(uname | tr '[:upper:]' '[:lower:]')" ;;
    esac
  fi

  local path="$dir/${base}.${sys}.sha256"
  if [ -f "$path" ]; then
    echo "$path"
    return 0
  fi
  return 1
}

enforce_binary_hash() {
  local expected_file
  if ! expected_file=$(resolve_expected_hash_file "$VARIANT"); then
    echo "ERROR: Expected hash file missing for variant '$VARIANT'." >&2
    # Print actual system to assist the user
    local sys
    if sys=$(nix eval --raw --expr 'builtins.currentSystem' 2>/dev/null); then :; else sys="unknown-system"; fi
    echo "       Required file: nix/expected-hashes/${VARIANT}.${sys}.sha256" >&2
    echo "Present files:" >&2
    ls -1 "$REPO_ROOT/nix/expected-hashes" >&2 || true
    exit 1
  fi
  local expected_hash actual_hash
  expected_hash=$(tr -d ' \t\r\n' <"$expected_file")
  if [ -z "$expected_hash" ]; then
    echo "ERROR: Expected hash in $expected_file is empty" >&2
    exit 1
  fi
  if [ ! -f "$BIN_OUT" ]; then
    echo "ERROR: Binary not found for hash check: $BIN_OUT" >&2
    exit 1
  fi
  actual_hash=$(sha256sum "$BIN_OUT" | awk '{print $1}')
  if [ "$actual_hash" != "$expected_hash" ]; then
    echo "ERROR: Binary hash mismatch (variant $VARIANT)." >&2
    echo "  Expected: $expected_hash (from $(basename "$expected_file"))" >&2
    echo "  Actual:   $actual_hash" >&2
    echo "Attempting fresh nix-build of kms-server-$VARIANT to confirm installCheckPhase failure…" >&2
    rm -f "$OUT_LINK" 2>/dev/null || true
    if nix-build -I "nixpkgs=${PIN_URL}" --option substituters "" -A "kms-server-${VARIANT}" -o "$OUT_LINK"; then
      echo "Unexpected success rebuilding derivation despite hash mismatch; investigate installCheckPhase." >&2
      exit 1
    else
      echo "Rebuild failed as expected due to deterministic hash mismatch." >&2
      exit 1
    fi
  fi
  echo "Deterministic hash OK ($actual_hash) for variant $VARIANT"
}

# 2) Get OpenSSL 3.1.2 path via Nix (for asset placeholders in Cargo.toml) offline
resolve_openssl_path() {
  local link="$REPO_ROOT/result-openssl-312"
  if [ -L "$link" ] && [ -d "$(readlink -f "$link")" ]; then :; else
    rm -f "$link" 2>/dev/null || true
    nix-build -I "nixpkgs=${PIN_URL}" --option substituters "" -A openssl312 -o "$link"
  fi
  OSSL_PATH=$(readlink -f "$link")
  OSSL_NO_SLASH="${OSSL_PATH#/}"
}

# 2.5) Ensure modern rust toolchain (Cargo 1.90) from Nix is on PATH to avoid rustup downloads
ensure_modern_rust() {
  local link="$REPO_ROOT/result-rust-1_90"
  if [ -L "$link" ] && [ -x "$link/bin/cargo" ] && [ -x "$link/bin/rustc" ]; then
    :
  else
    rm -f "$link" 2>/dev/null || true
    nix-build -I "nixpkgs=${PIN_URL}" -A rustToolchain -o "$link"
  fi
  export PATH="$link/bin:$PATH"
}

# 2.6) Sign packages with GPG if signing key is available
# Usage: sign_packages <dir> <pattern>
#   or:  sign_packages <file_path>  (for single file like DMG)
sign_packages() {
  local target="$1"
  local pattern="${2:-}"

  local keys_dir="$REPO_ROOT/nix/signing-keys"
  local key_id_file="$keys_dir/key-id.txt"

  # Signing is mandatory - fail if no key is configured
  if [ ! -f "$key_id_file" ]; then
    echo "ERROR: No signing key found at $key_id_file" >&2
    echo "Package signing is mandatory. Generate a signing key with: bash nix/scripts/generate_signing_key.sh" >&2
    exit 1
  fi

  local key_id
  key_id=$(cat "$key_id_file" | tr -d ' \t\r\n')

  if [ -z "$key_id" ]; then
    echo "ERROR: Empty key ID in $key_id_file" >&2
    exit 1
  fi

  # Check if passphrase is available
  if [ -z "${GPG_SIGNING_KEY_PASSPHRASE:-}" ]; then
    echo "ERROR: GPG_SIGNING_KEY_PASSPHRASE environment variable is not set" >&2
    echo "Package signing is mandatory. Set GPG_SIGNING_KEY_PASSPHRASE to continue." >&2
    exit 1
  fi

  # Import private key if not already in keyring
  local private_key="$keys_dir/cosmian-kms-private.asc"
  # If GPG_SIGNING_KEY env var is set, write it to the private key file and import immediately
  if [ -n "${GPG_SIGNING_KEY:-}" ]; then
    echo "Writing GPG_SIGNING_KEY to $private_key..."
    printf '%s\n' "$GPG_SIGNING_KEY" >"$private_key"
    echo "Importing signing key $key_id from GPG_SIGNING_KEY environment variable..."
    gpg --batch --import "$private_key" 2>/dev/null || {
      echo "ERROR: Failed to import GPG key from GPG_SIGNING_KEY environment variable" >&2
      exit 1
    }
  else
    # Check if the key is already imported (e.g., by CI action)
    if ! gpg --list-secret-keys "$key_id" >/dev/null 2>&1; then
      # Key not in keyring and GPG_SIGNING_KEY not set - try importing from file
      if [ -f "$private_key" ]; then
        echo "Importing signing key $key_id from $private_key..."
        gpg --batch --import "$private_key" 2>/dev/null || {
          echo "ERROR: Failed to import GPG key from $private_key" >&2
          exit 1
        }
      else
        echo "ERROR: Signing key $key_id not found in GPG keyring and $private_key does not exist" >&2
        echo "Either set GPG_SIGNING_KEY environment variable or ensure key is already imported" >&2
        exit 1
      fi
    else
      echo "Using signing key $key_id already present in GPG keyring"
    fi
  fi

  # Determine if target is a directory or a file
  local files_to_sign=()
  if [ -d "$target" ]; then
    # Directory mode: sign all files matching pattern
    if [ -z "$pattern" ]; then
      echo "ERROR: Pattern required when signing directory" >&2
      exit 1
    fi
    echo "Signing packages in $target matching $pattern with key $key_id..."
    for pkg in "$target"/$pattern; do
      [ -e "$pkg" ] && files_to_sign+=("$pkg")
    done
  elif [ -f "$target" ]; then
    # Single file mode
    echo "Signing package with key $key_id..."
    files_to_sign=("$target")
  else
    echo "ERROR: Target not found: $target" >&2
    exit 1
  fi

  # Sign each file
  for pkg in "${files_to_sign[@]}"; do
    local sig="${pkg}.asc"

    # Remove old signature if present
    rm -f "$sig"

    # Create detached ASCII-armored signature
    # Use --pinentry-mode loopback to avoid terminal/GUI prompts in non-interactive contexts
    echo "$GPG_SIGNING_KEY_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
      --passphrase-fd 0 --armor --detach-sign --local-user "$key_id" "$pkg"

    if [ -f "$sig" ]; then
      echo "  Signed: $(basename "$pkg") -> $(basename "$sig")"

      # Verify the signature immediately
      if gpg --verify "$sig" "$pkg" 2>&1 | grep -q "Good signature"; then
        echo "  ✓ Signature verified successfully"
      else
        echo "  ERROR: Signature verification failed for $(basename "$pkg")" >&2
        exit 1
      fi
    else
      echo "  ERROR: Failed to create signature for $(basename "$pkg")" >&2
      exit 1
    fi
  done
}

# Helper: map host triple to Debian/RPM architecture strings
detect_arches() {
  # Requires HOST_TRIPLE to be set (prepare_workspace)
  local mach
  mach=$(uname -m)
  case "$HOST_TRIPLE" in
  x86_64-*-linux*)
    DEB_ARCH="amd64"
    RPM_ARCH="x86_64"
    ;;
  aarch64-*-linux*)
    DEB_ARCH="arm64"
    RPM_ARCH="aarch64"
    ;;
  i686-*-linux* | i386-*-linux*)
    DEB_ARCH="i386"
    RPM_ARCH="i686"
    ;;
  armv7*-linux-gnueabihf | arm-*-linux-gnueabihf)
    DEB_ARCH="armhf"
    RPM_ARCH="armv7hl"
    ;;
  *)
    case "$mach" in
    x86_64)
      DEB_ARCH="amd64"
      RPM_ARCH="x86_64"
      ;;
    aarch64 | arm64)
      DEB_ARCH="arm64"
      RPM_ARCH="aarch64"
      ;;
    i686 | i386)
      DEB_ARCH="i386"
      RPM_ARCH="i686"
      ;;
    *)
      # Last-resort: try dpkg/rpm if available
      if command -v dpkg >/dev/null 2>&1; then
        DEB_ARCH=$(dpkg --print-architecture || echo "$mach")
      else
        DEB_ARCH="$mach"
      fi
      if command -v rpm >/dev/null 2>&1; then
        RPM_ARCH=$(rpm --eval '%{_arch}' 2>/dev/null || echo "$mach")
      else
        RPM_ARCH="$mach"
      fi
      ;;
    esac
    ;;
  esac
  export DEB_ARCH RPM_ARCH
}

# 3) Prepare cargo workspace
prepare_workspace() {
  HOST_TRIPLE=$(rustc -vV | awk '/host:/ {print $2}')
  mkdir -p "crate/server/target/$HOST_TRIPLE/release" "crate/server/target/release" "target/release"
  cp -f -v "$BIN_OUT" "crate/server/target/$HOST_TRIPLE/release/cosmian_kms"
  cp -f -v "$BIN_OUT" "crate/server/target/release/cosmian_kms"
  cp -f -v "$BIN_OUT" "target/release/cosmian_kms"
  export HOME="${TMPDIR:-/tmp}"
  # Keep a persistent CARGO_HOME if already set (from prewarm); otherwise fallback to temp
  export CARGO_HOME="${CARGO_HOME:-$OFFLINE_CARGO_HOME}"
  mkdir -p "$CARGO_HOME"
}

# 4) Substitute OpenSSL paths in Cargo.toml (temporary)
substitute_cargo_toml() {
  CARGO_TOML="crate/server/Cargo.toml"
  BACKUP_TOML="$CARGO_TOML.bak"
  cp -f "$CARGO_TOML" "$BACKUP_TOML"
  restore() { mv -f "$BACKUP_TOML" "$CARGO_TOML" 2>/dev/null || true; }
  trap restore INT TERM EXIT
  perl -0777 -pe "s|XXX|$OSSL_PATH|g; s|YYY|$OSSL_NO_SLASH|g" "$BACKUP_TOML" >"$CARGO_TOML"
}

# 5) Build package depending on format
build_deb() {
  # Ensure cargo-deb is available via Nix (pinned), add to PATH
  ensure_cargo_deb
  # Enforce offline Cargo operations during packaging
  export CARGO_HOME="${CARGO_HOME:-$OFFLINE_CARGO_HOME}"
  export CARGO_NET_OFFLINE=true
  pushd crate/server >/dev/null
  if [ "$VARIANT" = "fips" ]; then
    cargo deb --no-build --variant fips
  else
    cargo deb --no-build
  fi
  popd >/dev/null
}

collect_deb() {
  local result_dir="$REPO_ROOT/result-deb-${VARIANT}"
  rm -rf "$result_dir" 2>/dev/null || true
  mkdir -p "$result_dir"
  local found=0
  for p in \
    "$REPO_ROOT/crate/server/target/debian" \
    "$REPO_ROOT/crate/server/target/$HOST_TRIPLE/debian" \
    "$REPO_ROOT/target/debian" \
    "$REPO_ROOT/target/$HOST_TRIPLE/debian"; do
    if [ -d "$p" ]; then
      if [ "$VARIANT" = "fips" ]; then
        find "$p" -maxdepth 1 -type f -name '*-fips_*.deb' -print -exec cp -f -v {} "$result_dir/" \;
      else
        find "$p" -maxdepth 1 -type f -name '*.deb' ! -name '*-fips_*.deb' -print -exec cp -f -v {} "$result_dir/" \;
      fi
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "Error: No .deb produced by cargo-deb" >&2
    exit 1
  fi

  # Ensure Debian filenames include architecture suffix in the standard position
  # Expected: <name>_<version>_<arch>.deb
  for f in "$result_dir"/*.deb; do
    [ -e "$f" ] || continue
    local b
    b=$(basename "$f")
    if echo "$b" | grep -Eq "_(all|${DEB_ARCH})\\.deb$"; then
      : # already contains arch
    else
      local new
      new="${b%.deb}_${DEB_ARCH}.deb"
      mv -v "$result_dir/$b" "$result_dir/$new"
    fi
  done

  # Sign all .deb packages
  sign_packages "$result_dir" "*.deb"

  # Copy public key to result directory if it exists
  local public_key="$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc"
  if [ -f "$public_key" ]; then
    cp -v "$public_key" "$result_dir/"
    echo "  Copied public key to $result_dir/"
  fi

  echo "Built deb (${VARIANT}): $result_dir"
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

ensure_cargo_deb() {
  local link="$REPO_ROOT/result-cargo-deb"
  if [ -L "$link" ] && [ -x "$link/bin/cargo-deb" ]; then
    :
  else
    rm -f "$link" 2>/dev/null || true
    # Build cargo-deb from pinned nixpkgs and link it for PATH usage
    nix-build -I "nixpkgs=${PIN_URL}" -E 'with import <nixpkgs> {}; cargo-deb' -o "$link"
  fi
  export PATH="$link/bin:$PATH"
}

build_rpm() {
  export CARGO_HOME="${CARGO_HOME:-$OFFLINE_CARGO_HOME}"
  export CARGO_NET_OFFLINE=true
  if [ "$VARIANT" = "fips" ]; then
    cargo generate-rpm --target "$HOST_TRIPLE" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml --variant fips
  else
    cargo generate-rpm --target "$HOST_TRIPLE" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml
  fi
}

collect_rpm() {
  local result_dir="$REPO_ROOT/result-rpm-${VARIANT}"
  rm -rf "$result_dir" 2>/dev/null || true
  mkdir -p "$result_dir"
  local found=0
  for p in \
    "$REPO_ROOT/crate/server/target/$HOST_TRIPLE/generate-rpm" \
    "$REPO_ROOT/crate/server/target/generate-rpm" \
    "$REPO_ROOT/target/$HOST_TRIPLE/generate-rpm" \
    "$REPO_ROOT/target/generate-rpm"; do
    if [ -d "$p" ]; then
      find "$p" -maxdepth 1 -type f -name '*.rpm' -print -exec cp -f -v {} "$result_dir/" \;
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "Error: No .rpm produced by cargo-generate-rpm" >&2
    exit 1
  fi
  if [ "$VARIANT" = "fips" ]; then
    for f in "$result_dir"/*.rpm; do
      [ -e "$f" ] || continue
      local b
      b=$(basename "$f")
      local n
      n="${b/cosmian_kms_server-/cosmian_kms_server_fips-}"
      if [ "$n" != "$b" ]; then mv -v "$result_dir/$b" "$result_dir/$n"; fi
    done
  fi

  # Ensure RPM filenames include .<arch>.rpm
  for f in "$result_dir"/*.rpm; do
    [ -e "$f" ] || continue
    local b
    b=$(basename "$f")
    if echo "$b" | grep -Eq "\.(noarch|${RPM_ARCH})\.rpm$"; then
      : # already contains arch
    else
      local new
      new="${b%.rpm}.${RPM_ARCH}.rpm"
      mv -v "$result_dir/$b" "$result_dir/$new"
    fi
  done

  # Sign all .rpm packages
  sign_packages "$result_dir" "*.rpm"

  # Copy public key to result directory if it exists
  local public_key="$REPO_ROOT/nix/signing-keys/cosmian-kms-public.asc"
  if [ -f "$public_key" ]; then
    cp -v "$public_key" "$result_dir/"
    echo "  Copied public key to $result_dir/"
  fi

  echo "Built rpm (${VARIANT}): $result_dir"
}

# Execute flow
one_shot_fetch_openssl
prewarm_store
build_or_reuse_server
enforce_binary_hash
resolve_openssl_path
prewarm_cargo_registry
prepare_workspace
detect_arches
substitute_cargo_toml

case "$FORMAT" in
deb)
  ensure_modern_rust
  build_deb
  collect_deb
  ;;
rpm)
  ensure_modern_rust
  ensure_cargo_generate_rpm
  build_rpm
  collect_rpm
  ;;
esac

# Explicit restoration of substituted Cargo.toml (belt & suspenders in case trap did not fire)
if [ -f "crate/server/Cargo.toml.bak" ]; then
  mv -f "crate/server/Cargo.toml.bak" "crate/server/Cargo.toml" 2>/dev/null || true
fi
