#!/usr/bin/env bash
# Common packaging logic for Cosmian KMS
# Usage:
#   package_common.sh --format deb|rpm [--variant fips|non-fips]
# Notes:
# - Builds the prebuilt server via Nix (offline), enforces deterministic hash natively in derivation,
#   substitutes OpenSSL source paths into Cargo.toml, then invokes cargo-deb or cargo-generate-rpm.
# - Destination paths are hardcoded to /usr/local/cosmian/lib in Cargo.toml
# - Reuses existing result-server-<variant> symlink if present to avoid rebuilds.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
# Source unified PIN_URL and helpers
source "$REPO_ROOT/.github/scripts/common.sh"
cd "$REPO_ROOT"

# Defaults
FORMAT=""
VARIANT="fips"
LINK="static"

usage() {
  echo "Usage: $0 --format deb|rpm [--variant fips|non-fips] [--link static|dynamic]" >&2
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
  -l | --link)
    LINK="${2:-}"
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
case "$LINK" in
static | dynamic) : ;;
*)
  echo "Error: --link must be 'static' or 'dynamic'" >&2
  exit 1
  ;;

esac

# Ensure expected-hash files exist for this platform/variant/link before building
ensure_expected_hashes() {
  local sys arch os impl
  # Derive current system triple (best-effort)
  if sys=$(nix eval --raw --expr 'builtins.currentSystem' 2>/dev/null); then :; else
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) sys="x86_64-linux" ;;
    Linux-aarch64 | Linux-arm64) sys="aarch64-linux" ;;
    Darwin-x86_64) sys="x86_64-darwin" ;;
    Darwin-arm64) sys="aarch64-darwin" ;;
    *) sys="$(uname -m)-$(uname | tr '[:upper:]' '[:lower:]')" ;;
    esac
  fi
  arch="${sys%%-*}"
  os="${sys#*-}"
  impl=$([ "$LINK" = "dynamic" ] && echo no-openssl || echo openssl)

  local hashes_dir="$REPO_ROOT/nix/expected-hashes"
  mkdir -p "$hashes_dir"

  local missing=0
  # Server vendor cargo hash file
  local server_vendor_file="$hashes_dir/server.vendor.${VARIANT}.${impl}.${arch}.${os}.sha256"
  [ -s "$server_vendor_file" ] || missing=1
  # UI vendor cargo hash file
  local ui_vendor_file="$hashes_dir/ui.vendor.${VARIANT}.${arch}.${os}.sha256"
  [ -s "$ui_vendor_file" ] || missing=1
  # UI npm deps hash file
  local ui_npm_file="$hashes_dir/ui.npm.${VARIANT}.${arch}.${os}.sha256"
  [ -s "$ui_npm_file" ] || missing=1
  # UI WASM vendor cargo hash file (kept in sync with UI vendor)
  local ui_wasm_vendor_file="$hashes_dir/ui.wasm.vendor.${VARIANT}.${arch}.${os}.sha256"
  [ -s "$ui_wasm_vendor_file" ] || missing=1

  if [ $missing -eq 1 ]; then
    echo "WARNING: One or more expected hash files are missing for variant $VARIANT, link $LINK, system $sys." >&2
  fi
}

# Pin nixpkgs to match the dev shell (prefer a pre-resolved store path if provided)
# Default comes from common.sh; allow override via pre-resolved store path
if [ -n "${NIXPKGS_STORE:-}" ] && [ -e "${NIXPKGS_STORE}" ]; then
  PIN_URL="$NIXPKGS_STORE"
fi

# Persistent Cargo cache location used for offline packaging
OFFLINE_CARGO_HOME="$REPO_ROOT/target/cargo-offline-home"

# 0) Ensure OpenSSL tarball exists locally (offline build precondition)
# Only needed for static linking
OSSL_TARBALL_REL="resources/tarballs/openssl-3.1.2.tar.gz"
one_shot_fetch_openssl() {
  # Skip OpenSSL fetch for dynamic builds
  if [ "$LINK" = "dynamic" ]; then
    return 0
  fi

  local tarball="$REPO_ROOT/$OSSL_TARBALL_REL"
  if [ ! -f "$tarball" ]; then
    echo "OpenSSL 3.1.2 tarball missing at $OSSL_TARBALL_REL; downloading once so subsequent steps can run offline…"
    mkdir -p "$(dirname "$tarball")"
    curl -fL --retry 3 -o "$tarball" "https://package.cosmian.com/openssl/openssl-3.1.2.tar.gz" || {
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

  # Only need OpenSSL for static builds
  local need_openssl=0
  if [ "$LINK" = "static" ]; then
    need_openssl=1
    local openssl_link="$REPO_ROOT/result-openssl-312"
    if [ -L "$openssl_link" ] && [ -d "$(readlink -f "$openssl_link")" ]; then need_openssl=0; fi
  fi

  local need_server=1
  local server_link="$REPO_ROOT/result-server-${VARIANT}-${LINK}"
  if [ -L "$server_link" ] && [ -x "$(readlink -f "$server_link")/bin/cosmian_kms" ]; then need_server=0; fi

  if [ $need_openssl -eq 0 ] && [ $need_server -eq 0 ]; then
    echo "Prewarm skipped (artifacts already present)"
    return
  fi

  [ $need_openssl -eq 1 ] && nix-build -I "nixpkgs=${PIN_URL}" -A openssl312 --no-out-link >/dev/null || echo "OpenSSL derivation already present"

  # Determine Nix attribute for server
  local server_attr
  if [ "$LINK" = "dynamic" ]; then
    server_attr="kms-server-${VARIANT}-no-openssl"
  else
    server_attr="kms-server-${VARIANT}"
  fi
  [ $need_server -eq 1 ] && nix-build -I "nixpkgs=${PIN_URL}" -A "$server_attr" --no-out-link >/dev/null || echo "Server derivation already present"
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
  # Determine Nix attribute based on LINK type
  local attr
  if [ "$LINK" = "dynamic" ]; then
    attr="kms-server-${VARIANT}-dynamic"
  else
    attr="kms-server-${VARIANT}"
  fi

  OUT_LINK="$REPO_ROOT/result-server-${VARIANT}-${LINK}"

  # If we already have a built server at the expected link, reuse it blindly.
  # The link name encodes variant/linkage, so no need to parse --info output,
  # which can be ambiguous across modes and caused false mismatches.
  if [ -L "$OUT_LINK" ] && [ -x "$(readlink -f "$OUT_LINK")/bin/cosmian_kms" ]; then
    REAL_SERVER=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
  else
    nix-build -I "nixpkgs=${PIN_URL}" --option substituters "" -A "$attr" -o "$OUT_LINK"
    REAL_SERVER=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
  fi

  BIN_OUT="$REAL_SERVER/bin/cosmian_kms"

  # We no longer rely on embedded UI assets inside the server derivation.
  # UI is built (or reused) independently via build_or_reuse_ui() and copied later.
  echo "Reusing/built server OK: binary present (UI handled separately)"
}

# Build (or reuse) the Web UI once per variant, independent from server builds.
# This avoids rebuilding the UI for each linkage type (static/dynamic) and keeps
# the server derivations focused solely on the Rust backend.
build_or_reuse_ui() {
  local ui_attr
  if [ "$VARIANT" = "non-fips" ]; then
    ui_attr="ui-non-fips"
  else
    ui_attr="ui-fips"
  fi

  UI_OUT_LINK="$REPO_ROOT/result-ui-${VARIANT}"
  if [ -L "$UI_OUT_LINK" ] && [ -d "$(readlink -f "$UI_OUT_LINK")/dist" ]; then
    echo "Reusing prebuilt UI from $UI_OUT_LINK"
    REAL_UI=$(readlink -f "$UI_OUT_LINK" || echo "$UI_OUT_LINK")
  else
    echo "Building UI derivation ($ui_attr) once for variant $VARIANT…"
    nix-build -I "nixpkgs=${PIN_URL}" "$REPO_ROOT/default.nix" -A "$ui_attr" -o "$UI_OUT_LINK"
    REAL_UI=$(readlink -f "$UI_OUT_LINK" || echo "$UI_OUT_LINK")
    if [ ! -d "$REAL_UI/dist" ]; then
      echo "ERROR: UI derivation $REAL_UI lacks dist/ directory" >&2
      exit 1
    fi
  fi
  UI_DIST_PATH="$REAL_UI/dist"
}

# Enforce expected deterministic hash even on reuse path.
resolve_expected_hash_file() {
  # Naming convention:
  #   server.<fips|non-fips>.<openssl|no-openssl>.<arch>.<os>.sha256
  # Backward-compatible fallbacks:
  #   <base>.<arch-os>.sha256 (legacy)
  #   <variant>.<arch-os>.sha256 (legacy)
  local base="$1"
  local dir="$REPO_ROOT/nix/expected-hashes"
  local sys arch os impl variant_for_hash

  # Extract variant from base parameter (handles "fips-static", "non-fips-dynamic", "fips", "non-fips")
  # Remove -static or -dynamic suffix to get the variant
  variant_for_hash="${base%-static}"
  variant_for_hash="${variant_for_hash%-dynamic}"

  # Compute system string
  if sys=$(nix eval --raw --expr 'builtins.currentSystem' 2>/dev/null); then
    :
  else
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) sys="x86_64-linux" ;;
    Linux-aarch64 | Linux-arm64) sys="aarch64-linux" ;;
    Darwin-x86_64) sys="x86_64-darwin" ;;
    Darwin-arm64) sys="aarch64-darwin" ;;
    *) sys="$(uname -m)-$(uname | tr '[:upper:]' '[:lower:]')" ;;
    esac
  fi

  arch="${sys%%-*}"
  os="${sys#*-}"
  # Map link type to implementation tag:
  # static => openssl, dynamic => no-openssl
  if [ "$LINK" = "dynamic" ]; then
    impl="no-openssl"
  else
    impl="openssl"
  fi

  # Try new scheme first - use variant extracted from base parameter
  local new_path="$dir/server.${variant_for_hash}.$impl.$arch.$os.sha256"
  if [ -f "$new_path" ]; then
    echo "$new_path"
    return 0
  fi

  # Legacy fallbacks for transition
  local legacy1="$dir/${base}.${sys}.sha256"
  if [ -f "$legacy1" ]; then
    echo "$legacy1"
    return 0
  fi
  local legacy2="$dir/${VARIANT}.${sys}.sha256"
  if [ -f "$legacy2" ]; then
    echo "$legacy2"
    return 0
  fi

  return 1
}

enforce_binary_hash() {
  # Skip for non-fips variant
  if [ "$VARIANT" = "non-fips" ]; then
    echo "Skipping hash enforcement for non-fips variant"
    return 0
  fi

  # Build base key for lookup (variant + link to derive impl)
  local base_for_hash="${VARIANT}-${LINK}"
  local expected_file
  if ! expected_file=$(resolve_expected_hash_file "$base_for_hash"); then
    echo "Expected hash file missing; generating it via Nix…"
    # Build the Nix attribute that produces the expected-hash file
    local attr
    case "$VARIANT-$LINK" in
    fips-static) attr="expected-hash-server-fips-static" ;;
    fips-dynamic) attr="expected-hash-server-fips-dynamic" ;;
    non-fips-static) attr="expected-hash-server-non-fips-static" ;;
    non-fips-dynamic) attr="expected-hash-server-non-fips-dynamic" ;;
    *)
      echo "ERROR: Unknown variant/link: $VARIANT-$LINK" >&2
      exit 1
      ;;
    esac
    local store_out
    store_out=$(nix-build -I "nixpkgs=${PIN_URL}" -A "$attr" --no-out-link)
    mkdir -p "$REPO_ROOT/nix/expected-hashes"
    # Copy all .sha256 files from the derivation output (there should be exactly one)
    cp -f "$store_out"/*.sha256 "$REPO_ROOT/nix/expected-hashes/"
    # Re-resolve after generation
    if ! expected_file=$(resolve_expected_hash_file "$base_for_hash"); then
      echo "ERROR: Failed to generate expected hash file automatically" >&2
      exit 1
    fi
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
    echo "ERROR: Binary hash mismatch (variant $VARIANT, link $LINK)." >&2
    echo "  Expected: $expected_hash (from $(basename "$expected_file"))" >&2
    echo "  Actual:   $actual_hash" >&2
    exit 1
  fi
  echo "Deterministic hash OK ($actual_hash) for variant $VARIANT-$LINK"
}

# Create or refresh the expected binary hash file under nix/expected-hashes
# Naming: server.<fips|non-fips>.<openssl|no-openssl>.<arch>.<os>.sha256
write_binary_hash_file() {
  # Compute system triple
  local sys arch os impl out_dir out_file actual_hash
  if sys=$(nix eval --raw --expr 'builtins.currentSystem' 2>/dev/null); then :; else
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) sys="x86_64-linux" ;;
    Linux-aarch64 | Linux-arm64) sys="aarch64-linux" ;;
    Darwin-x86_64) sys="x86_64-darwin" ;;
    Darwin-arm64) sys="aarch64-darwin" ;;
    *) sys="$(uname -m)-$(uname | tr '[:upper:]' '[:lower:]')" ;;
    esac
  fi
  arch="${sys%%-*}"
  os="${sys#*-}"
  impl=$([ "$LINK" = "dynamic" ] && echo no-openssl || echo openssl)
  out_dir="$REPO_ROOT/nix/expected-hashes"
  out_file="$out_dir/server.${VARIANT}.${impl}.${arch}.${os}.sha256"
  mkdir -p "$out_dir"
  if [ ! -f "$BIN_OUT" ]; then
    echo "ERROR: Binary not found for hashing: $BIN_OUT" >&2
    return 1
  fi
  actual_hash=$(sha256sum "$BIN_OUT" | awk '{print $1}')
  printf '%s\n' "$actual_hash" >"$out_file"
  echo "Wrote expected-hash: $(basename "$out_file") = $actual_hash"
}

# 2) Get OpenSSL 3.1.2 path via Nix (for source files in Cargo.toml) offline
# Needed for both static and dynamic builds (dynamic builds ship OpenSSL .so files)
resolve_openssl_path() {
  local openssl_attr="openssl312-static"
  local link="$REPO_ROOT/result-openssl-312"

  # Use dynamic OpenSSL for dynamic builds
  if [ "$LINK" = "dynamic" ]; then
    openssl_attr="openssl312-dynamic"
    link="$REPO_ROOT/result-openssl-312-dynamic"
  fi

  if [ -L "$link" ] && [ -d "$(readlink -f "$link")" ]; then :; else
    rm -f "$link" 2>/dev/null || true
    nix-build -I "nixpkgs=${PIN_URL}" --option substituters "" -A "$openssl_attr" -o "$link"
  fi
  OSSL_PATH=$(readlink -f "$link")

  # Create symlinks at fixed locations that Cargo.toml can reference
  # cargo-deb/cargo-generate-rpm look for paths relative to the crate directory
  # Using target directory to avoid polluting workspace root
  local fixed_path_workspace="$REPO_ROOT/target/.openssl-staging"
  local fixed_path_server="$REPO_ROOT/crate/server/target/.openssl-staging"

  # Ensure parent directories exist
  mkdir -p "$REPO_ROOT/target"
  mkdir -p "$REPO_ROOT/crate/server/target"

  # Remove existing paths (use chmod to handle Nix store readonly files)
  for path in "$fixed_path_workspace" "$fixed_path_server"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      chmod -R u+w "$path" 2>/dev/null || true
      rm -rf "$path" 2>/dev/null || true
    fi
  done

  # For RPM builds, cargo-generate-rpm resolves symlinks and uses the resolved path
  # in the RPM package, so we need to copy files instead of symlinking
  if [ "$FORMAT" = "rpm" ]; then
    echo "Copying OpenSSL files for RPM build (cargo-generate-rpm doesn't handle symlinks correctly)"
    mkdir -p "$fixed_path_workspace" "$fixed_path_server"
    cp -rL "$OSSL_PATH"/* "$fixed_path_workspace"/ 2>/dev/null || cp -r "$OSSL_PATH"/* "$fixed_path_workspace"/
    cp -rL "$OSSL_PATH"/* "$fixed_path_server"/ 2>/dev/null || cp -r "$OSSL_PATH"/* "$fixed_path_server"/

    # Override FIPS configuration files with production versions from server derivation
    # This ensures portable paths (/usr/local/cosmian) instead of Nix store paths
    if [ -d "$REAL_SERVER/usr/local/cosmian/lib/ssl" ]; then
      echo "Using production FIPS config from server derivation (portable paths)"
      # Remove readonly ssl directories and replace with production config
      chmod -R u+w "$fixed_path_workspace/ssl" "$fixed_path_server/ssl" 2>/dev/null || true
      rm -rf "$fixed_path_workspace/ssl" "$fixed_path_server/ssl"
      mkdir -p "$fixed_path_workspace/ssl" "$fixed_path_server/ssl"
      cp "$REAL_SERVER/usr/local/cosmian/lib/ssl/openssl.cnf" "$fixed_path_workspace/ssl/"
      cp "$REAL_SERVER/usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$fixed_path_workspace/ssl/"
      cp "$REAL_SERVER/usr/local/cosmian/lib/ssl/openssl.cnf" "$fixed_path_server/ssl/"
      cp "$REAL_SERVER/usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$fixed_path_server/ssl/"
      # Fix permissions (Nix store files are readonly)
      chmod 644 "$fixed_path_workspace/ssl"/*.cnf "$fixed_path_server/ssl"/*.cnf
    fi
  else
    # For DEB builds, handle based on whether we need production FIPS config
    if [ -d "$REAL_SERVER/usr/local/cosmian/lib/ssl" ]; then
      echo "Using production FIPS config from server derivation (portable paths)"
      # Copy OpenSSL files but exclude ssl directory, then add production config
      mkdir -p "$fixed_path_workspace" "$fixed_path_server"

      for staging_dir in "$fixed_path_workspace" "$fixed_path_server"; do
        # Copy all files from OpenSSL except ssl directory
        for item in "$OSSL_PATH"/*; do
          base=$(basename "$item")
          if [ "$base" != "ssl" ]; then
            if [ -d "$item" ]; then
              cp -r "$item" "$staging_dir/" 2>/dev/null || true
            else
              cp "$item" "$staging_dir/" 2>/dev/null || true
            fi
          fi
        done

        # Now create ssl directory with production config
        # Remove any existing ssl directory first (may have readonly files from previous run)
        rm -rf "$staging_dir/ssl"
        mkdir -p "$staging_dir/ssl"
        cp "$REAL_SERVER/usr/local/cosmian/lib/ssl/openssl.cnf" "$staging_dir/ssl/"
        cp "$REAL_SERVER/usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$staging_dir/ssl/"
        # Fix permissions (Nix store files are readonly)
        chmod 644 "$staging_dir/ssl/openssl.cnf"
        chmod 644 "$staging_dir/ssl/fipsmodule.cnf"
      done
    else
      # No production config available, use symlinks
      ln -sf "$OSSL_PATH" "$fixed_path_workspace"
      ln -sf "$OSSL_PATH" "$fixed_path_server"
    fi
  fi
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

  # Determine if signing is required. Default: required in CI, optional locally.
  # Force signing by setting REQUIRE_SIGNING=1
  local require_signing="0"
  if [ "${REQUIRE_SIGNING:-}" = "1" ] || [ -n "${CI:-}" ]; then
    require_signing="1"
  fi

  # Signing is mandatory - fail if no key is configured
  if [ ! -f "$key_id_file" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: No signing key found at $key_id_file" >&2
      echo "Package signing is mandatory (CI or REQUIRE_SIGNING=1)." >&2
      echo "Generate a signing key with: bash nix/scripts/generate_signing_key.sh" >&2
      exit 1
    else
      echo "Signing skipped: no key-id.txt present (set REQUIRE_SIGNING=1 to enforce)"
      return 0
    fi
  fi

  local key_id
  key_id=$(tr -d ' \t\r\n' <"$key_id_file")

  if [ -z "$key_id" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: Empty key ID in $key_id_file" >&2
      exit 1
    else
      echo "Signing skipped: empty key ID (set REQUIRE_SIGNING=1 to enforce)"
      return 0
    fi
  fi

  # Check if passphrase is available
  if [ -z "${GPG_SIGNING_KEY_PASSPHRASE:-}" ]; then
    if [ "$require_signing" = "1" ]; then
      echo "ERROR: GPG_SIGNING_KEY_PASSPHRASE environment variable is not set" >&2
      echo "Package signing is mandatory (CI or REQUIRE_SIGNING=1)." >&2
      exit 1
    else
      echo "Signing skipped: GPG_SIGNING_KEY_PASSPHRASE not set (set REQUIRE_SIGNING=1 to enforce)"
      return 0
    fi
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
        if [ "$require_signing" = "1" ]; then
          echo "ERROR: Signing key $key_id not found in GPG keyring and $private_key does not exist" >&2
          echo "Either set GPG_SIGNING_KEY environment variable or ensure key is already imported" >&2
          exit 1
        else
          echo "Signing skipped: no private key available (set REQUIRE_SIGNING=1 to enforce)"
          return 0
        fi
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

  # For dynamic builds, patch the RPATH to point to /usr/local/cosmian/lib
  if [ "$LINK" = "dynamic" ] && command -v patchelf >/dev/null 2>&1; then
    echo "Patching RPATH for dynamic build to /usr/local/cosmian/lib"
    for binary in \
      "crate/server/target/$HOST_TRIPLE/release/cosmian_kms" \
      "crate/server/target/release/cosmian_kms" \
      "target/release/cosmian_kms"; do
      if [ -f "$binary" ]; then
        # Make binary writable
        chmod u+w "$binary"
        # Remove existing RPATH/RUNPATH and set to our standard path
        patchelf --remove-rpath "$binary" 2>/dev/null || true
        patchelf --set-rpath /usr/local/cosmian/lib "$binary"
        echo "  Patched: $binary"
      fi
    done
  fi

  # Copy UI assets from independently built UI derivation (REAL_UI)
  UI_SRC="$UI_DIST_PATH"
  # For non-fips, cargo expects ui_non_fips/dist; for fips it expects ui/dist
  if [ "$VARIANT" = "non-fips" ]; then
    UI_DEST="crate/server/ui_non_fips/dist"
  else
    UI_DEST="crate/server/ui/dist"
  fi

  echo "Copying UI assets from $UI_SRC to $UI_DEST"
  if [ -d "$UI_DEST" ]; then
    chmod -R u+w "$UI_DEST" 2>/dev/null || true
    rm -rf "$UI_DEST"
  fi
  mkdir -p "$UI_DEST"
  cp -r "$UI_SRC"/* "$UI_DEST/"
  echo "UI assets copied successfully. Contents:"
  find "$UI_DEST" -maxdepth 1 -print | head -n 20

  export HOME="${TMPDIR:-/tmp}"
  # Keep a persistent CARGO_HOME if already set (from prewarm); otherwise fallback to temp
  export CARGO_HOME="${CARGO_HOME:-$OFFLINE_CARGO_HOME}"
  mkdir -p "$CARGO_HOME"
}

# 4) Build package depending on format
build_deb() {
  # Ensure cargo-deb is available via Nix (pinned), add to PATH
  ensure_cargo_deb
  # Enforce offline Cargo operations during packaging
  export CARGO_HOME="${CARGO_HOME:-$OFFLINE_CARGO_HOME}"
  export CARGO_NET_OFFLINE=true
  pushd crate/server >/dev/null

  # Determine the cargo-deb variant based on VARIANT and LINK
  local deb_variant=""
  if [ "$LINK" = "dynamic" ]; then
    # For dynamic builds, use the -dynamic variant
    if [ "$VARIANT" = "fips" ]; then
      deb_variant="fips-dynamic"
    else
      deb_variant="non-fips-dynamic"
    fi
  else
    # For static builds, use existing variants
    if [ "$VARIANT" = "fips" ]; then
      deb_variant="fips"
    else
      # non-fips static is the default (no variant flag needed)
      deb_variant=""
    fi
  fi

  if [ -n "$deb_variant" ]; then
    cargo deb --no-build --variant "$deb_variant"
  else
    cargo deb --no-build
  fi
  popd >/dev/null
}

collect_deb() {
  local result_dir="$REPO_ROOT/result-deb-${VARIANT}-${LINK}"
  rm -rf "$result_dir" 2>/dev/null || true
  mkdir -p "$result_dir"
  local found=0
  local VERSION_STR
  VERSION_STR=$("$REPO_ROOT/nix/scripts/get_version.sh")

  # Build the package name pattern based on variant and link type
  local pattern=""
  if [ "$LINK" = "dynamic" ]; then
    if [ "$VARIANT" = "fips" ]; then
      pattern="*-fips-dynamic_*.deb"
    else
      pattern="*-non-fips-dynamic_*.deb"
    fi
  else
    # Static builds
    if [ "$VARIANT" = "fips" ]; then
      pattern="*-fips_*.deb"
    else
      pattern="*.deb"
    fi
  fi

  for p in \
    "$REPO_ROOT/crate/server/target/debian" \
    "$REPO_ROOT/crate/server/target/$HOST_TRIPLE/debian" \
    "$REPO_ROOT/target/debian" \
    "$REPO_ROOT/target/$HOST_TRIPLE/debian"; do
    if [ -d "$p" ]; then
      if [ "$LINK" = "static" ] && [ "$VARIANT" != "fips" ]; then
        # For non-fips static, exclude fips packages
        find "$p" -maxdepth 1 -type f -name "$pattern" ! -name '*-fips_*.deb' ! -name '*-fips-dynamic_*.deb' ! -name '*-non-fips-dynamic_*.deb' -print -exec cp -f -v {} "$result_dir/" \;
      else
        find "$p" -maxdepth 1 -type f -name "$pattern" -print -exec cp -f -v {} "$result_dir/" \;
      fi
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "Error: No .deb produced by cargo-deb" >&2
    exit 1
  fi

  # Remove packages that don't match the current variant/link
  # cargo-deb may build multiple variants, so filter the results
  for f in "$result_dir"/*.deb; do
    [ -e "$f" ] || continue
    local b
    b=$(basename "$f")
    local should_remove=false

    # Check if this package matches our variant/link
    if [ "$LINK" = "dynamic" ]; then
      if [ "$VARIANT" = "fips" ]; then
        # Keep only fips-dynamic (not non-fips-dynamic)
        if echo "$b" | grep -q "non-fips-dynamic" || ! echo "$b" | grep -q "fips-dynamic"; then
          should_remove=true
        fi
      else
        # Keep only non-fips-dynamic
        if ! echo "$b" | grep -q "non-fips-dynamic"; then
          should_remove=true
        fi
      fi
    else
      # Static builds
      # Remove any dynamic packages
      if echo "$b" | grep -Eq "(fips-dynamic|non-fips-dynamic)"; then
        should_remove=true
      elif [ "$VARIANT" = "fips" ]; then
        # Keep only fips static
        if echo "$b" | grep -q "non-fips" || ! echo "$b" | grep -q "fips"; then
          should_remove=true
        fi
      else
        # Keep only non-fips static (packages without fips or dynamic in name)
        if echo "$b" | grep -Eq "(fips|dynamic)"; then
          should_remove=true
        fi
      fi
    fi

    if [ "$should_remove" = true ]; then
      rm -f "$f"
    fi
  done

  # Add -static suffix to static build packages for clarity
  if [ "$LINK" = "static" ]; then
    for f in "$result_dir"/*.deb; do
      [ -e "$f" ] || continue
      local b
      b=$(basename "$f")
      # Insert -static before version number
      # Pattern: cosmian-kms-server[-fips]_VERSION_ARCH.deb -> cosmian-kms-server[-fips]-static_VERSION_ARCH.deb
      local n
      n="${b/_/-static_}"
      if [ "$n" != "$b" ]; then
        mv -v "$result_dir/$b" "$result_dir/$n"
      fi
    done
  fi

  # Ensure Debian filenames include architecture suffix in the standard position
  # Expected: <name>_<version>_<arch>.deb
  for f in "$result_dir"/*.deb; do
    [ -e "$f" ] || continue
    local b
    b=$(basename "$f")
    # Ensure arch suffix in Debian style
    if ! echo "$b" | grep -Eq "_(all|${DEB_ARCH})\\.deb$"; then
      mv -v "$result_dir/$b" "$result_dir/${b%.deb}_${DEB_ARCH}.deb"
      b="${b%.deb}_${DEB_ARCH}.deb"
    fi

    # Rename to new convention: cosmian-kms-server-<variant>-<static_openssl|dynamic_openssl>-version_<version>_<arch>.deb
    local link_n
    if [ "$LINK" = "static" ]; then link_n="static_openssl"; else link_n="dynamic_openssl"; fi
    local new_name
    new_name="cosmian-kms-server-${VARIANT}-${link_n}_${VERSION_STR}_${DEB_ARCH}.deb"
    if [ "$b" != "$new_name" ]; then
      mv -v "$result_dir/$b" "$result_dir/$new_name"
    fi
  done

  # Sign all .deb packages
  # Only attempt signing when running inside GitHub Actions where signing
  # credentials are expected to be provided. Avoid failing on developer
  # machines where the GPG key/passphrase are not configured.
  if [ -n "${GITHUB_ACTION:-}" ]; then
    sign_packages "$result_dir" "*.deb"
  else
    echo "Skipping package signing for .deb (not running in GitHub Actions)."
  fi

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

  # Determine the cargo-generate-rpm variant based on VARIANT and LINK
  local rpm_variant=""
  if [ "$LINK" = "dynamic" ]; then
    # For dynamic builds, use the -dynamic variant
    if [ "$VARIANT" = "fips" ]; then
      rpm_variant="fips-dynamic"
    else
      rpm_variant="non-fips-dynamic"
    fi
  else
    # For static builds, use existing variants
    if [ "$VARIANT" = "fips" ]; then
      rpm_variant="fips"
    else
      # non-fips static is the default (no variant flag needed)
      rpm_variant=""
    fi
  fi

  if [ -n "$rpm_variant" ]; then
    cargo generate-rpm --target "$HOST_TRIPLE" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml --variant "$rpm_variant"
  else
    cargo generate-rpm --target "$HOST_TRIPLE" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml
  fi
}

collect_rpm() {
  local result_dir="$REPO_ROOT/result-rpm-${VARIANT}-${LINK}"
  rm -rf "$result_dir" 2>/dev/null || true
  mkdir -p "$result_dir"
  local found=0
  local VERSION_STR
  VERSION_STR=$("$REPO_ROOT/nix/scripts/get_version.sh")

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

  # Rename packages based on variant and link type
  # Apply new naming convention
  for f in "$result_dir"/*.rpm; do
    [ -e "$f" ] || continue
    local b
    b=$(basename "$f")
    # Ensure RPM filenames include .<arch>.rpm
    if ! echo "$b" | grep -Eq "\.(noarch|${RPM_ARCH})\.rpm$"; then
      mv -v "$result_dir/$b" "$result_dir/${b%.rpm}.${RPM_ARCH}.rpm"
      b="${b%.rpm}.${RPM_ARCH}.rpm"
    fi

    # Rename to new convention: cosmian-kms-server-<variant>-<static_openssl|dynamic_openssl>-version_<version>_<arch>.rpm
    local link_n
    if [ "$LINK" = "static" ]; then link_n="static_openssl"; else link_n="dynamic_openssl"; fi
    local new_name
    new_name="cosmian-kms-server-${VARIANT}-${link_n}_${VERSION_STR}_${RPM_ARCH}.rpm"
    if [ "$b" != "$new_name" ]; then
      mv -v "$result_dir/$b" "$result_dir/$new_name"
    fi
  done

  # Sign all .rpm packages
  # Only attempt signing when running inside GitHub Actions where signing
  # credentials are expected to be provided. Avoid failing on developer
  # machines where the GPG key/passphrase are not configured.
  if [ -n "${GITHUB_ACTION:-}" ]; then
    sign_packages "$result_dir" "*.rpm"
  else
    echo "Skipping package signing for .rpm (not running in GitHub Actions)."
  fi

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
ensure_expected_hashes
build_or_reuse_ui
build_or_reuse_server
write_binary_hash_file || true
enforce_binary_hash
resolve_openssl_path
prewarm_cargo_registry
prepare_workspace
detect_arches

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
