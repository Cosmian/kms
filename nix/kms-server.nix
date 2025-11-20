{
  pkgs ? import <nixpkgs> { },
  pkgs228 ? pkgs, # Older nixpkgs with glibc 2.27 (for flake builds)
  lib ? pkgs.lib,
  openssl312,
  # Provide a rustPlatform that uses the desired Rust (e.g., 1.90.0) but
  # links against pkgs228 (glibc 2.27) on Linux for maximum compatibility.
  rustPlatform ? pkgs.rustPlatform,
  features ? [ ], # [ "non-fips" ] or []
  ui ? null, # Pre-built UI derivation providing dist/
  # Allow callers (e.g., Docker image build) to bypass deterministic hash
  # enforcement when the container build environment cannot yet reproduce
  # the committed expected hashes. Default remains strict (true) for
  # packaging and CI flows.
  enforceDeterministicHash ? true,
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  variant = if isFips then "fips" else "non-fips";

  # Expected deterministic sha256 of the final installed binary (cosmian_kms)
  # for each variant. These files are committed in the repository under
  # nix/expected-hashes/*.sha256 and contain exactly one line with the hex
  # digest. No fallback is allowed: the file MUST match the current
  # cargo features (fips vs non-fips), CPU architecture and OS.
  # Expected filenames:
  #   - fips.<system>.sha256       (e.g., aarch64-darwin, x86_64-linux)
  #   - non-fips.<system>.sha256
  expectedHashPath =
    base:
    let
      sys = pkgs.stdenv.hostPlatform.system;
      dir = toString ./expected-hashes;
      p = "${dir}/${base}.${sys}.sha256";
      tp = builtins.toPath p;
    in
    if builtins.pathExists tp then
      tp
    else
      builtins.throw ''
        Expected hash file not found for ${base} on system ${sys}.
        Missing file: ${p}
        No fallback is permitted. Please add this file with the expected SHA-256 of the built binary.
      '';

  baseVariant = if isFips then "fips" else "non-fips";
  expectedHashPathVariant = expectedHashPath baseVariant;
  expectedHashRaw = builtins.readFile expectedHashPathVariant;
  sanitizeHash =
    s:
    let
      noWS = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] s;
    in
    lib.strings.removeSuffix "\n" noWS;
  expectedHash = sanitizeHash expectedHashRaw;

  # Standard system dynamic linker paths by architecture. We explicitly set the
  # ELF interpreter away from the Nix store so packaged binaries (e.g., RPM)
  # do not reference /nix/store/…/ld-linux-*.so.*. We avoid patchelf by
  # instructing the linker at build time.
  dynamicLinker =
    if pkgs.stdenv.isLinux then
      if pkgs.stdenv.hostPlatform.system == "x86_64-linux" then
        "/lib64/ld-linux-x86-64.so.2"
      else if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then
        "/lib/ld-linux-aarch64.so.1"
      else
        null
    else
      null;

  # KMS version
  version = "5.12.0";

  srcRoot = ../.;
  # Whitelist only files needed to build the Rust workspace to prevent
  # spurious rebuilds from unrelated top-level changes (e.g. result*, reports).
  filteredSrc = lib.cleanSourceWith {
    src = srcRoot;
    filter =
      path: type:
      let
        rel = lib.removePrefix (toString srcRoot + "/") (toString path);
      in
      lib.cleanSourceFilter path type
      && (
        rel == "Cargo.toml"
        || rel == "Cargo.lock"
        || rel == "LICENSE"
        || rel == "README.md"
        || rel == "CHANGELOG.md"
        || rel == "crate"
        || lib.hasPrefix "crate/" rel
        # Include server resources if any live outside crate/ (typically they don't)
        || rel == "resources"
        || lib.hasPrefix "resources/" rel
        # Packaging metadata used by cargo-deb / generate-rpm
        || rel == "pkg"
        || lib.hasPrefix "pkg/" rel
      );
  };
in
rustPlatform.buildRustPackage rec {
  pname = "cosmian-kms-server";
  inherit version;
  # Disable cargo-auditable wrapper; it doesn't understand edition=2024 yet
  auditable = false;

  # Provide the whole workspace but filtered; build only the server crate.
  src = filteredSrc;

  # Deterministic vendoring: pinned cargo hash for workspace vendoring
  # Support both cargoHash (new) and cargoSha256 (legacy) for compatibility across nixpkgs versions.
  # Platform-specific vendor hashes (target-dependent deps). If out-of-date, temporarily set to ""
  # and rebuild to obtain the new suggested value from Nix ("got: sha256-...").
  cargoHash =
    if pkgs.stdenv.isDarwin then
      # Updated from build output (got: sha256-JDBiF5KfCeNy7e4PADbve7qvPByAazqXY7OY3vCvdNs=)
      "sha256-JDBiF5KfCeNy7e4PADbve7qvPByAazqXY7OY3vCvdNs="
    else
      # Linux vendor hash (got: sha256-NAy4vNoW7nkqJF263FkkEvAh1bMMDJkL0poxBzXFOO8=)
      "sha256-NAy4vNoW7nkqJF263FkkEvAh1bMMDJkL0poxBzXFOO8=";
  cargoSha256 = cargoHash;

  # Build only the server package with optional features.
  # We'll override build/install phases to control the final link step, so
  # these flags are informational for consistency only.
  cargoBuildFlags = [
    "-p"
    "cosmian_kms_server"
  ]
  ++ lib.optionals (features != [ ]) [
    "--features"
    (lib.concatStringsSep "," features)
  ];

  # Use release profile by default
  buildType = "release";

  nativeBuildInputs =
    with pkgs;
    [
      pkg-config
      git
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [
      binutils # provides readelf used during installCheckPhase
    ];
  buildInputs =
    (with pkgs228; [ openssl312 ])
    ++ lib.optionals pkgs.stdenv.isDarwin (
      let
        fw = pkgs.darwin.apple_sdk.frameworks;
      in
      [
        fw.SystemConfiguration
        fw.Security
        fw.CoreFoundation
        pkgs.libiconv
      ]
    );

  # Environment for openssl-sys to pick our static OpenSSL
  OPENSSL_DIR = openssl312;
  OPENSSL_STATIC = 1;
  OPENSSL_LIB_DIR = "${openssl312}/lib";
  OPENSSL_INCLUDE_DIR = "${openssl312}/include";
  OPENSSL_NO_VENDOR = 1;

  # Force deterministic timestamps and build IDs
  SOURCE_DATE_EPOCH = "1";
  ZERO_AR_DATE = "1";

  # Disable incremental compilation to ensure clean builds
  CARGO_INCREMENTAL = "0";

  # Deterministic Rust codegen and link flags to stabilize binary hashes across builds.
  # Core deterministic settings (LTO, strip, codegen-units, etc.) are now centralized
  # in Cargo.toml [profile.release] section. Here we only set flags that cannot be
  # configured in Cargo.toml:
  # - Path remapping: stabilize embedded file paths across build environments
  # - Linker flags: disable build-id and set hash style for deterministic ELF
  RUSTFLAGS =
    let
      remap = lib.concatStringsSep " " [
        "--remap-path-prefix"
        "/build=/cosmian-src"
        "--remap-path-prefix"
        "/tmp=/cosmian-src"
        "--remap-path-prefix"
        "${toString ../.}=/cosmian-src"
      ];
      linuxOnly = lib.concatStringsSep " " [
        "-C link-arg=-Wl,--build-id=none"
        "-C link-arg=-Wl,--hash-style=gnu"
      ];
    in
    if pkgs.stdenv.isLinux then remap + " " + linuxOnly else remap;

  # Prevent Nix from injecting RPATHs to /nix/store into the resulting binary.
  # This ensures the packaged binary will not try to load glibc from the store
  # when executed under the system loader.
  NIX_DONT_SET_RPATH = lib.optionalString pkgs.stdenv.isLinux "1";
  NIX_LDFLAGS = lib.optionalString pkgs.stdenv.isLinux "";
  NIX_CFLAGS_LINK = lib.optionalString pkgs.stdenv.isLinux "";

  # Allow passing a non-store absolute dynamic linker path to the linker.
  # The Nix cc-wrapper normally rejects such paths as "impure". This is
  # required to ensure the final ELF interpreter is not a /nix/store path
  # without relying on patchelf post-processing.
  NIX_ENFORCE_PURITY = lib.optionalString pkgs.stdenv.isLinux "0";

  doCheck = false;
  doInstallCheck = true;
  # Helper to embed a string literal for the boolean in shell script
  enforceDeterministicHashStr = if enforceDeterministicHash then "true" else "false";
  installCheckPhase = ''
    runHook preInstallCheck

    BINARY_PATH="$out/bin/cosmian_kms"

    echo "========================================="
    echo "Verifying installed binary: $BINARY_PATH"

    if [ ! -f "$BINARY_PATH" ]; then
      echo "ERROR: Binary not found at $BINARY_PATH"
      exit 1
    fi

    export OPENSSL_CONF="${openssl312}/ssl/openssl.cnf"
    VERSION_OUTPUT=$("$BINARY_PATH" --version 2>&1 || true)
    echo "Version: $VERSION_OUTPUT"
    echo "$VERSION_OUTPUT" | grep -q "cosmian_kms_server" || {
      echo "Direct exec failed or unexpected."
      ${lib.optionalString pkgs.stdenv.isLinux ''
        echo "Trying via glibc loader…"
        LOADER=""
        if [ "${pkgs.stdenv.hostPlatform.system}" = "x86_64-linux" ]; then
          LOADER="${pkgs228.glibc}/lib/ld-linux-x86-64.so.2";
        elif [ "${pkgs.stdenv.hostPlatform.system}" = "aarch64-linux" ]; then
          LOADER="${pkgs228.glibc}/lib/ld-linux-aarch64.so.1";
        fi
        if [ -n "$LOADER" ] && [ -x "$LOADER" ]; then
          VERSION_OUTPUT=$("$LOADER" --library-path "${pkgs228.glibc}/lib" "$BINARY_PATH" --version 2>&1 || true)
          echo "Version (via loader): $VERSION_OUTPUT"
          echo "$VERSION_OUTPUT" | grep -q "cosmian_kms_server" || {
            echo "Error: Binary does not report correct version even via loader"
            exit 1
          }
        else
          echo "Error: Could not locate glibc loader at $LOADER"
          exit 1
        fi
      ''}
      ${lib.optionalString (!pkgs.stdenv.isLinux) ''
        echo "Error: Binary does not report correct version"
        exit 1
      ''}
    }
    unset OPENSSL_CONF

    if [ "$(uname)" = "Linux" ]; then
      echo "Checking dynamic linkage..."
      echo "Interpreter:"
      interp=$(readelf -l "$BINARY_PATH" | sed -n 's/^.*interpreter: \(.*\)]$/\1/p') || true
      echo "$interp"
      ldd "$BINARY_PATH" || true

      if ldd "$BINARY_PATH" | grep -qi "libssl\|libcrypto"; then
        echo "ERROR: Dynamic OpenSSL linkage detected"
        exit 1
      fi

      # Ensure the ELF interpreter does not point inside the Nix store
      if echo "$interp" | grep -q "/nix/store/"; then
        echo "ERROR: ELF interpreter points to Nix store: $interp"
        exit 1
      fi

      # If we know the target dynamic linker from arch, assert it matches (no Nix-side interpolation)
      ARCH="$(uname -m)"
      EXPECTED_DL=""
      if [ "$ARCH" = "x86_64" ]; then
        EXPECTED_DL="/lib64/ld-linux-x86-64.so.2"
      elif [ "$ARCH" = "aarch64" ]; then
        EXPECTED_DL="/lib/ld-linux-aarch64.so.1"
      fi
      if [ -n "$EXPECTED_DL" ] && [ "$interp" != "$EXPECTED_DL" ]; then
        echo "ERROR: Unexpected ELF interpreter. Expected $EXPECTED_DL, got: $interp"
        exit 1
      fi

      echo "Checking GLIBC symbol versions..."
      GLIBC_SYMS=$(readelf -sW "$BINARY_PATH" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu)
      echo "GLIBC symbols found:"
      echo "$GLIBC_SYMS"
      MAX_GLIBC_VER=$(echo "$GLIBC_SYMS" | sed 's/^GLIBC_//' | sort -V | tail -n1 || echo "")
      echo "Maximum GLIBC version: $MAX_GLIBC_VER"
      if [ -n "$MAX_GLIBC_VER" ]; then
        if [ "$(printf '%s\n' "$MAX_GLIBC_VER" "2.28" | sort -V | tail -n1)" != "2.28" ]; then
          echo "ERROR: GLIBC symbols exceed 2.28 (max found: $MAX_GLIBC_VER)"
          exit 1
        fi
      fi
      echo "SUCCESS: GLIBC version check passed (max: $MAX_GLIBC_VER <= 2.28)"
    fi

    INFO=$("$BINARY_PATH" --info 2>&1 || true)
    if echo "$INFO" | grep -q "OpenSSL 3.1.2"; then
      :
    else
      echo "Direct --info failed or unexpected."
      ${lib.optionalString pkgs.stdenv.isLinux ''
        echo "Trying via glibc loader…"
        LOADER=""
        if [ "${pkgs.stdenv.hostPlatform.system}" = "x86_64-linux" ]; then
          LOADER="${pkgs228.glibc}/lib/ld-linux-x86-64.so.2";
        elif [ "${pkgs.stdenv.hostPlatform.system}" = "aarch64-linux" ]; then
          LOADER="${pkgs228.glibc}/lib/ld-linux-aarch64.so.1";
        fi
        if [ -n "$LOADER" ] && [ -x "$LOADER" ]; then
          INFO=$("$LOADER" --library-path "${pkgs228.glibc}/lib" "$BINARY_PATH" --info 2>&1 || true)
          echo "$INFO" | grep -q "OpenSSL 3.1.2" || {
            echo "ERROR: --info did not report expected OpenSSL 3.1.2"
            exit 1
          }
        else
          echo "ERROR: Could not locate glibc loader at $LOADER"
          exit 1
        fi
      ''}
      ${lib.optionalString (!pkgs.stdenv.isLinux) ''
        echo "ERROR: Failed to run --info on binary"
        exit 1
      ''}
    fi

    # Validate info content depending on FIPS mode
    ${lib.optionalString isFips ''
      echo "$INFO" | grep -Eq "OpenSSL FIPS mode" || {
        echo "ERROR: In FIPS mode, --info should contain 'OpenSSL FIPS mode, version:'"
        exit 1
      }
    ''}
    ${lib.optionalString (!isFips) ''
      echo "$INFO" | grep -q "OpenSSL default mode" || {
        echo "ERROR: In non-FIPS mode, --info must contain 'OpenSSL default mode version'"
        exit 1
      }
    ''}

    echo "$INFO"

    echo "========================================="
    echo "Binary verification completed successfully"

    # Deterministic hash enforcement (native in derivation):
    if [ "$(uname)" = "Linux" ]; then
      if [ "${enforceDeterministicHashStr}" != "true" ]; then
        echo "WARNING: enforceDeterministicHash=false -> Skipping deterministic hash enforcement (variant ${variant})."
      else
        echo "Using expected hash file: ${expectedHashPathVariant}"
        ACTUAL_SHA256=$(sha256sum "$BINARY_PATH" | awk '{print $1}')
        if [ -z "${expectedHash}" ]; then
          echo "ERROR: expectedHash is empty (variant ${variant})."; exit 1; fi
        if [ "$ACTUAL_SHA256" != "${expectedHash}" ]; then
          echo "ERROR: Deterministic hash mismatch for cosmian_kms (variant ${variant})." >&2
          echo " Expected: ${expectedHash}" >&2
          echo "   Actual: $ACTUAL_SHA256" >&2
          exit 1
        fi
        echo "Deterministic hash check passed: $ACTUAL_SHA256 == ${expectedHash}"
      fi
    else
      echo "Skipping deterministic hash enforcement on non-Linux platforms."
    fi

    runHook postInstallCheck
  '';

  # Custom build/install to re-link the final binary with the system dynamic
  # loader only for the main artifact (avoids impacting build scripts),
  # without touching crate sources or using patchelf.
  buildPhase = ''
    runHook preBuild
    echo "== cargo build cosmian_kms_server (release) =="
    cargo build --release -p cosmian_kms_server \
      ${lib.optionalString (features != [ ]) "--features ${lib.concatStringsSep "," features}"}

    if [ "$(uname)" = "Linux" ]; then
      # Determine system dynamic linker path by architecture (avoid Nix-side interpolation on Darwin)
      DL=""
      ARCH="$(uname -m)"
      if [ "$ARCH" = "x86_64" ]; then
        DL="/lib64/ld-linux-x86-64.so.2"
      elif [ "$ARCH" = "aarch64" ]; then
        DL="/lib/ld-linux-aarch64.so.1"
      fi
      if [ -n "$DL" ]; then
        echo "== Re-linking final binary with system dynamic linker: $DL =="
        export NIX_ENFORCE_PURITY=0
        export NIX_DONT_SET_RPATH=1
        export NIX_LDFLAGS=""
        export NIX_CFLAGS_LINK=""
        # Re-link the final binary (no rebuild of deps/build-scripts)
        cargo rustc --release -p cosmian_kms_server --bin cosmian_kms \
          ${lib.optionalString (features != [ ]) "--features ${lib.concatStringsSep "," features}"} \
          -- -C link-arg=-Wl,--dynamic-linker,$DL
      fi
    fi

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    # Copy the re-linked server binary
    install -m755 target/release/cosmian_kms "$out/bin/cosmian_kms"
    runHook postInstall
  '';

  # Then add UI assets and build-info in postInstall.
  postInstall = ''
        # Install Web UI (if provided)
        if [ -n "${lib.optionalString (ui != null) "yes"}" ]; then
          echo "Installing Web UI from ${ui}"
          mkdir -p "$out/usr/local/cosmian/ui/dist"
          if [ -d "${ui}/dist" ]; then
            cp -R "${ui}/dist/"* "$out/usr/local/cosmian/ui/dist/" 2>/dev/null || true
          else
            echo "Warning: UI dist folder not found in ${ui}; creating placeholder index.html"
            echo "<html><body><h1>KMS UI Not Built</h1></body></html>" > "$out/usr/local/cosmian/ui/dist/index.html"
          fi
        else
          echo "UI derivation not provided; skipping UI installation"
        fi

        # Write build info
        mkdir -p "$out/bin"
        cat > "$out/bin/build-info.txt" <<EOF
    KMS Server ${variant} build
    Version: ${version}
    Built with: Nix rustPlatform (glibc 2.27 on Linux)
    OpenSSL: ${openssl312}
    EOF
  '';

  passthru = {
    inherit variant isFips;
    opensslPath = openssl312;
    uiPath = ui;
    src = filteredSrc;
    version = version;
    hostTriple = pkgs228.stdenv.hostPlatform.config;
  };

  meta = with lib; {
    description = "Cosmian KMS - High-performance FIPS 140-3 compliant Key Management System (${variant} build, glibc 2.27 compatible)";
    homepage = "https://github.com/Cosmian/kms";
    license = {
      shortName = "BUSL-1.1";
      fullName = "Business Source License 1.1";
      url = "https://mariadb.com/bsl11/";
      free = false;
    };
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
    maintainers = [ ];
  };
}
