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
  # Linkage mode: true for static OpenSSL, false for dynamic OpenSSL
  static ? true,
  # Allow callers (e.g., Docker image build) to bypass deterministic hash
  # enforcement when the container build environment cannot yet reproduce
  # the committed expected hashes. Default remains strict (true) for
  # packaging and CI flows.
  enforceDeterministicHash ? true,
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  baseVariant = if isFips then "fips" else "non-fips";
  # Combine base variant with suffix for hash file lookup
  # Using -no-openssl for backward compatibility with existing hash files
  variant-suffix = if static then "" else "-no-openssl";
  variant = if variant-suffix == "" then baseVariant else "${baseVariant}${variant-suffix}";

  # Expected deterministic sha256 of the final installed binary (cosmian_kms)
  # New naming convention: <fips|non-fips>.<openssl|non-openssl>.<arch>.<os>.sha256
  expectedHashPath =
    _unused:
    let
      sys = pkgs.stdenv.hostPlatform.system; # e.g., x86_64-linux
      parts = lib.splitString "-" sys;
      arch = builtins.elemAt parts 0;
      os = builtins.elemAt parts 1;
      # Match repository's existing hash tags: static => openssl, dynamic => non-openssl
      impl = if static then "openssl" else "non-openssl";
      # Primary (new scheme)
      newFile = ./expected-hashes + "/${baseVariant}.${impl}.${arch}.${os}.sha256";
    in
    if builtins.pathExists newFile then
      newFile
    else
      builtins.throw ''
        Expected hash file not found for variant ${baseVariant} (impl ${impl}) on system ${sys}.
        Missing tried paths:
          - expected-hashes/${baseVariant}.${impl}.${arch}.${os}.sha256
        Please add the appropriate file with the expected SHA-256 of the built binary.
      '';

  expectedHashPathVariant = expectedHashPath variant;
  expectedHashRaw = builtins.readFile expectedHashPathVariant;
  sanitizeHash =
    s:
    let
      noWS = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] s;
    in
    lib.strings.removeSuffix "\n" noWS;
  expectedHash = sanitizeHash expectedHashRaw;

  # KMS version
  version = "5.13.0";

  # Force rebuild marker - increment to invalidate cache when only Nix expressions change
  rebuildMarker = "1";

  srcRoot = ../.;
  # Whitelist only files needed to build the Rust workspace
  filteredSrc = lib.cleanSourceWith {
    src = srcRoot;
    filter =
      path: type:
      let
        rel = lib.removePrefix (toString srcRoot + "/") (toString path);
        # Exclude ephemeral/build artifacts from host workspace to keep builds deterministic
        isEphemeral =
          lib.hasInfix "/target/" rel
          || lib.hasSuffix "/target" rel
          || lib.hasPrefix "crate/server/ui/dist" rel
          || lib.hasPrefix "crate/server/ui_non_fips/dist" rel;
      in
      lib.cleanSourceFilter path type
      && (!isEphemeral)
      && (
        rel == "Cargo.toml"
        || rel == "Cargo.lock"
        || rel == "LICENSE"
        || rel == "README.md"
        || rel == "CHANGELOG.md"
        || rel == "crate"
        || lib.hasPrefix "crate/" rel
        || rel == "resources"
        || lib.hasPrefix "resources/" rel
        || rel == "pkg"
        || lib.hasPrefix "pkg/" rel
        || rel == "test_data"
        || lib.hasPrefix "test_data/" rel
        || rel == "documentation"
        || lib.hasPrefix "documentation/" rel
      );
  };

  # Helper to embed boolean as string for shell script
  enforceDeterministicHashStr = if enforceDeterministicHash then "true" else "false";

  # Install check phase
  installCheckPhase =
    let
      checkStaticOpenSSL = static;
    in
    ''
      runHook preInstallCheck

      BINARY_PATH="$out/bin/cosmian_kms"

      echo "========================================="
      echo "Verifying installed binary: $BINARY_PATH"

      if [ ! -f "$BINARY_PATH" ]; then
        echo "ERROR: Binary not found at $BINARY_PATH"
        exit 1
      fi

      export OPENSSL_CONF="${openssl312}/ssl/openssl.cnf"
      ${lib.optionalString (
        !static
      ) ''export LD_LIBRARY_PATH="${openssl312}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"''}

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
            ${
              if !static then
                ''VERSION_OUTPUT=$("$LOADER" --library-path "${openssl312}/lib:${pkgs228.glibc}/lib" "$BINARY_PATH" --version 2>&1 || true)''
              else
                ''VERSION_OUTPUT=$("$LOADER" --library-path "${pkgs228.glibc}/lib" "$BINARY_PATH" --version 2>&1 || true)''
            }
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

        ${
          if checkStaticOpenSSL then
            ''
              if ldd "$BINARY_PATH" | grep -qi "libssl\|libcrypto"; then
                echo "ERROR: Dynamic OpenSSL linkage detected"
                exit 1
              fi
            ''
          else
            ''
              if ! ldd "$BINARY_PATH" | grep -qi "libssl\|libcrypto"; then
                echo "ERROR: No dynamic OpenSSL linkage detected (expected dynamic linking)"
                exit 1
              fi
              echo "SUCCESS: Dynamic OpenSSL linkage confirmed"
            ''
        }

        # Ensure the ELF interpreter does not point inside the Nix store
        if echo "$interp" | grep -q "/nix/store/"; then
          echo "ERROR: ELF interpreter points to Nix store: $interp"
          exit 1
        fi

        # If we know the target dynamic linker from arch, assert it matches
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
            ${
              if !static then
                ''INFO=$("$LOADER" --library-path "${openssl312}/lib:${pkgs228.glibc}/lib" "$BINARY_PATH" --info 2>&1 || true)''
              else
                ''INFO=$("$LOADER" --library-path "${pkgs228.glibc}/lib" "$BINARY_PATH" --info 2>&1 || true)''
            }
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

      # Deterministic hash enforcement
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
in
rustPlatform.buildRustPackage rec {
  pname = "cosmian-kms-server${if static then "" else "-dynamic"}-rebuild-${rebuildMarker}";
  inherit version;
  # Disable cargo-auditable wrapper; it doesn't understand edition=2024 yet
  auditable = false;
  # Run tests only for static builds; skip for dynamic to avoid runtime libssl issues
  doCheck = static;

  # Provide the whole workspace but filtered; build only the server crate.
  src = filteredSrc;

  # Deterministic vendoring: pinned cargo hash for workspace vendoring
  # Support both cargoHash (new) and cargoSha256 (legacy) for compatibility across nixpkgs versions.
  # Platform-specific vendor hashes (target-dependent deps). If out-of-date, temporarily set to ""
  # and rebuild to obtain the new suggested value from Nix ("got: sha256-...").
  cargoHash =
    if pkgs.stdenv.isDarwin then
      # macOS vendor hash - different for static vs dynamic builds
      if static then
        "sha256-dDu96ohNCURR9IfzJ2hG4ouRPrzbIQoaTpvypVi8ERA=" # static
      else
        "sha256-/+XNQN8Jd2ehj7skdI3R/D8zc0uhjSanOQis2jV3TXk=" # dynamic
    else
    # Linux vendor hash for SERVER build - different for static vs dynamic
    if static then
      "sha256-GRCXobXJ8m09rNJcNUP0noZZIkrLe/tTr/CE7JxGsbQ=" # static
    else
      "sha256-GRCXobXJ8m09rNJcNUP0noZZIkrLe/tTr/CE7JxGsbQ="; # dynamic
  cargoSha256 = cargoHash;

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

  buildInputs = [
    openssl312
  ]
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

  # Environment for openssl-sys to pick our OpenSSL
  OPENSSL_DIR = openssl312;
  OPENSSL_LIB_DIR = "${openssl312}/lib";
  OPENSSL_INCLUDE_DIR = "${openssl312}/include";
  OPENSSL_NO_VENDOR = 1;

  # Custom build/install to re-link the final binary with the system dynamic
  # loader only for the main artifact (avoids impacting build scripts),
  # without touching crate sources or using patchelf.
  buildPhase = ''
    echo "== cargo build cosmian_kms_server (release) =="
    cargo build --release -p cosmian_kms_server --no-default-features \
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
    # Note: NOT running postBuild hook to avoid test execution
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
        echo "=== Running postInstall phase ==="
        # Install Web UI (if provided)
        if [ -n "${lib.optionalString (ui != null) "yes"}" ]; then
          echo "Installing Web UI from ${ui}"
          mkdir -p "$out/usr/local/cosmian/ui/dist"
          if [ -d "${ui}/dist" ]; then
            echo "Copying UI files from ${ui}/dist to $out/usr/local/cosmian/ui/dist"
            cp -R "${ui}/dist/"* "$out/usr/local/cosmian/ui/dist/" || {
              echo "ERROR: Failed to copy UI files from ${ui}/dist"
              echo "Contents of ${ui}:"
              ls -la "${ui}" || true
              echo "Contents of ${ui}/dist:"
              ls -la "${ui}/dist" || true
              exit 1
            }
            echo "UI files copied successfully"
          else
            echo "ERROR: UI dist folder not found in ${ui}"
            echo "Contents of ${ui}:"
            ls -la "${ui}" || true
            exit 1
          fi
        else
          echo "UI derivation not provided; skipping UI installation"
        fi

        # Write build info
        mkdir -p "$out/bin"
        cat > "$out/bin/build-info.txt" <<EOF
    KMS Server ${variant} build (${if static then "static" else "dynamic"} OpenSSL linkage)
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
    inherit version;
    hostTriple = pkgs228.stdenv.hostPlatform.config;
  };

  meta = with lib; {
    description = "Cosmian KMS - High-performance Key Management System with FIPS 140-3 cryptographic module (${variant} build)";
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

  # Environment / determinism controls
  SOURCE_DATE_EPOCH = "1";
  ZERO_AR_DATE = "1";
  CARGO_INCREMENTAL = "0";
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
      dynamicOnly = lib.optionalString (
        !static && pkgs.stdenv.isLinux
      ) "-C link-arg=-Wl,-rpath,${openssl312}/lib";
    in
    if pkgs.stdenv.isLinux then remap + " " + linuxOnly + " " + dynamicOnly else remap;
  NIX_DONT_SET_RPATH = lib.optionalString pkgs.stdenv.isLinux "1";
  NIX_LDFLAGS = lib.optionalString pkgs.stdenv.isLinux "";
  NIX_CFLAGS_LINK = lib.optionalString pkgs.stdenv.isLinux "";
  NIX_ENFORCE_PURITY = lib.optionalString pkgs.stdenv.isLinux "0";
  dontCargoCheck = true;
  dontCheck = !static;
  dontUseCargoParallelTests = true;
  dontInstallCheck = false;
  cargoCheckHook = "";
  cargoNextestHook = "";
  checkPhase = ":";
  configurePhase = ''
    export CARGO_HOME="$(pwd)/.cargo-home"
  '';
  inherit installCheckPhase;
}
// lib.optionalAttrs static {
  # Only set OPENSSL_STATIC for static builds to avoid any value for dynamic
  OPENSSL_STATIC = "1";
}
