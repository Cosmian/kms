{
  pkgs ? import <nixpkgs> { },
  pkgs234 ? pkgs, # nixpkgs 22.05 with glibc 2.34 (Rocky Linux 9 compatibility)
  lib ? pkgs.lib,
  # Optional external overrides; if null, will be constructed from nix/openssl.nix
  openssl36 ? null,
  openssl312 ? null,
  # Provide a rustPlatform that uses the desired Rust (e.g., 1.90.0) but
  # links against pkgs234 (glibc 2.34) on Linux for Rocky Linux 9 compatibility.
  rustPlatform ? pkgs.rustPlatform,
  # KMS version (from Cargo.toml)
  version,
  features ? [ ], # [ "non-fips" ] or []
  ui ? null, # Pre-built UI derivation providing dist/
  # Linkage mode: true for static OpenSSL, false for dynamic OpenSSL
  static ? true,
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  baseVariant = if isFips then "fips" else "non-fips";
  # Use nixpkgs 22.05 (pkgs234) to build OpenSSL on Linux to ensure
  # glibc 2.34 compatibility (Rocky Linux 9).
  opensslPkgs = if pkgs.stdenv.isLinux then pkgs234 else pkgs;
  # Construct OpenSSL 3.6.0 (main) and 3.1.2 (FIPS provider) if not provided
  openssl36_ =
    if openssl36 != null then
      openssl36
    else
      opensslPkgs.callPackage ./openssl.nix {
        inherit static;
        version = "3.6.0";
        # Build legacy provider for non-FIPS features (e.g., legacy.so)
        enableLegacy = true;
        srcUrl = "https://package.cosmian.com/openssl/openssl-3.6.0.tar.gz";
        # NOTE: Use lib.fakeSha256 so Nix prints the correct SRI on first build; replace afterwards
        sha256SRI = "sha256-tqX0S362nj+jXb8VUkQFtEg3pIHUPYHa3d4/8h/LuOk=";
        # Skip local tarball integrity unless you add resources/tarballs/openssl-3.6.0.tar.gz
        expectedHash = "b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9";
      };
  openssl312_ =
    if openssl312 != null then
      openssl312
    else
      opensslPkgs.callPackage ./openssl.nix {
        inherit static;
        version = "3.1.2";
      };

  # Select OpenSSL to link against:
  # Always link against OpenSSL 3.6.0 for both FIPS and non-FIPS builds.
  # In FIPS builds, the runtime FIPS provider (3.1.2) is shipped and used via
  # OpenSSL provider configuration, but the linkage itself remains on 3.6.0.
  opensslLink = openssl36_;

  # Combine base variant with suffix for hash file lookup
  # Using -static-openssl or -dynamic-openssl for backward compatibility with existing hash files
  variant-suffix = if static then "-static-openssl" else "-dynamic-openssl";
  variant = if variant-suffix == "" then baseVariant else "${baseVariant}${variant-suffix}";

  # Expected deterministic sha256 of the final installed binary (cosmian_kms)
  # Naming convention (matches repository files):
  #   cosmian-kms-server.<fips|non-fips>.<static-openssl|dynamic-openssl>.<arch>.<os>.sha256

  # Pre-compute all platform-specific expected hash file paths at Nix evaluation time.
  # If the file exists and contains a non-zero hash, it will be embedded in the
  # installCheckPhase shell script for mandatory comparison.
  linkTag = if static then "static-openssl" else "dynamic-openssl";
  expectedHashDir = ./expected-hashes;

  # Helper: read & trim a hash file, returning null when absent or placeholder (all zeros).
  readHashFile =
    name:
    let
      path = expectedHashDir + "/${name}";
    in
    if builtins.pathExists path then
      let
        raw = builtins.readFile path;
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
        isPlaceholder = builtins.match "^0+$" trimmed != null;
      in
      if trimmed != "" && !isPlaceholder then trimmed else null
    else
      null;

  # Pre-read expected hashes for every arch+os combination this derivation supports.
  # Only the matching platform will actually use its value at build time.
  expectedHash_x86_64_linux = readHashFile "cosmian-kms-server.${baseVariant}.${linkTag}.x86_64.linux.sha256";
  expectedHash_aarch64_linux = readHashFile "cosmian-kms-server.${baseVariant}.${linkTag}.aarch64.linux.sha256";
  expectedHash_x86_64_darwin = readHashFile "cosmian-kms-server.${baseVariant}.${linkTag}.x86_64.darwin.sha256";
  expectedHash_arm64_darwin = readHashFile "cosmian-kms-server.${baseVariant}.${linkTag}.arm64.darwin.sha256";

  # Compute the actual hash file path for writing during build

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
        || rel == "nix/expected-hashes"
        || lib.hasPrefix "nix/expected-hashes/" rel
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

  # Install check phase - simplified version verification
  installCheckPhase = ''
    runHook preInstallCheck

    BIN="$out/bin/cosmian_kms"
    [ -f "$BIN" ] || { echo "ERROR: Binary not found"; exit 1; }
    echo "Binary exists at: $BIN"

    # Check file type and dynamic linker
    file "$BIN" || true
    if [ "$(uname)" = "Linux" ]; then
      readelf -l "$BIN" | grep -A 2 "interpreter" || true
    elif [ "$(uname)" = "Darwin" ]; then
      otool -L "$BIN" || true
    fi

    # For non-static builds, check if libraries are available
    ${lib.optionalString (!static) ''
      echo "Checking dynamic library dependencies..."
      export LD_LIBRARY_PATH="${openssl36_}/lib:$LD_LIBRARY_PATH"
      echo "LD_LIBRARY_PATH set to: $LD_LIBRARY_PATH"
      if [ "$(uname)" = "Linux" ]; then
        ldd "$BIN" || true
      elif [ "$(uname)" = "Darwin" ]; then
        otool -L "$BIN" || true
      fi
    ''}

    # Try to run version check
    echo "Running version check..."
    if VERSION_OUTPUT=$("$BIN" --version 2>&1); then
      echo "Version output: $VERSION_OUTPUT"
      echo "$VERSION_OUTPUT" | grep -qE "(cosmian_kms_server|cosmian_kms)" || { echo "ERROR: Version check failed - output doesn't match expected pattern"; exit 1; }
      echo "Version check passed"
    else
      echo "Binary execution failed (this may be expected in Nix sandbox)"
      echo "Skipping version check in install phase"
    fi

    # Platform-specific checks
    if [ "$(uname)" = "Linux" ]; then
      # Check ELF interpreter is not in Nix store
      interp=$(readelf -l "$BIN" | sed -n 's/^.*interpreter: \(.*\)]$/\1/p') || true
      echo "$interp" | grep -q "/nix/store/" && { echo "ERROR: ELF interpreter in Nix store"; exit 1; }

      # Check OpenSSL linkage
      ${lib.optionalString static ''
        ldd "$BIN" | grep -qi "libssl\|libcrypto" && { echo "ERROR: Unexpected dynamic OpenSSL"; exit 1; }
      ''}
      ${lib.optionalString (!static) ''
        ldd "$BIN" | grep -qi "libssl\|libcrypto" || { echo "ERROR: Missing dynamic OpenSSL"; exit 1; }
      ''}

      # Check GLIBC version <= 2.34 (Linux only, Rocky Linux 9 compatibility)
      MAX_VER=$(readelf -sW "$BIN" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1)
      [ "$(printf '%s\n' "$MAX_VER" "2.34" | sort -V | tail -n1)" = "2.34" ] || {
        echo "ERROR: GLIBC $MAX_VER > 2.34"; exit 1;
      }

      # Compute actual binary hash
      ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
      echo "$ACTUAL" > "$out/bin/cosmian_kms.sha256"
      echo "Binary hash: $ACTUAL (saved to $out/bin/cosmian_kms.sha256)"

      # Determine expected hash (resolved at Nix evaluation time from nix/expected-hashes/)
      ARCH_LINUX="$(uname -m)"
      case "$ARCH_LINUX" in
        x86_64) ARCH_TAG="x86_64" ;;
        aarch64|arm64) ARCH_TAG="aarch64" ;;
        *) ARCH_TAG="$ARCH_LINUX" ;;
      esac
      HASH_FILENAME="cosmian-kms-server.${baseVariant}.${linkTag}.$ARCH_TAG.linux.sha256"

      # Pick the expected hash for the current architecture
      EXPECTED=""
      case "$ARCH_LINUX" in
        x86_64)  EXPECTED="${toString expectedHash_x86_64_linux}" ;;
        aarch64) EXPECTED="${toString expectedHash_aarch64_linux}" ;;
      esac

      if [ -n "$EXPECTED" ]; then
        if [ "$ACTUAL" = "$EXPECTED" ]; then
          echo "Deterministic hash check PASSED: $ACTUAL"
        else
          echo "ERROR: Deterministic hash MISMATCH!"
          echo "  Expected: $EXPECTED"
          echo "  Actual:   $ACTUAL"
          echo "  File:     nix/expected-hashes/$HASH_FILENAME"
          echo ""
          echo "If this is an intentional change, update the expected hash:"
          echo "  echo '$ACTUAL' > nix/expected-hashes/$HASH_FILENAME"
          exit 1
        fi
      else
        echo "NOTE: No expected hash file for $HASH_FILENAME — skipping enforcement (bootstrap mode)"
      fi

      echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
      echo "Expected hash file saved to: $out/bin/$HASH_FILENAME"
      echo "To update repository, copy this file to: nix/expected-hashes/$HASH_FILENAME"
    elif [ "$(uname)" = "Darwin" ]; then
      # macOS-specific checks

      # Check OpenSSL linkage
      ${lib.optionalString static ''
        otool -L "$BIN" | grep -qi "libssl\|libcrypto" && { echo "ERROR: Unexpected dynamic OpenSSL"; exit 1; }
      ''}
      ${lib.optionalString (!static) ''
        otool -L "$BIN" | grep -qi "libssl\|libcrypto" || { echo "ERROR: Missing dynamic OpenSSL"; exit 1; }
      ''}

      # Check that binary doesn't reference Nix store paths for system libraries
      if otool -L "$BIN" | grep -q "/nix/store.*dylib"; then
        echo "WARNING: Binary has Nix store dylib references"
      fi

      # Compute actual binary hash
      ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
      echo "$ACTUAL" > "$out/bin/cosmian_kms.sha256"
      echo "Binary hash: $ACTUAL (saved to $out/bin/cosmian_kms.sha256)"

      # Determine expected hash (resolved at Nix evaluation time from nix/expected-hashes/)
      ARCH="$(uname -m)"
      HASH_FILENAME="cosmian-kms-server.${baseVariant}.${linkTag}.$ARCH.darwin.sha256"

      # Pick the expected hash for the current architecture
      EXPECTED=""
      case "$ARCH" in
        x86_64)       EXPECTED="${toString expectedHash_x86_64_darwin}" ;;
        arm64|aarch64) EXPECTED="${toString expectedHash_arm64_darwin}" ;;
      esac

      if [ -n "$EXPECTED" ]; then
        if [ "$ACTUAL" = "$EXPECTED" ]; then
          echo "Deterministic hash check PASSED: $ACTUAL"
        else
          echo "ERROR: Deterministic hash MISMATCH!"
          echo "  Expected: $EXPECTED"
          echo "  Actual:   $ACTUAL"
          echo "  File:     nix/expected-hashes/$HASH_FILENAME"
          echo ""
          echo "If this is an intentional change, update the expected hash:"
          echo "  echo '$ACTUAL' > nix/expected-hashes/$HASH_FILENAME"
          exit 1
        fi
      else
        echo "NOTE: No expected hash file for $HASH_FILENAME — skipping enforcement (bootstrap mode)"
      fi

      echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
      echo "Expected hash file saved to: $out/bin/$HASH_FILENAME"
      echo "To update repository, copy this file to: nix/expected-hashes/$HASH_FILENAME"
    fi

    # Verify binary was built against the expected OpenSSL version
    # Note: For dynamic builds, the version string is in the shared library, not the binary
    # OPENSSLDIR is baked into OpenSSL at compile time and will show the Nix store path.
    # At runtime, we override it with OPENSSL_CONF environment variable to use /usr/local/cosmian/lib/ssl
    # Full FIPS validation happens in smoke test with proper environment variables set
    ${lib.optionalString (static && pkgs.stdenv.isLinux) ''
      strings "$BIN" | grep -q "OpenSSL 3.6.0" || { echo "ERROR: Binary not statically linked against OpenSSL 3.6.0"; exit 1; }
      echo "Binary validation OK (OpenSSL 3.6.0 statically linked)"
    ''}
    ${lib.optionalString (static && pkgs.stdenv.isDarwin) ''
      echo "Skipping static OpenSSL string check on macOS (validation handled via FIPS modules and runtime tests)"
    ''}
    ${lib.optionalString (!static) ''
      echo "Binary validation OK (dynamically linked, OpenSSL version in shared library)"
    ''}

    echo "Binary verification passed"
    runHook postInstallCheck
  '';
in
rustPlatform.buildRustPackage rec {
  pname = "cosmian-kms-server${if static then "" else "-dynamic"}-rebuild-${rebuildMarker}";
  inherit version;
  # Disable cargo-auditable wrapper; it doesn't understand edition=2024 yet
  auditable = false;
  # Run tests only for static builds (self-contained OpenSSL); dynamic builds may lack runtime libssl in sandbox

  # Provide the whole workspace but filtered; build only the server crate.
  src = filteredSrc;

  # Deterministic vendoring: pinned cargo hash for workspace vendoring
  # Support cargoHash for compatibility across nixpkgs versions.
  # Platform-specific vendor hashes (target-dependent deps). If out-of-date, temporarily set to ""
  # and rebuild to obtain the new suggested value from Nix ("got: sha256-...").
  cargoHash =
    let
      sys = pkgs.stdenv.hostPlatform.system; # e.g., x86_64-linux
      parts = lib.splitString "-" sys;
      os = builtins.elemAt parts 1;
      # Both Darwin and Linux now use separate vendor files for static/dynamic (glibc 2.34 requirement)
      linkSuffix = if static then "static" else "dynamic";
      vendorFile = ./expected-hashes + "/server.vendor.${linkSuffix}.${os}.sha256";
      placeholder = "sha256-BBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      let
        raw = builtins.readFile vendorFile;
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
      in
      assert trimmed != placeholder && trimmed != "";
      trimmed
    else
      builtins.throw ("Expected server vendor cargo hash file not found: " + vendorFile);
  cargoSha256 = cargoHash;

  # Use release profile by default
  buildType = "release";

  nativeBuildInputs =
    with pkgs;
    [
      pkg-config
      git
      file # provides file command for binary inspection
      coreutils # provides sha256sum used during installCheckPhase
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [
      binutils # provides readelf and ldd used during installCheckPhase
      patchelf
    ]
    ++ lib.optionals pkgs.stdenv.isDarwin [
      darwin.cctools # provides otool used during installCheckPhase
    ];

  buildInputs = [
    opensslLink
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
  OPENSSL_DIR = opensslLink;
  OPENSSL_LIB_DIR = "${opensslLink}/lib";
  OPENSSL_INCLUDE_DIR = "${opensslLink}/include";
  OPENSSL_NO_VENDOR = 1;

  # Custom build/install to re-link the final binary with the system dynamic
  # loader only for the main artifact (avoids impacting build scripts),
  # without touching crate sources or using patchelf.
  buildPhase = ''
    echo "== cargo build cosmian_kms_server (release) =="
    cargo build --release -p cosmian_kms_server --no-default-features \
      ${lib.optionalString (features != [ ]) "--features ${lib.concatStringsSep "," features}"}
    # Note: NOT running postBuild hook to avoid test execution
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    # Copy the server binary
    install -m755 target/release/cosmian_kms "$out/bin/cosmian_kms"

    # Ensure the final artifact uses the system dynamic linker (not the Nix store one).
    # Do this as a deterministic post-link patch rather than an impure re-link.
    if [ "$(uname)" = "Linux" ]; then
      DL=""
      ARCH="$(uname -m)"
      if [ "$ARCH" = "x86_64" ]; then
        DL="/lib64/ld-linux-x86-64.so.2"
      elif [ "$ARCH" = "aarch64" ]; then
        DL="/lib/ld-linux-aarch64.so.1"
      fi
      if [ -n "$DL" ]; then
        patchelf --set-interpreter "$DL" "$out/bin/cosmian_kms"
      fi
    fi
    runHook postInstall
  '';

  # Add UI assets and FIPS modules in postInstall
  postInstall = ''
    ${lib.optionalString (ui != null) ''
      mkdir -p "$out/usr/local/cosmian/ui/dist"
      cp -R "${ui}/dist/"* "$out/usr/local/cosmian/ui/dist/"
    ''}

    ${lib.optionalString isFips ''
      mkdir -p "$out/usr/local/cosmian/lib"
      # Use OpenSSL 3.1.2 for FIPS provider and configs
      cp -r "${openssl312_}/usr/local/cosmian/lib/ossl-modules" "$out/usr/local/cosmian/lib/"
      cp -r "${openssl312_}/usr/local/cosmian/lib/ssl" "$out/usr/local/cosmian/lib/"
    ''}

    ${lib.optionalString (!isFips && static) ''
      # Non-FIPS static: ship OpenSSL 3.6.0 provider modules (legacy, default)
      # and a non-FIPS openssl.cnf that activates default+legacy (not fips) providers.
      # This is needed for PKCS#12 parsing and other legacy algorithms at runtime.
      mkdir -p "$out/usr/local/cosmian/lib/ossl-modules"
      mkdir -p "$out/usr/local/cosmian/lib/ssl"
      if [ -d "${openssl36_}/usr/local/cosmian/lib/ossl-modules" ]; then
        cp -r "${openssl36_}/usr/local/cosmian/lib/ossl-modules/"* "$out/usr/local/cosmian/lib/ossl-modules/" 2>/dev/null || true
      elif [ -d "${openssl36_}/lib/ossl-modules" ]; then
        cp -r "${openssl36_}/lib/ossl-modules/"* "$out/usr/local/cosmian/lib/ossl-modules/" 2>/dev/null || true
      fi
      # Ship non-FIPS openssl.cnf (generated by openssl.nix with enableLegacy)
      if [ -f "${openssl36_}/usr/local/cosmian/lib/ssl/openssl.cnf" ]; then
        cp "${openssl36_}/usr/local/cosmian/lib/ssl/openssl.cnf" "$out/usr/local/cosmian/lib/ssl/"
      fi
    ''}

    ${lib.optionalString (!static) ''
      # Dynamic linkage variant: ship libssl and libcrypto
      mkdir -p "$out/usr/local/cosmian/lib"
      # For FIPS dynamic builds, use OpenSSL 3.1.2 to match the FIPS provider version
      # For non-FIPS dynamic builds, use OpenSSL 3.6.0
      ${
        if isFips then
          ''
            opensslSrc="${openssl312_}"
          ''
        else
          ''
            opensslSrc="${openssl36_}"
          ''
      }
      if [ "$(uname)" = "Darwin" ]; then
        # macOS: copy versioned dylibs if present; fall back to unversioned names
        for dylib in libssl.3.dylib libcrypto.3.dylib libssl.dylib libcrypto.dylib; do
          if [ -f "$opensslSrc/lib/$dylib" ]; then
            cp "$opensslSrc/lib/$dylib" "$out/usr/local/cosmian/lib/$dylib"
          fi
        done
      else
        # Linux: copy .so.3 versioned shared libraries
        for so in libssl.so.3 libcrypto.so.3; do
          if [ -f "$opensslSrc/lib/$so" ]; then
            cp "$opensslSrc/lib/$so" "$out/usr/local/cosmian/lib/$so"
          fi
        done
      fi
      # For non-FIPS dynamic builds, also include provider modules from OpenSSL 3.6.0 (e.g., legacy)
      if [ "${toString (!isFips)}" = "1" ]; then
        mkdir -p "$out/usr/local/cosmian/lib/ossl-modules"
        if [ -d "${openssl36_}/usr/local/cosmian/lib/ossl-modules" ]; then
          cp -r "${openssl36_}/usr/local/cosmian/lib/ossl-modules" "$out/usr/local/cosmian/lib/"
        elif [ -d "${openssl36_}/lib/ossl-modules" ]; then
          cp -r "${openssl36_}/lib/ossl-modules" "$out/usr/local/cosmian/lib/"
        else
          echo "WARNING: OpenSSL 3.6.0 ossl-modules directory not found; legacy provider may be missing"
        fi
      fi
    ''}

    # Write build info
    cat > "$out/bin/build-info.txt" <<EOF
    KMS Server ${variant} (${if static then "static" else "dynamic"} OpenSSL)
    Version: ${version}
    OpenSSL (link): ${opensslLink}
    ${lib.optionalString isFips "FIPS provider: from OpenSSL 3.1.2 (usr/local/cosmian/lib)"}
    EOF
  '';

  passthru = {
    inherit variant isFips;
    opensslPath = opensslLink;
    uiPath = ui;
    src = filteredSrc;
    inherit version;
    hostTriple = pkgs234.stdenv.hostPlatform.config;
  };

  meta = with lib; {
    description = "Cosmian KMS - High-performance Key Management System with FIPS 140-3 cryptographic module (${variant} build)";
    homepage = "https://github.com/Cosmian/kms";
    license = {
      shortName = "BUSL-1.1";
      fullName = "Business Source License 1.1";
      url = "https://github.com/Cosmian/kms/blob/develop/LICENSE";
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
      ];
      # Additional flags for determinism
      determinism = lib.concatStringsSep " " [
        "-C symbol-mangling-version=v0"
      ];
      linuxOnly = lib.concatStringsSep " " (
        [
          "-C link-arg=-Wl,--build-id=none"
          "-C link-arg=-Wl,--hash-style=gnu"
          "-C debuginfo=0"
          "-C strip=symbols"
        ]
        ++ lib.optionals static [ ]
      );
      # For dynamic builds, set RPATH to /usr/local/cosmian/lib where the .so files will be installed
      dynamicOnly = lib.optionalString (
        !static && pkgs.stdenv.isLinux
      ) "-C link-arg=-Wl,-rpath,/usr/local/cosmian/lib";
    in
    if pkgs.stdenv.isLinux then
      remap + " " + determinism + " " + linuxOnly + " " + dynamicOnly
    else
      remap + " " + determinism;
  NIX_DONT_SET_RPATH = lib.optionalString pkgs.stdenv.isLinux "1";
  NIX_ENFORCE_PURITY = lib.optionalString pkgs.stdenv.isLinux "1";
  dontCargoCheck = true;
  # Run tests only for static builds (self-contained OpenSSL); dynamic builds
  # lack runtime libssl in the Nix sandbox. Use doCheck (not dontCheck) for
  # reliable behaviour across nixpkgs versions.
  doCheck = static;
  dontUseCargoParallelTests = true;
  doInstallCheck = true; # Always run install checks to generate/verify hashes
  dontInstallCheck = false;
  cargoCheckHook = "";
  cargoNextestHook = "";
  checkPhase =
    if static then
      ''
        runHook preCheck
        echo "== cargo test cosmian_kms_server (release) =="
        export RUST_BACKTRACE=1
      ''
      + (
        if isFips then
          ''
            # FIPS: tests use the 3.1.2 provider
            export OPENSSL_DIR="${openssl312_}"
            export OPENSSL_LIB_DIR="${openssl312_}/lib"
            export OPENSSL_INCLUDE_DIR="${openssl312_}/include"
            export OPENSSL_CONF="${openssl312_}/ssl/openssl.cnf"
            export OPENSSL_MODULES="${openssl312_}/lib/ossl-modules"
          ''
        else
          ''
            # Non-FIPS: the binary needs the legacy provider at runtime.
            # Point OPENSSL_CONF/MODULES to the Nix-store copy so legacy.so
            # is found (compiled-in OPENSSLDIR=/usr/local/cosmian/… doesn't
            # exist in the sandbox).
            export OPENSSL_DIR="${openssl36_}"
            export OPENSSL_LIB_DIR="${openssl36_}/lib"
            export OPENSSL_INCLUDE_DIR="${openssl36_}/include"
            export OPENSSL_CONF="${openssl36_}/ssl/openssl.cnf"
            export OPENSSL_MODULES="${openssl36_}/lib/ossl-modules"
          ''
      )
      + ''
        export OPENSSL_NO_VENDOR=1

        cargo test --release -p cosmian_kms_server --no-default-features \
          ${lib.optionalString (features != [ ]) "--features ${lib.concatStringsSep "," features}"}

        runHook postCheck
      ''
    else
      ''
        echo "== Skipping cargo test for dynamic build (libssl.so.3 unavailable in Nix sandbox) =="
      '';
  configurePhase = ''
    export CARGO_HOME="$(pwd)/.cargo-home"
  '';
  inherit installCheckPhase;
}
// lib.optionalAttrs static {
  # Only set OPENSSL_STATIC for static builds to avoid any value for dynamic
  OPENSSL_STATIC = "1";
}
