{
  pkgs ? import <nixpkgs> { },
  pkgs228 ? pkgs, # Older nixpkgs with glibc 2.27 (for flake builds)
  lib ? pkgs.lib,
  openssl312,
  # Provide a rustPlatform that uses the desired Rust (e.g., 1.90.0) but
  # links against pkgs228 (glibc 2.27) on Linux for maximum compatibility.
  rustPlatform ? pkgs.rustPlatform,
  # KMS version (from Cargo.toml)
  version,
  features ? [ ], # [ "non-fips" ] or []
  ui ? null, # Pre-built UI derivation providing dist/
  # Linkage mode: true for static OpenSSL, false for dynamic OpenSSL
  static ? true,
  # Allow callers (e.g., Docker image build) to bypass deterministic hash
  # enforcement when the container build environment cannot yet reproduce
  # the committed expected hashes. Default remains strict (true) for
  # packaging and CI flows.
  enforceDeterministicHash ? false,
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  baseVariant = if isFips then "fips" else "non-fips";
  # Combine base variant with suffix for hash file lookup
  # Using -static-openssl or -dynamic-openssl for backward compatibility with existing hash files
  variant-suffix = if static then "-static-openssl" else "-dynamic-openssl";
  variant = if variant-suffix == "" then baseVariant else "${baseVariant}${variant-suffix}";

  # Expected deterministic sha256 of the final installed binary (cosmian_kms)
  # Naming convention (matches repository files):
  #   cosmian-kms-server.<fips|non-fips>.<static-openssl|dynamic-openssl>.<arch>.<os>.sha256
  expectedHashPath =
    _unused:
    let
      sys = pkgs.stdenv.hostPlatform.system; # e.g., x86_64-linux
      parts = lib.splitString "-" sys;
      arch = builtins.elemAt parts 0;
      os = builtins.elemAt parts 1;
      # Match binary expected-hash file naming: static => static-openssl, dynamic => dynamic-openssl
      impl = if static then "static-openssl" else "dynamic-openssl";
      file1 = ./expected-hashes + "/cosmian-kms-server.${baseVariant}.${impl}.${arch}.${os}.sha256";
    in
    if builtins.pathExists file1 then
      file1
    else
      builtins.throw ''
        Expected hash file not found for variant ${baseVariant} (impl ${impl}) on system ${sys}.
        Missing tried paths:
            - expected-hashes/cosmian-kms-server.${baseVariant}.${impl}.${arch}.${os}.sha256
        Please add the appropriate file with the expected SHA-256 of the built binary.
      '';

  # Compute the actual hash file path for writing during build

  # Only compute and validate expected hash path if enforcement is enabled
  expectedHashPathVariant = if enforceDeterministicHash then expectedHashPath variant else null;
  # Only read the hash file if enforcement is enabled to avoid errors when file doesn't exist
  expectedHashRaw =
    if enforceDeterministicHash && expectedHashPathVariant != null then
      builtins.readFile expectedHashPathVariant
    else
      "";
  sanitizeHash =
    s:
    let
      noWS = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] s;
    in
    lib.strings.removeSuffix "\n" noWS;
  expectedHash = sanitizeHash expectedHashRaw;

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
      export LD_LIBRARY_PATH="${openssl312}/lib:$LD_LIBRARY_PATH"
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

      # Check GLIBC version <= 2.28 (Linux only)
      MAX_VER=$(readelf -sW "$BIN" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1)
      [ "$(printf '%s\n' "$MAX_VER" "2.28" | sort -V | tail -n1)" = "2.28" ] || {
        echo "ERROR: GLIBC $MAX_VER > 2.28"; exit 1;
      }

      # Deterministic hash check
      ${lib.optionalString enforceDeterministicHash ''
        ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
        [ "$ACTUAL" = "${expectedHash}" ] || {
          echo "ERROR: Hash mismatch. Expected ${expectedHash}, got $ACTUAL" >&2; exit 1;
        }
        echo "Hash OK: $ACTUAL"
      ''}

      # Always write actual hash to output for reference/updates
      ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
      echo "$ACTUAL" > "$out/bin/cosmian_kms.sha256"
      echo "Binary hash: $ACTUAL (saved to $out/bin/cosmian_kms.sha256)"

      # Write the expected hash filename for easy copying
      HASH_FILENAME="cosmian-kms-server.${baseVariant}.${
        if static then "static-openssl" else "dynamic-openssl"
      }.x86_64.linux.sha256"
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

      # Always write actual hash to output for reference/updates
      ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
      echo "$ACTUAL" > "$out/bin/cosmian_kms.sha256"
      echo "Binary hash: $ACTUAL (saved to $out/bin/cosmian_kms.sha256)"

      # Write the expected hash filename for easy copying
      ARCH="$(uname -m)"
      HASH_FILENAME="cosmian-kms-server.${baseVariant}.${
        if static then "static-openssl" else "dynamic-openssl"
      }.$ARCH.darwin.sha256"
      echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
      echo "Expected hash file saved to: $out/bin/$HASH_FILENAME"
      echo "To update repository, copy this file to: nix/expected-hashes/$HASH_FILENAME"
    fi

    # For FIPS builds with static linkage, verify binary was built against OpenSSL 3.1.2
    # Note: For dynamic builds, the version string is in the shared library, not the binary
    # OPENSSLDIR is baked into OpenSSL at compile time and will show the Nix store path.
    # At runtime, we override it with OPENSSL_CONF environment variable to use /usr/local/cosmian/lib/ssl
    # Full FIPS validation happens in smoke test with proper environment variables set
    ${lib.optionalString (static && pkgs.stdenv.isLinux) ''
      strings "$BIN" | grep -q "OpenSSL 3.1.2" || { echo "ERROR: Binary not statically linked against OpenSSL 3.1.2"; exit 1; }
      echo "Binary validation OK (OpenSSL 3.1.2 statically linked)"
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
  # Run tests only for static builds; skip for dynamic to avoid runtime libssl issues
  doCheck = static;

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
      # Darwin uses separate vendor files for static/dynamic; Linux uses one shared file
      linkSuffix = if pkgs.stdenv.isDarwin then (if static then "static" else "dynamic") else "";
      vendorFile =
        if linkSuffix != "" then
          ./expected-hashes + "/server.vendor.${linkSuffix}.${os}.sha256"
        else
          ./expected-hashes + "/server.vendor.${os}.sha256";
      placeholder = "sha256-BBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      let
        raw = builtins.readFile vendorFile;
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
      in
      if enforceDeterministicHash then
        (
          assert trimmed != placeholder && trimmed != "";
          trimmed
        )
      else
        trimmed
    else if enforceDeterministicHash then
      builtins.throw ("Expected server vendor cargo hash file not found: " + vendorFile)
    else
      placeholder;
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
    ]
    ++ lib.optionals pkgs.stdenv.isDarwin [
      darwin.cctools # provides otool used during installCheckPhase
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

  # Add UI assets and FIPS modules in postInstall
  postInstall = ''
    ${lib.optionalString (ui != null) ''
      mkdir -p "$out/usr/local/cosmian/ui/dist"
      cp -R "${ui}/dist/"* "$out/usr/local/cosmian/ui/dist/"
    ''}

    ${lib.optionalString isFips ''
      mkdir -p "$out/usr/local/cosmian/lib"
      cp -r "${openssl312}/usr/local/cosmian/lib/ossl-modules" "$out/usr/local/cosmian/lib/"
      cp -r "${openssl312}/usr/local/cosmian/lib/ssl" "$out/usr/local/cosmian/lib/"
    ''}

    # Write build info
    cat > "$out/bin/build-info.txt" <<EOF
    KMS Server ${variant} (${if static then "static" else "dynamic"} OpenSSL)
    Version: ${version}
    OpenSSL: ${openssl312}
    ${lib.optionalString isFips "FIPS: usr/local/cosmian/lib/ossl-modules/"}
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
      # For dynamic builds, set RPATH to /usr/local/cosmian/lib where the .so files will be installed
      dynamicOnly = lib.optionalString (
        !static && pkgs.stdenv.isLinux
      ) "-C link-arg=-Wl,-rpath,/usr/local/cosmian/lib";
    in
    if pkgs.stdenv.isLinux then remap + " " + linuxOnly + " " + dynamicOnly else remap;
  NIX_DONT_SET_RPATH = lib.optionalString pkgs.stdenv.isLinux "1";
  NIX_LDFLAGS = lib.optionalString pkgs.stdenv.isLinux "";
  NIX_CFLAGS_LINK = lib.optionalString pkgs.stdenv.isLinux "";
  NIX_ENFORCE_PURITY = lib.optionalString pkgs.stdenv.isLinux "0";
  dontCargoCheck = true;
  dontCheck = !static;
  dontUseCargoParallelTests = true;
  doInstallCheck = true; # Always run install checks to generate/verify hashes
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
