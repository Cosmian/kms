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

  # Install check phase - simplified version verification
  installCheckPhase = ''
    runHook preInstallCheck

    BIN="$out/bin/cosmian_kms"
    [ -f "$BIN" ] || { echo "ERROR: Binary not found"; exit 1; }

    # Run --version check
    "$BIN" --version 2>&1 | grep -q "cosmian_kms_server" || { echo "ERROR: Version check failed"; exit 1; }

    # Linux-specific checks
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

      # Check GLIBC version <= 2.28
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
    fi

    # For FIPS builds, verify binary was built against OpenSSL 3.1.2
    # Note: OPENSSLDIR is baked into OpenSSL at compile time and will show the Nix store path.
    # At runtime, we override it with OPENSSL_CONF environment variable to use /usr/local/lib/cosmian-kms/ssl
    # Full FIPS validation happens in smoke test with proper environment variables set
    strings "$BIN" | grep -q "OpenSSL 3.1.2" || { echo "ERROR: Binary not linked against OpenSSL 3.1.2"; exit 1; }
    echo "Binary validation OK (OpenSSL 3.1.2 detected)"

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
  # Support both cargoHash (new) and cargoSha256 (legacy) for compatibility across nixpkgs versions.
  # Platform-specific vendor hashes (target-dependent deps). If out-of-date, temporarily set to ""
  # and rebuild to obtain the new suggested value from Nix ("got: sha256-...").
  cargoHash =
    if pkgs.stdenv.isDarwin then
      # macOS vendor hash - different for static vs dynamic builds
      if static then
        "sha256-" # static
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

  # Add UI assets and FIPS modules in postInstall
  postInstall = ''
    ${lib.optionalString (ui != null) ''
      mkdir -p "$out/usr/local/cosmian/ui/dist"
      cp -R "${ui}/dist/"* "$out/usr/local/cosmian/ui/dist/"
    ''}

    ${lib.optionalString isFips ''
      mkdir -p "$out/usr/local/lib/cosmian-kms"
      cp -r "${openssl312}/usr/local/lib/cosmian-kms/ossl-modules" "$out/usr/local/lib/cosmian-kms/"
      cp -r "${openssl312}/usr/local/lib/cosmian-kms/ssl" "$out/usr/local/lib/cosmian-kms/"
    ''}

    # Write build info
    cat > "$out/bin/build-info.txt" <<EOF
    KMS Server ${variant} (${if static then "static" else "dynamic"} OpenSSL)
    Version: ${version}
    OpenSSL: ${openssl312}
    ${lib.optionalString isFips "FIPS: usr/local/lib/cosmian-kms/ossl-modules/"}
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
      # For dynamic builds, set RPATH to /usr/local/lib/cosmian-kms where the .so files will be installed
      dynamicOnly = lib.optionalString (
        !static && pkgs.stdenv.isLinux
      ) "-C link-arg=-Wl,-rpath,/usr/local/lib/cosmian-kms";
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
