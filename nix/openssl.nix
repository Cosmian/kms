{
  stdenv,
  lib,
  fetchurl,
  perl,
  coreutils,
  # Linkage mode: true for static libraries only, false for shared libraries
  static ? true,
}:

# OpenSSL 3.1.2 built with FIPS provider and fipsmodule.cnf generated.
# Can build either static-only or shared libraries based on the 'static' parameter.
# Output layout mirrors a typical OPENSSL_DIR tree for ease of consumption:
#   $out/bin/openssl
#   $out/include
#   $out/lib/{libcrypto.a,libssl.a,libcrypto.so,libssl.so}
#   $out/lib/ossl-modules/fips.{so|dylib}
#   $out/ssl/fipsmodule.cnf
#
# Note: The FIPS provider module (fips.so) is a shared library that will be
# dynamically loaded at runtime. It must be built with a glibc version compatible
# with your target deployment environment. For maximum compatibility,
# use an older nixpkgs snapshot (e.g., nixos-19.03 with glibc <= 2.28).

let
  localTarball = ../resources/tarballs/openssl-3.1.2.tar.gz;

  # Expected SHA256 hash of the official OpenSSL 3.1.2 tarball
  expectedHash = "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539";

  # Validate local tarball hash and select source
  opensslSrc =
    if builtins.pathExists localTarball then
      let
        actualHash = builtins.hashFile "sha256" localTarball;
        hashValidation = lib.assertMsg (actualHash == expectedHash) (
          "Local OpenSSL tarball hash mismatch!\n"
          + "Expected: ${expectedHash}\n"
          + "Actual:   ${actualHash}\n"
          + "Please verify the integrity of ${toString localTarball}"
        );
      in
      # Force evaluation of hash validation
      builtins.seq hashValidation localTarball
    else
      fetchurl {
        url = "https://www.openssl.org/source/old/3.1/openssl-3.1.2.tar.gz";
        # SRI hash pinned from nix fetch (sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk=)
        sha256 = "sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk=";
      };
in
stdenv.mkDerivation rec {
  pname = "openssl";
  version = "3.1.2";

  src = opensslSrc;

  # Force evaluation of source path to trigger hash validation early
  passthru.srcPath = toString opensslSrc;

  # We need perl for OpenSSL build system, and coreutils for runtime scripts
  nativeBuildInputs = [
    perl
    coreutils
  ];

  # Force static libraries and enable FIPS provider
  # We also ensure the platform target is correct (darwin64-arm64-cc on Apple Silicon)
  # Choose OpenSSL build target based on host platform
  target =
    if stdenv.isDarwin then
      (if stdenv.hostPlatform.isAarch64 then "darwin64-arm64-cc" else "darwin64-x86_64-cc")
    else if stdenv.hostPlatform.isAarch64 then
      "linux-aarch64"
    else
      "linux-x86_64";

  soExt = if stdenv.isDarwin then "dylib" else "so";

  configurePhase = ''
    runHook preConfigure
    export CC="${stdenv.cc.targetPrefix}cc"

    echo "Configuring OpenSSL ${version} for target ${target} (${
      if static then "static" else "shared"
    } linkage)"
    # Configure with explicit libdir to normalize to 'lib' across platforms
    # Note: We use $out/ssl during build, then reorganize in postInstall
    perl ./Configure \
      ${if static then "no-shared" else "shared"} \
      enable-fips \
      --prefix=$out \
      --openssldir=$out/ssl \
      --libdir=lib \
      ${target}

  '';

  buildPhase = ''
    runHook preBuild
    echo "Building OpenSSL ${version}..."
    make depend > /dev/null 2>&1
    # Determine job count as (cores - 1), minimum 1
    if command -v nproc >/dev/null 2>&1; then
      CORES=$(nproc)
    elif command -v sysctl >/dev/null 2>&1; then
      CORES=$(sysctl -n hw.ncpu)
    elif command -v getconf >/dev/null 2>&1; then
      CORES=$(getconf _NPROCESSORS_ONLN)
    else
      CORES=2
    fi
    JOBS=$(( CORES > 1 ? CORES - 1 : 1 ))
    echo "Using $JOBS parallel jobs (from $CORES cores)"
    make -j"$JOBS" > /dev/null 2>&1
    echo "OpenSSL build completed."
  '';

  installPhase = ''
    runHook preInstall
    echo "Installing OpenSSL ${version} to target paths..."
    # Determine job count as (cores - 1), minimum 1
    if command -v nproc >/dev/null 2>&1; then
      CORES=$(nproc)
    elif command -v sysctl >/dev/null 2>&1; then
      CORES=$(sysctl -n hw.ncpu)
    elif command -v getconf >/dev/null 2>&1; then
      CORES=$(getconf _NPROCESSORS_ONLN)
    else
      CORES=2
    fi
    JOBS=$(( CORES > 1 ? CORES - 1 : 1 ))
    make -j"$JOBS" install_sw install_ssldirs install_fips > /dev/null 2>&1

    # Reorganize output to match final installation layout
    # Create target directory structure
    mkdir -p "$out/usr/local/cosmian/lib/ossl-modules"
    mkdir -p "$out/usr/local/cosmian/lib/ssl"

    # Copy FIPS provider module to target location (keep original for tests/dev)
    if [ -f "$out/lib/ossl-modules/fips.${soExt}" ]; then
      cp "$out/lib/ossl-modules/fips.${soExt}" "$out/usr/local/cosmian/lib/ossl-modules/"
    elif [ -f "$out/lib64/ossl-modules/fips.${soExt}" ]; then
      cp "$out/lib64/ossl-modules/fips.${soExt}" "$out/usr/local/cosmian/lib/ossl-modules/"
    else
      echo "ERROR: FIPS provider module not found"
      exit 1
    fi

    # Move OpenSSL configuration files to target location (keep originals for dev/test)
    if [ ! -f "$out/ssl/openssl.cnf" ]; then
      echo "openssl.cnf not found, seeding from ./apps/openssl.cnf"
      install -Dm644 "./apps/openssl.cnf" "$out/ssl/openssl.cnf"
    fi

    cp "$out/ssl/fipsmodule.cnf" "$out/usr/local/cosmian/lib/ssl/"
    cp "$out/ssl/openssl.cnf" "$out/usr/local/cosmian/lib/ssl/"

    # Enable FIPS in both locations (original $out/ssl and target usr/local/cosmian/lib/ssl)
    # This ensures FIPS works during both development/testing and production
    for conf_dir in "$out/ssl" "$out/usr/local/cosmian/lib/ssl"; do
      # Use explicit local path for .include to ensure it finds fipsmodule.cnf in same directory
      # OpenSSL resolves ./ paths relative to the directory containing the config file
      sed -i "s|^# \\.include fipsmodule\\.cnf|.include ./fipsmodule.cnf|g" "$conf_dir/openssl.cnf"

      # Uncomment the fips provider line
      sed -i 's|^# fips = fips_sect|fips = fips_sect|g' "$conf_dir/openssl.cnf"

      # Add base provider (for non-FIPS algorithms still needed)
      # First check if base_sect already exists to avoid duplication
      if ! grep -q "^base = base_sect" "$conf_dir/openssl.cnf"; then
        sed -i '/^fips = fips_sect/a base = base_sect' "$conf_dir/openssl.cnf"
      fi

      # Add base_sect configuration if not already present
      if ! grep -q "^\[ base_sect \]" "$conf_dir/openssl.cnf"; then
        echo "" >> "$conf_dir/openssl.cnf"
        echo "[ base_sect ]" >> "$conf_dir/openssl.cnf"
        echo "activate = 1" >> "$conf_dir/openssl.cnf"
      fi
    done

    echo "OpenSSL FIPS modules and config installed to $out/usr/local/cosmian/lib/"
    echo "OpenSSL FIPS config also enabled in $out/ssl/ for development/testing"

    runHook postInstall
  '';

  # Post-install: For dynamic builds, remove static libraries to force dynamic linking
  postInstall = lib.optionalString (!static) ''
    echo "Removing static libraries from dynamic OpenSSL build..."
    rm -f $out/lib/libcrypto.a $out/lib/libssl.a
    echo "Static libraries removed. Only shared libraries remain."
  '';

  # Critical for FIPS: do not strip or patch ELF on the provider module, as it
  # would invalidate the module integrity MAC and break self-tests at runtime.
  dontStrip = true;
  dontPatchELF = true;

  # No passthru needed; consumers can use the derivation path as OPENSSL_DIR

  meta = with lib; {
    description = "OpenSSL 3.1.2 with FIPS provider (${if static then "static" else "shared"} linkage)";
    homepage = "https://www.openssl.org";
    license = licenses.openssl;
    platforms = platforms.unix;
    maintainers = [ ];
  };
}
