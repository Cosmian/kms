{
  stdenv,
  lib,
  fetchurl,
  perl,
  coreutils,
  # Linkage mode: true for static libraries only, false for shared libraries
  static ? true,
  # OpenSSL version to build (e.g. "3.6.0" or "3.1.2")
  version ? "3.1.2",
  # Optional override for source URL and hashes. When not provided, defaults to Cosmian mirror
  # and known hashes for 3.1.2. For other versions, callers should provide these.
  srcUrl ? null,
  # SRI sha256 for fetchurl (e.g. "sha256-oM5p...")
  sha256SRI ? null,
  # Expected plain hex sha256 for validating local tarball in resources/tarballs
  expectedHash ? null,
}:

# OpenSSL ${version} built with FIPS provider and fipsmodule.cnf generated.
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
  tarballName = "openssl-${version}.tar.gz";
  localTarball = ../resources/tarballs/${tarballName};

  # Provide sensible defaults for 3.1.2 to preserve historical behavior.
  defaultUrl = "https://package.cosmian.com/openssl/${tarballName}";
  defaultExpectedHash = "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539"; # 3.1.2
  defaultSRI = "sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk="; # 3.1.2

  url = if srcUrl != null then srcUrl else defaultUrl;
  sri = if sha256SRI != null then sha256SRI else defaultSRI;
  expected = if expectedHash != null then expectedHash else defaultExpectedHash;

  # Validate local tarball hash and select source
  opensslSrc =
    if builtins.pathExists localTarball then
      let
        actualHash = builtins.hashFile "sha256" localTarball;
        hashValidation = lib.assertMsg (actualHash == expected) (
          "Local OpenSSL tarball hash mismatch!\n"
          + "Expected: ${expected}\n"
          + "Actual:   ${actualHash}\n"
          + "Please verify the integrity of ${toString localTarball}"
        );
      in
      # Force evaluation of hash validation
      builtins.seq hashValidation localTarball
    else
      fetchurl {
        # Prefer Cosmian mirror for reliability; callers can override via srcUrl
        inherit url;
        # SRI hash pinned by caller or defaults (3.1.2)
        sha256 = sri;
      };
in
stdenv.mkDerivation rec {
  pname = "openssl";
  inherit version;

  src = opensslSrc;

  # Force evaluation of source path to trigger hash validation early
  passthru.srcPath = toString opensslSrc;

  # We need perl for OpenSSL build system and coreutils for runtime scripts
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

    # Force use of system glibc by unsetting Nix's linker/compiler wrappers
    # This prevents the built libraries from depending on /nix/store paths
    unset NIX_LDFLAGS
    unset NIX_CFLAGS_COMPILE
    unset NIX_CFLAGS_LINK
    export NIX_DONT_SET_RPATH=1
    export NIX_NO_SELF_RPATH=1

    echo "Configuring OpenSSL ${version} for target ${target} (${
      if static then "static" else "shared"
    } linkage)"
    # Configure with production openssldir path for portability
    # This hardcodes /usr/local/cosmian/lib/ssl into the library, making binaries portable
    # During build, we'll create this directory structure in $out for FIPS module generation
    perl ./Configure \
      ${if static then "no-shared" else "shared"} \
      no-zlib \
      enable-fips \
      --prefix=$out \
      --openssldir=/usr/local/cosmian/lib/ssl \
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

        # Install OpenSSL binaries and libraries only (not ssldirs - we'll handle that manually)
        echo "Running make install_sw..."
        if ! make -j"$JOBS" install_sw; then
          echo "ERROR: make install_sw failed"
          exit 1
        fi
        echo "Make install_sw completed successfully."

        # Now manually create the production directory structure
        mkdir -p "$out/usr/local/cosmian/lib/ossl-modules"
        mkdir -p "$out/usr/local/cosmian/lib/ssl"
        mkdir -p "$out/lib/ossl-modules"
        mkdir -p "$out/ssl"

        # The FIPS module was built but not installed by install_sw
        # Find and copy it to both dev and production locations
        echo "Looking for FIPS provider module..."
        if [ -f "providers/fips.${soExt}" ]; then
          echo "Found FIPS module at providers/fips.${soExt}"
          cp "providers/fips.${soExt}" "$out/usr/local/cosmian/lib/ossl-modules/"
          cp "providers/fips.${soExt}" "$out/lib/ossl-modules/"
        else
          echo "ERROR: FIPS provider module not found at providers/fips.${soExt}"
          ls -la providers/ || true
          exit 1
        fi

        # Generate fipsmodule.cnf in production location
        echo "Generating FIPS module configuration..."
        ${
          if static then "" else "LD_LIBRARY_PATH=$out/lib:$LD_LIBRARY_PATH "
        }$out/bin/openssl fipsinstall -out "$out/usr/local/cosmian/lib/ssl/fipsmodule.cnf" \
          -module "$out/usr/local/cosmian/lib/ossl-modules/fips.${soExt}"

        # Copy base openssl.cnf to production location
        if [ -f "./apps/openssl.cnf" ]; then
          cp "./apps/openssl.cnf" "$out/usr/local/cosmian/lib/ssl/openssl.cnf"
        else
          echo "ERROR: openssl.cnf template not found"
          exit 1
        fi

        # Also create dev/test copies in $out/ssl
        cp "$out/usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$out/ssl/"
        cp "$out/usr/local/cosmian/lib/ssl/openssl.cnf" "$out/ssl/"

        # Enable FIPS in production config (robust include + activation)
        conf_dir_prod="$out/usr/local/cosmian/lib/ssl"
        include_path_prod="/usr/local/cosmian/lib/ssl/fipsmodule.cnf"
        # Prepend include if not present
        if ! grep -q "^\\.include $include_path_prod$" "$conf_dir_prod/openssl.cnf"; then
          tmp_conf="$conf_dir_prod/openssl.cnf.tmp"
          echo ".include $include_path_prod" > "$tmp_conf"
          cat "$conf_dir_prod/openssl.cnf" >> "$tmp_conf"
          mv "$tmp_conf" "$conf_dir_prod/openssl.cnf"
        fi
        # Activate providers inside the [provider_sect] block
        if grep -q "^\[provider_sect\]" "$conf_dir_prod/openssl.cnf"; then
          # Uncomment existing fips mapping if present; otherwise insert after provider_sect header
          if grep -q "^# *fips = fips_sect" "$conf_dir_prod/openssl.cnf"; then
            sed -i "s/^# *fips = fips_sect$/fips = fips_sect/" "$conf_dir_prod/openssl.cnf"
          elif ! grep -q "^fips = fips_sect" "$conf_dir_prod/openssl.cnf"; then
            awk 'BEGIN{s=0} {print} /^\[provider_sect\]/{s=1; next} s && !done {print "fips = fips_sect"; done=1; s=0} END{}' "$conf_dir_prod/openssl.cnf" > "$conf_dir_prod/openssl.cnf.tmp" && mv "$conf_dir_prod/openssl.cnf.tmp" "$conf_dir_prod/openssl.cnf"
          fi
          # Insert base mapping similarly
          if ! grep -q "^base = base_sect" "$conf_dir_prod/openssl.cnf"; then
            awk 'BEGIN{s=0} {print} /^\[provider_sect\]/{s=1; next} s && !done2 {print "base = base_sect"; done2=1; s=0} END{}' "$conf_dir_prod/openssl.cnf" > "$conf_dir_prod/openssl.cnf.tmp" && mv "$conf_dir_prod/openssl.cnf.tmp" "$conf_dir_prod/openssl.cnf"
          fi
        else
          # Fallback: append a provider_sect with required mappings
          cat >> "$conf_dir_prod/openssl.cnf" <<'EOF'

    [provider_sect]
    fips = fips_sect
    base = base_sect
    EOF
        fi
        # Ensure base section activates providers
        if ! grep -q "^\[ base_sect \]" "$conf_dir_prod/openssl.cnf"; then
          cat >> "$conf_dir_prod/openssl.cnf" <<'EOF'

    [ base_sect ]
    activate = 1
    EOF
        fi

        # Create a dev/test FIPS config alongside the original non-FIPS one in $out/ssl
        cp "$conf_dir_prod/openssl.cnf" "$out/ssl/openssl-fips.cnf"
        conf_dir_dev="$out/ssl"
        include_path_dev="$conf_dir_dev/fipsmodule.cnf"
        # Rewrite include path for dev copy
        sed -i "s|^\\.include $include_path_prod$|.include $include_path_dev|" "$out/ssl/openssl-fips.cnf"

        # Also install a production-named FIPS config for Docker runtime expectations
        cp "$conf_dir_prod/openssl.cnf" "$conf_dir_prod/openssl-fips.cnf"

        echo "OpenSSL FIPS modules and config installed to $out/usr/local/cosmian/lib/"
        echo "OpenSSL FIPS dev/test config available at $out/ssl/openssl-fips.cnf; original non-FIPS config at $out/ssl/openssl.cnf"

        runHook postInstall
  '';

  # Post-install: For dynamic builds, remove static libraries to force dynamic linking
  postInstall = lib.optionalString (!static) ''
    echo "Removing static libraries from dynamic OpenSSL build..."
    rm -f $out/lib/libcrypto.a $out/lib/libssl.a
    echo "Static libraries removed. Only shared libraries remain."
  '';

  # Critical for FIPS: do not strip the provider module, as it would invalidate
  # the module integrity MAC and break self-tests at runtime.
  # Also don't patch ELF - we use compiler flags to link against system glibc
  dontStrip = true;
  dontPatchELF = true;

  # No postFixup needed - libraries are built with system glibc due to unsetting
  # NIX_LDFLAGS/NIX_CFLAGS in configurePhase

  # No passthru needed; consumers can use the derivation path as OPENSSL_DIR

  meta = with lib; {
    description = "OpenSSL ${version} with FIPS provider (${
      if static then "static" else "shared"
    } linkage)";
    homepage = "https://www.openssl.org";
    license = licenses.openssl;
    platforms = platforms.unix;
    maintainers = [ ];
  };
}
