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
  # Build the legacy provider module (needed for non-FIPS features)
  enableLegacy ? false,
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
# use a stdenv with glibc 2.34 (Rocky Linux 9 compatibility).

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

  # Compute optimal make job count: (nCores - 1), minimum 1
  coresJobsSnippet = ''
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
  '';
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
    #
    # Use fixed (non-Nix-store) paths for enginesdir and modulesdir so that
    # these compiled-in strings are identical across machines, regardless of the
    # OpenSSL derivation's Nix store hash.  For static builds these directories
    # are never opened at runtime; for dynamic/FIPS builds the provider is
    # loaded from /usr/local/cosmian/lib/ossl-modules via openssl.cnf.
    #
    # Note: OpenSSL 3.x Configure does NOT support --enginesdir / --modulesdir
    # as separate flags (they are misinterpreted as CFLAGS).  Instead, we
    # override the Makefile variables ENGINESDIR and MODULESDIR after Configure
    # so the -D defines compiled into libcrypto use fixed paths.
    perl ./Configure \
      ${if static then "no-shared" else "shared"} \
      no-zlib \
      enable-fips \
      ${if enableLegacy then "enable-legacy" else ""} \
      --prefix=$out \
      --openssldir=/usr/local/cosmian/lib/ssl \
      --libdir=lib \
      ${target}

    # Override compiled-in ENGINESDIR and MODULESDIR in the generated Makefile
    # to avoid embedding Nix store paths.  The Makefile derives these from
    # --prefix, so without this patch they would contain $out (/nix/store/...).
    echo "Patching Makefile to use fixed ENGINESDIR / MODULESDIR..."
    sed -i 's|^ENGINESDIR=.*|ENGINESDIR=/usr/local/cosmian/lib/engines-3|' Makefile
    sed -i 's|^MODULESDIR=.*|MODULESDIR=/usr/local/cosmian/lib/ossl-modules|' Makefile
    echo "ENGINESDIR=$(grep '^ENGINESDIR=' Makefile)"
    echo "MODULESDIR=$(grep '^MODULESDIR=' Makefile)"

  '';

  buildPhase = ''
    runHook preBuild

    # Apply deterministic timestamp for reproducible builds
    export SOURCE_DATE_EPOCH=1
    export ZERO_AR_DATE=1

    echo "Building OpenSSL ${version}..."
    make depend > /dev/null 2>&1

    # Scrub Nix store paths from buildinf.h to ensure deterministic builds.
    # OpenSSL generates this file during `make depend`, embedding the CC path and flags.
    # The compiler wrapper may contain /nix/store/... paths that vary between machines.
    if [ -f "crypto/buildinf.h" ]; then
      echo "Scrubbing Nix store paths from crypto/buildinf.h..."
      sed -i 's|/nix/store/[a-z0-9]\{32\}-[^/"]*|/usr/bin|g' crypto/buildinf.h
      echo "buildinf.h after scrub:"
      cat crypto/buildinf.h
    fi
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

    # Apply deterministic timestamp for reproducible builds
    export SOURCE_DATE_EPOCH=1
    export ZERO_AR_DATE=1

    echo "Installing OpenSSL ${version} to target paths..."
    ${coresJobsSnippet}

    # Install OpenSSL binaries and libraries only (not ssldirs - we'll handle that manually)
    # Override ENGINESDIR and MODULESDIR back to $out paths for the install step,
    # since the Makefile values were patched to fixed /usr/local/cosmian paths
    # (needed for deterministic compile-time defines, but install must write to $out).
    echo "Running make install_sw..."
    if ! make -j"$JOBS" install_sw ENGINESDIR=$out/lib/engines-3 MODULESDIR=$out/lib/ossl-modules; then
      echo "ERROR: make install_sw failed"
      exit 1
    fi
    echo "Make install_sw completed successfully."

    # Create expected directories
    mkdir -p "$out/usr/local/cosmian/lib/ossl-modules"
    mkdir -p "$out/usr/local/cosmian/lib/ssl"
    mkdir -p "$out/lib/ossl-modules"
    mkdir -p "$out/ssl"

    # Copy FIPS provider module to both prod and dev locations
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

    # Optionally copy legacy provider module when enabled
    if [ "${toString enableLegacy}" = "1" ]; then
      echo "Checking for legacy provider module (enableLegacy=true)..."
      if [ -f "providers/legacy.${soExt}" ]; then
        echo "Found legacy module at providers/legacy.${soExt}"
        cp "providers/legacy.${soExt}" "$out/usr/local/cosmian/lib/ossl-modules/"
        cp "providers/legacy.${soExt}" "$out/lib/ossl-modules/"
        # Normalize timestamps for deterministic builds
        touch --date=@1 "$out/usr/local/cosmian/lib/ossl-modules/legacy.${soExt}"
        touch --date=@1 "$out/lib/ossl-modules/legacy.${soExt}"
      else
        echo "WARNING: legacy provider not found at providers/legacy.${soExt}"
        ls -la providers/ || true
      fi
    fi

    # Generate fipsmodule.cnf in production location (runs self-tests)
    echo "Generating FIPS module configuration (with install self-tests)..."
    ${
      if static then "" else "LD_LIBRARY_PATH=$out/lib:$LD_LIBRARY_PATH "
    }$out/bin/openssl fipsinstall -self_test_oninstall -out "$out/usr/local/cosmian/lib/ssl/fipsmodule.cnf" \
      -module "$out/usr/local/cosmian/lib/ossl-modules/fips.${soExt}"

    # Reuse fipsmodule.cnf as generated by openssl fipsinstall without modifications
    cp "$out/usr/local/cosmian/lib/ssl/fipsmodule.cnf" "$out/ssl/"

    # Reuse the openssl.cnf installed by install_sw
    if [ -f "$out/ssl/openssl.cnf" ]; then
      cp "$out/ssl/openssl.cnf" "$out/usr/local/cosmian/lib/ssl/openssl.cnf"
    elif [ -f "./apps/openssl.cnf" ]; then
      cp "./apps/openssl.cnf" "$out/usr/local/cosmian/lib/ssl/openssl.cnf"
    else
      echo "ERROR: openssl.cnf not found in install output or build tree"
      exit 1
    fi
    # Ensure dev copy exists
    cp "$out/usr/local/cosmian/lib/ssl/openssl.cnf" "$out/ssl/"

    ${
      if enableLegacy then
        # Non-FIPS build (enableLegacy=true): configure default + legacy + base providers.
        # Do NOT reference fipsmodule.cnf or fips_sect — the FIPS provider may not be
        # present at runtime in non-FIPS deployments.
        ''
          echo "Configuring openssl.cnf for non-FIPS mode (default + legacy + base providers)..."
          for conf_dir in "$out/ssl" "$out/usr/local/cosmian/lib/ssl"; do
            # Write a clean provider configuration for non-FIPS usage
            # Remove any leftover FIPS references from the default openssl.cnf
            sed -i '/^# \.include fipsmodule\.cnf/d' "$conf_dir/openssl.cnf"
            sed -i '/^\.include.*fipsmodule\.cnf/d' "$conf_dir/openssl.cnf"
            sed -i '/^# fips = fips_sect/d' "$conf_dir/openssl.cnf"
            sed -i '/^fips = fips_sect/d' "$conf_dir/openssl.cnf"

            # Ensure providers section is enabled under [openssl_init]
            if ! grep -q "^providers[[:space:]]*=" "$conf_dir/openssl.cnf"; then
              awk '
                BEGIN{in_init=0}
                /^\[ *openssl_init *\]/{in_init=1; print; next}
                in_init && /^[[:space:]]*#?[[:space:]]*providers[[:space:]]*=/{in_init=0}
                in_init && NF==0{print "providers = provider_sect"; in_init=0}
                {print}
              ' "$conf_dir/openssl.cnf" > "$conf_dir/openssl.cnf.tmp" && mv "$conf_dir/openssl.cnf.tmp" "$conf_dir/openssl.cnf"
            fi

            # Ensure provider_sect references default + legacy + base
            # The stock openssl.cnf may already have [provider_sect] with just `default = default_sect`
            if grep -q "^\[ *provider_sect *\]" "$conf_dir/openssl.cnf"; then
              # Add legacy and base references if missing
              if ! awk 'f&&/^[[:space:]]*legacy[[:space:]]*=/{found=1} /^\[/{f=($0 ~ /provider_sect/)} END{exit found?0:1}' "$conf_dir/openssl.cnf"; then
                sed -i '/^default = default_sect/a legacy = legacy_sect' "$conf_dir/openssl.cnf"
              fi
              if ! awk 'f&&/^[[:space:]]*base[[:space:]]*=/{found=1} /^\[/{f=($0 ~ /provider_sect/)} END{exit found?0:1}' "$conf_dir/openssl.cnf"; then
                sed -i '/^legacy = legacy_sect/a base = base_sect' "$conf_dir/openssl.cnf"
              fi
            else
              {
                echo ""
                echo "[ provider_sect ]"
                echo "default = default_sect"
                echo "legacy = legacy_sect"
                echo "base = base_sect"
              } >> "$conf_dir/openssl.cnf"
            fi

            # Activate default_sect — the stock config has `# activate = 1` commented out.
            # When we explicitly list providers, default must be activated.
            if grep -q "^\[ *default_sect *\]" "$conf_dir/openssl.cnf"; then
              # Uncomment activate = 1 if it's commented
              sed -i '/^\[ *default_sect *\]/,/^\[/ s/^# *activate *= *1/activate = 1/' "$conf_dir/openssl.cnf"
              # If no activate line at all, add one
              if ! awk 'f&&/^[[:space:]]*activate[[:space:]]*=/{found=1} /^\[/{f=($0 ~ /default_sect/)} END{exit found?0:1}' "$conf_dir/openssl.cnf"; then
                sed -i '/^\[ *default_sect *\]/a activate = 1' "$conf_dir/openssl.cnf"
              fi
            else
              echo "" >> "$conf_dir/openssl.cnf"
              echo "[ default_sect ]" >> "$conf_dir/openssl.cnf"
              echo "activate = 1" >> "$conf_dir/openssl.cnf"
            fi

            # Add legacy_sect
            if ! grep -q "^\[ *legacy_sect *\]" "$conf_dir/openssl.cnf"; then
              echo "" >> "$conf_dir/openssl.cnf"
              echo "[ legacy_sect ]" >> "$conf_dir/openssl.cnf"
              echo "activate = 1" >> "$conf_dir/openssl.cnf"
            fi

            # Add base_sect
            if ! grep -q "^\[ *base_sect *\]" "$conf_dir/openssl.cnf"; then
              echo "" >> "$conf_dir/openssl.cnf"
              echo "[ base_sect ]" >> "$conf_dir/openssl.cnf"
              echo "activate = 1" >> "$conf_dir/openssl.cnf"
            fi
          done
          echo "Non-FIPS openssl.cnf configured with default + legacy + base providers"
        ''
      else
        # FIPS build (enableLegacy=false): configure fips + base providers with fipsmodule.cnf
        ''
          echo "Configuring openssl.cnf for FIPS mode (fips + base providers)..."
          # Enable FIPS in both locations (original $out/ssl and target usr/local/cosmian/lib/ssl)
          for conf_dir in "$out/ssl" "$out/usr/local/cosmian/lib/ssl"; do
            # Determine the appropriate include path based on the config directory
            if [ "$conf_dir" = "$out/usr/local/cosmian/lib/ssl" ]; then
              include_path="/usr/local/cosmian/lib/ssl/fipsmodule.cnf"
            else
              include_path="$conf_dir/fipsmodule.cnf"
            fi

            sed -i "s|^# \\.include fipsmodule\\.cnf|.include $include_path|g" "$conf_dir/openssl.cnf"
            sed -i 's|^# fips = fips_sect|fips = fips_sect|g' "$conf_dir/openssl.cnf"

            # Ensure providers section is enabled
            if ! grep -q "^providers[[:space:]]*=" "$conf_dir/openssl.cnf"; then
              awk '
                BEGIN{in_init=0}
                /^\[ *openssl_init *\]/{in_init=1; print; next}
                in_init && /^[[:space:]]*#?[[:space:]]*providers[[:space:]]*=/{in_init=0}
                in_init && NF==0{print "providers = provider_sect"; in_init=0}
                {print}
              ' "$conf_dir/openssl.cnf" > "$conf_dir/openssl.cnf.tmp" && mv "$conf_dir/openssl.cnf.tmp" "$conf_dir/openssl.cnf"
            fi

            # Ensure provider_sect exists with fips + base
            if ! grep -q "^\[ *provider_sect *\]" "$conf_dir/openssl.cnf"; then
              {
                echo ""
                echo "[ provider_sect ]"
                echo "fips = fips_sect"
                echo "base = base_sect"
              } >> "$conf_dir/openssl.cnf"
            else
              if ! awk 'f&&/^[[:space:]]*base[[:space:]]*=/{found=1} /^\[/{f=($0 ~ /provider_sect/)} END{exit found?0:1}' "$conf_dir/openssl.cnf"; then
                awk '
                  BEGIN{in_prov=0}
                  /^\[ *provider_sect *\]/{in_prov=1; print; next}
                  in_prov && NF==0{print "base = base_sect"; in_prov=0}
                  {print}
                ' "$conf_dir/openssl.cnf" > "$conf_dir/openssl.cnf.tmp" && mv "$conf_dir/openssl.cnf.tmp" "$conf_dir/openssl.cnf"
              fi
            fi

            if ! grep -q "^base = base_sect" "$conf_dir/openssl.cnf"; then
              sed -i '/^fips = fips_sect/a base = base_sect' "$conf_dir/openssl.cnf"
            fi

            if ! grep -q "^\[ base_sect \]" "$conf_dir/openssl.cnf"; then
              echo "" >> "$conf_dir/openssl.cnf"
              echo "[ base_sect ]" >> "$conf_dir/openssl.cnf"
              echo "activate = 1" >> "$conf_dir/openssl.cnf"
            fi
          done
          echo "FIPS openssl.cnf configured with fips + base providers"
        ''
    }

    echo "OpenSSL modules and config installed to $out/usr/local/cosmian/lib/"

    # Normalize all file timestamps for deterministic builds
    echo "Normalizing timestamps for reproducibility..."
    find "$out" -exec touch --date=@1 {} +

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
