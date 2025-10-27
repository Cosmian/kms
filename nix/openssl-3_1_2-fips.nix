{ stdenv, lib, fetchurl, perl, coreutils }:

# OpenSSL 3.1.2 built statically with FIPS provider and fipsmodule.cnf generated.
# Output layout mirrors a typical OPENSSL_DIR tree for ease of consumption:
#   $out/bin/openssl
#   $out/include
#   $out/lib/{libcrypto.a,libssl.a}
#   $out/lib/ossl-modules/fips.{so|dylib}
#   $out/ssl/fipsmodule.cnf

let
  glibcVersion = stdenv.cc.libc.version or (lib.getVersion stdenv.cc.libc);
  _ = lib.assertMsg (lib.versionAtMost glibcVersion "2.28")
    ("cosmian_kms OpenSSL derivation requires glibc <= 2.28; detected glibc "
      + glibcVersion + ". Use an older Nixpkgs or compatible environment.");

  # Path to local tarball relative to the Nix expression
  localTarball = ../resources/tarballs/openssl-3.1.2.tar.gz;

  # Expected SHA256 hash of the official OpenSSL 3.1.2 tarball
  expectedHash = "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539";

  # Validate local tarball hash and select source
  opensslSrc = if builtins.pathExists localTarball
    then
      let
        actualHash = builtins.hashFile "sha256" localTarball;
        hashValidation = lib.assertMsg (actualHash == expectedHash)
          ("Local OpenSSL tarball hash mismatch!\n" +
           "Expected: ${expectedHash}\n" +
           "Actual:   ${actualHash}\n" +
           "Please verify the integrity of ${toString localTarball}");
      in
      # Force evaluation of hash validation
      builtins.seq hashValidation localTarball
    else fetchurl {
      url = "https://www.openssl.org/source/old/3.1/openssl-3.1.2.tar.gz";
      # SRI hash pinned from nix fetch (sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk=)
      sha256 = "sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk=";
    };
in stdenv.mkDerivation rec {
  pname = "openssl";
  version = "3.1.2";

  src = opensslSrc;

  # Force evaluation of source path to trigger hash validation early
  passthru.srcPath = toString opensslSrc;

  # We need perl for OpenSSL build system, and coreutils for runtime scripts
  nativeBuildInputs = [ perl coreutils ];

  # Force static libraries and enable FIPS provider
  # We also ensure the platform target is correct (darwin64-arm64-cc on Apple Silicon)
  # Choose OpenSSL build target based on host platform
  target = if stdenv.isDarwin
           then (if stdenv.hostPlatform.isAarch64 then "darwin64-arm64-cc" else "darwin64-x86_64-cc")
           else if stdenv.hostPlatform.isAarch64 then "linux-aarch64"
           else "linux-x86_64";

  soExt = if stdenv.isDarwin then "dylib" else "so";

  configurePhase = ''
    runHook preConfigure
    export CC="${stdenv.cc.targetPrefix}cc"

    echo "Configuring OpenSSL ${version} for target ${target}"
    perl ./Configure \
      no-shared \
      enable-fips \
      --prefix=$out \
      --openssldir=$out/ssl \
      ${target}

  '';

  buildPhase = ''
    runHook preBuild
    make depend
    make -j
  '';

  installPhase = ''
    runHook preInstall
    make -j install

    # Enable FIPS provider in the installed OpenSSL configuration.
    # 1) Include the generated fipsmodule.cnf
    # 2) Activate FIPS by default and define a base provider section
    if [ -f "$out/ssl/openssl.cnf" ]; then
      sed -i.bu "s,# \.include fipsmodule\.cnf,\.include $out/ssl/fipsmodule.cnf," "$out/ssl/openssl.cnf"
      sed -i.bu 's/# activate = 1/activate = 1/' "$out/ssl/openssl.cnf"
      sed -i.bu 's/# fips = fips_sect/fips = fips_sect\nbase = base_sect\n\n[ base_sect ]\nactivate = 1\n/' "$out/ssl/openssl.cnf"
    fi

    # OpenSSL on some Linux targets installs modules under lib64/ossl-modules.
    # Do NOT create symlinks here; Nix fixupPhase will move lib64/* to lib/*.
    # Just detect the actual module path for fipsinstall.
    if [ -f "$out/lib/ossl-modules/fips.${soExt}" ]; then
      moddir="$out/lib/ossl-modules"
    elif [ -f "$out/lib64/ossl-modules/fips.${soExt}" ]; then
      moddir="$out/lib64/ossl-modules"
    else
      moddir="$out/lib/ossl-modules" # default for error message below
    fi
    fips_mod="$moddir/fips.${soExt}"
    if [ ! -f "$fips_mod" ]; then
      echo "FIPS provider module missing at $fips_mod" >&2
      echo "Searched in: $out/lib/ossl-modules and $out/lib64/ossl-modules" >&2
      exit 1
    fi

    # Create ssl dir if not present
    mkdir -p "$out/ssl"
    "$out/bin/openssl" fipsinstall -module "$fips_mod" -out "$out/ssl/fipsmodule.cnf"

    # Sanity checks
    test -x "$out/bin/openssl"

    # Validate presence of static libs in either lib or lib64
    if [ ! -f "$out/lib/libcrypto.a" ] && [ ! -f "$out/lib64/libcrypto.a" ]; then
      echo "Error: Missing libcrypto.a in $out/lib or $out/lib64" >&2
      exit 1
    fi
    if [ ! -f "$out/lib/libssl.a" ] && [ ! -f "$out/lib64/libssl.a" ]; then
      echo "Error: Missing libssl.a in $out/lib or $out/lib64" >&2
      exit 1
    fi
    test -f "$out/ssl/fipsmodule.cnf"

    runHook postInstall
  '';

  # Critical for FIPS: do not strip or patch ELF on the provider module, as it
  # would invalidate the module integrity MAC and break self-tests at runtime.
  dontStrip = true;
  dontPatchELF = true;

  # Provide .pc files in $out/lib/pkgconfig so that pkg-config picks them up
  postInstall = ''
    # OpenSSL's install_sw installs pc files automatically into lib/pkgconfig
    if [ -d "$out/lib/pkgconfig" ]; then
      echo "pkgconfig available at $out/lib/pkgconfig"
    fi
  '';

  # No passthru needed; consumers can use the derivation path as OPENSSL_DIR

  meta = with lib; {
    description = "OpenSSL 3.1.2 (static) with FIPS provider and fipsmodule.cnf";
    homepage = "https://www.openssl.org";
    license = licenses.openssl;
    platforms = platforms.unix;
    maintainers = [];
    longDescription = ''
      Built against glibc <= 2.28 as enforced by the calling shell expression.
    '';
  };
}
