{ stdenv, lib, fetchurl, perl, coreutils }:

# OpenSSL 3.1.2 built statically with FIPS provider and fipsmodule.cnf generated.
# Output layout mirrors a typical OPENSSL_DIR tree for ease of consumption:
#   $out/bin/openssl
#   $out/include
#   $out/lib/{libcrypto.a,libssl.a}
#   $out/lib/ossl-modules/fips.{so|dylib}
#   $out/ssl/fipsmodule.cnf

stdenv.mkDerivation rec {
  pname = "openssl";
  version = "3.1.2";

  src = fetchurl {
    url = "https://www.openssl.org/source/old/3.1/openssl-${version}.tar.gz";
    # SRI hash pinned from nix fetch (sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk=)
    sha256 = "sha256-oM5puLl+pqNblodSNapFO5Zro8uory3iNlfYtnZ9ZTk=";
  };

  # We need perl for OpenSSL build system, and coreutils for runtime scripts
  nativeBuildInputs = [ perl coreutils ];

  # Force static libraries and enable FIPS provider
  # We also ensure the platform target is correct (darwin64-arm64-cc on Apple Silicon)
  # Choose OpenSSL build target based on host platform
  target = if stdenv.isDarwin then (if stdenv.hostPlatform.parsed.cpu == "aarch64" then "darwin64-arm64-cc" else "darwin64-x86_64-cc")
           else if stdenv.hostPlatform.parsed.cpu == "aarch64" then "linux-aarch64"
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
    : "Use available parallelism if provided by Nix"
    if [ -z "$NIX_BUILD_CORES" ]; then export NIX_BUILD_CORES=4; fi
    make -j"$NIX_BUILD_CORES"
  '';

  installPhase = ''
    runHook preInstall
    make install_sw
    # Explicitly install the FIPS provider module and its config
    make install_fips || true

    # Generate fipsmodule.cnf using the built openssl and installed fips module
    fips_mod="$out/lib/ossl-modules/fips.${soExt}"
    if [ ! -f "$fips_mod" ]; then
      echo "FIPS provider module missing at $fips_mod" >&2
      exit 1
    fi

    # Create ssl dir if not present
    mkdir -p "$out/ssl"
    "$out/bin/openssl" fipsinstall -module "$fips_mod" -out "$out/ssl/fipsmodule.cnf"

    # Sanity checks
    test -x "$out/bin/openssl"
    test -f "$out/lib/libcrypto.a"
    test -f "$out/lib/libssl.a"
    test -f "$out/ssl/fipsmodule.cnf"

    runHook postInstall
  '';

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
  };
}
