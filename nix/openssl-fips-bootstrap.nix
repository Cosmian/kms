{ pkgs }:

pkgs.stdenv.mkDerivation {
  pname = "openssl-fips-bootstrap";
  version = "1.0.0";

  src = ./openssl-fips-bootstrap.c;

  dontUnpack = true;

  buildInputs = [ ];
  nativeBuildInputs = [ pkgs.pkg-config ];

  installPhase = ''
    mkdir -p $out/lib
    ${pkgs.stdenv.cc.targetPrefix}cc -fPIC -shared -o $out/lib/libopenssl_fips_bootstrap.so "$src"
  '';

  meta = with pkgs.lib; {
    description = "LD_PRELOAD shim to load OpenSSL FIPS/base providers and set default properties";
    license = licenses.mit;
    platforms = platforms.unix;
  };
}
