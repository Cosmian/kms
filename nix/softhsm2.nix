{
  pkgs ? import <nixpkgs> { },
  # The OpenSSL SoftHSM2 links and runs against. The FIPS variant passes the shared
  # OpenSSL 3.1.2 build (nix/openssl.nix, enableLegacy = false), whose ssl/openssl.cnf
  # activates only the fips + base providers and includes the generated fipsmodule.cnf.
  openssl ? pkgs.openssl,
}:

let
  inherit (pkgs) lib;
in

# Build SoftHSM2 but force the OpenSSL crypto backend to match
# system behavior (libcrypto) and avoid Botan-specific differences
# that break our softhsm2 tests under nix.
#
# SoftHSM2 2.6.x cannot enter FIPS mode itself (`--enable-fips` needs the OpenSSL 1.x
# `FIPS_mode_set`, which OpenSSL 3 no longer has), so the FIPS configuration is applied the
# OpenSSL 3 way: link against exactly `openssl` and run every SoftHSM2 tool with that
# OpenSSL's own `openssl.cnf` and provider directory.
pkgs.softhsm.overrideAttrs (old: {
  configureFlags = (old.configureFlags or [ ]) ++ [
    "--with-crypto-backend=openssl"
    # Without this, configure picks whichever libcrypto comes first among the build inputs.
    "--with-openssl=${openssl}"
  ];

  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.makeWrapper ];

  # Ensure `openssl` is the only OpenSSL on the build path: a second libcrypto (the nixpkgs
  # one) would make the header/library pair, and so the provider set, ambiguous. Botan is
  # dropped as well.
  buildInputs =
    let
      oldInputs = old.buildInputs or [ ];
      isOpenssl = i: lib.hasPrefix "openssl" (lib.getName i);
      kept = lib.filter (i: i != pkgs.botan2 && !(isOpenssl i)) oldInputs;
    in
    lib.unique (kept ++ [ openssl ]);

  # `softhsm2-util` initializes tokens (PIN hashing, key generation) through libcrypto, so
  # it must load the same provider configuration as the PKCS#11 module. `--set` (not
  # `--set-default`): an ambient OPENSSL_CONF activating the default provider must not
  # win over the FIPS one. The module itself is dlopen()ed by the host process, which
  # selects its configuration through the same two variables (see shell.nix).
  postFixup = (old.postFixup or "") + ''
    for tool in $out/bin/*; do
      wrapProgram "$tool" \
        --set OPENSSL_CONF "${openssl}/ssl/openssl.cnf" \
        --set OPENSSL_MODULES "${openssl}/lib/ossl-modules"
    done
  '';
})
