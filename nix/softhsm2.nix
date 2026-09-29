{
  pkgs ? import <nixpkgs> { },
  openssl ? pkgs.openssl,
}:

let
  inherit (pkgs) lib;
in

# Build SoftHSM2 but force the OpenSSL crypto backend to match
# system behavior (libcrypto) and avoid Botan-specific differences
# that break our softhsm2 tests under nix.
pkgs.softhsm.overrideAttrs (old: {
  configureFlags = (old.configureFlags or [ ]) ++ [
    "--with-crypto-backend=openssl"
  ];

  # Ensure OpenSSL is available and try to avoid pulling Botan alongside it.
  buildInputs =
    let
      oldInputs = old.buildInputs or [ ];
      withoutBotan = lib.filter (i: i != pkgs.botan2) oldInputs;
    in
    lib.unique (withoutBotan ++ [ openssl ]);
})
