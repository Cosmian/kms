{ pkgs ? import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
    sha256 = "1lr1h35prqkd1mkmzriwlpvxcb34kmhc9dnr48gkm8hh089hifmx";
  }) {} }:

let
  isLinux = pkgs.stdenv.isLinux;
  hostGlibc = if isLinux then (pkgs.stdenv.cc.libc.version or (pkgs.lib.getVersion pkgs.stdenv.cc.libc)) else "n/a";
  nixpkgs1903 = builtins.getEnv "NIXPKGS_GLIBC_228_URL";
  pkgs228 = if isLinux && !(pkgs.lib.versionOlder hostGlibc "2.29")
            then import (builtins.fetchTarball { url = if nixpkgs1903 != "" then nixpkgs1903 else "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixos-19.03.tar.gz"; }) {}
            else pkgs;
  openssl312 = pkgs228.callPackage ./nix/openssl-3_1_2-fips.nix {};
in
pkgs228.mkShell {
  name = "cosmian-kms-dev-shell";
  buildInputs = [ pkgs228.pkg-config pkgs228.cmake pkgs228.git pkgs228.rustup pkgs228.curl ]
    ++ (if isLinux then [ pkgs228.gcc pkgs228.binutils ] else [])
    ++ (if pkgs228.stdenv.isDarwin then [ pkgs228.libiconv ] ++ (with pkgs228.darwin.apple_sdk.frameworks; [ SystemConfiguration Security CoreFoundation ]) else [])
    ++ [ openssl312 ];
  shellHook = ''
    export NIX_OPENSSL_OUT="${builtins.toString openssl312}"
    ${if isLinux then ''
      export NIX_CC_BIN="${pkgs228.stdenv.cc}/bin"
      export NIX_BINUTILS_BIN="${pkgs228.binutils}/bin"
      export NIX_BINUTILS_UNWRAPPED_BIN="${(pkgs228.binutils-unwrapped or pkgs228.binutils)}/bin"
      export NIX_GLIBC_LIB="${pkgs228.glibc}/lib"
      export NIX_DYN_LINKER="${pkgs228.glibc}/lib/ld-linux-x86-64.so.2"
    '' else ""}
    source ${./nix/shell-hook.sh}
  '';
}
