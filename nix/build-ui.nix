{ pkgs ? import <nixpkgs> { }
, stdenv ? pkgs.stdenv
, lib ? pkgs.lib
, features ? [ ] # [ "non-fips" ] or []
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  variant = if isFips then "fips" else "non-fips";

  # Select UI directory based on variant
  uiDir = if isFips then ../crate/server/ui else ../crate/server/ui_non_fips;
  uiExists = builtins.pathExists uiDir;

in
stdenv.mkDerivation {
  pname = "cosmian-kms-ui-${variant}";
  version = "5.11.0";

  # Use a placeholder source if UI doesn't exist
  src = if uiExists then lib.cleanSource uiDir else pkgs.runCommand "empty-ui" {} "mkdir -p $out";

  buildPhase = ''
    # Nothing to build - we expect pre-built UI
    echo "Using pre-built UI from ${uiDir}"
  '';

  installPhase = ''
    mkdir -p $out/dist
    if [ -d "$src" ] && [ "$(ls -A $src 2>/dev/null)" ]; then
      cp -R $src/* $out/dist/ 2>/dev/null || echo "No UI files to copy"
    else
      echo "No pre-built UI found - creating empty placeholder"
      echo "<html><body><h1>KMS UI Not Built</h1><p>Build the UI with: bash .github/scripts/build_ui.sh</p></body></html>" > $out/dist/index.html
    fi
  '';

  meta = with lib; {
    description = "Cosmian KMS Web UI (${variant} variant) - pre-built";
    homepage = "https://github.com/Cosmian/kms";
    platforms = platforms.unix;
  };
}
