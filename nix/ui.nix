{
  pkgs ? import <nixpkgs> { },
  stdenv ? pkgs.stdenv,
  lib ? pkgs.lib,
  # KMS version (from Cargo.toml)
  version,
  features ? [ ], # [ "non-fips" ] or []
  rustToolchain ? null, # Optional custom Rust toolchain (e.g., 1.90.0 for edition2024 support)
  # Allow callers to bypass strict enforcement for NPM deps hash discovery
  enforceDeterministicHash ? false,
}:

let
  # Normalize features: accept list or space-separated string; default to []
  featuresList =
    if builtins.isList features then
      features
    else if builtins.isString features then
      lib.filter (s: s != "") (lib.splitString " " features)
    else
      [ ];

  # Determine variant from features only
  derivedIsFips = !(builtins.elem "non-fips" featuresList);
  finalVariant = if derivedIsFips then "fips" else "non-fips";
  isFips = derivedIsFips;

  # Determine cargo vendor hash for building the WASM crate via external file
  actualCargoHash =
    let
      placeholder = "sha256-CCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      hashFile = ../nix/expected-hashes + "/ui.vendor." + finalVariant + ".sha256";
    in
    if builtins.pathExists hashFile then
      let
        raw = builtins.readFile hashFile;
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
      in
      if enforceDeterministicHash then
        (
          assert trimmed != placeholder && trimmed != "";
          trimmed
        )
      else
        trimmed
    else if enforceDeterministicHash then
      builtins.throw ("Expected UI vendor cargo hash file not found: " + hashFile)
    else
      placeholder;

  # Filter source to exclude large directories
  sourceFilter =
    path: _type:
    let
      baseName = baseNameOf path;
      relPath = lib.removePrefix (toString ../. + "/") (toString path);
    in
    # Exclude target, node_modules, and other large directories
    # BUT include ui/src/wasm directory structure (even if pkg is gitignored)
    !(lib.hasPrefix "target/" relPath)
    && !(lib.hasPrefix "result" relPath)
    && !(lib.hasPrefix "ui/node_modules/" relPath)
    && !(lib.hasPrefix "ui/dist/" relPath)
    && !(lib.hasPrefix ".git/" relPath)
    && baseName != "node_modules"
    && baseName != "target"
    && baseName != "dist";

  # Select rust platform (allow override). If a concrete toolchain is provided,
  # construct a rustPlatform from it to ensure Cargo 1.90 (edition2024) support.
  rustPlatform =
    if rustToolchain != null then
      pkgs.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      }
    else
      pkgs.rustPlatform;

  # Build a matching wasm-bindgen-cli to the version used by the crates
  wasmBindgenCli = rustPlatform.buildRustPackage rec {
    pname = "wasm-bindgen-cli";
    version = "0.2.106";

    src = pkgs.fetchCrate {
      inherit pname version;
      sha256 = "sha256-M6WuGl7EruNopHZbqBpucu4RWz44/MSdv6f0zkYw+44=";
    };

    cargoHash = "sha256-/zJzxtzOZuGyvDLdJNEQFPzFHC6IbEiWOeZYrKgGxEk=";
    doCheck = false;
  };

  # Build the WASM crate from source to avoid relying on prebuilt ui/src/wasm/pkg
  wasmPkg = rustPlatform.buildRustPackage {
    pname = "cosmian-kms-ui-wasm-${finalVariant}";
    inherit version;

    # Build from the whole workspace so path dependencies resolve
    src = lib.cleanSourceWith {
      src = ../.;
      filter = sourceFilter;
      name = "source";
    };

    # Ensure reproducible cargo vendoring
    cargoHash = actualCargoHash;

    # Disable cargo-auditable wrapper which doesn't support Rust 2024 yet
    auditable = false;

    # Build only the wasm client crate for the web target
    # Force target via flags to override default host target
    cargoBuildFlags = [
      "--target"
      "wasm32-unknown-unknown"
      "-p"
      "cosmian_kms_client_wasm"
    ];
    buildFeatures = lib.optionals (!isFips) [ "non-fips" ];

    preBuild = ''
      if [ -n "$RUSTC_WRAPPER" ]; then
        echo "Disabling RUSTC_WRAPPER ($RUSTC_WRAPPER) for WASM build"
        unset RUSTC_WRAPPER
      fi
      if [ -n "$RUSTC_WORKSPACE_WRAPPER" ]; then
        echo "Disabling RUSTC_WORKSPACE_WRAPPER ($RUSTC_WORKSPACE_WRAPPER) for WASM build"
        unset RUSTC_WORKSPACE_WRAPPER
      fi
    '';

    # We generate the JS glue with wasm-bindgen-cli after cargo build
    nativeBuildInputs = [
      wasmBindgenCli
      pkgs.llvmPackages.lld
    ];
    # Ensure wasm linking uses lld provided by Nix
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "${pkgs.llvmPackages.lld}/bin/wasm-ld";
    doCheck = false;

    # Override build phase to fully bypass cargo-auditable wrappers
    buildPhase = ''
      runHook preBuild
      unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
      FEAT_ARGS='${lib.optionalString (!isFips) "--features non-fips"}'
      ${lib.optionalString (!isFips) ''
        echo "Building WASM crate (variant=${finalVariant}) with non-fips features";
      ''}
      ${lib.optionalString isFips ''
        echo "Building WASM crate (variant=${finalVariant}) in FIPS mode (no non-fips features)";
      ''}
      echo cargo build -j $(nproc) --frozen --profile release --target wasm32-unknown-unknown -p cosmian_kms_client_wasm $FEAT_ARGS
      cargo build -j $(nproc) --frozen --profile release --target wasm32-unknown-unknown -p cosmian_kms_client_wasm $FEAT_ARGS
      runHook postBuild
    '';

    installPhase = ''
      set -euo pipefail
      mkdir -p $out/pkg
      # Wasm artifact produced by cargo
      WASM_PATH=target/wasm32-unknown-unknown/release/cosmian_kms_client_wasm.wasm
      if [ ! -f "$WASM_PATH" ]; then
        echo "ERROR: Wasm artifact not found at $WASM_PATH" >&2
        find target -name '*.wasm' -maxdepth 6 -print || true
        exit 1
      fi
      # Generate JS glue consumable by Vite
      wasm-bindgen \
        --target web \
        --typescript \
        --out-dir $out/pkg \
        "$WASM_PATH"

      # Basic sanity check
      test -f "$out/pkg/cosmian_kms_client_wasm_bg.wasm"
      test -f "$out/pkg/cosmian_kms_client_wasm.js"
      test -f "$out/pkg/cosmian_kms_client_wasm.d.ts"
    '';
  };

  # Build the UI using buildNpmPackage for proper dependency management
  uiBuild = pkgs.buildNpmPackage {
    pname = "cosmian-kms-ui-deps-${finalVariant}";
    inherit version;

    src = lib.cleanSourceWith {
      src = ../ui;
      filter =
        path: _type:
        let
          baseName = baseNameOf path;
        in
        baseName != "node_modules" && baseName != "dist";
    };

    # Read NPM dependencies hash from external file
    npmDepsHash =
      let
        placeholder = "sha256-DDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        hashFile = ../nix/expected-hashes + "/ui.npm.sha256";
      in
      if builtins.pathExists hashFile then
        let
          raw = builtins.readFile hashFile;
          trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
        in
        if enforceDeterministicHash then
          (
            assert trimmed != placeholder && trimmed != "";
            trimmed
          )
        else
          trimmed
      else if enforceDeterministicHash then
        builtins.throw ("Expected UI npm deps hash file not found: " + hashFile)
      else
        placeholder;

    # Disable build phase - we only want dependencies installed
    dontBuild = true;

    installPhase = ''
      mkdir -p $out
      cp -r node_modules $out/
      cp package*.json $out/
    '';
  };

in
stdenv.mkDerivation {
  pname = "cosmian-kms-ui-${finalVariant}";
  inherit version;

  # Build from source with filtering (name = null disables gitignore filtering)
  src = lib.cleanSourceWith {
    src = ../.;
    filter = sourceFilter;
    name = "source";
  };

  # Vite requires Node >= 20.19; use a recent Node to avoid warnings
  nativeBuildInputs = with pkgs; [ nodejs_22 ];

  buildPhase = ''
      export HOME=$TMPDIR

      # Build UI with pre-fetched dependencies
      cd ui

      # Copy pre-installed node_modules with write permissions
      cp -r ${uiBuild}/node_modules .
      chmod -R u+w node_modules

      # Replace any checked-in prebuilt pkg with freshly built WASM from Nix
      rm -rf src/wasm/pkg
      mkdir -p src/wasm
      cp -r ${wasmPkg}/pkg src/wasm/pkg
      # Basic sanity check
      test -f src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm
      # Ensure pkg directory is writable for shims
      chmod -R u+w src/wasm/pkg
      # Add a package.json and index shim so imports from "./wasm/pkg" resolve
      cat > src/wasm/pkg/package.json << 'EOF'
    {
      "name": "cosmian-kms-client-wasm-pkg",
      "private": true,
      "module": "./cosmian_kms_client_wasm.js",
      "types": "./cosmian_kms_client_wasm.d.ts"
    }
    EOF
      cat > src/wasm/pkg/index.ts << 'EOF'
    export * from "./cosmian_kms_client_wasm";
    import init from "./cosmian_kms_client_wasm";
    export default init;
    EOF
      cat > src/wasm/pkg/index.d.ts << 'EOF'
    export * from "./cosmian_kms_client_wasm";
    import init from "./cosmian_kms_client_wasm";
    export default init;
    EOF

      # Avoid depending on pnpm being present in the Nix build env.
      # Use npm directly to run TypeScript + Vite build.
      npm run build

      # Return to root directory after build
      cd ..
  '';

  installPhase = ''
    mkdir -p $out/dist
    # Copy all files from ui/dist to $out/dist
    if [ -d ui/dist ]; then
      echo "Installing UI dist to $out/dist"
      cp -r ui/dist/. $out/dist/
      echo "UI installation complete. Contents of $out/dist:"
      ls -la $out/dist/ || true
      # Verify critical files exist
      if [ ! -f "$out/dist/index.html" ]; then
        echo "ERROR: index.html not found in UI dist"
        exit 1
      fi
      echo "UI build verification successful"
    else
      echo "Error: ui/dist directory not found after npm build"
      echo "Current directory: $(pwd)"
      echo "Looking for dist directories:"
      find . -name dist -type d || true
      echo "Contents of ui directory:"
      ls -la ui/ || true
      exit 1
    fi
  '';

  meta = with lib; {
    description = "Cosmian KMS Web UI (${finalVariant} variant)";
    homepage = "https://github.com/Cosmian/kms";
    platforms = platforms.unix;
  };
}
