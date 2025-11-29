{
  pkgs ? import <nixpkgs> { },
  stdenv ? pkgs.stdenv,
  lib ? pkgs.lib,
  features ? [ ], # [ "non-fips" ] or []
  rustToolchain ? null, # Optional custom Rust toolchain (e.g., 1.90.0 for edition2024 support)
  # Cargo vendor hash for the workspace used to build the WASM crate
  # Different hashes for fips vs non-fips due to different crypto dependencies
  cargoHash ? null,
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  variant = if isFips then "fips" else "non-fips";

  # Determine cargo hash for building the WASM crate
  actualCargoHash =
    if cargoHash != null then
      cargoHash
    else if isFips then
      # Updated vendor hash for WASM/UI FIPS build
      "sha256-3t531rxDX6syyUCguKax8hv+L7rFTBVeNlypcDZSndg="
    else
      # Updated vendor hash for WASM/UI non-FIPS build (previous mismatch fixed)
      "sha256-JzLOE+jQn1qHfJJ9+QZXqCZxH9oS3R5YWchZBFKEctg=";

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
    pname = "cosmian-kms-ui-wasm-${variant}";
    version = "5.12.1";

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
      cargo build -j $(nproc) --frozen --profile release --target wasm32-unknown-unknown -p cosmian_kms_client_wasm
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
    pname = "cosmian-kms-ui-deps-${variant}";
    version = "5.12.0";

    src = lib.cleanSourceWith {
      src = ../ui;
      filter =
        path: _type:
        let
          baseName = baseNameOf path;
        in
        baseName != "node_modules" && baseName != "dist";
    };

    # TODO: Update this hash when dependencies change
    # Run with an empty string to get the correct hash
    npmDepsHash = "sha256-vs6HY6anfQ0X6jRZkl5nJxnLlp5a/XKvjEEviFNOp6I=";

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
  pname = "cosmian-kms-ui-${variant}";
  version = "5.12.0";

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
    description = "Cosmian KMS Web UI (${variant} variant)";
    homepage = "https://github.com/Cosmian/kms";
    platforms = platforms.unix;
  };
}
