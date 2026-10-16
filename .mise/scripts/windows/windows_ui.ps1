$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true

function Build-UI {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("fips", "non-fips")]
        [string]$Variant = "non-fips"
    )

    Write-Host "Building Cosmian KMS UI ($Variant variant)..."

    # Install wasm32-unknown-unknown target
    Write-Host "Installing wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown

    # Install wasm-bindgen-cli with matching version
    # --locked pins the exact dependency versions shipped with the crate's Cargo.lock,
    # preventing newly published transitive dependencies (e.g. brotli-decompressor v5)
    # from breaking compilation on the current toolchain.
    Write-Host "Installing wasm-bindgen-cli 0.2.108..."
    cargo install wasm-bindgen-cli --version 0.2.108 --locked --force

    # Build WASM package
    Write-Host "Building WASM package..."
    Push-Location crate\clients\wasm

    try {
        # Set the linker for WASM target (Windows uses rust-lld)
        $env:CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "rust-lld"

        # Build the WASM binary with cargo
        if ($Variant -eq "fips") {
            cargo build --release --target wasm32-unknown-unknown
        }
        else {
            cargo build --release --target wasm32-unknown-unknown --features non-fips
        }

        # Create pkg directory
        if (Test-Path "pkg") {
            Remove-Item -Recurse -Force pkg
        }
        New-Item -ItemType Directory -Path pkg | Out-Null

        # Use wasm-bindgen to generate JavaScript bindings
        $wasmPath = "..\..\..\target\wasm32-unknown-unknown\release\cosmian_kms_client_wasm.wasm"
        if (-not (Test-Path $wasmPath)) {
            Write-Error "WASM binary not found at: $wasmPath"
            exit 1
        }

        Write-Host "Running wasm-bindgen..."
        wasm-bindgen --target web --out-dir pkg $wasmPath

        # Create minimal package.json for TypeScript module resolution
        Write-Host "Creating package.json..."
        $packageJson = @"
{
  "name": "cosmian_kms_client_wasm",
  "type": "module",
  "version": "5.28.0",
  "main": "cosmian_kms_client_wasm.js",
  "types": "cosmian_kms_client_wasm.d.ts"
}
"@
        $packageJson | Out-File -FilePath "pkg\package.json" -Encoding utf8 -NoNewline

        # Verify WASM files were created
        if (-not (Test-Path "pkg\cosmian_kms_client_wasm_bg.wasm")) {
            Write-Error "WASM file not found in pkg directory"
            Get-ChildItem pkg
            exit 1
        }

        if (-not (Test-Path "pkg\package.json")) {
            Write-Error "package.json not found in pkg directory"
            Get-ChildItem pkg
            exit 1
        }

        Write-Host "WASM package built successfully"
        Get-ChildItem pkg
    }
    finally {
        Pop-Location
    }

    # Copy WASM artifacts to UI source directory
    Write-Host "Copying WASM package to UI source directory..."
    $wasmPkgDir = "ui\src\wasm\pkg"

    if (Test-Path $wasmPkgDir) {
        Remove-Item -Recurse -Force $wasmPkgDir
    }
    New-Item -ItemType Directory -Path $wasmPkgDir -Force | Out-Null

    Copy-Item -Recurse -Force "crate\clients\wasm\pkg\*" $wasmPkgDir

    # Verify copy succeeded
    if (-not (Test-Path "$wasmPkgDir\cosmian_kms_client_wasm_bg.wasm")) {
        Write-Error "WASM file not found after copy to UI directory"
        Get-ChildItem $wasmPkgDir
        exit 1
    }

    if (-not (Test-Path "$wasmPkgDir\package.json")) {
        Write-Error "package.json not found after copy to UI directory"
        Get-ChildItem $wasmPkgDir
        exit 1
    }

    Write-Host "WASM artifacts copied successfully"

    # Build UI
    Write-Host "Building UI..."
    Push-Location ui

    try {
        # Verify WASM files are accessible
        if (-not (Test-Path "src\wasm\pkg\cosmian_kms_client_wasm_bg.wasm")) {
            Write-Error "WASM files not accessible from UI directory"
            Get-ChildItem src\wasm\pkg
            exit 1
        }

        # pnpm only: npm would ignore pnpm-lock.yaml and the ui/.npmrc supply-chain policy.
        if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
            Write-Error "pnpm not found on PATH. Run 'corepack enable pnpm' (Node.js 22)."
            exit 1
        }
        $packageManager = "pnpm"

        # Install dependencies
        Write-Host "Installing dependencies with $packageManager..."
        & $packageManager install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) {
            Write-Error "$packageManager install failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }

        # Build the UI (WASM already built above; only run the Vite/tsc step)
        Write-Host "Running $packageManager build:vite..."
        & $packageManager run build:vite

        # Verify dist directory was created
        if (-not (Test-Path "dist")) {
            Write-Error "UI dist directory not found after build"
            Get-ChildItem .
            exit 1
        }

        Write-Host "UI built successfully"
        Get-ChildItem dist
    }
    finally {
        Pop-Location
    }

    Write-Host "UI build completed successfully!"
}

# Example usage:
# Build-UI -Variant non-fips
# Build-UI -Variant fips
