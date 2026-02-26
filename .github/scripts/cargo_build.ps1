$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
# Note: $PSNativeCommandUseErrorActionPreference is PS 7.3+ only.
# We use Invoke-NativeCommand below which handles exit codes explicitly and
# works correctly in both PowerShell 5.1 and 7.

# ---------------------------------------------------------------------------
# Helper: run a native command, stream its output, and throw on non-zero exit.
# Works in both PS 5.1 and PS 7:
#   - PS 5.1 sends native stderr to the error stream as ErrorRecord objects.
#     Setting $ErrorActionPreference = "Continue" locally prevents termination
#     while still letting cargo/rustup output flow through normally.
#   - PS 7 does not have this issue; Continue is still harmless there.
#   - Exit code is always checked explicitly after the command.
# ---------------------------------------------------------------------------
function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(ValueFromRemainingArguments)][string[]] $Arguments
    )
    # Override locally so native stderr does not trigger $ErrorActionPreference = "Stop"
    $ErrorActionPreference = "Continue"
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Exe $($Arguments -join ' ')' failed with exit code $LASTEXITCODE"
    }
}

function BuildProject
{
    # -------------------------------------------------------------------------
    # Toolchain
    # -------------------------------------------------------------------------

    # Add target - rustup exits 1 when the target is already installed.
    try {
        Invoke-NativeCommand rustup target add x86_64-pc-windows-msvc
    } catch {
        Write-Host "Note: $_ (target is likely already installed)"
    }

    # -------------------------------------------------------------------------
    # OpenSSL (static, from vcpkg)
    # CI sets VCPKG_INSTALLATION_ROOT; local dev sets VCPKG_ROOT
    # -------------------------------------------------------------------------
    $vcpkgRoot = if ($env:VCPKG_INSTALLATION_ROOT) { $env:VCPKG_INSTALLATION_ROOT } `
                 elseif ($env:VCPKG_ROOT)            { $env:VCPKG_ROOT } `
                 else { throw "Neither VCPKG_INSTALLATION_ROOT nor VCPKG_ROOT is set" }
    $env:OPENSSL_DIR = "$vcpkgRoot\packages\openssl_x64-windows-static"
    Write-Host "OPENSSL_DIR=$env:OPENSSL_DIR"
    if (-not (Test-Path $env:OPENSSL_DIR)) {
        throw "OPENSSL_DIR not found: $env:OPENSSL_DIR"
    }
    Get-ChildItem $env:OPENSSL_DIR

    # -------------------------------------------------------------------------
    # cargo-packager - install only when the installed version differs
    # -------------------------------------------------------------------------
    $requiredPackagerVersion = "0.11.7"
    $installedVersion = $null
    try {
        $verLine = & cargo packager --version 2>&1 | Select-Object -First 1
        if ($verLine -match "cargo-packager\s+(\S+)") { $installedVersion = $Matches[1] }
    } catch { }

    if ($installedVersion -ne $requiredPackagerVersion) {
        Write-Host "Installing cargo-packager $requiredPackagerVersion (found: '$installedVersion')..."
        Invoke-NativeCommand cargo install --version $requiredPackagerVersion cargo-packager --locked
    } else {
        Write-Host "cargo-packager $requiredPackagerVersion already installed - skipping."
    }

    # -------------------------------------------------------------------------
    # Build all binaries from workspace root
    # -------------------------------------------------------------------------
    # Server needs --no-default-features; PKCS#11 DLL and ckms CLI keep defaults.
    Invoke-NativeCommand cargo build --release --package cosmian_kms_server --features "non-fips" --no-default-features
    Invoke-NativeCommand cargo build --release --package cosmian_pkcs11 --package ckms --features "non-fips"

    # -------------------------------------------------------------------------
    # Package server NSIS installer
    # -------------------------------------------------------------------------
    Invoke-NativeCommand cargo packager --verbose --formats nsis --release --packages cosmian_kms_server

    Get-ChildItem -Path "target\release" -Filter "cosmian_kms*setup.exe" | ForEach-Object {
        Write-Host "Server installer: $($_.Name)"
    }

    # -------------------------------------------------------------------------
    # Verify no dynamic OpenSSL dependency in the server binary
    # -------------------------------------------------------------------------
    $dumpbin = $null

    # 1. Try vswhere (available on GitHub Actions and most VS 2022 installs)
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($vsPath) {
            $dumpbin = Get-ChildItem -Recurse "$vsPath\VC\Tools\MSVC" -Filter "dumpbin.exe" `
                           -ErrorAction SilentlyContinue |
                       Where-Object { $_.FullName -like "*HostX64\x64*" } |
                       Select-Object -First 1 -ExpandProperty FullName
        }
    }

    # 2. Fallback: search under the standard VS 2022 install path
    if (-not $dumpbin) {
        $dumpbin = Get-ChildItem -Recurse "C:\Program Files\Microsoft Visual Studio\2022" `
                       -Filter "dumpbin.exe" -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -like "*HostX64\x64*" } |
                   Select-Object -First 1 -ExpandProperty FullName
    }

    if ($dumpbin) {
        Write-Host "Using dumpbin: $dumpbin"
        $dynamicLibs = & $dumpbin /dependents target\release\cosmian_kms.exe 2>&1
        if ($dynamicLibs | Select-String "libcrypto") {
            throw "OpenSSL (libcrypto) found in dynamic dependencies of cosmian_kms - build must link OpenSSL statically."
        }
        Write-Host "OK: cosmian_kms.exe has no dynamic libcrypto dependency."
    } else {
        Write-Warning "dumpbin.exe not found - skipping dynamic-link check."
    }

    # -------------------------------------------------------------------------
    # Package ckms CLI NSIS installer
    # -------------------------------------------------------------------------
    # Copy the PKCS#11 DLL where cargo-packager looks for it (relative to ckms crate)
    New-Item -ItemType Directory -Path "crate\clients\ckms\target\release" -Force | Out-Null
    Copy-Item -Force "target\release\cosmian_pkcs11.dll" "crate\clients\ckms\target\release\cosmian_pkcs11.dll"
    Write-Host "Copied cosmian_pkcs11.dll to crate\clients\ckms\target\release\"

    Invoke-NativeCommand cargo packager --verbose --formats nsis --release --packages ckms

    Get-ChildItem -Path "target\release" -Filter "ckms*setup.exe" | ForEach-Object {
        Write-Host "CLI installer: $($_.Name)"
    }

    exit 0
}


# Example usage:
# BuildProject
