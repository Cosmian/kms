$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
# Shared helpers (Invoke-Native, Read-DotEnv, Get-WorkspaceVersion, ...). Note that
# $PSNativeCommandUseErrorActionPreference is PS 7.3+ only: Invoke-Native checks exit codes
# explicitly, which works in both PowerShell 5.1 and 7.
. (Join-Path $PSScriptRoot "common.ps1")

# Usage (from the repository root):
#   . .\.mise\scripts\windows\cargo_build.ps1
#   BuildProject [-Variant non-fips|fips]
#
# non-fips: server + ckms CLI (with the PKCS#11 and CNG DLLs) installers.
# fips:     server installer only; it ships the OpenSSL FIPS provider (see New-PackageOpensslDir).

# Environment setup: pin volumes to the workspace drive, toolchain, static OpenSSL.
function Initialize-BuildEnvironment {
    # GitHub Actions Windows runners may have workspace on D: while CARGO_HOME
    # defaults to C: (via HOME).  C: has limited free space (~14 GB total, ~2 GB
    # free) and cargo-packager downloads NSIS (~3 MB base + plugins) into the
    # cargo cache.  Pinning CARGO_HOME to the workspace volume avoids filling up
    # the system drive and makes the build work regardless of whether
    # GITHUB_WORKSPACE is on C: or D:.
    $workspaceDrive = (Get-Location).Drive.Name
    $env:CARGO_HOME = "${workspaceDrive}:\cargo_home"
    # Ensure cargo-installed binaries (cargo-packager) are on PATH
    $env:PATH = "$env:CARGO_HOME\bin;$env:PATH"
    Write-Host "CARGO_HOME=$env:CARGO_HOME"

    # Fix TMP/TEMP to valid Windows paths.  The GHA runner shell (Git Bash)
    # sets TMP=TEMP=/tmp, which PowerShell and native Windows tools (incl.
    # cargo-packager via GetTempPathW) cannot resolve to a real directory.
    $windowsTemp = "${workspaceDrive}:\Temp"
    if (-not (Test-Path $windowsTemp)) {
        New-Item -ItemType Directory -Path $windowsTemp -Force | Out-Null
    }
    $env:TMP = $windowsTemp
    $env:TEMP = $windowsTemp
    Write-Host "TMP=$env:TMP TEMP=$env:TEMP"

    # Add target - rustup exits 1 when the target is already installed.
    try {
        Invoke-Native "rustup" @("target", "add", "x86_64-pc-windows-msvc")
    }
    catch {
        Write-Host "Note: $_ (target is likely already installed)"
    }

    # OpenSSL (static, from vcpkg): manifest-mode path first, then classic mode.
    $openSslDir = Resolve-OpenSslDir
    if (-not $openSslDir) { throw "OPENSSL_DIR not found: neither vcpkg_installed nor VCPKG_INSTALLATION_ROOT/VCPKG_ROOT is available" }
    $env:OPENSSL_DIR = $openSslDir
    Write-Host "OPENSSL_DIR=$env:OPENSSL_DIR"
    if (-not (Test-Path $env:OPENSSL_DIR)) {
        throw "OPENSSL_DIR not found: $env:OPENSSL_DIR"
    }
    Get-ChildItem $env:OPENSSL_DIR
}

# cargo-packager - install only when the installed version differs.
function Install-CargoPackager {
    $requiredPackagerVersion = "0.11.7"
    $installedVersion = $null
    try {
        $verLine = & cargo packager --version 2>&1 | Select-Object -First 1
        if ($verLine -match "cargo-packager\s+(\S+)") { $installedVersion = $Matches[1] }
    }
    catch { }

    if ($installedVersion -ne $requiredPackagerVersion) {
        Write-Host "Installing cargo-packager $requiredPackagerVersion (found: '$installedVersion')..."
        Invoke-Native "cargo" @("install", "--version", $requiredPackagerVersion, "cargo-packager", "--locked")
    }
    else {
        Write-Host "cargo-packager $requiredPackagerVersion already installed - skipping."
    }
}

# Build all binaries from the workspace root.
function Build-Binaries {
    param([ValidateSet("non-fips", "fips")][string]$Variant)
    if ($Variant -eq "fips") {
        # Default features = FIPS. No CLI, PKCS#11 or CNG in the FIPS installer.
        Invoke-Native "cargo" @("build", "--release", "--package", "cosmian_kms_server")
        return
    }
    # Server needs --no-default-features; PKCS#11 DLL and ckms CLI keep defaults.
    Invoke-Native "cargo" @("build", "--release", "--package", "cosmian_kms_server", "--features", "non-fips", "--no-default-features")
    Invoke-Native "cargo" @("build", "--release", "--package", "cosmian_pkcs11", "--package", "ckms", "--features", "non-fips")
    # CNG KSP DLL (bundled into the ckms NSIS installer via cargo-packager)
    Invoke-Native "cargo" @("build", "--release", "--package", "cosmian_cng", "--features", "non-fips")
}

# Verify no dynamic OpenSSL dependency in the server binary.
function Assert-StaticOpenSsl {
    $dumpbin = Find-Dumpbin
    if ($dumpbin) {
        Write-Host "Using dumpbin: $dumpbin"
        $dynamicLibs = & $dumpbin /dependents target\release\cosmian_kms.exe 2>&1
        if ($dynamicLibs | Select-String "libcrypto") {
            throw "OpenSSL (libcrypto) found in dynamic dependencies of cosmian_kms - build must link OpenSSL statically."
        }
        Write-Host "OK: cosmian_kms.exe has no dynamic libcrypto dependency."
    }
    else {
        Write-Warning "dumpbin.exe not found - skipping dynamic-link check."
    }
}

# Stage target\windows-package-openssl, the `openssl/` resource of the server installer
# (crate/server/Cargo.toml). It always holds variant.txt; the FIPS variant adds the relocatable
# OpenSSL FIPS provider setup. It must exist before New-Installers (the packager copies it).
function New-PackageOpensslDir {
    param([ValidateSet("non-fips", "fips")][string]$Variant, [string]$OutDir = "target\windows-package-openssl")
    if (Test-Path -LiteralPath $OutDir) { Remove-Item -Recurse -Force -LiteralPath $OutDir }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    Set-Content -Encoding ASCII -LiteralPath (Join-Path $OutDir "variant.txt") -Value $Variant
    if ($Variant -ne "fips") { return }

    # Builds fips.dll in C:\openssl-fips and writes .openssl-fips\env; idempotent.
    & (Join-Path $PSScriptRoot "prepare_windows_fips_provider.ps1")
    $fipsEnv = Read-DotEnv ".openssl-fips\env"
    $sslDir = Join-Path $OutDir "ssl"
    $modulesDir = Join-Path $OutDir "ossl-modules"
    New-Item -ItemType Directory -Force -Path $sslDir, $modulesDir | Out-Null

    Copy-Item -LiteralPath (Join-Path $fipsEnv["OPENSSL_MODULES"] "fips.dll") -Destination $modulesDir
    Copy-Item -LiteralPath (Join-Path (Split-Path $fipsEnv["OPENSSL_CONF"]) "fipsmodule.cnf") -Destination $sslDir

    # The provider's openssl.cnf includes fipsmodule.cnf by absolute build path: make it relative
    # (resolved through OPENSSL_CONF_INCLUDE) so that it works wherever the installer puts it.
    $includePattern = '(?m)^\.include[ \t]+.*fipsmodule\.cnf(?=[ \t]*\r?$)'
    $cnf = Get-Content -Raw -LiteralPath $fipsEnv["OPENSSL_CONF"]
    if ($cnf -notmatch $includePattern) { throw "no '.include ...fipsmodule.cnf' line in $($fipsEnv['OPENSSL_CONF'])" }
    $cnf = $cnf -replace $includePattern, ".include fipsmodule.cnf"
    Set-Content -Encoding ASCII -LiteralPath (Join-Path $sslDir "openssl.cnf") -Value $cnf

    # Console launcher: the service gets the same variables from the registry (installer.nsi).
    $launcher = @(
        "@echo off",
        "set `"KMS_HOME=%~dp0..`"",
        "set `"OPENSSL_CONF=%KMS_HOME%\openssl\ssl\openssl.cnf`"",
        "set `"OPENSSL_MODULES=%KMS_HOME%\openssl\ossl-modules`"",
        "set `"OPENSSL_CONF_INCLUDE=%KMS_HOME%\openssl\ssl`"",
        "`"%KMS_HOME%\cosmian_kms.exe`" %*"
    ) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path (Resolve-Path $OutDir).Path "cosmian_kms_fips.cmd"), "$launcher`r`n", [System.Text.Encoding]::ASCII)
    Write-Host "Staged the OpenSSL FIPS provider package in $OutDir"
    Get-ChildItem -Recurse $OutDir | ForEach-Object { Write-Host $_.FullName }
}

# Rename the cargo-packager outputs to cosmian-kms-{server,cli}-<variant>-static-openssl_<ver>_x86_64.exe
# (cargo-packager names them after the binary: cosmian_kms_{version}_{arch}-setup.exe).
function Rename-Installers {
    param([ValidateSet("non-fips", "fips")][string]$Variant)
    $version = Get-WorkspaceVersion
    $arch = "x86_64"
    $servers = @(Get-ChildItem -Path "target\release" -Filter "cosmian_kms_*setup.exe")
    if ($servers.Count -eq 0) { throw "no server installer (cosmian_kms_*setup.exe) found in target\release" }
    foreach ($file in $servers) {
        $newName = "cosmian-kms-server-$Variant-static-openssl_${version}_${arch}.exe"
        Move-Item -Force $file.FullName (Join-Path $file.DirectoryName $newName)
        Write-Host "Renamed $($file.Name) -> $newName"
    }
    if ($Variant -ne "non-fips") { return }
    foreach ($file in @(Get-ChildItem -Path "target\release" -Filter "ckms*setup.exe")) {
        $newName = "cosmian-kms-cli-non-fips-static-openssl_${version}_${arch}.exe"
        Move-Item -Force $file.FullName (Join-Path $file.DirectoryName $newName)
        Write-Host "Renamed $($file.Name) -> $newName"
    }
}

# Package the NSIS installers and give them their final names.
function New-Installers {
    param([ValidateSet("non-fips", "fips")][string]$Variant)
    Invoke-Native "cargo" @("packager", "--verbose", "--formats", "nsis", "--release", "--packages", "cosmian_kms_server")
    Get-ChildItem -Path "target\release" -Filter "cosmian_kms*setup.exe" | ForEach-Object {
        Write-Host "Server installer: $($_.Name)"
    }

    if ($Variant -eq "non-fips") {
        # Copy DLLs where cargo-packager looks for them (relative to ckms crate)
        New-Item -ItemType Directory -Path "crate\clients\ckms\target\release" -Force | Out-Null
        Copy-Item -Force "target\release\cosmian_pkcs11.dll" "crate\clients\ckms\target\release\cosmian_pkcs11.dll"
        Copy-Item -Force "target\release\cosmian_cng.dll" "crate\clients\ckms\target\release\cosmian_cng.dll"
        Write-Host "Copied cosmian_pkcs11.dll and cosmian_cng.dll to crate\clients\ckms\target\release\"

        Invoke-Native "cargo" @("packager", "--verbose", "--formats", "nsis", "--release", "--packages", "ckms")
        Get-ChildItem -Path "target\release" -Filter "ckms*setup.exe" | ForEach-Object {
            Write-Host "CLI installer: $($_.Name)"
        }
    }

    Rename-Installers -Variant $Variant
}

function BuildProject {
    param([ValidateSet("non-fips", "fips")][string]$Variant = "non-fips")
    Initialize-BuildEnvironment
    Install-CargoPackager
    Build-Binaries -Variant $Variant
    Assert-StaticOpenSsl
    New-PackageOpensslDir -Variant $Variant
    New-Installers -Variant $Variant
}
