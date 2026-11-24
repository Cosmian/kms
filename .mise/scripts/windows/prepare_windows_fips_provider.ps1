<#
.SYNOPSIS
  Build the OpenSSL FIPS provider (fips.dll) on Windows and stage it for the KMS.

.DESCRIPTION
  The KMS loads the CMVP-validated OpenSSL FIPS provider at runtime next to a newer
  libcrypto (see crate/crypto/build.rs, which does the same on Linux/macOS). On Windows the
  KMS links the vcpkg OpenSSL, which ships no FIPS module, so this script:
    1. downloads the pinned FIPS provider tarball (crate/crypto/openssl_versions.json, as crate/crypto/build.rs),
    2. builds fips.dll with `Configure VC-WIN64A enable-fips no-shared no-asm` + nmake
       (Visual Studio environment located through vswhere / vcvars64.bat),
    3. runs `nmake install_fips install_ssldirs`, then regenerates fipsmodule.cnf with
       `openssl fipsinstall -self_test_oninstall` (the defaults, as the Nix release packages):
       `install_fips` writes the pedantic config of util/mk-fipsmodule-cnf.pl, which refuses
       inputs the released provider accepts (short HMAC/KDF keys, ...),
    4. patches openssl.cnf so that only the `fips` and `base` providers are activated
       (the `default` provider is NOT activated, as in crate/crypto/build.rs),
    5. writes a dotenv file (-EnvFile) with OPENSSL_CONF and OPENSSL_MODULES. They are NOT
       exported to the calling process nor to GITHUB_ENV: the KMS steps of test_hsm_idemia.ps1 /
       test_hsm_other.ps1 pass them to the KMS only (see hsm_common.ps1).
  Idempotent: an existing complete install in -InstallDir is reused.

  This proves the KMS FIPS-mode policy and wiring on Windows only; it does not make the
  resulting build a validated module deployment.

.EXAMPLE
  .\.mise\scripts\windows\prepare_windows_fips_provider.ps1
#>
param(
    [string]$InstallDir = "C:\openssl-fips",
    [string]$WorkDir = $(Join-Path ([System.IO.Path]::GetTempPath()) "openssl-fips-build"),
    [string]$EnvFile = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") { throw "prepare_windows_fips_provider.ps1 runs on Windows only" }

. (Join-Path $PSScriptRoot "common.ps1")

$scriptDir = (Resolve-Path -LiteralPath $PSScriptRoot).Path
if ($scriptDir -match '[\\/]\.mise[\\/]scripts[\\/]windows$') {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..\..")).Path
} else {
    $repoRoot = (Get-Location).Path
}
if (-not $EnvFile) { $EnvFile = Join-Path $repoRoot ".openssl-fips\env" }

# Single source of truth shared with crate/crypto/build.rs, the Nix build and the packaging scripts.
$pinned = (Get-Content -Raw -LiteralPath (Join-Path $repoRoot "crate\crypto\openssl_versions.json") |
    ConvertFrom-Json).fips
$Version = $pinned.version
$Tarball = "openssl-$Version.tar.gz"
$Url = "https://package.cosmian.com/openssl/$Tarball"
$Sha256 = $pinned.sha256

$modulesDir = Join-Path $InstallDir "lib\ossl-modules"
$sslDir = Join-Path $InstallDir "ssl"
$fipsDll = Join-Path $modulesDir "fips.dll"
$opensslCnf = Join-Path $sslDir "openssl.cnf"
$fipsModuleCnf = Join-Path $sslDir "fipsmodule.cnf"

function Write-Outputs {
    $lines = @("OPENSSL_CONF=$opensslCnf", "OPENSSL_MODULES=$modulesDir")
    New-Item -ItemType Directory -Force -Path (Split-Path $EnvFile) | Out-Null
    Set-Content -Encoding ASCII -LiteralPath $EnvFile -Value $lines
    Write-Host "FIPS provider ready: $fipsDll (env file $EnvFile)"
}

if ((Test-Path -LiteralPath $fipsDll) -and (Test-Path -LiteralPath $opensslCnf) -and
    (Test-Path -LiteralPath $fipsModuleCnf) -and
    (Select-String -LiteralPath $opensslCnf -SimpleMatch -Quiet -Pattern "fips = fips_sect") -and
    (Select-String -LiteralPath $fipsModuleCnf -SimpleMatch -Quiet -Pattern "hmac-key-check = 0")) {
    Write-Host "Reusing the FIPS provider installed in $InstallDir"
    Write-Outputs
    return
}

# -- Toolchain ----------------------------------------------------------------
# OpenSSL's Configure needs a native Windows perl: the MSYS perl of Git for Windows fails.
$perl = $null
foreach ($candidate in @("C:\Strawberry\perl\bin\perl.exe") + @(Get-Command perl -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
        $os = (& $candidate -e 'print $^O' 2>$null)
        if ($os -eq "MSWin32") { $perl = $candidate; break }
    }
}
if (-not $perl) { throw "a native Windows perl (Strawberry Perl) is required to build OpenSSL" }

$vcvars = (Get-VisualStudio).VcVars

# -- Source -------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$tarPath = Join-Path $WorkDir $Tarball
if (-not (Test-Path -LiteralPath $tarPath)) {
    Write-Host "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $tarPath -UseBasicParsing
}
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tarPath).Hash.ToLowerInvariant()
if ($actual -ne $Sha256) {
    Remove-Item -Force -LiteralPath $tarPath
    throw "SHA-256 mismatch for ${Tarball}: expected $Sha256, got $actual"
}
$srcRoot = Join-Path $WorkDir "openssl-$Version"
if (Test-Path -LiteralPath $srcRoot) { Remove-Item -Recurse -Force -LiteralPath $srcRoot }
& tar.exe -xf $tarPath -C $WorkDir
if ($LASTEXITCODE -ne 0) { throw "tar -xf $tarPath failed" }

# -- Build --------------------------------------------------------------------
if (Test-Path -LiteralPath $InstallDir) { Remove-Item -Recurse -Force -LiteralPath $InstallDir }
$perlDir = Split-Path $perl
$prefixFwd = $InstallDir
$batch = Join-Path $WorkDir "build_fips.cmd"
@(
    "@echo off",
    "call `"$vcvars`" || exit /b 1",
    "set PATH=$perlDir;%PATH%",
    "cd /d `"$srcRoot`" || exit /b 1",
    "perl Configure VC-WIN64A enable-fips no-shared no-asm no-tests --prefix=`"$prefixFwd`" --openssldir=`"$sslDir`" || exit /b 1",
    "nmake /nologo || exit /b 1",
    "nmake /nologo install_fips install_ssldirs || exit /b 1"
) | Set-Content -Encoding ASCII -LiteralPath $batch
Write-Host "Building the OpenSSL $Version FIPS provider (this takes several minutes)"
cmd /c "`"$batch`" 2>&1" | ForEach-Object { Write-Host "$_" }
if ($LASTEXITCODE -ne 0) { throw "the OpenSSL FIPS provider build failed with exit code $LASTEXITCODE" }

# nmake installs the module under <prefix>\lib\ossl-modules (or lib64 on some layouts).
if (-not (Test-Path -LiteralPath $fipsDll)) {
    $found = Get-ChildItem -Recurse -Filter fips.dll -LiteralPath $InstallDir -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { throw "fips.dll was not produced under $InstallDir" }
    New-Item -ItemType Directory -Force -Path $modulesDir | Out-Null
    Copy-Item -Force -LiteralPath $found.FullName -Destination $fipsDll
}
# `install_fips` wrote the pedantic fipsmodule.cnf: regenerate it with the `fipsinstall` defaults.
# The build-tree openssl.exe is static (no-shared); `install_fips` installs no binary.
& (Join-Path $srcRoot "apps\openssl.exe") fipsinstall -self_test_oninstall -module $fipsDll -out $fipsModuleCnf
if ($LASTEXITCODE -ne 0) { throw "openssl fipsinstall failed with exit code $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $fipsModuleCnf)) { throw "$fipsModuleCnf was not produced by 'openssl fipsinstall'" }
if (-not (Test-Path -LiteralPath $opensslCnf)) { throw "$opensslCnf was not installed" }

# -- openssl.cnf: activate `fips` + `base` only -------------------------------
$cnf = Get-Content -Raw -LiteralPath $opensslCnf
$includePath = $fipsModuleCnf -replace '\\', '/'
$cnf = $cnf -replace '(?m)^#\s*\.include\s+(\./)?fipsmodule\.cnf\s*$', ".include $includePath"
if ($cnf -notmatch '(?m)^# fips = fips_sect') { throw "unexpected openssl.cnf layout: no '# fips = fips_sect' line" }
# Never activate the default provider: algorithms (and the DRBG) must come from the FIPS provider.
$cnf = $cnf -replace '(?m)^# fips = fips_sect\s*$', "fips = fips_sect`nbase = base_sect`n`n[ base_sect ]`nactivate = 1`n"
if ($cnf -notmatch [regex]::Escape(".include $includePath")) { throw "failed to include fipsmodule.cnf in openssl.cnf" }
Set-Content -Encoding ASCII -LiteralPath $opensslCnf -Value $cnf

Write-Outputs
