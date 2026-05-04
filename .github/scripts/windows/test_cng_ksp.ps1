# ============================================================================
# test_cng_ksp.ps1 -- End-to-end CNG KSP integration tests on Windows.
#
# This script exercises the full Cosmian KMS CNG KSP integration:
#   1. Build the CNG KSP DLL and verification tool
#   2. Start a local KMS server (SQLite backend)
#   3. Register the KSP in the Windows registry
#   4. Run the cng_verify tool against the live KMS
#   5. Run the Rust in-process tests (cosmian_kms_cng_ksp --lib)
#   6. Validate ckms CLI CNG commands (list-keys, status)
#   7. Clean up (unregister KSP, stop KMS)
#
# Prerequisites:
#   - Windows 10/11 or Server 2019+
#   - Rust toolchain (MSVC target)
#   - Administrator privileges (for registry write)
#   - vcpkg with openssl_x64-windows-static (set OPENSSL_DIR or VCPKG_INSTALLATION_ROOT)
#
# No Azure account or Intune credentials are needed -- this tests the CNG KSP
# DLL against a local KMS server, not the Intune enrollment pipeline.
#
# Usage:
#   # From an elevated PowerShell prompt at the repository root:
#   .\\.github\\scripts\\windows\\test_cng_ksp.ps1
#
#   # Or via CI:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File .github/scripts/windows/test_cng_ksp.ps1
# ============================================================================
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# -- Configuration ------------------------------------------------------------

$KMS_PORT = 9998
$KMS_URL = "http://127.0.0.1:${KMS_PORT}"
$SQLITE_PATH = Join-Path $env:TEMP "kms-cng-test-data"
$KMS_LOG = Join-Path $env:TEMP "kms-cng-test-server.log"
$FEATURES = "non-fips"

# Build profile: debug for CI speed, release for production validation
$PROFILE = if ($env:CNG_TEST_RELEASE -eq "1") { "release" } else { "debug" }
$PROFILE_FLAG = if ($PROFILE -eq "release") { @("--release") } else { @() }
$TARGET_DIR = "target\$PROFILE"

# -- Helpers ------------------------------------------------------------------

function Write-Step { param([string]$Msg) Write-Host "`n=== $Msg ===" -ForegroundColor Cyan }
function Write-Ok { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Fail { param([string]$Msg) Write-Host "  [FAIL] $Msg" -ForegroundColor Red }

# Invoke a native program and throw only on non-zero exit code.
# In PowerShell 5.1, cargo's stderr (build progress / warnings) is converted
# to error records.  Wrapping in try/catch absorbs those records while still
# letting us check the real exit code via $LASTEXITCODE.
function Invoke-Native {
    param([string]$Program, [string[]]$Arguments, [string]$FailMessage)
    try { & $Program @Arguments } catch { }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "$FailMessage (exit code $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

function Wait-ForKms {
    param([int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri "${KMS_URL}/version" -Method GET -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($resp.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

$KmsProcess = $null

function Start-KmsServer {
    Write-Step "Starting local KMS server (SQLite, port $KMS_PORT)"

    # Clean previous data
    if (Test-Path $SQLITE_PATH) { Remove-Item -Recurse -Force $SQLITE_PATH }
    New-Item -ItemType Directory -Force -Path $SQLITE_PATH | Out-Null

    $kmsExe = Join-Path $TARGET_DIR "cosmian_kms.exe"
    if (-not (Test-Path $kmsExe)) {
        Write-Error "KMS server binary not found at $kmsExe -- build it first."
        exit 1
    }

    $env:RUST_LOG = "cosmian_kms_server=info,cosmian_kms_cng_ksp=debug"
    $script:KmsProcess = Start-Process -FilePath $kmsExe `
        -ArgumentList "--database-type", "sqlite", "--sqlite-path", $SQLITE_PATH, "--port", $KMS_PORT `
        -PassThru -NoNewWindow -RedirectStandardOutput $KMS_LOG -RedirectStandardError "${KMS_LOG}.err"

    if (-not (Wait-ForKms -TimeoutSec 60)) {
        Write-Error "KMS server did not start within 60 s. Log: $KMS_LOG"
        exit 1
    }
    Write-Ok "KMS server running (PID $($script:KmsProcess.Id))"
}

function Stop-KmsServer {
    if ($null -ne $script:KmsProcess -and -not $script:KmsProcess.HasExited) {
        Write-Step "Stopping KMS server (PID $($script:KmsProcess.Id))"
        Stop-Process -Id $script:KmsProcess.Id -Force -ErrorAction SilentlyContinue
        $script:KmsProcess.WaitForExit(5000) | Out-Null
        Write-Ok "KMS server stopped"
    }
}

# -- 0. OpenSSL environment --------------------------------------------------

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    Write-Host "Running as Administrator: registry steps will be executed."
} else {
    Write-Host "WARNING: Not running as Administrator. Registry register/unregister steps will be skipped." -ForegroundColor Yellow
}

if (-not $env:OPENSSL_DIR) {
    if ($env:VCPKG_INSTALLATION_ROOT) {
        $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    }
}
if ($env:OPENSSL_DIR) {
    Write-Host "OPENSSL_DIR = $env:OPENSSL_DIR"
} else {
    Write-Host "WARNING: OPENSSL_DIR not set; build may fail if OpenSSL is not found." -ForegroundColor Yellow
}

# -- 1. Build -----------------------------------------------------------------

Write-Step "Building KMS server, CNG KSP DLL, verification tool, and ckms CLI"

# Build the server binary
Invoke-Native cargo (@("build", "--bin", "cosmian_kms", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build KMS server"

# Build the CNG KSP DLL (cdylib)
Invoke-Native cargo (@("build", "--package", "cosmian_kms_cng_ksp", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build CNG KSP DLL"

$DllPath = Join-Path $TARGET_DIR "cosmian_kms_cng_ksp.dll"
if (-not (Test-Path $DllPath)) { Write-Error "DLL not found: $DllPath"; exit 1 }
Write-Ok "CNG KSP DLL built: $DllPath"

# Build the verification tool
Invoke-Native cargo (@("build", "--package", "cosmian_kms_cng_ksp_verify", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build cng_verify"
Write-Ok "cng_verify built"

# Build ckms CLI
Invoke-Native cargo (@("build", "--package", "ckms", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build ckms"
Write-Ok "ckms CLI built"

# -- 2. Start KMS server -----------------------------------------------------

try {
    Start-KmsServer

    # -- 3. Configure ckms.toml -------------------------------------------

    Write-Step "Writing ckms.toml for local KMS"

    # Place ckms.toml next to the DLL so the KSP finds it automatically
    $CkmsToml = Join-Path $TARGET_DIR "ckms.toml"
    @"
[http_config]
server_url = "$KMS_URL"
"@ | Set-Content -Path $CkmsToml -Encoding UTF8
    $env:CKMS_CONF = $CkmsToml
    Write-Ok "ckms.toml written to $CkmsToml"

    # -- 4. Smoke-test: KMS is reachable ---------------------------------

    Write-Step "Smoke-testing KMS endpoint"
    $smokeResp = Invoke-WebRequest -Uri "${KMS_URL}/version" -Method GET -TimeoutSec 5 -UseBasicParsing
    if ($smokeResp.StatusCode -ne 200) {
        Write-Error "KMS /version returned $($smokeResp.StatusCode)"
        exit 1
    }
    Write-Ok "KMS reachable at $KMS_URL"

    # -- 5. Register the KSP (requires Administrator) --------------------

    $ckmsExe = Join-Path $TARGET_DIR "ckms.exe"
    if ($IsAdmin) {
        Write-Step "Registering CNG KSP in Windows registry"
        Invoke-Native $ckmsExe @("cng", "register", "--dll", (Resolve-Path $DllPath).Path) "ckms cng register failed"
        Write-Ok "KSP registered"

        Invoke-Native $ckmsExe @("cng", "status") "ckms cng status failed"
        Write-Ok "ckms cng status confirms registration"
    } else {
        Write-Step "Skipping KSP registry registration (not Administrator)"
        Write-Host "  [SKIP] ckms cng register" -ForegroundColor Yellow
    }

    # -- 6. Run cng_verify tool (NCrypt DLL surface tests) ----------------

    Write-Step "Running CNG KSP verification tool (DLL surface tests)"
    $verifyExe = Join-Path $TARGET_DIR "cosmian_kms_cng_ksp_verify.exe"
    Invoke-Native $verifyExe @("--dll", (Resolve-Path $DllPath).Path) "cng_verify failed"
    Write-Ok "cng_verify: all DLL surface tests passed"

    # -- 7. Run Rust in-process lib tests ---------------------------------

    Write-Step "Running Rust lib tests (cosmian_kms_cng_ksp)"
    Invoke-Native cargo @("test", "--lib", "--package", "cosmian_kms_cng_ksp", "--features", $FEATURES, "--", "--nocapture") "cosmian_kms_cng_ksp lib tests failed"
    Write-Ok "Rust lib tests passed"

    # -- 8. Validate ckms CLI CNG commands --------------------------------

    Write-Step "Validating ckms CLI CNG commands"

    # list-keys (should return at least 0 keys without error)
    Invoke-Native $ckmsExe @("cng", "list-keys") "ckms cng list-keys failed"
    Write-Ok "ckms cng list-keys works"

    # status (already tested above, but confirm again after test operations)
    Invoke-Native $ckmsExe @("cng", "status") "ckms cng status works"
    Write-Ok "ckms cng status works"

    # -- 9. Check KMS server logs for errors ------------------------------

    Write-Step "Checking KMS server logs for errors"
    $logErrors = @()
    if (Test-Path $KMS_LOG) {
        $logErrors += @(Select-String -Path $KMS_LOG -Pattern "ERROR|PANIC" -CaseSensitive | Select-Object -First 10)
    }
    if (Test-Path "${KMS_LOG}.err") {
        $logErrors += @(Select-String -Path "${KMS_LOG}.err" -Pattern "ERROR|PANIC" -CaseSensitive | Select-Object -First 10)
    }
    if ($logErrors.Count -gt 0) {
        Write-Host "WARNING: KMS server logs contain errors:" -ForegroundColor Yellow
        $logErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    } else {
        Write-Ok "No ERROR/PANIC in KMS server logs"
    }

    # -- 10. Unregister the KSP ------------------------------------------

    if ($IsAdmin) {
        Write-Step "Unregistering CNG KSP"
        try { & $ckmsExe cng unregister } catch { }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: ckms cng unregister failed (non-fatal)" -ForegroundColor Yellow
        } else {
            Write-Ok "KSP unregistered"
        }
    } else {
        Write-Step "Skipping KSP unregistration (not Administrator)"
        Write-Host "  [SKIP] ckms cng unregister" -ForegroundColor Yellow
    }
}
finally {
    # Always stop the server and clean up
    Stop-KmsServer

    # Clean up temp data
    if (Test-Path $SQLITE_PATH) {
        Remove-Item -Recurse -Force $SQLITE_PATH -ErrorAction SilentlyContinue
    }
}

# -- Summary ------------------------------------------------------------------

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "  CNG KSP integration tests PASSED" -ForegroundColor Green
Write-Host "==========================================`n" -ForegroundColor Green
