# ============================================================================
# test_cng_ksp.ps1 -- End-to-end CNG KSP integration tests on Windows.
#
# This script exercises the full Cosmian KMS CNG KSP integration:
#   1. Build the CNG KSP DLL and verification tool
#   2. Start a local KMS server (SQLite backend)
#   3. Register the KSP in the Windows registry
#   4. Run `ckms cng verify` against the live KMS
#   5. Run the Rust in-process tests (cosmian_cng --lib)
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

# Invoke a native program and fail hard on non-zero exit code.
# PowerShell 5.1 treats ANY stderr output as a NativeCommandError when
# $ErrorActionPreference="Stop", even with file-based redirects. The only
# reliable workaround is to run the native program via cmd /c so that
# PowerShell never sees the stderr stream at all.
function Invoke-Native {
    param([string]$Program, [string[]]$Arguments, [string]$FailMessage)
    $stderrFile = [System.IO.Path]::GetTempFileName()
    # Build a single command line for cmd /c.  Quote arguments that contain spaces.
    $escapedArgs = @($Program) + ($Arguments | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    })
    $cmdLine = $escapedArgs -join ' '
    cmd /c "$cmdLine 2>`"$stderrFile`""
    $exitCode = $LASTEXITCODE
    if (Test-Path $stderrFile) {
        $stderrContent = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
        if ($stderrContent) {
            Write-Host $stderrContent -ForegroundColor DarkGray
        }
        Remove-Item $stderrFile -Force -ErrorAction SilentlyContinue
    }
    if ($exitCode -ne 0) {
        Write-Host "`n  FAILED: $FailMessage (exit code $exitCode)" -ForegroundColor Red
        exit $exitCode
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

    # Write a minimal test config to avoid conflicts with an existing default kms.toml
    $kmsTestConf = Join-Path $env:TEMP "kms-cng-test.toml"
    # Double backslashes for TOML string escaping (prevents \t, \f, etc. being
    # interpreted as TOML escape sequences).
    $escapedSqlitePath = $SQLITE_PATH -replace '\\', '\\\\'
    @"
[db]
database_type = "sqlite"
sqlite_path = "$escapedSqlitePath"

[http]
port = $KMS_PORT
hostname = "0.0.0.0"
"@ | Set-Content -Path $kmsTestConf -Encoding UTF8

    $env:RUST_LOG = "cosmian_kms_server=info,cosmian_cng=debug"
    $script:KmsProcess = Start-Process -FilePath $kmsExe `
        -ArgumentList "-c", $kmsTestConf `
        -PassThru -NoNewWindow -RedirectStandardOutput $KMS_LOG -RedirectStandardError "${KMS_LOG}.err"

    if (-not (Wait-ForKms -TimeoutSec 60)) {
        Write-Error "KMS server did not start within 60 s. Log: $KMS_LOG"
        if (Test-Path "${KMS_LOG}.err") { Get-Content "${KMS_LOG}.err" | Select-Object -First 20 | Write-Host }
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

# Kill any pre-existing KMS process to avoid "access denied" when overwriting the binary
Get-Process cosmian_kms -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Build the server binary
Invoke-Native cargo (@("build", "--bin", "cosmian_kms", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build KMS server"

# Build the CNG KSP DLL (cdylib)
Invoke-Native cargo (@("build", "--package", "cosmian_cng", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build CNG KSP DLL"

$DllPath = Join-Path $TARGET_DIR "cosmian_cng.dll"
if (-not (Test-Path $DllPath)) { Write-Error "DLL not found: $DllPath"; exit 1 }
Write-Ok "CNG KSP DLL built: $DllPath"

# Build the PKCS#11 provider DLL (cdylib)
Invoke-Native cargo (@("build", "--package", "cosmian_pkcs11", "--features", $FEATURES) + $PROFILE_FLAG) "Failed to build PKCS#11 provider DLL"

$Pkcs11DllPath = Join-Path $TARGET_DIR "cosmian_pkcs11.dll"
if (-not (Test-Path $Pkcs11DllPath)) { Write-Error "PKCS#11 DLL not found: $Pkcs11DllPath"; exit 1 }
Write-Ok "PKCS#11 provider DLL built: $Pkcs11DllPath"

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
        # Unregister first in case a previous run left it registered (avoids STATUS_OBJECT_NAME_COLLISION)
        cmd /c "`"$ckmsExe`" cng unregister 2>nul" | Out-Null
        Invoke-Native $ckmsExe @("cng", "register", "--dll", (Resolve-Path $DllPath).Path) "ckms cng register failed"
        Write-Ok "KSP registered"

        # Copy ckms.toml to System32 so the DLL finds its config at runtime
        $sys32Toml = Join-Path $env:SystemRoot "System32\ckms.toml"
        Copy-Item -Path $CkmsToml -Destination $sys32Toml -Force
        Write-Ok "ckms.toml deployed to $sys32Toml"

        Invoke-Native $ckmsExe @("cng", "status") "ckms cng status failed"
        Write-Ok "ckms cng status confirms registration"

        # Verify the provider is visible to Windows via certutil
        $cspOutput = certutil.exe -csplist 2>&1 | Select-String "Cosmian"
        if ($cspOutput) {
            Write-Ok "certutil -csplist shows: $($cspOutput.Line.Trim())"
        } else {
            Write-Fail "certutil -csplist does not list the Cosmian KSP"
            exit 1
        }
    } else {
        Write-Step "Skipping KSP registry registration (not Administrator)"
        Write-Host "  [SKIP] ckms cng register" -ForegroundColor Yellow
    }

    # -- 6. Run CNG KSP verification via ckms CLI (NCrypt DLL surface tests) --

    Write-Step "Running CNG KSP verification tool (DLL surface tests)"
    Invoke-Native $ckmsExe @("cng", "verify", "--dll", (Resolve-Path $DllPath).Path) "ckms cng verify failed"
    Write-Ok "ckms cng verify: all DLL surface tests passed"

    # -- 6b. Run PKCS#11 provider verification via ckms CLI -------------------

    Write-Step "Running PKCS#11 provider verification (DLL surface tests)"
    Invoke-Native $ckmsExe @("pkcs11", "verify", "--dll", (Resolve-Path $Pkcs11DllPath).Path) "ckms pkcs11 verify failed"
    Write-Ok "ckms pkcs11 verify: all PKCS#11 surface tests passed"

    # -- 7. Run Rust in-process lib tests ---------------------------------

    Write-Step "Running Rust lib tests (cosmian_cng)"
    Invoke-Native cargo @("test", "--lib", "--package", "cosmian_cng", "--features", $FEATURES, "--", "--nocapture") "cosmian_cng lib tests failed"
    Write-Ok "Rust lib tests passed"

    # -- 8. Validate ckms CLI CNG commands --------------------------------

    Write-Step "Validating ckms CLI CNG commands"

    # list-keys (should return at least 0 keys without error)
    Invoke-Native $ckmsExe @("cng", "list-keys") "ckms cng list-keys failed"
    Write-Ok "ckms cng list-keys works"

    # status (already tested above, but confirm again after test operations)
    Invoke-Native $ckmsExe @("cng", "status") "ckms cng status works"
    Write-Ok "ckms cng status works"

    # -- 8b. Intune PFX Import workflow (Add-IntuneKspKey + Export) --------

    if ($IsAdmin) {
        Write-Step "Testing Intune PFX Import workflow (Add-IntuneKspKey + Export-IntunePublicKey)"

        # Locate IntunePfxImport module.
        # Override with INTUNE_PFX_MODULE_PATH env var, otherwise use the copy
        # committed to test_data/intune/ (hard dependency — test FAILS if absent).
        $intuneModulePath = $null
        if ($env:INTUNE_PFX_MODULE_PATH -and (Test-Path $env:INTUNE_PFX_MODULE_PATH)) {
            $intuneModulePath = $env:INTUNE_PFX_MODULE_PATH
        } else {
            $defaultPath = (Resolve-Path "$PSScriptRoot\..\..\..\test_data\intune\IntunePfxImport.psd1" -ErrorAction SilentlyContinue)
            if ($defaultPath) {
                $intuneModulePath = $defaultPath.Path
            }
        }

        if (-not $intuneModulePath) {
            Write-Fail "IntunePfxImport module not found at test_data\intune\IntunePfxImport.psd1"
            Write-Fail "The module must be committed to the test_data submodule."
            exit 1
        }

        Import-Module $intuneModulePath -Force
        Write-Ok "IntunePfxImport module loaded from $intuneModulePath"

        # Use a unique key name per run to avoid collisions from leftover KMS state.
        $intuneKeyName = "intune-pfx-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
        try {
            Add-IntuneKspKey `
                -ProviderName "Cosmian KMS Key Storage Provider" `
                -KeyName $intuneKeyName `
                -MakeExportable
            Write-Ok "Add-IntuneKspKey created key '$intuneKeyName' in Cosmian KMS"
        } catch {
            Write-Fail "Add-IntuneKspKey failed: $($_.Exception.Message)"
            exit 1
        }

        # Verify the key exists via ckms list-keys (output shows UIDs, not names)
        $listOutput = & $ckmsExe cng list-keys 2>&1 | Out-String
        if ($listOutput -match "No CNG KSP keys found") {
            Write-Fail "Key '$intuneKeyName' NOT found in ckms cng list-keys (no keys listed)"
            exit 1
        } elseif ($listOutput -match "CNG KSP keys in the KMS:") {
            Write-Ok "Key '$intuneKeyName' visible in ckms cng list-keys"
        } else {
            Write-Fail "ckms cng list-keys returned unexpected output: $listOutput"
            exit 1
        }

        # Export the public key via Export-IntunePublicKey.
        # This calls NCryptOpenKey → NCryptExportKey (BCRYPT_RSAPUBLIC_BLOB)
        # and writes the CNG blob to a file.
        $exportPath = Join-Path $env:TEMP "intune-pfx-test-key.pfx"
        if (Test-Path $exportPath) { Remove-Item -Force $exportPath }
        try {
            Export-IntunePublicKey `
                -ProviderName "Cosmian KMS Key Storage Provider" `
                -KeyName $intuneKeyName `
                -FilePath $exportPath
        } catch {
            Write-Fail "Export-IntunePublicKey failed: $($_.Exception.Message)"
            exit 1
        }
        if (Test-Path $exportPath) {
            $fileSize = (Get-Item $exportPath).Length
            if ($fileSize -lt 100) {
                Write-Fail "Export-IntunePublicKey file too small ($fileSize bytes)"
                exit 1
            }
            Write-Ok "Export-IntunePublicKey wrote $fileSize bytes to $exportPath"

            # Validate the BCrypt blob magic: first 4 bytes must be "RSA1"
            # (0x52 0x53 0x41 0x31 in little-endian).  A wrong magic such as
            # "RAS1" causes the Intune connector to reject the key with
            # "Key is not a RSA key of BCrypt format".
            $blobBytes = [System.IO.File]::ReadAllBytes($exportPath)
            $magic = [System.Text.Encoding]::ASCII.GetString($blobBytes, 0, 4)
            if ($magic -ne "RSA1") {
                Write-Fail "BCrypt blob has wrong magic '$magic' (expected 'RSA1'). Check BCRYPT_RSAPUBLIC_MAGIC constant."
                exit 1
            }
            Write-Ok "BCrypt blob magic is 'RSA1' (correct)"
        } else {
            Write-Fail "Export-IntunePublicKey did not create output file"
            exit 1
        }

        # Export the public key in PEM format.
        # This exercises the -FileFormat PEM path of NCryptExportKey, which
        # requires a valid "RSA1" magic to succeed.
        $pemExportPath = Join-Path $env:TEMP "intune-pfx-test-key.pempub"
        if (Test-Path $pemExportPath) { Remove-Item -Force $pemExportPath }
        try {
            Export-IntunePublicKey `
                -ProviderName "Cosmian KMS Key Storage Provider" `
                -KeyName $intuneKeyName `
                -FilePath $pemExportPath `
                -FileFormat PEM
            if (Test-Path $pemExportPath) {
                $pemContent = Get-Content $pemExportPath -Raw
                if ($pemContent -notmatch "-----BEGIN PUBLIC KEY-----") {
                    Write-Fail "PEM export does not contain expected header"
                    exit 1
                }
                Write-Ok "Export-IntunePublicKey PEM export succeeded"
            } else {
                Write-Fail "Export-IntunePublicKey -FileFormat PEM did not create output file"
                exit 1
            }
        } catch {
            Write-Fail "Export-IntunePublicKey -FileFormat PEM failed: $($_.Exception.Message)"
            exit 1
        }

        # Clean up exported public key files
        Remove-Item -Force $exportPath -ErrorAction SilentlyContinue
        Remove-Item -Force $pemExportPath -ErrorAction SilentlyContinue

        # Export the private key via Export-IntunePrivateKey.
        # This calls NCryptOpenKey → NCryptExportKey with PKCS8_PRIVATEKEY blob type.
        $privExportPath = Join-Path $env:TEMP "intune-pfx-test-key-priv.pfx"
        if (Test-Path $privExportPath) { Remove-Item -Force $privExportPath }
        Export-IntunePrivateKey `
            -ProviderName "Cosmian KMS Key Storage Provider" `
            -KeyName $intuneKeyName `
            -FilePath $privExportPath
        if (-not (Test-Path $privExportPath)) {
            throw "Export-IntunePrivateKey did not produce output file"
        }
        $privFileSize = (Get-Item $privExportPath).Length
        if ($privFileSize -eq 0) {
            throw "Export-IntunePrivateKey produced empty file"
        }
        Write-Ok "Export-IntunePrivateKey wrote $privFileSize bytes"

        # Import a private key via Import-IntunePrivateKey.
        # This calls NCryptImportKey with RSAFULLPRIVATEBLOB blob type.
        $importKeyName = "intune-pfx-import-$($intuneKeyName.Substring($intuneKeyName.LastIndexOf('-') + 1))"
        Import-IntunePrivateKey `
            -ProviderName "Cosmian KMS Key Storage Provider" `
            -KeyName $importKeyName `
            -FilePath $privExportPath `
            -MakeExportable
        Write-Ok "Import-IntunePrivateKey succeeded"

        # Clean up
        Remove-Item -Force $privExportPath -ErrorAction SilentlyContinue

        Write-Ok "Intune PFX Import workflow: PASSED (Add + ExportPublicBcrypt + ExportPublicPEM + ExportPrivate + Import)"
    } else {
        Write-Step "Skipping Intune PFX Import test (not Administrator)"
        Write-Host "  [SKIP] Add-IntuneKspKey requires a registered KSP (Administrator)" -ForegroundColor Yellow
    }

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
        # Remove ckms.toml from System32
        $sys32Toml = Join-Path $env:SystemRoot "System32\ckms.toml"
        Remove-Item -Path $sys32Toml -Force -ErrorAction SilentlyContinue
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
