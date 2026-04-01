#Requires -Version 5.1
<#
.SYNOPSIS
    Orchestrates a native Windows Oracle TDE HSM integration test using
    cosmian_pkcs11.dll (no Docker containers — neither for Oracle nor for KMS).

.DESCRIPTION
    This script verifies that cosmian_pkcs11.dll correctly provides TDE
    support for an Oracle Database installed natively on Windows.

    Flow:
      1. Validates prerequisites (Oracle, sqlplus, DLL)
      2. Starts a Cosmian KMS server (native binary or detects an existing one)
      3. Calls set_hsm.ps1 to install the DLL and configure TDE
      4. Stops the KMS server process
      5. Optionally cleans up Oracle configuration

    Prerequisites:
      - Oracle Database installed on Windows (23ai/26ai Free or Enterprise)
      - ORACLE_HOME and ORACLE_SID environment variables set
      - cosmian_pkcs11.dll built: cargo build -p cosmian_pkcs11 --features non-fips --release
      - cosmian_kms.exe built:    cargo build -p cosmian_kms_server --features non-fips --release
        (or a KMS server already running at KmsUrl before the script is invoked)
      - No administrator privileges required (PFILE bypass is used for
        Oracle 26ai Windows porting issues; see set_hsm.ps1 for details)

    Example:
        $env:ORACLE_HOME = 'C:\app\rndde\product\26ai\dbhomeFree'
        $env:ORACLE_SID  = 'FREE'
        & .\.github\scripts\oracle\test_oracle_tde.ps1

    To use a pre-built KMS binary at a non-default path:
        $env:KMS_BINARY = 'C:\path\to\cosmian_kms.exe'
        & .\.github\scripts\oracle\test_oracle_tde.ps1

.PARAMETER NoCleanup
    Skip post-test cleanup of Oracle configuration and KMS server process.

.PARAMETER KmsUrl
    URL where KMS is (or will be) reachable. Default: http://localhost:9998
#>

param(
    [switch] $NoCleanup,
    [string] $KmsUrl = 'http://localhost:9998'
)

$ErrorActionPreference = 'Stop'

# ── paths ─────────────────────────────────────────────────────────────────────

$RepoRoot = (Get-Location).Path
$OracleDir = Join-Path $RepoRoot '.github\scripts\oracle'
$DllPath = Join-Path $RepoRoot 'target\debug\cosmian_pkcs11.dll'
$KmsDataDir = Join-Path $OracleDir 'cosmian-kms'

# ── auto-detect Oracle environment if not set ─────────────────────────────────
if (-not $env:ORACLE_HOME) {
    $candidate = 'C:\app\rndde\product\26ai\dbhomeFree'
    if (Test-Path $candidate) { $env:ORACLE_HOME = $candidate }
}
if (-not $env:ORACLE_SID) {
    # Infer SID from the running OracleService* service name
    $svc = Get-Service -Name 'OracleService*' -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
    if ($svc) { $env:ORACLE_SID = $svc.Name -replace '^OracleService', '' }
}

Write-Host '=== Oracle TDE HSM test (native Windows) ==='
Write-Host "Repository root : $RepoRoot"
Write-Host "ORACLE_HOME     : $env:ORACLE_HOME"
Write-Host "ORACLE_SID      : $env:ORACLE_SID"
Write-Host "DLL path        : $DllPath"
Write-Host "KMS URL         : $KmsUrl"

# ── validate prerequisites ────────────────────────────────────────────────────

$errors = @()

if (-not $env:ORACLE_HOME) { $errors += 'ORACLE_HOME is not set.' }
elseif (-not (Test-Path $env:ORACLE_HOME)) { $errors += "ORACLE_HOME does not exist: $env:ORACLE_HOME" }

if (-not $env:ORACLE_SID) { $errors += 'ORACLE_SID is not set.' }

$sqlplusExe = if ($env:ORACLE_HOME) { Join-Path $env:ORACLE_HOME 'bin\sqlplus.exe' } else { '' }
if ($sqlplusExe -and -not (Test-Path $sqlplusExe)) { $errors += "sqlplus not found at $sqlplusExe" }

if (-not (Test-Path $DllPath)) {
    $errors += @"
cosmian_pkcs11.dll not found at $DllPath
Build with: cargo build -p cosmian_pkcs11 --features non-fips
"@
}

# Check Oracle service
$serviceName = if ($env:ORACLE_SID) { "OracleService$($env:ORACLE_SID)" } else { 'OracleService*' }
$oracleService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $oracleService) {
    $oracleService = Get-Service -Name 'OracleService*' -ErrorAction SilentlyContinue
}
if (-not $oracleService) {
    $errors += @"
No Oracle Windows service found.
Install Oracle Database 23ai Free from:
    https://www.oracle.com/database/free/get-started/
"@
}

if ($errors.Count -gt 0) {
    Write-Host "`nPrerequisite errors:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "Oracle service  : $($oracleService.Name) ($($oracleService.Status))"

# ── start KMS server ─────────────────────────────────────────────────────────

$kmsWasStarted = $false  # track whether we started the KMS (for cleanup)
$kmsProcess = $null
$kmsStdout = Join-Path $env:TEMP 'kms_stdout.txt'
$kmsStderr = Join-Path $env:TEMP 'kms_stderr.txt'

# Check if KMS is already running at the target URL.
$kmsAlive = $false
try {
    $saved = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    $null = Invoke-WebRequest -Uri "$KmsUrl/version" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
    $ProgressPreference = $saved
    $kmsAlive = $true
}
catch { $ProgressPreference = $saved }

if ($kmsAlive) {
    Write-Host "`nKMS already running at $KmsUrl — reusing it."
}
else {
    Write-Host "`n--- Starting KMS server ---"

    # Resolve KMS binary: env var override, pre-built debug binary, or build it.
    $kmsBinary = if ($env:KMS_BINARY -and (Test-Path $env:KMS_BINARY)) {
        $env:KMS_BINARY
    }
    else {
        Join-Path $RepoRoot 'target\debug\cosmian_kms.exe'
    }

    if (-not (Test-Path $kmsBinary)) {
        Write-Host 'KMS debug binary not found — building (cargo build -p cosmian_kms_server --features non-fips)...'
        $savedEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        cargo build -p cosmian_kms_server --features non-fips
        $ErrorActionPreference = $savedEAP
        if ($LASTEXITCODE -ne 0) { throw 'Failed to build KMS server.' }
    }

    # Keep SQLite data persistent across runs: Oracle stores the active TDE
    # master key ID in its control file.  If the KMS database were wiped,
    # KEYSTORE OPEN would fail on the second run because the key no longer
    # exists in the KMS.
    New-Item -ItemType Directory -Path $KmsDataDir -Force | Out-Null

    Write-Host "KMS binary : $kmsBinary"
    Write-Host "KMS data   : $KmsDataDir"

    # The KMS binary ignores CLI args and env vars when it finds its default
    # config file (C:\Users\<user>\AppData\Local\Cosmian KMS Server\kms.toml).
    # Work around by writing a minimal test-specific config and passing -c.
    $kmsConfigPath = Join-Path $KmsDataDir 'kms_test.toml'
    $sqlitePathFwd = ($KmsDataDir -replace '\\', '/').TrimEnd('/')
    @"
# Minimal Cosmian KMS config generated by test_oracle_tde.ps1.
[db]
database_type = "sqlite"
sqlite_path = "$sqlitePathFwd"

[http]
port = 9998
hostname = "0.0.0.0"

[logging]
rust_log = "info"
quiet = false
ansi_colors = false
"@ | Set-Content -Path $kmsConfigPath -Encoding UTF8
    Write-Host "KMS config : $kmsConfigPath (port 9998, sqlite-path $KmsDataDir)"

    $env:RUST_LOG = 'cosmian_kms_server=info'
    $kmsProcess = Start-Process -FilePath $kmsBinary `
        -ArgumentList '-c', $kmsConfigPath `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $kmsStdout `
        -RedirectStandardError  $kmsStderr

    if (-not $kmsProcess -or $kmsProcess.HasExited) {
        throw 'KMS process failed to start immediately.'
    }
    $kmsWasStarted = $true

    # Wait for KMS to be healthy.
    Write-Host "Waiting for KMS to become healthy (PID $($kmsProcess.Id))..."
    $deadline = (Get-Date).AddSeconds(60)
    $healthy = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if ($kmsProcess.HasExited) {
            Write-Host '--- KMS stdout (last 30 lines) ---'
            Get-Content $kmsStdout -ErrorAction SilentlyContinue | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
            Write-Host '--- KMS stderr ---'
            Get-Content $kmsStderr -ErrorAction SilentlyContinue | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
            throw "KMS process exited unexpectedly (exit $($kmsProcess.ExitCode))."
        }
        try {
            $saved = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
            $null = Invoke-WebRequest -Uri "$KmsUrl/version" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            $ProgressPreference = $saved
            $healthy = $true
            break
        }
        catch { $ProgressPreference = $saved; Write-Host '  Waiting...' }
    }
    if (-not $healthy) {
        Write-Host '--- KMS stdout (last 30 lines) ---'
        Get-Content $kmsStdout -ErrorAction SilentlyContinue | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
        Write-Host '--- KMS stderr (last 30 lines) ---'
        Get-Content $kmsStderr -ErrorAction SilentlyContinue | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
        throw "KMS did not become healthy at $KmsUrl within 60 seconds."
    }
    Write-Host "KMS is healthy at $KmsUrl"
}

# ── run the TDE setup ────────────────────────────────────────────────────────

$testFailed = $false
try {
    Write-Host "`n--- Running set_hsm.ps1 ---"
    $setHsmScript = Join-Path $OracleDir 'set_hsm.ps1'
    & $setHsmScript -DllPath $DllPath -KmsUrl $KmsUrl
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "set_hsm.ps1 failed with exit code $LASTEXITCODE"
    }
}
catch {
    $testFailed = $true
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red

    # Dump KMS server logs if we started the process.
    if ($kmsWasStarted) {
        Write-Host ''
        Write-Host '--- KMS stdout (last 40 lines) ---'
        Get-Content $kmsStdout -ErrorAction SilentlyContinue | Select-Object -Last 40 | ForEach-Object { Write-Host $_ }
        Write-Host '--- KMS stderr (last 40 lines) ---'
        Get-Content $kmsStderr -ErrorAction SilentlyContinue | Select-Object -Last 40 | ForEach-Object { Write-Host $_ }
    }

    # Check PKCS#11 log (service user home and current user home).
    $sid = $env:ORACLE_SID
    $logLocations = @(
        "C:\WINDOWS\ServiceProfiles\OracleService${sid}\.cosmian\cosmian-pkcs11.log",
        "$env:USERPROFILE\.cosmian\cosmian-pkcs11.log"
    )
    foreach ($logFile in $logLocations) {
        if (Test-Path $logFile -ErrorAction SilentlyContinue) {
            Write-Host ''
            Write-Host "--- PKCS#11 log: $logFile (last 40 lines) ---"
            Get-Content $logFile -Tail 40 | ForEach-Object { Write-Host $_ }
        }
    }
}

# ── cleanup ──────────────────────────────────────────────────────────────────

if (-not $NoCleanup) {
    Write-Host "`n--- Cleanup ---"

    # Stop KMS server process if we started it.
    if ($kmsWasStarted -and $kmsProcess -and -not $kmsProcess.HasExited) {
        Write-Host 'Stopping KMS server...'
        try { $kmsProcess.Kill(); $null = $kmsProcess.WaitForExit(5000) } catch {}
    }
    Remove-Item $kmsStdout, $kmsStderr -ErrorAction SilentlyContinue

    # Remove system env vars (best-effort).
    try {
        [System.Environment]::SetEnvironmentVariable('CKMS_CONF', $null, 'Machine')
        [System.Environment]::SetEnvironmentVariable('COSMIAN_PKCS11_LOGGING_LEVEL', $null, 'Machine')
        Write-Host 'Removed system env vars (CKMS_CONF, COSMIAN_PKCS11_LOGGING_LEVEL).'
    }
    catch {
        Write-Warning "Could not remove system env vars: $_"
    }

    # Optionally remove the DLL and config from Oracle home.
    # Leave them in place by default — they are harmless without a running KMS.
    # To fully clean up Oracle's TDE config, a DBA should:
    #   ALTER SYSTEM RESET WALLET_ROOT SCOPE=SPFILE;
    #   ALTER SYSTEM RESET TDE_CONFIGURATION SCOPE=BOTH;
    #   SHUTDOWN IMMEDIATE; STARTUP;
}
else {
    Write-Host "`nCleanup skipped (-NoCleanup). KMS process and Oracle config remain in place."
}

# ── result ───────────────────────────────────────────────────────────────────

if ($testFailed) {
    Write-Host "`n=== Oracle TDE native Windows test FAILED ===" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Oracle TDE native Windows test completed successfully ==="
