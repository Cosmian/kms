#Requires -Version 5.1

<#
.SYNOPSIS
    Installs cosmian_pkcs11.dll into a Windows Oracle Database and
    configures Oracle TDE to use Cosmian KMS as its HSM.

.DESCRIPTION
    Configures Oracle TDE to use cosmian_pkcs11.dll on a Windows-native
    Oracle installation (no Docker required for Oracle).

    This script:
      1. Copies cosmian_pkcs11.dll to C:\opt\oracle\extapi\64\pkcs11\
         (a Linux-style path that satisfies Oracle 26ai's hardcoded prefix
         check — see Oracle porting notes below)
      2. Writes ckms.toml to the Oracle service user home via UTL_FILE so
         the DLL's KMS client can locate its configuration at runtime
      3. Captures the current in-memory parameters via CREATE PFILE FROM MEMORY,
         then injects WALLET_ROOT, TDE_CONFIGURATION, and pkcs11_library_location
         directly into the plain-text PFILE (avoids SPFILE dependency)
      4. Restarts the database with STARTUP PFILE= so all three parameters
         take effect simultaneously
      5. Persists the effective configuration back to SPFILE with
         CREATE SPFILE FROM PFILE
      6. Runs KEYSTORE OPEN and SET KEY, verifies wallet/key status

    Oracle 26ai Free for Windows porting notes
    ------------------------------------------
    Oracle 26ai ships a Windows binary with two unfixed HSM/PKCS#11 issues:

    1.  skgdllDiscover finds nothing on Windows.
        The auto-discovery function only scans the hard-coded path
        "/opt/oracle/extapi/64/pkcs11/" which does not exist on Windows, so
        Oracle cannot locate any PKCS#11 DLL automatically.

    2.  pkcs11_library_location rejects Windows paths.
        The SPFILE parameter validator (kzcp_pkcs11_lib_location_spfile_cb)
        checks that the supplied path starts with the prefix
        "/opt/oracle/extapi/64/pkcs11/".  Any Windows path (C:\...) is
        therefore rejected with ORA-46707 / ORA-32017.

    Workaround applied by this script
    ----------------------------------
    • Place the DLL at  C:\opt\oracle\extapi\64\pkcs11\cosmian_pkcs11.dll
      On Windows, a path starting with "/..." is treated as drive-relative by
      LoadLibrary, so  /opt/oracle/extapi/64/pkcs11/cosmian_pkcs11.dll
      resolves to  C:\opt\oracle\extapi\64\pkcs11\cosmian_pkcs11.dll
      on any system where C: is the current drive.

    • Set pkcs11_library_location='/opt/oracle/extapi/64/pkcs11/cosmian_pkcs11.dll'
      inside a plain PFILE (init.ora).  Oracle reads this value at startup
      without invoking the ALTER SYSTEM SPFILE validator, so the prefix check
      is bypassed.  We then use  STARTUP PFILE=...  to bring up the database
      with this value active, and finally write the resulting state back to
      SPFILE with  CREATE SPFILE FROM PFILE.

    Prerequisites:
      - Oracle Database installed on Windows (23ai/26ai Free or Enterprise)
      - ORACLE_HOME and ORACLE_SID environment variables set
      - KMS server reachable at KmsUrl (default: http://localhost:9998)
      - cosmian_pkcs11.dll built (default: target\release\cosmian_pkcs11.dll)
      - No admin required (PFILE bypass avoids ALTER SYSTEM; service restart
        is done via SQL SHUTDOWN/STARTUP with OS authentication)

.PARAMETER DllPath
    Path to cosmian_pkcs11.dll. Defaults to target\release\cosmian_pkcs11.dll
    relative to the repository root.

.PARAMETER KmsUrl
    URL of the running KMS server. Default: http://localhost:9998

.EXAMPLE
    $env:ORACLE_HOME = 'C:\app\rndde\product\26ai\dbhomeFree'
    $env:ORACLE_SID  = 'FREE'
    & .\.github\scripts\oracle\set_hsm.ps1

.NOTES
    Companion orchestrator: .github/scripts/oracle/test_oracle_tde.ps1
#>

param(
    [string] $DllPath = '',
    [string] $KmsUrl = 'http://localhost:9998'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── helpers ───────────────────────────────────────────────────────────────────

function Invoke-OracleSql {
    <#
    .SYNOPSIS
        Run a list of SQL statements/commands in sqlplus as SYSDBA.
        Uses Start-Process with stdin redirect and a timeout so sqlplus can
        never hang the PowerShell session — critical on Windows where Oracle's
        named-pipe disconnect after SHUTDOWN IMMEDIATE would otherwise block
        the calling process indefinitely.

    .PARAMETER AllowDisconnect
        After SHUTDOWN IMMEDIATE, Oracle severs the named-pipe connection and
        WHENEVER OSERROR causes sqlplus to exit with code 1.  Pass this switch
        to treat exit code 1 as success for that specific call.
    #>
    param(
        [Parameter(Mandatory)] [string]   $Description,
        [Parameter(Mandatory)] [string[]] $SqlLines,
        [int]    $TimeoutSeconds = 120,
        [switch] $AllowDisconnect       # tolerate exit 1 (SHUTDOWN/disconnect)
    )

    Write-Host "`nSQL: $Description"

    $script = @(
        'WHENEVER SQLERROR EXIT SQL.SQLCODE;',
        'WHENEVER OSERROR EXIT FAILURE;'
    )
    $script += $SqlLines
    $script += 'exit'

    $tempFile = Join-Path $env:TEMP 'oracle_tde_config.sql'
    $tempOut = Join-Path $env:TEMP 'oracle_tde_out.txt'
    $tempErr = Join-Path $env:TEMP 'oracle_tde_err.txt'
    $tempIn = Join-Path $env:TEMP 'oracle_tde_in.txt'

    ($script -join "`r`n") | Set-Content -Path $tempFile -Encoding ASCII
    # Empty stdin file — prevents sqlplus from blocking on any prompt (password,
    # "press Enter", etc.) when stdin is not a real terminal.
    [string]::Empty | Set-Content -Path $tempIn -Encoding ASCII

    $sqlplusExe = Join-Path $env:ORACLE_HOME 'bin\sqlplus.exe'

    # Build argument string as a single value so Start-Process passes it
    # verbatim to CreateProcess.  Windows CRT splits on spaces respecting
    # double-quotes, so sqlplus receives exactly two arguments:
    #   argv[1] = / as sysdba
    #   argv[2] = @C:\...\script.sql
    $argStr = '"/ as sysdba" "@' + $tempFile + '"'

    $proc = Start-Process -FilePath $sqlplusExe `
        -ArgumentList $argStr `
        -NoNewWindow -PassThru `
        -RedirectStandardInput  $tempIn `
        -RedirectStandardOutput $tempOut `
        -RedirectStandardError  $tempErr

    $finished = $proc.WaitForExit($TimeoutSeconds * 1000)
    Start-Sleep -Milliseconds 300   # let file I/O buffers flush

    if (Test-Path $tempOut) { Get-Content $tempOut | ForEach-Object { Write-Host $_ } }
    if (Test-Path $tempErr) {
        $errLines = Get-Content $tempErr | Where-Object { $_ -match '\S' }
        if ($errLines) { $errLines | ForEach-Object { Write-Host "  [stderr] $_" } }
    }

    $outText = if (Test-Path $tempOut) { Get-Content $tempOut -Raw } else { '' }
    Remove-Item $tempFile, $tempOut, $tempErr, $tempIn -ErrorAction SilentlyContinue

    if (-not $finished) {
        try { $proc.Kill() } catch {}
        # SHUTDOWN IMMEDIATE severs the Oracle named-pipe connection and Oracle
        # may close the instance before sqlplus gets a chance to process
        # WHENEVER OSERROR and exit.  If Oracle's process is gone the database
        # did shut down — treat the sqlplus hang as a non-fatal disconnect.
        if ($AllowDisconnect -and -not (Get-Process -Name oracle -ErrorAction SilentlyContinue)) {
            Write-Host "  (sqlplus timed out but oracle.exe is gone — SHUTDOWN succeeded)"
        }
        else {
            throw "sqlplus timed out after ${TimeoutSeconds}s for: $Description"
        }
    }

    $rc = $proc.ExitCode
    if ($null -eq $rc) { $rc = 0 }  # Start-Process race: null means process exited cleanly

    # Also detect Oracle errors directly from stdout (ExitCode can be unreliable
    # with Start-Process on Windows when the process exits very quickly).
    $hasOracleError = $outText -match 'ORA-\d+|ERROR at line \d'
    if (($rc -ne 0 -or $hasOracleError) -and -not ($AllowDisconnect -and $rc -le 1 -and -not $hasOracleError)) {
        throw "sqlplus failed (exit $rc) for: $Description"
    }
    Start-Sleep -Seconds 2
}

function Show-OracleWallet {
    <# Display wallet and encryption key status. #>
    Invoke-OracleSql 'Show wallet status' @(
        'COLUMN WRL_PARAMETER FORMAT A50;',
        'SET LINES 200;',
        'SELECT WRL_TYPE, WRL_PARAMETER, WALLET_TYPE, STATUS FROM V$ENCRYPTION_WALLET;'
    )
    Invoke-OracleSql 'Show encryption keys' @(
        'SET LINES 400;',
        'SELECT KEY_ID, KEYSTORE_TYPE, CREATOR_DBNAME, ACTIVATION_TIME, KEY_USE, ORIGIN FROM V$ENCRYPTION_KEYS;'
    )
}

function Wait-OracleReady {
    <# Poll sqlplus until Oracle is responding after a STARTUP. #>
    param([int] $TimeoutSeconds = 120)

    $sqlplusExe = Join-Path $env:ORACLE_HOME 'bin\sqlplus.exe'
    $checkSql = Join-Path $env:TEMP 'oracle_ready_check.sql'
    @(
        'WHENEVER SQLERROR EXIT SQL.SQLCODE;',
        "SELECT 'ORACLE_READY' FROM DUAL;",
        'exit'
    ) -join "`r`n" | Set-Content -Path $checkSql -Encoding ASCII

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $ready = $false

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $saved = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $output = & $sqlplusExe '/ as sysdba' "@$checkSql" 2>&1 | Out-String
        $ErrorActionPreference = $saved
        if ($output -match 'ORACLE_READY') { $ready = $true; break }
        Write-Host '  Waiting for Oracle...'
    }

    Remove-Item $checkSql -ErrorAction SilentlyContinue
    if (-not $ready) { throw "Oracle did not become ready within $TimeoutSeconds s" }
    Write-Host 'Oracle is ready.'
}

# ── validate prerequisites ────────────────────────────────────────────────────

if (-not $env:ORACLE_HOME) { throw 'ORACLE_HOME is not set.' }
if (-not (Test-Path $env:ORACLE_HOME)) { throw "ORACLE_HOME does not exist: $env:ORACLE_HOME" }
if (-not $env:ORACLE_SID) { throw 'ORACLE_SID is not set.' }

$sqlplusExe = Join-Path $env:ORACLE_HOME 'bin\sqlplus.exe'
if (-not (Test-Path $sqlplusExe)) { throw "sqlplus not found at $sqlplusExe" }

$RepoRoot = if ($env:REPO_ROOT) { $env:REPO_ROOT } else { (Get-Location).Path }

if (-not $DllPath) {
    $DllPath = Join-Path $RepoRoot 'target\debug\cosmian_pkcs11.dll'
}
if (-not (Test-Path $DllPath)) {
    throw @"
cosmian_pkcs11.dll not found at $DllPath
Build it with:
    cargo build -p cosmian_pkcs11 --features non-fips
"@
}

Write-Host '=== Configuring Oracle TDE with Cosmian PKCS#11 (native Windows) ==='
Write-Host "DLL source  : $DllPath ($('{0:N1} MB' -f ((Get-Item $DllPath).Length / 1MB)))"
Write-Host "ORACLE_HOME : $env:ORACLE_HOME"
Write-Host "ORACLE_SID  : $env:ORACLE_SID"
Write-Host "KMS URL     : $KmsUrl"

# ── check DLL exports ────────────────────────────────────────────────────────

$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($dumpbin) {
    Write-Host "`n--- Checking DLL exports ---"
    & dumpbin.exe /exports $DllPath 2>&1 | Select-String 'C_GetFunctionList|C_Initialize|C_Finalize'
}

# ── install DLL at the Linux-style path (Oracle 26ai Windows workaround) ─────
#
# Place at C:\opt\oracle\extapi\64\pkcs11\ so that when Oracle's
# LoadLibrary is called with the forward-slash path
#   /opt/oracle/extapi/64/pkcs11/cosmian_pkcs11.dll
# Windows resolves it drive-relative to
#   C:\opt\oracle\extapi\64\pkcs11\cosmian_pkcs11.dll

$pkcs11Dir = 'C:\opt\oracle\extapi\64\pkcs11'
New-Item -ItemType Directory -Path $pkcs11Dir -Force | Out-Null
$destDll = Join-Path $pkcs11Dir 'cosmian_pkcs11.dll'
# NOTE: the actual DLL copy happens later, after SHUTDOWN ABORT, because
# Oracle locks the file once it is loaded.  Copying here would fail with
# "file is being used by another process" on repeat runs.

# Also prepare the Oracle extapi reference directory (not used at runtime).
$extapiDir = Join-Path $env:ORACLE_HOME 'extapi\64\hsm\Cosmian'
New-Item -ItemType Directory -Path $extapiDir -Force | Out-Null

# ── ensure Oracle instance is OPEN ────────────────────────────────────────────
#
# The ckms.toml write (via UTL_FILE) and CREATE PFILE FROM MEMORY both require
# an open Oracle instance.  If the instance is idle (e.g. after SHUTDOWN from a
# previous test run), start it now so the rest of the script can proceed.

Write-Host "`n--- Checking Oracle instance status ---"
$tmpChkSql = Join-Path $env:TEMP 'ora_check_status.sql'
$tmpChkIn = Join-Path $env:TEMP 'ora_check_status.in'
$tmpChkOut = Join-Path $env:TEMP 'ora_check_status.out'
$tmpChkErr = Join-Path $env:TEMP 'ora_check_status.err'
"SET HEADING OFF FEEDBACK OFF PAGESIZE 0 TRIMSPOOL ON`nSELECT STATUS FROM V`$INSTANCE;`nEXIT;" |
Set-Content -Path $tmpChkSql -Encoding ASCII
'' | Set-Content -Path $tmpChkIn -Encoding ASCII   # empty stdin so sqlplus never waits for keyboard
$chkProc = Start-Process -FilePath $sqlplusExe `
    -ArgumentList '-s', '/ as sysdba', "@$tmpChkSql" `
    -NoNewWindow -PassThru `
    -RedirectStandardInput  $tmpChkIn `
    -RedirectStandardOutput $tmpChkOut `
    -RedirectStandardError  $tmpChkErr
$chkDone = $chkProc.WaitForExit(30000)   # 30-second timeout
if (-not $chkDone) {
    try { $chkProc.Kill() } catch {}
    Write-Host "  (sqlplus status check timed out — oracle not ready)"
}
$oraStatusOut = ((Get-Content $tmpChkOut -ErrorAction SilentlyContinue) -join ' ').Trim()
Remove-Item $tmpChkSql, $tmpChkIn, $tmpChkOut, $tmpChkErr -ErrorAction SilentlyContinue
Write-Host "Oracle status check output: '$oraStatusOut'"

if ($oraStatusOut -notmatch 'OPEN') {
    Write-Host "Oracle instance is not OPEN -- preparing safe startup..."

    $oraServiceName = "OracleService$($env:ORACLE_SID)"

    # Step 1 — clear any stuck state with SHUTDOWN ABORT.
    # This is safe in all scenarios:
    #   • DB cleanly shut down  → ORA-01034 (caught, ignored)
    #   • STARTUP still running → ABORT kills the startup immediately
    #   • SHUTDOWN IMMEDIATE stuck (e.g., Data Pump + memory pressure)
    #     → ABORT supersedes it and exits instantly when oracle.exe can process IPC
    #   • oracle.exe completely unresponsive (stuck in kernel I/O)
    #     → ABORT times out, handled below via Stop-Service
    #
    # NOTE: On Windows, oracle.exe (the service host) NEVER exits after a DB
    # SHUTDOWN — it remains alive waiting for the next STARTUP command.
    # We therefore do NOT wait for oracle.exe to exit; a brief sleep after ABORT
    # is sufficient for internal Oracle cleanup.
    Write-Host "  Sending SHUTDOWN ABORT to clear any pending state..."
    $savedEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $abortTimedOut = $false
    try {
        Invoke-OracleSql 'Shutdown Oracle (ABORT)' @('SHUTDOWN ABORT;') `
            -TimeoutSeconds 30 -AllowDisconnect
    }
    catch {
        if ($_.Exception.Message -match 'timed out') {
            # oracle.exe is unresponsive (stuck in kernel I/O, Data Pump shutdown, etc.)
            $abortTimedOut = $true
            Write-Host "  ABORT timed out — oracle.exe is unresponsive"
        }
        else {
            # Any other error (ORA-01034 = already shut down, ORA-01507, etc.) is fine.
            Write-Host "  SHUTDOWN ABORT: $($_.Exception.Message) (ignored)"
        }
    }
    $ErrorActionPreference = $savedEAP

    if ($abortTimedOut) {
        # oracle.exe cannot process IPC commands (stuck in kernel wait state).
        # Use Windows SCM — Stop-Service terminates oracle.exe through the service
        # control manager, which can force-stop it via TerminateProcess after the
        # service's wait-hint expires.
        Write-Host "  Stopping Oracle service ($oraServiceName) via SCM..."
        Stop-Service -Name $oraServiceName -ErrorAction SilentlyContinue
        $stopDl = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $stopDl) {
            if (-not (Get-Process -Name oracle -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Seconds 3
            Write-Host '  Waiting for oracle.exe to exit...'
        }
    }
    else {
        # ABORT was processed (success or expected error like ORA-01034).
        # oracle.exe is alive and responsive; brief pause for internal cleanup.
        Start-Sleep -Seconds 5
    }

    # Step 2 — bring the Oracle instance to OPEN state.
    if (Get-Process -Name oracle -ErrorAction SilentlyContinue) {
        # oracle.exe is running (after a successful ABORT, or Stop-Service didn't
        # terminate it within 60 s but it became responsive again).
        # Issue a plain STARTUP (uses the existing SPFILE).
        Write-Host "  Starting Oracle instance (STARTUP from SPFILE)..."
        Invoke-OracleSql 'Startup Oracle' @('STARTUP;') -TimeoutSeconds 120
    }
    else {
        # oracle.exe is not running (service was STOPPED or terminated by SCM).
        # Start-Service launches oracle.exe and runs STARTUP from the SPFILE.
        Write-Host "  Starting Oracle service ($oraServiceName)..."
        Start-Service -Name $oraServiceName
        Start-Sleep -Seconds 5   # give oracle.exe time to initialize before polling
    }

    Wait-OracleReady
    Write-Host "Oracle instance is now OPEN."
}
else {
    Write-Host "Oracle instance is OPEN."
}

# ── write ckms.toml ───────────────────────────────────────────────────────────
#
# The DLL now looks for ckms.toml in its own directory first (before falling
# back to ~/.cosmian/ckms.toml).  Since the DLL is installed at
#   C:\opt\oracle\extapi\64\pkcs11\cosmian_pkcs11.dll
# placing ckms.toml alongside it is the most reliable approach:
#   • No admin required  — the current user created that directory above
#   • No profile access  — works regardless of Oracle service account type
#   • Readable by Oracle — same ACLs that allow loading the DLL

$sid = $env:ORACLE_SID
$noBomEnc = [System.Text.UTF8Encoding]::new($false)
# ClientConfig uses #[serde(flatten)] on kms_config, so http_config is at the
# root level — NOT wrapped in [kms_config].  Correct TOML format:
#   [http_config]
#   server_url = "..."
$ckmsContent = "[http_config]`nserver_url = `"$KmsUrl`"`n"

# ── PRIMARY: write alongside the DLL ─────────────────────────────────────────
$dllSideCkmsToml = Join-Path $pkcs11Dir 'ckms.toml'
[System.IO.File]::WriteAllText($dllSideCkmsToml, $ckmsContent, $noBomEnc)
Write-Host "`nckms.toml (primary) : $dllSideCkmsToml"

# ── SECONDARY (best-effort): Oracle service user profile ─────────────────────
# cosmian_pkcs11.dll's initialize_logging() creates ~/.cosmian/ the first time
# the DLL is loaded (as a side-effect of writing the PKCS#11 log file).
# After the first Oracle startup with pkcs11_library_location configured, that
# directory will exist and UTL_FILE can write into it.
# Attempt a direct write first; fall back to UTL_FILE (runs as Oracle service
# user and therefore has write access to its own profile directory).
$serviceProfile = "C:\WINDOWS\ServiceProfiles\OracleService$sid"
$cosmianDir = "$serviceProfile\.cosmian"
$svcCkmsToml = "$cosmianDir\ckms.toml"

$directOk = $false
try {
    New-Item -ItemType Directory -Path $cosmianDir -Force -ErrorAction Stop | Out-Null
    [System.IO.File]::WriteAllText($svcCkmsToml, $ckmsContent, $noBomEnc)
    $directOk = $true
    Write-Host "ckms.toml (service profile, direct) : $svcCkmsToml"
}
catch {
    Write-Host "Direct write to service profile not permitted (expected on first run)."
    Write-Host "  -> DLL will create the directory on first load; UTL_FILE will write"
    Write-Host "  -> the file on subsequent runs.  Primary DLL-side config is in place."
}

# UTL_FILE fallback (no-op on first run if directory does not exist yet;
# succeeds on repeat runs once the DLL has created the directory).
if (-not $directOk) {
    $utlSql = Join-Path $env:TEMP 'write_ckms.sql'
    # NOTE: WHENEVER SQLERROR EXIT makes sqlplus exit non-zero on ORA errors,
    # which is caught by the $savedEAP block below.  If the directory does not
    # yet exist on this run, Oracle raises ORA-29283 (UTL_FILE.FOPEN fails) and
    # sqlplus exits 1 — we treat that as a non-fatal warning.
    @"
WHENEVER SQLERROR EXIT SQL.SQLCODE;
DECLARE
  fh UTL_FILE.FILE_TYPE;
BEGIN
  EXECUTE IMMEDIATE 'CREATE OR REPLACE DIRECTORY COSMIAN_CONF AS ''$cosmianDir''';
  fh := UTL_FILE.FOPEN('COSMIAN_CONF', 'ckms.toml', 'w');
  UTL_FILE.PUT_LINE(fh, '[http_config]');
  UTL_FILE.PUT_LINE(fh, 'server_url = "$KmsUrl"');
  UTL_FILE.FCLOSE(fh);
END;
/
EXIT;
"@ | Set-Content $utlSql -Encoding ASCII
    $savedEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $utlOut = & $sqlplusExe '/ as sysdba' "@$utlSql" 2>&1 | ForEach-Object { "$_" }
    $utlExit = $LASTEXITCODE
    $ErrorActionPreference = $savedEAP
    $utlOut | ForEach-Object { Write-Host "  [utl_file] $_" }
    Remove-Item $utlSql -ErrorAction SilentlyContinue
    if ($utlExit -eq 0) {
        Write-Host "ckms.toml (service profile, UTL_FILE) : $svcCkmsToml"
    }
    else {
        Write-Host "  (UTL_FILE write skipped — directory does not exist yet; DLL will create it on load)"
    }
}

# ── BEST-EFFORT: machine-level CKMS_CONF env var ─────────────────────────────
# If this succeeds (admin context), the Oracle service will use $svcCkmsToml
# directly rather than the DLL-side fallback.  Non-fatal if it fails.
try {
    [System.Environment]::SetEnvironmentVariable('CKMS_CONF', $svcCkmsToml, 'Machine')
    [System.Environment]::SetEnvironmentVariable('COSMIAN_PKCS11_LOGGING_LEVEL', 'trace', 'Machine')
    Write-Host "System env CKMS_CONF=$svcCkmsToml"
}
catch {
    Write-Host "(Could not set Machine-level env vars — DLL-side ckms.toml will be used instead)"
}
$env:CKMS_CONF = $dllSideCkmsToml
$env:COSMIAN_PKCS11_LOGGING_LEVEL = 'trace'

# ── determine ORACLE_BASE and wallet directory ────────────────────────────────

$oraBase = $env:ORACLE_BASE
if (-not $oraBase) {
    $regKey = 'HKLM:\SOFTWARE\Oracle\KEY_OraDB23Home1'
    $oraBase = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue).ORACLE_BASE
}
if (-not $oraBase) { $oraBase = Split-Path (Split-Path $env:ORACLE_HOME) }

$walletDir = "$oraBase\admin\$sid\wallet"
New-Item -ItemType Directory -Path $walletDir -Force | Out-Null
Write-Host "Wallet dir   : $walletDir"

# ── configure WALLET_ROOT and TDE_CONFIGURATION (SCOPE=SPFILE, no restart yet) ─
#
# Both parameters are written to SPFILE only — no restart at this point.
# They will become active together with pkcs11_library_location in the single
# PFILE restart below, reducing the total number of Oracle restarts to one.

# ── configure WALLET_ROOT, TDE_CONFIGURATION, pkcs11_library_location via PFILE ─
#
# We use CREATE PFILE FROM MEMORY (works whether the instance started from an
# SPFILE or a PFILE) and inject all three TDE/HSM parameters directly into the
# plain-text init file.  This avoids:
#   • ORA-32001  — no SPFILE when ALTER SYSTEM … SCOPE=SPFILE is attempted
#   • ORA-46707  — pkcs11_library_location prefix-check validator that rejects
#                  Windows paths (only "/opt/oracle/extapi/64/pkcs11/" prefix
#                  is accepted by Oracle 26ai's binary)

# The forward-slash value passes Oracle's prefix validation AND Windows
# LoadLibrary resolves /opt/... → C:\opt\... (drive-relative).
$pkcs11LibValue = '/opt/oracle/extapi/64/pkcs11/cosmian_pkcs11.dll'
$pfilePath = "$env:ORACLE_HOME\database\init${sid}_pkcs11.ora"
$walletRootFwd = $walletDir -replace '\\', '/'

Write-Host "`n--- Capturing current parameters to PFILE (CREATE PFILE FROM MEMORY) ---"
Invoke-OracleSql 'Create PFILE from memory' @(
    "CREATE PFILE='$pfilePath' FROM MEMORY;"
)

# Inject / update all three TDE parameters (remove stale copies first).
$pfileText = Get-Content $pfilePath -Raw
foreach ($param in @('wallet_root', 'tde_configuration', 'pkcs11_library_location')) {
    $pfileText = [regex]::Replace($pfileText, "(?mi)^\*\.$param=.*$\r?\n?", '')
}
$pfileText = $pfileText.TrimEnd()
$pfileText += "`r`n*.wallet_root='$walletRootFwd'"
$pfileText += "`r`n*.tde_configuration='KEYSTORE_CONFIGURATION=HSM'"
$pfileText += "`r`n*.pkcs11_library_location='$pkcs11LibValue'`r`n"
Set-Content -Path $pfilePath -Value $pfileText -Encoding ASCII
Write-Host "PFILE written : $pfilePath"
Write-Host "  wallet_root             = $walletRootFwd"
Write-Host "  tde_configuration       = KEYSTORE_CONFIGURATION=HSM"
Write-Host "  pkcs11_library_location = $pkcs11LibValue"

# ── restart Oracle with PFILE ─────────────────────────────────────────────────
#
# SHUTDOWN and STARTUP are issued in SEPARATE sqlplus calls.  On Windows,
# Oracle severs the named-pipe IPC connection after SHUTDOWN IMMEDIATE;
# issuing STARTUP in the same session would block forever waiting for a
# response on a dead pipe.  Each call has its own timeout so sqlplus can
# never hang the script indefinitely.

Write-Host "`n--- Restarting Oracle with PFILE (WALLET_ROOT + TDE_CONFIGURATION + pkcs11_library_location) ---"

# SHUTDOWN: use ABORT (instant) rather than IMMEDIATE.
# SHUTDOWN IMMEDIATE can hang indefinitely when background jobs (Data Pump,
# Scheduler) are running or when the system is under memory pressure that
# causes very slow checkpoint I/O.  SHUTDOWN ABORT exits without waiting for
# those operations; Oracle performs crash recovery automatically on the next
# STARTUP, which adds only a few seconds.  This is acceptable for a test setup.
#
# AllowDisconnect: Oracle severs the named-pipe connection immediately after
# ABORT; WHENEVER OSERROR may fire before sqlplus reads the response, causing
# exit code 1.  That is expected.
Invoke-OracleSql 'Shutdown Oracle' @('SHUTDOWN ABORT;') -TimeoutSeconds 30 -AllowDisconnect

# oracle.exe (the Windows service host) never exits after a DB shutdown — it
# stays alive waiting for the next STARTUP command.  A brief sleep is enough
# for Oracle to finish its internal ABORT cleanup.
Write-Host '  Waiting for Oracle shutdown cleanup...'
Start-Sleep -Seconds 5

# ── install DLL now (after SHUTDOWN so Oracle releases the write lock) ────────
# On Windows, oracle.exe stays alive after SHUTDOWN and the DLL mapping remains
# in memory, but LoadLibrary opens the file with FILE_SHARE_DELETE, which lets
# us rename the current file and copy a fresh one in its place.
# The in-memory mapping continues using the old content; the next STARTUP loads
# the new file.
Write-Host "  Installing DLL to $destDll ..."
try {
    if (Test-Path $destDll) {
        # Oracle keeps the DLL mapped between database restarts (oracle.exe never exits
        # on SHUTDOWN ABORT).  The file is opened with FILE_SHARE_DELETE so we can
        # rename it away, but we cannot delete it while oracle holds the handle.
        # Strategy: try the fixed .old name first (delete it if it's unlocked from an
        # earlier run), and fall back to a unique timestamped name if it's still locked.
        $oldDll = $destDll + '.old'
        if (Test-Path $oldDll) {
            Remove-Item $oldDll -Force -ErrorAction SilentlyContinue
            if (Test-Path $oldDll) {
                # Still locked by oracle from a prior run — use a unique name instead.
                $oldDll = $destDll + '.' + [System.DateTime]::Now.ToString('yyyyMMdd_HHmmss') + '.old'
            }
        }
        [System.IO.File]::Move($destDll, $oldDll)
        Remove-Item $oldDll -ErrorAction SilentlyContinue   # best-effort; may be locked
    }
    Copy-Item -Force $DllPath $destDll
    Copy-Item -Force $DllPath (Join-Path $extapiDir 'cosmian_pkcs11.dll')
    Write-Host "  DLL installed: $destDll"
    Write-Host "  DLL also at  : $extapiDir\cosmian_pkcs11.dll"
    # Brief pause so Windows Defender can finish scanning the newly-copied file
    # before Oracle tries to LoadLibrary it (avoids transient ORA-28376).
    Write-Host "  Waiting for antivirus scan to complete..."
    Start-Sleep -Seconds 10
}
catch {
    Write-Warning "  Could not update DLL (${_}); Oracle will use the already-loaded version."
    Write-Warning "  This is OK if the DLL was not changed since the last run."
}

Write-Host '  Oracle shut down. Starting with PFILE...'

Invoke-OracleSql 'Startup Oracle with PFILE' @("STARTUP PFILE='$pfilePath';") -TimeoutSeconds 120
Wait-OracleReady

Write-Host "`n--- Persisting configuration to SPFILE ---"
Invoke-OracleSql 'Create SPFILE from PFILE' @(
    "CREATE SPFILE FROM PFILE='$pfilePath';"
)

# ── force-restart oracle.exe to clear any cached DLL load failure ─────────────
#
# oracle.exe (the Windows service host) is a long-running process that survives
# SHUTDOWN ABORT.  If a previous PKCS#11 LoadLibrary call failed, oracle.exe may
# have cached that failure internally and will not retry — causing ORA-28376 on
# every subsequent KEYSTORE OPEN regardless of the DLL on disk.
# Stopping and starting the Windows service forces oracle.exe to exit and
# re-launch, guaranteeing a fresh LoadLibrary attempt with the new DLL.
# After service restart, the database auto-starts from SPFILE (which now has
# the correct pkcs11_library_location / wallet_root / tde_configuration).

$oraServiceName = "OracleService$sid"
Write-Host "`n--- Restarting OracleService to flush DLL load cache ---"
Write-Host "  Stopping $oraServiceName ..."
Stop-Service -Name $oraServiceName -Force -ErrorAction SilentlyContinue

# Wait for oracle.exe to fully exit (up to 60 s)
$exitDl = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $exitDl) {
    if (-not (Get-Process -Name oracle -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 3
    Write-Host '  Waiting for oracle.exe to exit...'
}

Write-Host "  Starting $oraServiceName ..."
Start-Service -Name $oraServiceName
# The Oracle Windows service automatically runs STARTUP from SPFILE on start.
# Give oracle.exe a moment before polling.
Start-Sleep -Seconds 5
Wait-OracleReady

# ── seed KMS with placeholder keys for stale master-key references ───────────
#
# After STARTUP PFILE, Oracle's keystore is CLOSED but the database is OPEN.
# V$DATABASE_KEY_INFO exposes any master-key IDs that are stored in the
# datafile headers from previous KMS instances (e.g. a Docker-based KMS that
# no longer exists).  When a fresh KMS SQLite database has none of those keys,
# KEYSTORE OPEN fails with ORA-28353 because Oracle checks that each activated
# master key EXISTS in the HSM (PKCS#11 C_FindObjects by CKA_LABEL).
#
# Fix: import a random AES-256 placeholder into the fresh KMS under the KMIP
# unique ID "ORACLE.TDE.HSM.MK.<stale_key_id>".  The Cosmian PKCS#11 module
# maps Oracle's "ORACLE.SECURITY.KM.ENCRYPTION.<hex>" CKA_LABEL lookups to
# exactly that UID format, so C_FindObjects succeeds.  Oracle only checks
# existence — it does NOT call C_Decrypt during KEYSTORE OPEN, so a random
# placeholder passes the check.  The subsequent SET KEY then creates a real
# new master key that replaces all stale references in the datafiles.
#
# On repeat runs the placeholder import is a no-op: the import command is
# issued without --replace, so it fails silently if the real key already exists.

Write-Host "`n--- Seeding KMS with placeholders for stale TDE master keys ---"

$tmpStaleKeysSql = Join-Path $env:TEMP 'stale_keys.sql'
$tmpStaleKeysOut = Join-Path $env:TEMP 'stale_keys.out'
$tmpStaleKeysErr = Join-Path $env:TEMP 'stale_keys.err'
# Prefix each row with '06' to reconstruct the full 17-byte key ID that Oracle
# passes to the PKCS#11 module.  V$DATABASE_KEY_INFO strips the leading version
# byte (0x06 = AES256), so we restore it here.
@"
SET HEADING OFF FEEDBACK OFF PAGESIZE 0 TRIMSPOOL ON LINESIZE 200
SELECT TRIM('06' || MASTERKEYID)
FROM V`$DATABASE_KEY_INFO
WHERE ENCRYPTIONALG != 'NONE'
  AND MASTERKEYID != '00000000000000000000000000000000';
EXIT;
"@ | Set-Content -Path $tmpStaleKeysSql -Encoding ASCII

# Use a single argument string (same technique as Invoke-OracleSql) so that
# Windows CRT receives exactly two args: '/ as sysdba' and '@script.sql'.
$staleArgStr = "-s `"/ as sysdba`" `"@$tmpStaleKeysSql`""
$staleProc = Start-Process -FilePath $sqlplusExe `
    -ArgumentList $staleArgStr `
    -NoNewWindow -PassThru `
    -RedirectStandardOutput $tmpStaleKeysOut `
    -RedirectStandardError  $tmpStaleKeysErr
$null = $staleProc.WaitForExit(30000)   # 30 s timeout for simple SELECT

$staleKeyIds = (Get-Content $tmpStaleKeysOut -ErrorAction SilentlyContinue) |
Where-Object { $_ -match '^06[0-9A-Fa-f]{32}' } |
ForEach-Object { $_.Trim() } |
Select-Object -Unique
Remove-Item $tmpStaleKeysSql, $tmpStaleKeysOut, $tmpStaleKeysErr -ErrorAction SilentlyContinue

$ckmsExe = Join-Path $RepoRoot 'target\debug\ckms.exe'

if ($staleKeyIds) {
    Write-Host "  Found $($staleKeyIds.Count) stale key ID(s): $($staleKeyIds -join ', ')"

    if (-not (Test-Path $ckmsExe)) {
        Write-Host "  WARNING: ckms.exe not found at $ckmsExe"
        Write-Host "           KEYSTORE OPEN may fail.  Build with: cargo build -p ckms --release"
    }
    else {
        # One random 32-byte placeholder is re-used for all stale keys.
        # Oracle KEYSTORE OPEN only verifies existence (C_FindObjects), not
        # functional decryption, so any 256-bit value passes the check.
        # Use RNGCryptoServiceProvider.GetBytes — compatible with both
        # .NET Framework 4.x (PowerShell 5.1) and .NET 5+/Core.
        $randBytes = [byte[]]::new(32)
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        try { $rng.GetBytes($randBytes) } finally { $rng.Dispose() }
        $fakKeyFile = Join-Path $env:TEMP 'fake_tde_placeholder.bin'
        [System.IO.File]::WriteAllBytes($fakKeyFile, $randBytes)

        # ckms.exe reads its config from the CKMS_CONF environment variable.
        # At this point $env:CKMS_CONF points to the Oracle service user's
        # profile (C:\WINDOWS\ServiceProfiles\...) which the current user cannot
        # read.  Write a minimal ckms.toml to TEMP so the ckms commands work.
        $tmpCkmsDir = Join-Path $env:TEMP 'cosmian_kms_seed'
        $tmpCkmsToml = Join-Path $tmpCkmsDir 'ckms.toml'
        New-Item -ItemType Directory -Path $tmpCkmsDir -Force | Out-Null
        # Write WITHOUT BOM: PowerShell 5.1's Set-Content -Encoding UTF8 adds a
        # UTF-8 BOM which breaks TOML parsers (parse error at line 1 col 1).
        $noBomEnc = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText(
            $tmpCkmsToml,
            "[kms_config.http_config]`nserver_url = `"$KmsUrl`"`n",
            $noBomEnc
        )
        $savedCkmsConf = $env:CKMS_CONF
        $env:CKMS_CONF = $tmpCkmsToml

        foreach ($keyId in $staleKeyIds) {
            $kmipUid = "ORACLE.TDE.HSM.MK.$keyId"
            Write-Host "  Importing placeholder for: $kmipUid"
            # Import WITHOUT --replace: if the real key already exists from a
            # prior successful run the import fails silently and the real key
            # is preserved.
            # Use ErrorActionPreference = Continue so that ErrorRecord objects
            # in the 2>&1-merged output don't throw with 'Stop' mode.
            $savedEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $ckmsOut = & $ckmsExe --kms-url $KmsUrl `
                kms sym keys import `
                -f aes `
                $fakKeyFile $kmipUid 2>&1
            $ErrorActionPreference = $savedEAP
            $ckmsStr = ($ckmsOut | ForEach-Object { "$_" }) -join ' '
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    ckms: placeholder imported."
            }
            elseif ($ckmsStr -match 'already exist') {
                Write-Host "    (key already exists in KMS — real key preserved, no placeholder needed)"
            }
            else {
                Write-Warning "    ckms import warning (exit $LASTEXITCODE): $ckmsStr"
            }
        }
        Remove-Item $fakKeyFile -ErrorAction SilentlyContinue

        # Restore original CKMS_CONF (may be needed for subsequent operations).
        $env:CKMS_CONF = $savedCkmsConf
        Remove-Item $tmpCkmsToml -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host "  No stale master keys found (clean database or all keys already in KMS)."
}

# ── open HSM keystore ─────────────────────────────────────────────────────────

Write-Host "`n--- Opening HSM keystore (loads cosmian_pkcs11.dll) ---"
Invoke-OracleSql 'Open HSM keystore' @(
    'ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;'
)

# ── bootstrap TDE_MASTER_KEY_ID in props$ if missing ─────────────────────────
#
# After KEYSTORE OPEN the database may be in an inconsistent state from a prior
# partial run: TDE_PRIMARY_KEYSTORE=HSM is set (written by the first KEYSTORE
# OPEN that ever ran) but TDE_MASTER_KEY_ID is absent because the prior SET KEY
# crashed or was interrupted before completing.
#
# Oracle's rekey path (triggered when the control file already has a master key
# record) calls kzthsmgmkid(), which reads TDE_MASTER_KEY_ID from props$.  If
# the entry is missing Oracle raises ORA-00600 [TDE_MASTER_KEY_ID entry not in
# props$] before it ever calls C_GenerateKey.
#
# Fix: if TDE_PRIMARY_KEYSTORE=HSM exists but TDE_MASTER_KEY_ID is absent,
# bootstrap it from V$DATABASE_KEY_INFO.  The corresponding placeholder key was
# already imported into the KMS above, so C_FindObjects will succeed when
# Oracle searches for it during the rekey.

Write-Host "`n--- Bootstrapping TDE_MASTER_KEY_ID in props$ if missing ---"
Invoke-OracleSql 'Bootstrap TDE_MASTER_KEY_ID in props$ if missing' @(
    'INSERT INTO sys.props$(name, value$, comment$)',
    'SELECT ''TDE_MASTER_KEY_ID'', ''06'' || MASTERKEYID,',
    '       ''TDE Master Key ID bootstrapped for HSM first keying''',
    'FROM V$DATABASE_KEY_INFO',
    'WHERE ENCRYPTIONALG != ''NONE''',
    '  AND MASTERKEYID != ''00000000000000000000000000000000''',
    '  AND ROWNUM = 1',
    '  AND NOT EXISTS (SELECT 1 FROM sys.props$ WHERE name = ''TDE_MASTER_KEY_ID'')',
    '  AND EXISTS    (SELECT 1 FROM sys.props$',
    '                 WHERE  name = ''TDE_PRIMARY_KEYSTORE'' AND value$ = ''HSM'');',
    'COMMIT;'
)

# ── set TDE master key ────────────────────────────────────────────────────────

Write-Host "`n--- Setting TDE master key in HSM ---"
# Creates a new AES-256 master key in the Cosmian KMS via PKCS#11 (C_GenerateKey).
# This replaces any stale master-key reference in the datafile headers with a
# freshly-generated key that the KMS actually owns.
Invoke-OracleSql 'Set TDE master key' @(
    'ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY hsm_identity_pass;'
)

# ── verify ────────────────────────────────────────────────────────────────────

Write-Host "`n--- Verifying wallet and key status ---"
Show-OracleWallet

$traceDir = "$oraBase\diag\rdbms\$($sid.ToLower())\$sid\trace"

Write-Host "`n=== Oracle TDE configuration with Cosmian PKCS#11 DLL complete ==="
Write-Host @"

Key files:
  DLL (active)   : $destDll
  DLL (reference): $extapiDir\cosmian_pkcs11.dll
  ckms.toml (DLL): $dllSideCkmsToml
  ckms.toml (svc): $svcCkmsToml
  PFILE          : $pfilePath
  Wallet dir     : $walletDir

Troubleshooting:
  Oracle alert   : $traceDir\alert_${sid}.log
  Oracle traces  : $traceDir\
  PKCS#11 log    : $serviceProfile\.cosmian\cosmian-pkcs11.log  (service user)
                   $env:USERPROFILE\.cosmian\cosmian-pkcs11.log  (current user)

Oracle 26ai Windows HSM workarounds applied:
  * skgdllDiscover — no Windows scan path in binary; bypassed via pkcs11_library_location
  * pkcs11_library_location prefix check — satisfied by using /opt/oracle/... path
    which Windows LoadLibrary resolves to C:\opt\oracle\... (drive-relative)
  * ALTER SYSTEM SET validator — bypassed by editing a plain PFILE + STARTUP PFILE=
"@

# Reset $LASTEXITCODE: the ckms.exe calls earlier in this script may have left a
# non-zero value (e.g. "key already exists" is a non-zero exit from ckms) even
# though everything succeeded.  Subsequent Invoke-OracleSql calls use Start-Process
# which does NOT update $LASTEXITCODE, so the stale value would mislead callers
# (like test_oracle_tde.ps1) into thinking the script failed.
$global:LASTEXITCODE = 0
