# ============================================================================
# hsm_common.ps1 -- helpers shared by test_hsm_idemia.ps1 and test_hsm_other.ps1.
#
# Dot-source it:  . (Join-Path $PSScriptRoot "hsm_common.ps1")
# Expects $RepoRoot to be set by the caller. Runs under Windows PowerShell 5.1 and PowerShell 7.
#
# FIPS variant. The KMS then loads the OpenSSL FIPS provider (fips.dll, built by
# .mise\scripts\windows\prepare_windows_fips_provider.ps1) through OPENSSL_CONF /
# OPENSSL_MODULES. Those variables must NOT be set for the loader tests (they use a plain
# OpenSSL) and are therefore handed only to the KMS steps, with Invoke-WithEnv.
# An OpenSSL-based PKCS#11 backend (SoftHSM2, also behind the Idemia simulator) running in the
# same process would load that same fips.dll twice and fail (SoftHSM2 answers CKR_PIN_INCORRECT),
# so every KMS step reaches its HSM through the IV shim, which sets
# SHIM_BACKEND_ISOLATE_OPENSSL (see .mise\scripts\test\pkcs11_fips_iv_shim.c).
# ============================================================================

# A previous CI step may have exported the FIPS configuration to every later step: drop it, the
# KMS steps get it explicitly (Invoke-WithEnv), the loader tests and builds must not see it.
Remove-Item Env:OPENSSL_CONF -ErrorAction SilentlyContinue
Remove-Item Env:OPENSSL_MODULES -ErrorAction SilentlyContinue

function Write-Step { param([string]$Msg) Write-Host "`n=== $Msg ===" -ForegroundColor Cyan }

# Run cargo and fail on a non-zero exit code. cargo writes its progress on stderr:
# Windows PowerShell 5.1 would turn that into a terminating error under "Stop".
function Invoke-Cargo {
    param([string[]]$CargoArgs)
    Write-Host "> cargo $($CargoArgs -join ' ')"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & cargo @CargoArgs 2>&1 | ForEach-Object { Write-Host "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { throw "cargo $($CargoArgs -join ' ') failed with exit code $code" }
}

function Import-DotEnv {
    param([string]$Path)
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^([A-Z0-9_]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
    }
}

# Read a dotenv file into a hashtable without touching the process environment.
function Read-DotEnv {
    param([string]$Path)
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^([A-Z0-9_]+)=(.*)$') { $values[$Matches[1]] = $Matches[2] }
    }
    return $values
}

# Run a script block with extra environment variables, restoring the previous values afterwards.
function Invoke-WithEnv {
    param([hashtable]$Vars, [scriptblock]$Block)
    $saved = @{}
    foreach ($name in $Vars.Keys) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, [string]$Vars[$name], "Process")
    }
    try {
        & $Block
    } finally {
        foreach ($name in $Vars.Keys) {
            [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process")
        }
    }
}

# vcpkg manifest mode installs to vcpkg_installed\<triplet> (project-relative);
# classic mode installs to %VCPKG_INSTALLATION_ROOT%\packages\<port>_<triplet>.
function Set-BuildEnv {
    $manifestDir = Join-Path (Get-Location) "vcpkg_installed\x64-windows-static"
    if (Test-Path $manifestDir) {
        $env:OPENSSL_DIR = $manifestDir
    } elseif ($env:VCPKG_INSTALLATION_ROOT) {
        $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    }
    $env:RUST_LOG = "cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"
}

# Build the IV shim variants shim-v2, shim-v3 and shim-v3-stubs into <OutDir>\gen (a module that
# generates the GCM IV and refuses a caller IV: FIPS behaviour) and <OutDir>\accept (a module
# that accepts the caller's IV: non-FIPS behaviour, -DACCEPT_CALLER_IV).
# gcc (mingw) is preferred; MSVC (cl through vcvars64.bat) is the fallback.
function New-IvShims {
    param([string]$OutDir)
    $source = Join-Path $RepoRoot ".mise\scripts\test\pkcs11_fips_iv_shim.c"
    $variants = [ordered]@{
        "shim-v2"       = @()
        "shim-v3"       = @("V3_MESSAGE")
        "shim-v3-stubs" = @("V3_MESSAGE", "MESSAGE_INIT_NOT_SUPPORTED")
    }
    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
    foreach ($policy in @("gen", "accept")) {
        $dir = Join-Path $OutDir $policy
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $policyDefines = if ($policy -eq "accept") { @("ACCEPT_CALLER_IV") } else { @() }
        foreach ($name in $variants.Keys) {
            $out = Join-Path $dir "$name.dll"
            $defines = @($variants[$name]) + $policyDefines
            if ($gcc) {
                $gccArgs = @("-shared", "-O2", "-Wall", "-Wextra", "-Wno-cast-function-type") +
                    ($defines | ForEach-Object { "-D$_" }) + @("-o", $out, $source, "-lbcrypt")
                & $gcc.Source @gccArgs
                if ($LASTEXITCODE -ne 0) { throw "gcc failed building $policy\$name" }
            } else {
                $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
                $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
                if (-not $vsPath) { throw "neither gcc nor MSVC found: cannot build the IV shim" }
                $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
                $clDefines = ($defines | ForEach-Object { "/D$_" }) -join " "
                $objDir = Join-Path $dir "obj-$name"
                New-Item -ItemType Directory -Force -Path $objDir | Out-Null
                cmd /c "`"$vcvars`" >nul && cl /nologo /LD /O2 $clDefines /Fo`"$objDir\\`" /Fe`"$out`" `"$source`" bcrypt.lib"
                if ($LASTEXITCODE -ne 0) { throw "cl failed building $policy\$name" }
            }
        }
    }
}

# The IV shim writes its calls to the file named by FIPS_IV_SHIM_MARKER. The KMS in FIPS mode must
# only ever hand the module an all-zero GCM IV buffer and receive a generated IV back.
function Assert-ShimMarker {
    param([string]$Path, [string[]]$Require, [string[]]$Forbid = @())
    if (-not (Test-Path -LiteralPath $Path)) { throw "the IV shim wrote no marker file ($Path): the HSM was not reached through the shim" }
    $lines = @(Get-Content -LiteralPath $Path)
    foreach ($needle in $Require) {
        if (-not ($lines -contains $needle)) { throw "shim marker $Path lacks '$needle'" }
    }
    foreach ($needle in $Forbid) {
        if ($lines -contains $needle) { throw "shim marker $Path contains forbidden '$needle'" }
    }
    $summary = ($lines | Group-Object | ForEach-Object { "$($_.Count) x $($_.Name)" }) -join "; "
    Write-Host "Shim marker OK: $summary"
}

# FIPS variant: every GCM encryption init handed a zero IV buffer and the shim generated each IV.
function Assert-HsmGeneratedIvs {
    param([string]$Path)
    Assert-ShimMarker -Path $Path -Require @("gcm-iv-zero", "gcm-iv-generated") -Forbid @("gcm-iv-nonzero", "gcm-iv-invalid")
    $lines = @(Get-Content -LiteralPath $Path)
    $zero = @($lines | Where-Object { $_ -eq "gcm-iv-zero" }).Count
    $generated = @($lines | Where-Object { $_ -eq "gcm-iv-generated" }).Count
    if ($zero -ne $generated) { throw "$zero zero-IV GCM inits but $generated generated IVs in $Path" }
}

# Start a real cosmian_kms.exe with the given TOML, wait for GET /version, then stop it.
function Test-RealKmsStart {
    param(
        [string]$ConfFile,
        [int]$Port,
        [string]$LogFile,
        [hashtable]$ExtraEnv = @{}
    )
    $kmsExe = Join-Path $RepoRoot "target\debug\cosmian_kms.exe"
    if (-not (Test-Path $kmsExe)) { throw "KMS binary not found at $kmsExe" }
    Invoke-WithEnv $ExtraEnv {
        $kms = Start-Process -FilePath $kmsExe -ArgumentList "-c", $ConfFile -PassThru -NoNewWindow `
            -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err"
        try {
            $up = $false
            $deadline = (Get-Date).AddSeconds(60)
            while ((Get-Date) -lt $deadline -and -not $kms.HasExited) {
                try {
                    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/version" -Method GET -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
                    if ($resp.StatusCode -eq 200) { $up = $true; break }
                } catch { }
                Start-Sleep -Milliseconds 500
            }
            if (-not $up) {
                if (Test-Path "$LogFile.err") { Get-Content "$LogFile.err" | Select-Object -First 40 | Write-Host }
                throw "cosmian_kms.exe did not answer on http://127.0.0.1:$Port/version within 60 s"
            }
            Write-Host "GET /version -> 200: $($resp.Content)"
        } finally {
            if (-not $kms.HasExited) {
                Stop-Process -Id $kms.Id -Force -ErrorAction SilentlyContinue
                $kms.WaitForExit(5000) | Out-Null
            }
        }
    }
}

# Write a minimal KMS TOML (SQLite, plain HTTP on 127.0.0.1) for a real-binary start.
function New-KmsConf {
    param([string]$WorkDir, [int]$Port, [string]$Model, [string]$Slot, [string]$Password)
    if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
    $sqlitePath = Join-Path $WorkDir "data"
    New-Item -ItemType Directory -Force -Path $sqlitePath | Out-Null
    # Top-level keys must precede the tables. Backslashes are doubled for TOML string escaping.
    $escapedSqlite = $sqlitePath -replace '\\', '\\\\'
    $confFile = Join-Path $WorkDir "kms.toml"
    @"
hsm_model = "$Model"
hsm_admin = ["admin"]
hsm_slot = [$Slot]
hsm_password = ["$Password"]

[db]
database_type = "sqlite"
sqlite_path = "$escapedSqlite"

[http]
port = $Port
hostname = "127.0.0.1"
"@ | Set-Content -Path $confFile -Encoding ASCII
    return $confFile
}

# The Idemia simulator cfg is fixed at staging time: the variant must match it.
function Assert-SimulatorSecurityLevel {
    param([string]$Expected)
    $cfg = "C:\Idemia_HSM_Simulator\rooky-simulator.cfg"
    $line = Select-String -LiteralPath $cfg -Pattern '^\s*SECURITY_LEVEL\s*=\s*(\S+)' | Select-Object -First 1
    if (-not $line) { throw "no SECURITY_LEVEL in $cfg" }
    $actual = $line.Matches[0].Groups[1].Value
    if ($actual -ne $Expected) {
        throw "the staged simulator runs SECURITY_LEVEL=$actual but this run needs ${Expected}: re-stage it with prepare_idemia_hsm.ps1 -SecurityLevel $Expected"
    }
}
