# ============================================================================
# test_hsm_other.ps1 -- KMS startup against hsm_model = "other" PKCS#11 backends (Windows).
#
# Windows counterpart of .mise/tasks/test/hsm/other: SoftHSM2 (C:\SoftHSMv2, staged by
# .github\reusable_scripts\prepare_idemia_hsm.ps1) sits behind the IV shim
# (.mise\scripts\test\pkcs11_fips_iv_shim.c), which models who generates the AES-GCM IV:
#
#   -Fips (default build, OpenSSL FIPS provider = fips.dll)
#       gen shim      the module generates every IV and refuses a caller IV: the KMS boots with an
#                     HSM-held AES-GCM KEK and a GCM user key round-trips (PKCS#11 v2, v3 and v3
#                     with stubbed message functions);
#       plain module  the zero IV the KMS sends comes back unchanged (accept shim = passthrough):
#                     the KMS refuses the AES-GCM KEK at startup rather than send its own IV.
#   default (--features non-fips)
#       accept shim   the KMS chooses the IV and the module accepts it: boots and round-trips;
#       gen shim      a module that refuses caller IVs: the KMS refuses the KEK, naming
#                     key_encryption_key_wrapping_algorithm = "aes-key-wrap-padding".
#
# Usage (from the repository root):
#   .\.mise\scripts\windows\test_hsm_other.ps1 [-Fips] [-PackageDir <dir>]
# Runs under Windows PowerShell 5.1 and PowerShell 7.
# ============================================================================
param(
    [string]$PackageDir = $env:IDEMIA_SIM_PACKAGE_DIR,
    [switch]$Fips
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $RepoRoot
. (Join-Path $PSScriptRoot "hsm_common.ps1")

$ShimDir = Join-Path $RepoRoot "target\shim\other"
$SoftHsmLib = "C:\SoftHSMv2\lib\softhsm\libsofthsm2.dll"
$FeatureArgs = if ($Fips) { @() } else { @("--features", "non-fips") }
$Variant = if ($Fips) { "FIPS" } else { "non-FIPS" }

Set-BuildEnv

# -- SoftHSM2 token -----------------------------------------------------------
if (-not (Test-Path -LiteralPath $SoftHsmLib) -or -not $env:HSM_SLOT_ID) {
    Write-Step "Staging SoftHSM2 and a fresh token"
    $prepare = Join-Path $RepoRoot ".github\reusable_scripts\prepare_idemia_hsm.ps1"
    $prepareArgs = @{}
    if ($PackageDir) { $prepareArgs["PackageDir"] = $PackageDir }
    & $prepare @prepareArgs
    Import-DotEnv (Join-Path $RepoRoot ".idemia-sim\env")
}
$env:PATH = "C:\SoftHSMv2\bin;$env:PATH"
foreach ($name in @("SOFTHSM2_CONF", "HSM_SLOT_ID", "HSM_USER_PASSWORD")) {
    if (-not (Test-Path "env:$name")) { throw "$name is not set: SoftHSM2 is not staged" }
}
$env:HSM_MODEL = "other"

# -- FIPS provider and IV shims -----------------------------------------------
Write-Step "IV shims ($Variant)"
New-IvShims -OutDir $ShimDir
$BaseEnv = @{ SHIM_BACKEND_LIB = $SoftHsmLib }
if ($Fips) {
    & (Join-Path $RepoRoot ".mise\scripts\windows\prepare_windows_fips_provider.ps1")
    $fipsEnv = Read-DotEnv (Join-Path $RepoRoot ".openssl-fips\env")
    # SoftHSM2 loads its own OpenSSL: it must not load the KMS's FIPS provider into the same process.
    $BaseEnv["OPENSSL_CONF"] = $fipsEnv["OPENSSL_CONF"]
    $BaseEnv["OPENSSL_MODULES"] = $fipsEnv["OPENSSL_MODULES"]
    $BaseEnv["SHIM_BACKEND_ISOLATE_OPENSSL"] = "1"
}

# Run one test against a shim; returns the marker path.
function Invoke-OtherTest {
    param([string]$Policy, [string]$Mode, [string]$TestName)
    $marker = Join-Path $ShimDir "other-$Policy-$Mode-$TestName.txt"
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
    $vars = $BaseEnv.Clone()
    $vars["OTHER_HSM_PKCS11_LIB"] = Join-Path $ShimDir "$Policy\shim-$Mode.dll"
    $vars["FIPS_IV_SHIM_MARKER"] = $marker
    Invoke-WithEnv $vars {
        Invoke-Cargo (@("test", "-p", "test_kms_server") + $FeatureArgs + @("--lib", "--",
            "--ignored", "--exact", "hsm_startup_tests::$TestName", "--nocapture"))
    }
    return $marker
}

# What each PKCS#11 flavour must have exercised: v2 has no message API; v3 attempts it (and falls
# back to classic GCM); v3 with stubbed message functions also attempts the message decrypt.
function Get-ModeMarkers {
    param([string]$Mode)
    switch ($Mode) {
        "v2"       { return @{ Require = @("classic-encrypt-init"); Forbid = @("message-encrypt-init") } }
        "v3"       { return @{ Require = @("classic-encrypt-init", "message-encrypt-init"); Forbid = @() } }
        "v3-stubs" { return @{ Require = @("classic-encrypt-init", "message-encrypt-init", "message-decrypt-init"); Forbid = @() } }
    }
}

$modes = @("v2", "v3", "v3-stubs")
foreach ($mode in $modes) {
    $policy = if ($Fips) { "gen" } else { "accept" }
    Write-Step "$policy shim, PKCS#11 $mode ($Variant)"
    $expected = Get-ModeMarkers $mode
    foreach ($test in @("test_startup_with_hsm_kek_other", "test_hsm_kek_gcm_user_key_round_trip_other")) {
        $marker = Invoke-OtherTest -Policy $policy -Mode $mode -TestName $test
        if ($Fips) {
            Assert-ShimMarker -Path $marker -Require ($expected.Require + @("gcm-iv-zero", "gcm-iv-generated")) `
                -Forbid ($expected.Forbid + @("gcm-iv-nonzero", "gcm-iv-invalid"))
        } else {
            Assert-ShimMarker -Path $marker -Require ($expected.Require + @("gcm-iv-nonzero")) `
                -Forbid ($expected.Forbid + @("gcm-iv-generated"))
        }
    }
}

if ($Fips) {
    Write-Step "FIPS: a module that does not generate the GCM IV is refused"
    $marker = Invoke-OtherTest -Policy "accept" -Mode "v2" -TestName "test_startup_with_hsm_kek_other_without_iv_generation"
    Assert-ShimMarker -Path $marker -Require @("gcm-iv-zero") -Forbid @("gcm-iv-generated", "gcm-iv-nonzero")
} else {
    Write-Step "non-FIPS: a module that refuses caller IVs is refused"
    $marker = Invoke-OtherTest -Policy "gen" -Mode "v2" -TestName "test_startup_with_hsm_kek_other_refusing_caller_iv"
    Assert-ShimMarker -Path $marker -Require @("gcm-iv-nonzero")
}

Write-Host "`nhsm_model=other startup scenarios ($Variant): all steps passed" -ForegroundColor Green
