# ============================================================================
# test_hsm_idemia.ps1 -- KMS tests on the Idemia SPHERE HSM simulator (Windows).
#
# The Idemia HSM Simulator is a Windows-only PKCS#11 DLL forwarding to SoftHSM2. It runs in
# one of two security levels, selected by -Fips:
#
#   default  SECURITY_LEVEL=NON_FIPS, KMS built with --features non-fips.
#   -Fips    SECURITY_LEVEL=FIPS, KMS built without `non-fips`, running against the OpenSSL FIPS
#            provider (fips.dll, built by .mise\scripts\windows\prepare_windows_fips_provider.ps1).
#            The simulator then offers no AES key wrap and does not generate AES-GCM IVs, so the
#            KMS-side tests reach it through the IV shim (.mise\scripts\test\pkcs11_fips_iv_shim.c),
#            which plays a FIPS module that generates the IV (see hsm_common.ps1 for why the shim
#            also isolates the backend from the KMS's OPENSSL_CONF).
#
# Steps (each with the build variant above):
#   1. the loader tests,
#   2. the server tests::hsm::test_hsm_all,
#   3. the HSM test vectors,
#   4. the KMS startup with an HSM-held KEK (-Fips: the IV-generating module boots, and a module
#      that does not generate the IV is refused),
#   5. the shared-server suite (normal launch),
#   6. the shared-server suite (KMS_HSM_KEK=1: the KEK is held by the HSM),
#   7. a real cosmian_kms.exe start with hsm_model = "idemia_sphere".
#
# Usage (from the repository root):
#   .\.mise\scripts\windows\test_hsm_idemia.ps1 [-Fips] [-PackageDir <dir with librooky-simulator.dll, ...>]
#
# Without -PackageDir (nor $env:IDEMIA_SIM_PACKAGE_DIR) prepare_idemia_hsm.ps1 uses the
# hsm-idemia-simulator.zip shipped in the reusable_scripts submodule. When IDEMIA_SPHERE_PKCS11_LIB
# is already exported (CI), the simulator
# must have been staged with the matching security level.
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

$KMS_PORT = 9997
$SIM_LOG = "C:\Idemia_HSM_Simulator\log\HSM_simulator.log"
$ShimDir = Join-Path $RepoRoot "target\shim\idemia"
$TOTAL = 7

if ($Fips) {
    $SecurityLevel = "FIPS"
    $FeatureArgs = @()
} else {
    $SecurityLevel = "NON_FIPS"
    $FeatureArgs = @("--features", "non-fips")
}
# The loader tests enable the `idemia_sphere` feature too.
$LoaderFeatures = if ($Fips) { "idemia_sphere" } else { "idemia_sphere non-fips" }

Set-BuildEnv

# -- Simulator ----------------------------------------------------------------
if (-not $env:IDEMIA_SPHERE_PKCS11_LIB) {
    Write-Step "Staging the Idemia HSM simulator ($SecurityLevel)"
    Initialize-SoftHsmStaging -PackageDir $PackageDir -PrepareArgs @{ SecurityLevel = $SecurityLevel }
}
foreach ($name in @("IDEMIA_SPHERE_PKCS11_LIB", "HSM_MODEL", "HSM_SLOT_ID", "HSM_USER_PASSWORD")) {
    if (-not (Test-Path "env:$name")) { throw "$name is not set: the Idemia simulator is not staged" }
}
Assert-SimulatorSecurityLevel -Expected $SecurityLevel
$SimLib = $env:IDEMIA_SPHERE_PKCS11_LIB
Write-Host "Simulator ($SecurityLevel): $SimLib (slot $env:HSM_SLOT_ID)"

# -- FIPS: provider + IV shims, and the environment of every KMS step ----------
$KmsEnv = @{}
$MarkerBase = Join-Path $ShimDir "idemia"
if ($Fips) {
    Write-Step "FIPS provider and IV shims"
    $KmsEnv = Initialize-FipsHsmEnv -ShimDir $ShimDir -Backend @{ SHIM_BACKEND_LIB = $SimLib }
}
$ShimCommon = @{ ShimDir = $ShimDir; BaseEnv = $KmsEnv; LibVar = "IDEMIA_SPHERE_PKCS11_LIB" }

# -- Tests --------------------------------------------------------------------
Write-Step "1/$TOTAL Loader tests"
Invoke-Cargo @("test", "-p", "idemia_sphere_pkcs11_loader", "--features", $LoaderFeatures, "--",
    "--nocapture", "tests::test_hsm_idemia_sphere_all", "--ignored", "--exact")

# Skipped in both shared-server launches: the two tests running the `hsm_kek` Synology vector (it
# runs as soon as HSM_SLOT_ID is set) fail on their Register step with a KMIP parse error, before
# any HSM call (`Unknown enumeration value: 0x004200a1 for SecretDataType`); the Linux SoftHSM2
# replay (.mise/lib/softhsm2.sh, run_db_softhsm2_tests) skips them too. Tracked as a separate bug.
$SynologySkips = @(
    "--skip", "vector_runner::tests::test_integration_synology_dsm",
    "--skip", "vector_runner::tests::test_vec_synology_dsm")

# The KMS steps. In -Fips mode they run behind the IV-generating shim (ivEnv); otherwise directly.
$ivEnv = @{}
if ($Fips) {
    $ivMarker = "$MarkerBase-iv.txt"
    $ivEnv = Get-ShimEnv @ShimCommon -Variant "gen\shim-v2" -Marker $ivMarker
}

Write-Step "2/$TOTAL Server key-level HSM tests"
# HSM_GENERATES_GCM_IV is read at compile time by the server's own tests only
# (hsm_cannot_generate_gcm_iv): it tells them the shim in front of the module generates the IV.
$step2Env = $ivEnv.Clone()
if ($Fips) { $step2Env["HSM_GENERATES_GCM_IV"] = "1" }
Invoke-KmsTest -Env $step2Env -Features $FeatureArgs -CargoTestArgs @("-p", "cosmian_kms_server", "--",
    "tests::hsm::test_hsm_all", "--ignored", "--exact", "--nocapture")

Write-Step "3/$TOTAL HSM test vectors"
Invoke-KmsTest -Env $ivEnv -Features $FeatureArgs -CargoTestArgs @("-p", "test_kms_server", "--lib", "--", "test_vec_hsm", "--nocapture")

Write-Step "4/$TOTAL KMS startup with an HSM-held KEK"
if ($Fips) {
    # The simulator cannot generate GCM IVs itself: behind the shim (which generates them) the
    # AES-GCM KEK boots and every IV is HSM-generated.
    Invoke-KmsTest -Env $ivEnv -CargoTestArgs @("-p", "test_kms_server", "--lib", "--", "--ignored", "--exact",
        "hsm_startup_tests::test_startup_with_hsm_kek_idemia_sphere_simulator_iv_layer", "--nocapture")
    Assert-HsmGeneratedIvs -Path $ivMarker
} else {
    Invoke-KmsTest -Features $FeatureArgs -CargoTestArgs @("-p", "test_kms_server", "--lib", "--",
        "--ignored", "--exact", "hsm_startup_tests::test_startup_with_hsm_kek_idemia_sphere_simulator", "--nocapture")
}

Write-Step "5/$TOTAL Shared-server suite (normal launch)"
Remove-Item Env:KMS_HSM_KEK -ErrorAction SilentlyContinue
Invoke-KmsTest -Env $ivEnv -Features $FeatureArgs -CargoTestArgs (@("--lib", "-p", "test_kms_server", "--", "--nocapture") + $SynologySkips)

Write-Step "6/$TOTAL Shared-server suite (HSM-held KEK, KMS_HSM_KEK=1)"
# KMS_HSM_KEK is read at runtime by the singleton test server, hence a separate cargo invocation.
$env:KMS_HSM_KEK = "1"
try {
    Invoke-KmsTest -Env $ivEnv -Features $FeatureArgs -CargoTestArgs (@("--lib", "-p", "test_kms_server", "--", "--nocapture") + $SynologySkips)
} finally {
    Remove-Item Env:KMS_HSM_KEK -ErrorAction SilentlyContinue
}
if ($Fips) { Assert-HsmGeneratedIvs -Path $ivMarker }

Write-Step "7/$TOTAL Real cosmian_kms.exe start with hsm_model = idemia_sphere"
Invoke-Cargo (@("build", "-p", "cosmian_kms_server", "--bin", "cosmian_kms") + $FeatureArgs)
$work = Join-Path $env:TEMP "kms-idemia-test"
$confFile = New-KmsConf -WorkDir $work -Port $KMS_PORT -Model "idemia_sphere" -Slot $env:HSM_SLOT_ID -Password $env:HSM_USER_PASSWORD
$realEnv = if ($Fips) { Get-ShimEnv @ShimCommon -Variant "gen\shim-v2" -Marker "$MarkerBase-real.txt" } else { @{} }
Test-RealKmsStart -ConfFile $confFile -Port $KMS_PORT -LogFile (Join-Path $work "kms.log") -ExtraEnv $realEnv
if (-not (Select-String -LiteralPath $SIM_LOG -SimpleMatch -Quiet -Pattern "C_Initialize")) {
    throw "$SIM_LOG has no C_Initialize: the server did not load the Idemia simulator"
}
Write-Host "The simulator log shows C_Initialize: the server loaded the Idemia simulator"

if ($Fips) {
    # The shim lets the caller's zero IV through (a module that does not generate the IV, as the
    # plain simulator), so the KMS must refuse the AES-GCM KEK at startup rather than send its own
    # IV. Run last: it is a negative scenario.
    Write-Step "FIPS: a module that does not generate the GCM IV is refused"
    $refuseMarker = "$MarkerBase-refuse.txt"
    $refuseEnv = Get-ShimEnv @ShimCommon -Variant "accept\shim-v2" -Marker $refuseMarker
    Invoke-KmsTest -Env $refuseEnv -CargoTestArgs @("-p", "test_kms_server", "--lib", "--", "--ignored", "--exact",
        "hsm_startup_tests::test_startup_with_hsm_kek_idemia_sphere_simulator", "--nocapture")
    Assert-ShimMarker -Path $refuseMarker -Require @("gcm-iv-zero") -Forbid @("gcm-iv-generated", "gcm-iv-nonzero")
}

Write-Host "`nIdemia SPHERE HSM tests ($SecurityLevel): all steps passed" -ForegroundColor Green
