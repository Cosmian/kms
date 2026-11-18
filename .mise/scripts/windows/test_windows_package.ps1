<#
.SYNOPSIS
  Install a Windows KMS server installer silently, smoke-test the installed service, uninstall.

.DESCRIPTION
  Needs an elevated shell: the installer registers the machine service CosmianKMS.
  Flow (the package is always uninstalled at the end):
    1. silent install (/S),
    2. package layout (and, for the FIPS variant, the OpenSSL FIPS provider files),
    3. FIPS variant: the service environment holds OPENSSL_CONF / OPENSSL_MODULES /
       OPENSSL_CONF_INCLUDE pointing into the install directory,
    4. the service runs and answers GET /version (the FIPS server proves it loaded fips.dll),
    5. FIPS variant: without OPENSSL_* the server must refuse to start (fail closed),
    6. FIPS variant: openssl\cosmian_kms_fips.cmd starts a working server on its own,
    7. uninstall removes the service and the binary.

.EXAMPLE
  .\.mise\scripts\windows\test_windows_package.ps1 -Installer target\release\cosmian-kms-server-fips-static-openssl_<ver>_x86_64.exe -Variant fips
#>
param(
    [Parameter(Mandatory)][string]$Installer,
    [ValidateSet("non-fips", "fips")][string]$Variant = "fips"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "common.ps1")

if (-not (Test-IsAdministrator)) {
    throw "run from an elevated shell (installer registers a machine service)"
}

$ServiceName = "CosmianKMS"
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$VersionUri = "http://127.0.0.1:9998/version"
$OpenSslVars = @("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_CONF_INCLUDE")
$script:ChecksOk = $false

function Install-KmsPackage {
    Write-Step "Silent install of $Installer"
    $p = Start-Process -FilePath $Installer -ArgumentList "/S" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "the installer exited with code $($p.ExitCode)" }
}

# Directory of the service executable, from the ImagePath of the service.
function Get-InstalledKmsDir {
    if (-not (Test-Path $ServiceKey)) { throw "service $ServiceName is not registered" }
    $imagePath = (Get-ItemProperty $ServiceKey).ImagePath
    if ($imagePath -notmatch '^"([^"]+)"') { throw "unexpected ImagePath of $ServiceName : $imagePath" }
    return Split-Path -Parent $Matches[1]
}

function Assert-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "missing file: $Path" }
}

function Assert-PackageLayout {
    param([string]$Dir, [string]$Variant)
    Write-Step "Package layout ($Variant)"
    Assert-File (Join-Path $Dir "cosmian_kms.exe")
    Assert-File (Join-Path $Dir "kms.toml")
    $variantFile = Join-Path $Dir "openssl\variant.txt"
    Assert-File $variantFile
    $actual = (Get-Content -Raw -LiteralPath $variantFile).Trim()
    if ($actual -ne $Variant) { throw "openssl\variant.txt says '$actual', expected '$Variant'" }
    if ($Variant -eq "fips") {
        foreach ($rel in @("openssl\ssl\openssl.cnf", "openssl\ssl\fipsmodule.cnf",
                "openssl\ossl-modules\fips.dll", "openssl\cosmian_kms_fips.cmd")) {
            Assert-File (Join-Path $Dir $rel)
        }
        if (-not (Select-String -LiteralPath (Join-Path $Dir "openssl\ssl\openssl.cnf") -SimpleMatch -Quiet -Pattern ".include fipsmodule.cnf")) {
            throw "openssl.cnf lacks '.include fipsmodule.cnf'"
        }
    }
    Write-Host "OK: package layout"
}

function Assert-ServiceEnvironment {
    param([string]$Dir)
    Write-Step "Service environment"
    $props = Get-ItemProperty $ServiceKey
    if (-not $props.PSObject.Properties["Environment"]) { throw "service $ServiceName has no Environment value" }
    $expected = @(
        "OPENSSL_CONF=$Dir\openssl\ssl\openssl.cnf",
        "OPENSSL_MODULES=$Dir\openssl\ossl-modules",
        "OPENSSL_CONF_INCLUDE=$Dir\openssl\ssl"
    )
    $actual = @($props.Environment)
    if ((($actual | Sort-Object) -join "`n") -ne (($expected | Sort-Object) -join "`n")) {
        throw "unexpected service environment:`n$($actual -join "`n")`nexpected:`n$($expected -join "`n")"
    }
    Write-Host "OK: service environment"
}

function Assert-ServiceAnswers {
    Write-Step "Service $ServiceName"
    $svc = Get-Service $ServiceName
    if ($svc.Status -ne "Running") {
        try { $svc.WaitForStatus("Running", [TimeSpan]::FromSeconds(60)) } catch { }
        $svc.Refresh()
    }
    if ($svc.Status -ne "Running") { throw "service $ServiceName is $($svc.Status), expected Running" }
    $resp = Wait-ForHttp $VersionUri 90
    Write-Host "OK: GET /version -> $($resp.StatusCode): $($resp.Content)"
}

# Environment that hides the FIPS provider from a child process.
function Get-NoOpenSslEnv {
    $vars = @{}
    foreach ($name in $OpenSslVars) { $vars[$name] = "" }
    return $vars
}

# A FIPS-only server cannot start without the FIPS provider: it must exit non-zero.
function Assert-FailsClosedWithoutProvider {
    param([string]$Dir)
    Write-Step "FIPS server without OPENSSL_* must refuse to start"
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    $p = Invoke-WithEnv (Get-NoOpenSslEnv) {
        Start-Process -FilePath (Join-Path $Dir "cosmian_kms.exe") `
            -ArgumentList "-c", "`"$Dir\kms.toml`"" -PassThru -WindowStyle Hidden
    }
    try {
        $null = $p.Handle
        if (-not $p.WaitForExit(30000)) {
            throw "FIPS server started without the FIPS provider"
        }
        if ($p.ExitCode -eq 0) { throw "FIPS server exited with code 0 without the FIPS provider" }
        Write-Host "OK: exited with code $($p.ExitCode) without the FIPS provider"
    } finally {
        if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}

# openssl\cosmian_kms_fips.cmd sets the environment itself.
function Assert-LauncherWorks {
    param([string]$Dir)
    Write-Step "openssl\cosmian_kms_fips.cmd"
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    $launcher = Join-Path $Dir "openssl\cosmian_kms_fips.cmd"
    $p = Invoke-WithEnv (Get-NoOpenSslEnv) {
        Start-Process -FilePath $env:ComSpec `
            -ArgumentList "/c `"`"$launcher`" -c `"$Dir\kms.toml`"`"" -PassThru -WindowStyle Hidden
    }
    try {
        $resp = Wait-ForHttp $VersionUri 60 $p
        Write-Host "OK: launcher answers GET /version -> $($resp.StatusCode): $($resp.Content)"
    } finally {
        if (-not $p.HasExited) { & taskkill /T /F /PID $p.Id | Out-Null }
        $p.WaitForExit(10000) | Out-Null
    }
}

function Test-ServiceAbsent {
    & sc.exe query $ServiceName | Out-Null
    return ($LASTEXITCODE -eq 1060)
}

# Always runs; a failure here only fails the script when the checks themselves passed.
function Remove-KmsPackage {
    param([string]$Dir)
    Write-Step "Uninstall"
    try {
        if (-not $Dir) {
            try { $Dir = Get-InstalledKmsDir } catch { Write-Host "nothing installed"; return }
        }
        Stop-Service $ServiceName -ErrorAction SilentlyContinue
        $uninstaller = Join-Path $Dir "uninstall.exe"
        Assert-File $uninstaller
        # The NSIS uninstaller relaunches a temporary copy of itself and returns at once: poll.
        Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait
        $deadline = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $deadline -and
            -not ((Test-ServiceAbsent) -and -not (Test-Path -LiteralPath (Join-Path $Dir "cosmian_kms.exe")))) {
            Start-Sleep -Seconds 1
        }
        if (-not (Test-ServiceAbsent)) { throw "service $ServiceName still registered after uninstall" }
        if (Test-Path -LiteralPath (Join-Path $Dir "cosmian_kms.exe")) { throw "cosmian_kms.exe still present after uninstall" }
        Write-Host "OK: uninstalled (service removed, binary removed)"
    } catch {
        if ($script:ChecksOk) { throw }
        Write-Warning "uninstall failed: $_"
    }
}

$installedDir = $null
try {
    Install-KmsPackage
    $installedDir = Get-InstalledKmsDir
    Write-Host "Installed in $installedDir"
    Assert-PackageLayout -Dir $installedDir -Variant $Variant
    if ($Variant -eq "fips") { Assert-ServiceEnvironment -Dir $installedDir }
    Assert-ServiceAnswers
    if ($Variant -eq "fips") {
        Assert-FailsClosedWithoutProvider -Dir $installedDir
        Assert-LauncherWorks -Dir $installedDir
    }
    $script:ChecksOk = $true
} finally {
    Remove-KmsPackage -Dir $installedDir
}
Write-Host "`nWindows package smoke test ($Variant): all checks passed" -ForegroundColor Green
