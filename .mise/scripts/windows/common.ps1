# ============================================================================
# common.ps1 -- helpers shared by the Windows build, packaging and test scripts.
#
# Dot-source it:  . (Join-Path $PSScriptRoot "common.ps1")
# Only defines functions (no parameters, no side effects). Runs unchanged under Windows
# PowerShell 5.1 and PowerShell 7.
# ============================================================================

function Write-Step { param([string]$Msg) Write-Host "`n=== $Msg ===" -ForegroundColor Cyan }

# Run a native command, stream its output and throw on a non-zero exit code.
#   - Windows PowerShell 5.1 turns native stderr into ErrorRecords, which would be terminating
#     under $ErrorActionPreference = "Stop" (cargo and rustup write their progress on stderr):
#     the preference is lowered locally.
#   - PowerShell 7 does not have the issue; "Continue" is harmless there.
#   - $PSNativeCommandUseErrorActionPreference is PS 7.3+ only: the exit code is checked here.
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments = @())
    Write-Host "> $Exe $($Arguments -join ' ')"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { throw "'$Exe $($Arguments -join ' ')' failed with exit code $code" }
}

function Invoke-Cargo {
    param([string[]]$CargoArgs)
    Invoke-Native "cargo" $CargoArgs
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

# Export a dotenv file to the process environment.
function Import-DotEnv {
    param([string]$Path)
    $values = Read-DotEnv $Path
    foreach ($name in $values.Keys) { Set-Item -Path "env:$name" -Value $values[$name] }
}

# Run a script block with extra environment variables, restoring the previous values afterwards.
# An empty value removes the variable for the duration of the block (as far as .NET is concerned,
# an empty value and an unset variable are the same).
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

# Locate the Visual Studio installation that has the MSVC x64 tools.
function Get-VisualStudio {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "Visual Studio with the MSVC x64 tools not found (no vswhere.exe)"
    }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $path) { throw "Visual Studio with the MSVC x64 tools not found" }
    $path = @($path)[0]
    $vcvars = Join-Path $path "VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path -LiteralPath $vcvars)) {
        throw "Visual Studio with the MSVC x64 tools not found (no vcvars64.bat in $path)"
    }
    return [pscustomobject]@{ Path = $path; VcVars = $vcvars }
}

# Run a command line inside the Visual Studio x64 environment (vcvars64.bat).
function Invoke-InVsEnv {
    param([string]$CommandLine)
    $vs = Get-VisualStudio
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        cmd /c "`"$($vs.VcVars)`" >nul && $CommandLine" 2>&1 | ForEach-Object { Write-Host "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { throw "'$CommandLine' failed with exit code $code" }
}

# Path of the x64-hosted dumpbin.exe, or $null when Visual Studio has none.
function Find-Dumpbin {
    $dumpbin = $null
    try {
        $vsPath = (Get-VisualStudio).Path
        $dumpbin = Get-ChildItem -Recurse "$vsPath\VC\Tools\MSVC" -Filter "dumpbin.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*HostX64\x64*" } |
            Select-Object -First 1 -ExpandProperty FullName
    } catch { }
    if (-not $dumpbin) {
        $dumpbin = Get-ChildItem -Recurse "$env:ProgramFiles\Microsoft Visual Studio\2022" -Filter "dumpbin.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*HostX64\x64*" } |
            Select-Object -First 1 -ExpandProperty FullName
    }
    return $dumpbin
}

# Static OpenSSL from vcpkg. Manifest mode (vcpkg.json in the repo root) installs to
# vcpkg_installed\<triplet> (project-relative); classic mode installs to
# %VCPKG_INSTALLATION_ROOT%\packages\<port>_<triplet>. Returns $null when neither applies.
function Resolve-OpenSslDir {
    $manifestDir = Join-Path (Get-Location) "vcpkg_installed\x64-windows-static"
    if (Test-Path $manifestDir) { return $manifestDir }
    $vcpkgRoot = if ($env:VCPKG_INSTALLATION_ROOT) { $env:VCPKG_INSTALLATION_ROOT } elseif ($env:VCPKG_ROOT) { $env:VCPKG_ROOT } else { $null }
    if ($vcpkgRoot) { return "$vcpkgRoot\packages\openssl_x64-windows-static" }
    return $null
}

function Set-BuildEnv {
    $dir = Resolve-OpenSslDir
    if ($dir) { $env:OPENSSL_DIR = $dir }
    $env:RUST_LOG = "cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"
}

# Poll a URL until it answers 200 and return the response. Throws on timeout, or at once when
# $Process (the server being waited for) has exited.
function Wait-ForHttp {
    param([string]$Uri, [int]$TimeoutSec = 60, [System.Diagnostics.Process]$Process = $null)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($null -ne $Process -and $Process.HasExited) {
            throw "the process exited with code $($Process.ExitCode) before $Uri answered"
        }
        try {
            $resp = Invoke-WebRequest -Uri $Uri -Method GET -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($null -ne $resp -and $resp.StatusCode -eq 200) { return $resp }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "$Uri did not answer within $TimeoutSec s"
}

# Version of [workspace.package] in the root Cargo.toml.
function Get-WorkspaceVersion {
    $inWorkspace = $false
    foreach ($line in (Get-Content -LiteralPath "Cargo.toml")) {
        if ($line -match '^\[workspace\.package\]') { $inWorkspace = $true; continue }
        if ($inWorkspace -and $line -match '^version\s*=\s*"([^"]+)"') { return $Matches[1] }
        if ($inWorkspace -and $line -match '^\[') { break }
    }
    throw "Unable to parse the [workspace.package] version from Cargo.toml"
}

function Test-IsAdministrator {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
