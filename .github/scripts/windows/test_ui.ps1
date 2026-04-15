# =============================================================================
# test_ui.ps1 – Run Playwright E2E tests for the KMS web UI on Windows.
#
# Mirrors the Linux test_ui.sh, adapted for PowerShell / Windows CI:
#   1.  Build the WASM package (non-fips, web target) using wasm-pack.
#   2.  Copy the generated pkg\ into ui\src\wasm\pkg\.
#   3.  Install JS dependencies and build the Vite bundle, baking the local
#       KMS URL into the bundle via VITE_KMS_URL.
#   4.  Install Playwright's Chromium browser.
#   5.  Start the KMS server in the background and wait for it to be ready.
#   6.  Start `vite preview` in the background.
#   7.  Run `pnpm run test:e2e` (Playwright).
#
# Prerequisite tools expected on PATH (installed by the CI workflow steps):
#   • cargo / rustup  (with wasm32-unknown-unknown target)
#   • wasm-pack       (cargo install wasm-pack --locked)
#   • pnpm or npm     (pnpm/action-setup GitHub Action)
# =============================================================================

$ErrorActionPreference = "Stop"

# ── Resolve paths ─────────────────────────────────────────────────────────────
$RepoRoot = (Get-Item (Join-Path (Join-Path (Join-Path $PSScriptRoot "..") "..") "..")).FullName
$WasmCrate = Join-Path (Join-Path (Join-Path $RepoRoot "crate") "clients") "wasm"
$UiDir = Join-Path $RepoRoot "ui"

# ── Detect pnpm / npm ─────────────────────────────────────────────────────────
$pnpmCmd = if (Get-Command pnpm -ErrorAction SilentlyContinue) { "pnpm" } else { "npm" }

# Resolve the full .cmd path for use with Start-Process (Win32 requires a real executable)
$pnpmExe = (Get-Command $pnpmCmd).Source
if ($pnpmExe -notmatch '\.exe$') {
    # It's a .cmd shim — wrap via cmd.exe
    $pnpmStartExe = "cmd.exe"
    $pnpmStartPrefix = @("/c", $pnpmCmd)
}
else {
    $pnpmStartExe = $pnpmExe
    $pnpmStartPrefix = @()
}

# ── Helper: run a command and throw on non-zero exit ─────────────────────────
function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command '$Exe $Arguments' exited with code $LASTEXITCODE"
    }
}

function Get-FreeTcpPort {
    param([int]$StartPort, [int]$EndPort)
    for ($p = $StartPort; $p -le $EndPort; $p++) {
        $listeners = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
        if (-not $listeners) {
            return $p
        }
    }
    throw "No free TCP port found in range ${StartPort}-${EndPort}"
}

# ── 1. Build WASM (non-fips, web target) ─────────────────────────────────────
Write-Host "==> Building WASM (non-fips, web target) ..." -ForegroundColor Cyan
Push-Location $WasmCrate
try {
    Invoke-Checked wasm-pack @("build", "--target", "web", "--features", "non-fips")
}
finally {
    Pop-Location
}

# Copy generated artefacts into the UI source tree.
$PkgSrc = Join-Path $WasmCrate "pkg"
$PkgDst = Join-Path (Join-Path (Join-Path $UiDir "src") "wasm") "pkg"
New-Item -ItemType Directory -Force -Path $PkgDst | Out-Null
Copy-Item (Join-Path $PkgSrc "*") -Destination $PkgDst -Recurse -Force

# ── 2. Install JS deps and build UI ──────────────────────────────────────────
Write-Host "==> Installing UI dependencies ..." -ForegroundColor Cyan
Push-Location $UiDir
try {
    Invoke-Checked $pnpmCmd @("install", "--no-frozen-lockfile", "--no-audit")

    Write-Host "==> Building UI (VITE_KMS_URL=http://127.0.0.1:9998, VITE_DEV_MODE=true) ..." -ForegroundColor Cyan
    # Write a .env.production.local file so Vite picks up the variables even
    # if the process-level env vars are not visible to the pnpm child process.
    $EnvFile = Join-Path $UiDir ".env.production.local"
    "VITE_KMS_URL=http://127.0.0.1:9998`nVITE_DEV_MODE=true" | Out-File -FilePath $EnvFile -Encoding utf8 -NoNewline
    $env:VITE_KMS_URL = "http://127.0.0.1:9998"
    $env:VITE_DEV_MODE = "true"
    try {
        Invoke-Checked $pnpmCmd @("run", "build:vite")
    }
    finally {
        Remove-Item -Force $EnvFile -ErrorAction SilentlyContinue
        Remove-Item Env:VITE_KMS_URL -ErrorAction SilentlyContinue
        Remove-Item Env:VITE_DEV_MODE -ErrorAction SilentlyContinue
    }

    # ── 3. Install Playwright's Chromium browser ──────────────────────────────
    Write-Host "==> Installing Playwright Chromium browser ..." -ForegroundColor Cyan
    Invoke-Checked $pnpmCmd @("exec", "playwright", "install", "chromium", "--with-deps")
}
finally {
    Pop-Location
}

# ── 4. Start KMS server ───────────────────────────────────────────────────────
$SqliteDir = Join-Path ([System.IO.Path]::GetTempPath()) ("kms-e2e-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $SqliteDir | Out-Null

# Set OpenSSL env vars the same way cargo_build.ps1 does so that the cargo
# build below can link against the vcpkg static OpenSSL.
if ($env:VCPKG_INSTALLATION_ROOT) {
    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
}

# Build the KMS server in the foreground so compilation does not race against
# the readiness-poll timeout below.  On a fresh CI runner a debug build can
# easily take 5-10 minutes; launching via 'cargo run' in the background would
# time out long before the binary is ready to serve requests.
Write-Host "==> Building KMS server (non-fips, debug) ..." -ForegroundColor Cyan
Invoke-Checked cargo @(
    "build",
    "-p", "cosmian_kms_server",
    "--bin", "cosmian_kms",
    "--features", "non-fips"
)

$KmsBin = Join-Path $RepoRoot "target\debug\cosmian_kms.exe"
if (-not (Test-Path $KmsBin)) {
    throw "KMS binary not found after build: $KmsBin"
}

Write-Host "==> Starting KMS server (non-fips, sqlite) ..." -ForegroundColor Cyan
# Use RUNNER_TEMP when available (GitHub Actions) so that the paths match the
# `path:` globs in the "Upload logs on failure" workflow step; fall back to
# the system temp directory for local runs.
$LogTempDir = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$KmsLogOut = Join-Path $LogTempDir "kms-stdout.log"
$KmsLogErr = Join-Path $LogTempDir "kms-stderr.log"

# Launch the pre-built binary directly — startup is near-instant.
$oldRustLog = $env:RUST_LOG
$env:RUST_LOG = "cosmian_kms_server=info,cosmian_kms_server_database=info"
try {
    $KmsProc = Start-Process -FilePath $KmsBin `
        -ArgumentList @(
        "--database-type", "sqlite",
        "--sqlite-path", $SqliteDir,
        "--hostname", "127.0.0.1",
        "--port", "9998",
        "--vendor-identification", "test_vendor"
    ) `
        -PassThru -NoNewWindow -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $KmsLogOut `
        -RedirectStandardError $KmsLogErr
}
finally {
    $env:RUST_LOG = $oldRustLog
}

Write-Host "==> Waiting for KMS to be ready ..." -ForegroundColor Cyan
$KmsReady = $false
for ($i = 1; $i -le 300; $i++) {
    $KmsProc.Refresh()
    if ($KmsProc.HasExited) {
        Write-Host "KMS stdout:"; Get-Content $KmsLogOut -ErrorAction SilentlyContinue
        Write-Host "KMS stderr:"; Get-Content $KmsLogErr -ErrorAction SilentlyContinue
        throw "KMS server process exited unexpectedly (exit code $($KmsProc.ExitCode))"
    }
    try {
        # -SkipHttpErrorCheck (PS7+) returns the response object for any HTTP
        # status code instead of throwing, so a KMIP 4xx validation error from
        # a healthy server correctly signals readiness.
        $resp = Invoke-WebRequest `
            -Uri "http://127.0.0.1:9998/kmip/2_1" `
            -Method POST -Body "{}" -ContentType "application/json" `
            -UseBasicParsing -SkipHttpErrorCheck -ErrorAction SilentlyContinue
        if ($null -ne $resp) { $KmsReady = $true; Write-Host "    KMS ready after ${i}s"; break }
    }
    catch { }
    Start-Sleep -Seconds 1
}
if (-not $KmsReady) {
    try { Stop-Process -Id $KmsProc.Id -Force -ErrorAction SilentlyContinue } catch { }
    Get-Content $KmsLogErr -ErrorAction SilentlyContinue | Write-Host
    Remove-Item -Recurse -Force -Path $SqliteDir -ErrorAction SilentlyContinue
    throw "KMS did not become ready within 300 s"
}

# ── 5. Start Vite preview server ─────────────────────────────────────────────
$PreviewPort = Get-FreeTcpPort -StartPort 5173 -EndPort 5190
Write-Host "==> Starting Vite preview server (port $PreviewPort) ..." -ForegroundColor Cyan
$PreviewLogOut = Join-Path ([System.IO.Path]::GetTempPath()) "kms-ui-preview.log"
$PreviewLogErr = Join-Path ([System.IO.Path]::GetTempPath()) "kms-ui-preview.err"
$PreviewProc = Start-Process -FilePath $pnpmStartExe `
    -ArgumentList ($pnpmStartPrefix + @("preview", "--port", "$PreviewPort", "--host", "127.0.0.1")) `
    -PassThru -NoNewWindow -WorkingDirectory $UiDir `
    -RedirectStandardOutput $PreviewLogOut `
    -RedirectStandardError $PreviewLogErr

Write-Host "==> Waiting for Vite preview to be ready ..." -ForegroundColor Cyan
for ($i = 1; $i -le 60; $i++) {
    if ($PreviewProc.HasExited) {
        Write-Host "Vite preview stdout:"; Get-Content $PreviewLogOut -ErrorAction SilentlyContinue
        Write-Host "Vite preview stderr:"; Get-Content $PreviewLogErr -ErrorAction SilentlyContinue
        throw "Vite preview process exited unexpectedly (exit code $($PreviewProc.ExitCode))"
    }
    try {
        $resp = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$PreviewPort/ui/" `
            -UseBasicParsing -ErrorAction SilentlyContinue
        if ($null -ne $resp) { Write-Host "    Vite preview ready after ${i}s"; break }
    }
    catch { }
    Start-Sleep -Seconds 1
    if ($i -eq 60) {
        try { $KmsProc.Kill() } catch { }
        try { $PreviewProc.Kill() } catch { }
        Remove-Item -Recurse -Force -Path $SqliteDir -ErrorAction SilentlyContinue
        throw "Vite preview did not become ready within 60 s"
    }
}

# ── 6. Run Playwright E2E tests ───────────────────────────────────────────────
try {
    Write-Host "==> Running Playwright E2E tests ..." -ForegroundColor Cyan
    Push-Location $UiDir
    $env:CI = "true"
    $env:PLAYWRIGHT_BASE_URL = "http://127.0.0.1:$PreviewPort"
    # SoftHSM2 is not available on Windows; signal to the specs that no HSM
    # keys are pre-created so the HSM-specific tests are skipped.
    $env:PLAYWRIGHT_HSM_KEY_COUNT = "0"
    try {
        Invoke-Checked $pnpmCmd @("run", "test:e2e")
    }
    finally {
        Remove-Item Env:CI -ErrorAction SilentlyContinue
        Remove-Item Env:PLAYWRIGHT_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:PLAYWRIGHT_HSM_KEY_COUNT -ErrorAction SilentlyContinue
        Pop-Location
    }
}
finally {
    Write-Host "==> Stopping servers ..." -ForegroundColor Cyan
    try { Stop-Process -Id $KmsProc.Id -Force -ErrorAction SilentlyContinue } catch { }
    try { $PreviewProc.Kill() } catch { }
    Remove-Item -Recurse -Force -Path $SqliteDir -ErrorAction SilentlyContinue
}

Write-Host "==> UI E2E tests passed!" -ForegroundColor Green
