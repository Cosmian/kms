# Install Ninja from its official GitHub release, verified against a pinned SHA-256,
# and add it to PATH for the following workflow steps (replaces `choco install ninja`).
# Recompute the hash: curl -fsSL <url> | shasum -a 256  (also published as the asset digest
# of the release: gh api repos/ninja-build/ninja/releases/tags/v1.13.2 --jq '.assets[] | select(.name=="ninja-win.zip").digest')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$version = '1.13.2'
$sha256 = '07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65'
$url = "https://github.com/ninja-build/ninja/releases/download/v$version/ninja-win.zip"

$root = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$zip = Join-Path $root 'ninja-win.zip'
$dir = Join-Path $root "ninja-$version"

Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
if ($actual -ne $sha256) {
    throw "ninja-win.zip SHA-256 mismatch: expected $sha256, got $actual"
}
Expand-Archive -Path $zip -DestinationPath $dir -Force
if ($env:GITHUB_PATH) { Add-Content $env:GITHUB_PATH $dir }
$env:PATH = "$dir;$env:PATH"
Write-Host "Installed Ninja $version to $dir"
