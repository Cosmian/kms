# ============================================================================
# test_scep_windows.ps1 -- Windows MDM SCEP interoperability test (elevated, local).
#
# Drives the real Windows MDM SCEP client (ClientCertificateInstall CSP, through the
# MDM WMI bridge, as SYSTEM) against a live KMS behind a recording proxy:
#   1. Start a KMS with SCEP + an `mdm_device` template; create and delegate an RSA CA.
#   2. Enroll (PKCSReq, challenge): check the request (GetCACaps/GetCACert/PKIOperation,
#      SHA-256, AES, RSA-2048, challenge) and the issued certificate in LocalMachine\My.
#   3. Enroll with a wrong challenge: rejected, nothing installed.
#   4. Optionally (-SaveFixture) store the captured request under
#      test_data\scep\windows\win-<build>\ for the CI replay test.
#
# Prerequisites: elevated PowerShell, Windows 10/11 (any edition), Python 3, built or
# buildable cosmian_kms + ckms (Rust MSVC toolchain), optional openssl.exe for the
# request analysis. Not for CI: needs elevation and a persistent machine certificate store.
#
# Usage (elevated, repo root):
#   powershell -ExecutionPolicy Bypass -File .mise\scripts\windows\test_scep_windows.ps1
#     [-Variant fips|non-fips] [-NoBuild] [-SaveFixture] [-KeepWork] [-TimeoutSec 120]
# ============================================================================
param(
    [ValidateSet("fips", "non-fips")][string]$Variant = "non-fips",
    [switch]$NoBuild,
    [switch]$SaveFixture,
    [switch]$KeepWork,
    [int]$TimeoutSec = 120
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$CspScript = Join-Path $PSScriptRoot "scep_windows_csp.ps1"
$ProxyScript = Join-Path $RepoRoot ".mise\scripts\test\scep_capture_proxy.py"
$ProfileDir = "debug"
$TargetDir = Join-Path $RepoRoot "target\$ProfileDir"
$FeatureArgs = if ($Variant -eq "non-fips") { @("--features", "non-fips") } else { @() }

# Same values style as the Apple script; CN must match the template regex below.
$Challenge = "SecretChallenge123"
$CaUid = "windows-scep-ca"
$RunId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$GoodId = "kmsscep$RunId"
$BadId = "kmsscepbad$RunId"
$GoodCn = "win-test-01.mdm.example"
$BadCn = "win-bad-01.mdm.example"

function Write-Step { param([string]$Msg) Write-Host "`n=== $Msg ===" -ForegroundColor Cyan }
function Write-Ok { param([string]$Msg) Write-Host "  [PASS] $Msg" -ForegroundColor Green }
function Write-Info { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor DarkGray }
function Fail { param([string]$Msg) throw "FAIL: $Msg" }
function Assert-That { param([bool]$Cond, [string]$Pass, [string]$FailMsg) if ($Cond) { Write-Ok $Pass } else { Fail $FailMsg } }

# Runs a native program without PowerShell turning stderr into errors; returns stdout.
function Invoke-Native {
    param([string]$Program, [string[]]$Arguments, [string]$FailMessage = "", [switch]$AllowFail)
    $o = [IO.Path]::GetTempFileName(); $e = [IO.Path]::GetTempFileName()
    try {
        $argLine = ($Arguments | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
        $p = Start-Process -FilePath $Program -ArgumentList $argLine -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
        $null = $p.Handle
        $stdout = Get-Content $o -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content $e -Raw -ErrorAction SilentlyContinue
        if ($p.ExitCode -ne 0 -and -not $AllowFail) { Fail "$FailMessage (exit $($p.ExitCode)): $stderr $stdout" }
        if ($null -eq $stdout) { $stdout = "" }
        return $stdout
    } finally { Remove-Item $o, $e -Force -ErrorAction SilentlyContinue }
}

function Get-FreePort {
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop(); return $port
}

function Wait-ForHttp {
    param([string]$Url, [int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try { if ((Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { return $true } } catch { }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# Runs scep_windows_csp.ps1 as SYSTEM through a one-shot scheduled task; returns its JSON result.
function Invoke-Csp {
    param([hashtable]$Params, [int]$Timeout)
    $out = Join-Path $WorkDir ("csp-" + [guid]::NewGuid().ToString("N").Substring(0, 6) + ".json")
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$CspScript`" -OutFile `"$out`""
    foreach ($k in $Params.Keys) { $argLine += " -$k `"$($Params[$k])`"" }
    $name = "KmsScepWin$RunId"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argLine
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal | Out-Null
    try {
        Start-ScheduledTask -TaskName $name
        $deadline = (Get-Date).AddSeconds($Timeout + 30)
        while (-not (Test-Path $out) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    } finally { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue }
    if (Test-Path "$out.log") { Get-Content "$out.log" | ForEach-Object { Write-Info "csp: $_" } }
    if (-not (Test-Path $out)) { Fail "CSP worker produced no result within $($Timeout + 30)s" }
    return Get-Content $out -Raw | ConvertFrom-Json
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated PowerShell (the MDM WMI bridge needs SYSTEM, set up via a scheduled task)."
}
$Python = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $Python) { throw "python.exe not found in PATH (needed for the recording proxy)." }
$Openssl = Get-Command openssl -ErrorAction SilentlyContinue

$WorkDir = Join-Path $env:TEMP "kms-scep-win-$RunId"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$CaptureDir = Join-Path $WorkDir "capture"
$KmsProc = $null; $ProxyProc = $null
$InstalledThumbprints = @()
$KmsLog = Join-Path $WorkDir "kms.log"

try {
    Write-Step "Build KMS server and ckms ($Variant)"
    if (-not $NoBuild) {
        Push-Location $RepoRoot
        try {
            Get-Process cosmian_kms -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Invoke-Native cargo (@("build", "--bin", "cosmian_kms") + $FeatureArgs) "cargo build cosmian_kms failed" | Out-Null
            Invoke-Native cargo (@("build", "--package", "ckms") + $FeatureArgs) "cargo build ckms failed" | Out-Null
        } finally { Pop-Location }
    }
    $KmsExe = Join-Path $TargetDir "cosmian_kms.exe"
    $CkmsExe = Join-Path $TargetDir "ckms.exe"
    foreach ($b in $KmsExe, $CkmsExe) { if (-not (Test-Path $b)) { Fail "binary not found: $b" } }

    Write-Step "Start KMS (SCEP + template) and recording proxy"
    $kmsPort = Get-FreePort
    $kmsUrl = "http://127.0.0.1:$kmsPort"
    $toml = $WorkDir.Replace('\', '/')
    @(
        'default_username = "admin"', '',
        '[db]', 'database_type = "sqlite"', "sqlite_path = `"$toml/db`"", 'clear_database = true', '',
        '[http]', 'hostname = "127.0.0.1"', "port = $kmsPort", '',
        '[logging]', 'rust_log = "info,cosmian_kms=info"', 'ansi_colors = false', '',
        '[scep]', 'scep_enabled = true', "scep_ca_uid = `"$CaUid`"", "scep_challenge_password = `"$Challenge`"",
        'scep_allow_renewal_without_challenge = true', 'scep_template = "mdm_device"', '',
        '[templates.mdm_device]', 'name = "mdm_device"', 'min_rsa_key_bits = 2048', 'allowed_ekus = ["clientAuth"]',
        'max_validity_days = 365', 'default_validity_days = 90', 'subject_cn_regex = "[a-z0-9-]+\\.mdm\\.example"'
    ) | Set-Content -Path (Join-Path $WorkDir "kms.toml") -Encoding ASCII
    New-Item -ItemType Directory -Force -Path (Join-Path $WorkDir "db") | Out-Null
    $KmsProc = Start-Process -FilePath $KmsExe -ArgumentList "-c", "`"$(Join-Path $WorkDir 'kms.toml')`"" -PassThru -NoNewWindow `
        -RedirectStandardOutput $KmsLog -RedirectStandardError "$KmsLog.err"
    if (-not (Wait-ForHttp "$kmsUrl/version" 60)) { Fail "KMS did not start; see $KmsLog.err" }
    Write-Ok "KMS running on $kmsUrl (PID $($KmsProc.Id))"

    $CkmsConf = Join-Path $WorkDir "ckms.toml"
    "[http_config]`nserver_url = `"$kmsUrl`"" | Set-Content -Path $CkmsConf -Encoding ASCII
    function Ckms { param([string[]]$A) Invoke-Native $CkmsExe (@("--conf-path", $CkmsConf) + $A) "ckms $($A -join ' ')" }

    @("[ v3_ca ]", "basicConstraints=critical,CA:TRUE", "keyUsage=critical,keyCertSign,crlSign,digitalSignature,keyEncipherment") |
        Set-Content -Path (Join-Path $WorkDir "ca.ext") -Encoding ASCII
    Ckms @("certificates", "certify", "--certificate-id", $CaUid, "--generate-key-pair", "--algorithm", "rsa2048",
        "--subject-name", "CN=Windows SCEP Interop Test CA,O=Cosmian Test,C=FR", "--days", "3650",
        "--certificate-extensions", (Join-Path $WorkDir "ca.ext")) | Out-Null
    $CaPem = Join-Path $WorkDir "ca.crt"
    Ckms @("certificates", "export", $CaPem, "--certificate-id", $CaUid, "--format", "pem") | Out-Null
    $linksFile = Join-Path $WorkDir "ca-links.json"
    Ckms @("attributes", "get", "-i", $CaUid, "-a", "LinkType", "-l", "private-key", "-o", $linksFile) | Out-Null
    $CaSkUid = (Get-Content $linksFile -Raw | ConvertFrom-Json).PrivateKeyLink
    # Test-only CA: key exported so the captured (CA-encrypted) request can be decrypted below.
    $CaKey = Join-Path $WorkDir "ca.key"
    Ckms @("rsa", "keys", "export", "-k", $CaSkUid, "-f", "pkcs8-pem", $CaKey) | Out-Null
    Ckms @("access-rights", "grant", "[enrollment-service]", "-i", $CaUid, "certify") | Out-Null
    Ckms @("access-rights", "grant", "[enrollment-service]", "-i", $CaSkUid, "certify") | Out-Null

    $caB64 = ((Get-Content $CaPem) | Where-Object { $_ -notmatch "-----" }) -join ""
    $caBytes = [Convert]::FromBase64String($caB64)
    $caCert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($caBytes)
    $caSha1 = $caCert.Thumbprint

    $proxyPort = Get-FreePort
    New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null
    $ProxyProc = Start-Process -FilePath $Python.Source -ArgumentList $ProxyScript, $proxyPort, $kmsUrl, "`"$CaptureDir`"" -PassThru -NoNewWindow `
        -RedirectStandardError (Join-Path $WorkDir "proxy.log")
    $proxyUp = $false
    for ($i = 0; $i -lt 30 -and -not $proxyUp; $i++) {
        $tcp = [Net.Sockets.TcpClient]::new()
        try { $tcp.Connect("127.0.0.1", $proxyPort); $proxyUp = $true } catch { Start-Sleep -Milliseconds 500 } finally { $tcp.Close() }
    }
    if (-not $proxyUp) { Fail "capture proxy did not start" }
    $scepUrl = "http://127.0.0.1:$proxyPort/scep"
    Write-Ok "proxy on $scepUrl"

    Write-Step "Scenario 1: Windows MDM PKCSReq enrollment (challenge)"
    $r = Invoke-Csp -Timeout $TimeoutSec -Params @{
        Mode = "enroll"; UniqueId = $GoodId; ServerUrl = $scepUrl; Challenge = $Challenge
        SubjectName = "CN=$GoodCn"; CaThumbprint = $caSha1; TimeoutSec = $TimeoutSec
    }
    Write-Info ("csp result: " + ($r | ConvertTo-Json -Compress))
    if (-not $r.ok) { Fail "Windows enrollment failed: $($r.error)" }
    $InstalledThumbprints += $r.thumbprint
    $log = Get-Content (Join-Path $CaptureDir "exchanges.log") -Raw
    Write-Info $log
    Assert-That ($log -match "-GET-GetCACaps ") "client queried GetCACaps" "Windows client did not query GetCACaps"
    Assert-That ($log -match "-GET-GetCACert ") "client queried GetCACert" "Windows client did not query GetCACert"
    Assert-That ($log -match "-(POST|GET)-PKIOperation ") "client sent PKIOperation" "no PKIOperation received"
    if ($log -match "-GET-PKIOperation ") { Write-Info "NOTE: Windows used GET for PKIOperation" }

    $cert = Get-Item "Cert:\LocalMachine\My\$($r.thumbprint)"
    Assert-That ($cert.Subject -match "CN=$([regex]::Escape($GoodCn))") "certificate subject is CN=$GoodCn" "unexpected subject: $($cert.Subject)"
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = "NoCheck"
    $chain.ChainPolicy.VerificationFlags = "AllowUnknownCertificateAuthority"
    $chain.ChainPolicy.ExtraStore.Add($caCert) | Out-Null
    $null = $chain.Build($cert)
    $top = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
    Assert-That ($top -eq $caCert.Thumbprint) "certificate chains to the KMS CA" "chain top $top is not the KMS CA $($caCert.Thumbprint)"
    $eku = @($cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
    Assert-That ($eku -contains "1.3.6.1.5.5.7.3.2") "template EKU clientAuth present" "clientAuth EKU missing: $($eku -join ',')"
    Assert-That (($cert.NotAfter - $cert.NotBefore).TotalDays -le 366) "validity within template maximum" "validity exceeds template maximum"
    Assert-That ($cert.PublicKey.Key.KeySize -ge 2048) "RSA key >= 2048 bits" "weak key"

    $req = Get-ChildItem $CaptureDir -Filter "*-PKIOperation.req" | Sort-Object Name | Select-Object -First 1
    if ($Openssl) {
        # Some Windows openssl builds (Strawberry) default to a config path that does not exist.
        $emptyConf = Join-Path $WorkDir "openssl.cnf"
        Set-Content -Path $emptyConf -Value "" -Encoding ASCII
        $env:OPENSSL_CONF = $emptyConf
        $env_der = Join-Path $WorkDir "envelope.der"; $csr_der = Join-Path $WorkDir "csr.der"
        Invoke-Native $Openssl.Source @("cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", $req.FullName, "-out", $env_der) "pkiMessage signature does not verify" | Out-Null
        $signed = Invoke-Native $Openssl.Source @("cms", "-cmsout", "-print", "-inform", "DER", "-in", $req.FullName)
        Assert-That ($signed -match "sha256") "pkiMessage signed with SHA-256" "pkiMessage not signed with SHA-256"
        $envTxt = Invoke-Native $Openssl.Source @("cms", "-cmsout", "-print", "-inform", "DER", "-in", $env_der)
        $enc = [regex]::Match($envTxt, "aes-\d+-cbc|des-ede3-cbc|des-cbc").Value
        Assert-That ($enc -like "aes-*") "envelope uses $enc" "envelope uses '$enc', expected AES"
        Invoke-Native $Openssl.Source @("cms", "-decrypt", "-binary", "-inform", "DER", "-in", $env_der, "-recip", $CaPem, "-inkey", $CaKey, "-out", $csr_der) "cannot decrypt the request" | Out-Null
        $csrTxt = Invoke-Native $Openssl.Source @("req", "-inform", "DER", "-in", $csr_der, "-noout", "-text", "-verify") "CSR does not parse or its proof of possession is invalid"
        Assert-That ($csrTxt -match "Public-Key: \(2048 bit\)") "CSR is RSA-2048" "CSR is not RSA-2048"
        Assert-That ($csrTxt -match "challengePassword") "CSR carries the challengePassword" "CSR has no challengePassword"
    } else {
        Write-Host "  [SKIP] openssl.exe not found: request analysis skipped" -ForegroundColor Yellow
    }

    Write-Step "Scenario 2: wrong challenge is rejected"
    $before = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match [regex]::Escape($BadCn) }).Count
    $r2 = Invoke-Csp -Timeout 60 -Params @{
        Mode = "enroll"; UniqueId = $BadId; ServerUrl = $scepUrl; Challenge = "WrongSecret"
        SubjectName = "CN=$BadCn"; CaThumbprint = $caSha1; TimeoutSec = 60
    }
    Write-Info ("csp result: " + ($r2 | ConvertTo-Json -Compress))
    Assert-That (-not $r2.ok) "enrollment with a wrong challenge failed" "wrong challenge was accepted"
    $after = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match [regex]::Escape($BadCn) })
    Assert-That ($after.Count -eq $before) "no certificate installed for the wrong challenge" "certificate installed despite wrong challenge"
    foreach ($c in $after) { $InstalledThumbprints += $c.Thumbprint }

    if ($SaveFixture) {
        $build = [Environment]::OSVersion.Version.ToString()
        $fx = Join-Path $RepoRoot "test_data\scep\windows\win-$build"
        New-Item -ItemType Directory -Force -Path $fx | Out-Null
        Copy-Item $CaPem (Join-Path $fx "ca.crt"); Copy-Item $CaKey (Join-Path $fx "ca.key")
        Copy-Item $req.FullName (Join-Path $fx "pkcsreq.der")
        Write-Ok "fixture written to $fx"
    }
    Write-Host "`nWindows SCEP interoperability test PASSED" -ForegroundColor Green
} catch {
    Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
    foreach ($f in $KmsLog, "$KmsLog.err") { if (Test-Path $f) { Write-Host "--- tail $f ---"; Get-Content $f -Tail 25 } }
    $script:failed = $true
} finally {
    Write-Step "Cleanup"
    foreach ($uid in $GoodId, $BadId) {
        try { Invoke-Csp -Timeout 30 -Params @{ Mode = "cleanup"; UniqueId = $uid } | Out-Null } catch { Write-Info "cleanup $uid : $($_.Exception.Message)" }
    }
    foreach ($t in $InstalledThumbprints | Where-Object { $_ }) { Remove-Item "Cert:\LocalMachine\My\$t" -Force -ErrorAction SilentlyContinue }
    foreach ($p in $ProxyProc, $KmsProc) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    if ($KeepWork -or (Get-Variable failed -Scope Script -ErrorAction SilentlyContinue)) { Write-Info "work dir kept: $WorkDir" }
    else { Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}
if (Get-Variable failed -Scope Script -ErrorAction SilentlyContinue) { exit 1 }
