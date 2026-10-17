# ============================================================================
# test_est_windows.ps1 -- Windows RFC 7030 EST interoperability test.
#
# Drives github.com/globalsign/est/cmd/estclient against a live KMS over TLS:
#   1. /cacerts returns the KMS EST CA.
#   2. /csrattrs returns attributes for the configured template.
#   3. /simpleenroll issues a Basic-authenticated bootstrap certificate.
#   4. Invalid bootstrap credentials and an out-of-template CSR are rejected.
#   5. /simplereenroll accepts mutual TLS for the same identity and rejects a changed one.
#
# The runner is deliberately non-FIPS: the Windows CI image provisions only the
# static OpenSSL Vcpkg triplet, which does not support the FIPS provider.
#
# Usage (repository root):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .mise\scripts\windows\test_est_windows.ps1 [-NoBuild] [-KeepWork]
# ============================================================================
param(
    [switch]$NoBuild,
    [switch]$KeepWork
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$TargetDir = Join-Path $RepoRoot "target\debug"
$CaUid = "windows-est-ca"
$BootstrapUser = "bootstrap"
$BootstrapPassword = "bootstrap-secret"
$RunId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$WorkDir = Join-Path $WorkRoot "kms-est-win-$RunId"
$KmsProc = $null
$script:Failed = $false
$script:LastNativeExitCode = 0

function Write-Step { param([string]$Message) Write-Host "`n=== $Message ===" -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host "  [PASS] $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "  $Message" -ForegroundColor DarkGray }
function Fail { param([string]$Message) throw "FAIL: $Message" }
function Assert-That {
    param([bool]$Condition, [string]$Pass, [string]$FailMessage)
    if ($Condition) { Write-Ok $Pass } else { Fail $FailMessage }
}

# Runs a native program without PowerShell converting stderr into an ErrorRecord.
# The output files keep argument quoting and stdout/stderr handling uniform across
# cargo, openssl, ckms, curl, and estclient.
function Invoke-Native {
    param(
        [string]$Program,
        [string[]]$Arguments,
        [string]$FailMessage = "",
        [switch]$AllowFail
    )
    $stdoutFile = [IO.Path]::GetTempFileName()
    $stderrFile = [IO.Path]::GetTempFileName()
    try {
        $argumentLine = ($Arguments | ForEach-Object {
            if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
        }) -join ' '
        $process = Start-Process -FilePath $Program -ArgumentList $argumentLine -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
        $null = $process.Handle
        $stdout = Get-Content -Path $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -Path $stderrFile -Raw -ErrorAction SilentlyContinue
        $script:LastNativeExitCode = $process.ExitCode
        $script:LastNativeOutput = "$stdout$stderr"
        if ($process.ExitCode -ne 0 -and -not $AllowFail) {
            Fail "$FailMessage (exit $($process.ExitCode)): $stderr $stdout"
        }
        if ($null -eq $stdout) { return "" }
        return $stdout
    } finally {
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return $listener.LocalEndpoint.Port } finally { $listener.Stop() }
}

function Stop-Kms {
    if ($script:KmsProc -and -not $script:KmsProc.HasExited) {
        Stop-Process -Id $script:KmsProc.Id -Force -ErrorAction SilentlyContinue
        $script:KmsProc.WaitForExit()
    }
    $script:KmsProc = $null
}

function Start-Kms {
    param([string]$KmsExe, [string]$ConfigPath, [string]$LogPath)
    $script:KmsProc = Start-Process -FilePath $KmsExe -ArgumentList "-c `"$ConfigPath`"" -PassThru -NoNewWindow `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.err"
}

function Wait-ForTlsKms {
    param([string]$CurlExe, [string]$TlsCa, [int]$Port, [string]$LogPath)
    $url = "https://127.0.0.1:$Port/version"
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        Invoke-Native $CurlExe @("--fail", "--silent", "--show-error", "--ssl-no-revoke", "--cacert", $TlsCa, $url) "curl readiness probe failed" -AllowFail | Out-Null
        if ($script:LastNativeExitCode -eq 0) { return }
        if (-not $script:KmsProc -or $script:KmsProc.HasExited) {
            Fail "KMS exited during TLS startup; see $LogPath.err"
        }
        Start-Sleep -Milliseconds 500
    }
    Fail "KMS did not become ready over TLS; see $LogPath.err"
}

function New-DeviceCsr {
    param([string]$OpensslExe, [string]$OpenSslConfig, [string]$CommonName, [string]$KeyPath, [string]$CsrPath)
    Invoke-Native $OpensslExe @("req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", $OpenSslConfig,
        "-subj", "/CN=$CommonName", "-keyout", $KeyPath, "-out", $CsrPath) "failed to create CSR for $CommonName" | Out-Null
}

function Get-CertificateSerial {
    param([string]$OpensslExe, [string]$CertificatePath)
    return (Invoke-Native $OpensslExe @("x509", "-in", $CertificatePath, "-noout", "-serial") "failed to read certificate serial").Trim()
}

function Set-OpenSslDirectory {
    param([string]$RepositoryRoot)
    $manifestDir = Join-Path $RepositoryRoot "vcpkg_installed\x64-windows-static"
    $manifestHeader = Join-Path $manifestDir "include\openssl\ssl.h"
    if (Test-Path $manifestHeader) {
        $env:OPENSSL_DIR = $manifestDir
        return
    }
    if ($env:VCPKG_INSTALLATION_ROOT) {
        $classicDir = Join-Path $env:VCPKG_INSTALLATION_ROOT "packages\openssl_x64-windows-static"
        $classicHeader = Join-Path $classicDir "include\openssl\ssl.h"
        if (Test-Path $classicHeader) {
            $env:OPENSSL_DIR = $classicDir
            return
        }
    }
    Fail "OpenSSL headers were not found in $manifestDir or the VCPKG_INSTALLATION_ROOT package directory"
}

try {
    foreach ($command in "go", "openssl", "cargo", "curl.exe") {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { Fail "$command not found in PATH" }
    }
    $Go = (Get-Command go).Source
    $Openssl = (Get-Command openssl).Source
    $Cargo = (Get-Command cargo).Source
    $Curl = (Get-Command curl.exe).Source

    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $env:GOBIN = Join-Path $WorkDir "bin"
    $env:OPENSSL_CONF = Join-Path $WorkDir "openssl.cnf"
    @(
        '[req]',
        'distinguished_name = req_distinguished_name',
        'prompt = no',
        'x509_extensions = v3_ca',
        '',
        '[req_distinguished_name]',
        'CN = localhost',
        '',
        '[v3_ca]',
        'basicConstraints = critical,CA:TRUE',
        'keyUsage = critical,keyCertSign,cRLSign,digitalSignature',
        'subjectKeyIdentifier = hash'
    ) | Set-Content -Path $env:OPENSSL_CONF -Encoding ASCII

    Set-OpenSslDirectory $RepoRoot
    Write-Step "Build KMS server and ckms (non-fips)"
    if (-not $NoBuild) {
        Push-Location $RepoRoot
        try {
            Invoke-Native $Cargo @("build", "--bin", "cosmian_kms", "--features", "non-fips") "cargo build cosmian_kms failed" | Out-Null
            Invoke-Native $Cargo @("build", "--package", "ckms", "--features", "non-fips") "cargo build ckms failed" | Out-Null
        } finally { Pop-Location }
    }
    $KmsExe = Join-Path $TargetDir "cosmian_kms.exe"
    $CkmsExe = Join-Path $TargetDir "ckms.exe"
    foreach ($binary in $KmsExe, $CkmsExe) {
        if (-not (Test-Path $binary)) { Fail "binary not found: $binary" }
    }

    Write-Step "Install pinned EST client"
    Invoke-Native $Go @("install", "github.com/globalsign/est/cmd/estclient@v1.0.7") "failed to install pinned estclient" | Out-Null
    $EstClient = Join-Path $env:GOBIN "estclient.exe"
    if (-not (Test-Path $EstClient)) { Fail "pinned estclient was not installed at $EstClient" }
    # v1.0.7 treats --help as an invalid command; its help command lists the available EST operations.
    Invoke-Native $EstClient @("help") "pinned estclient help failed" | Out-Null
    $requiredEstCommands = @("cacerts", "csrattrs", "enroll", "reenroll")
    $missingEstCommands = @($requiredEstCommands | Where-Object { $script:LastNativeOutput -notmatch "\b$([regex]::Escape($_))\b" })
    if ($missingEstCommands.Count -ne 0) {
        Fail "pinned estclient usage does not advertise: $($missingEstCommands -join ', ')`n$($script:LastNativeOutput)"
    }

    $dbDir = Join-Path $WorkDir "db"
    $bootstrapPort = Get-FreePort
    $bootstrapUrl = "http://127.0.0.1:$bootstrapPort"
    $tomlPath = $WorkDir.Replace('\', '/')
    $bootstrapConfig = Join-Path $WorkDir "kms-bootstrap.toml"
    @(
        'default_username = "admin"', '',
        '[db]', 'database_type = "sqlite"', "sqlite_path = `"$tomlPath/db`"", 'clear_database = true', '',
        '[http]', 'hostname = "127.0.0.1"', "port = $bootstrapPort", '',
        '[logging]', 'rust_log = "info,cosmian_kms=info"', 'ansi_colors = false'
    ) | Set-Content -Path $bootstrapConfig -Encoding ASCII
    New-Item -ItemType Directory -Force -Path $dbDir | Out-Null

    Write-Step "Provision EST CA and enrollment authorization"
    $bootstrapLog = Join-Path $WorkDir "kms-bootstrap.log"
    Start-Kms $KmsExe $bootstrapConfig $bootstrapLog
    $deadline = (Get-Date).AddSeconds(60)
    $bootstrapReady = $false
    while ((Get-Date) -lt $deadline) {
        Invoke-Native $Curl @("--fail", "--silent", "--show-error", "$bootstrapUrl/version") "bootstrap KMS readiness probe failed" -AllowFail | Out-Null
        if ($script:LastNativeExitCode -eq 0) { $bootstrapReady = $true; break }
        if ($script:KmsProc.HasExited) { Fail "bootstrap KMS exited; see $bootstrapLog.err" }
        Start-Sleep -Milliseconds 500
    }
    if (-not $bootstrapReady) { Fail "bootstrap KMS did not become ready; see $bootstrapLog.err" }

    $CkmsConfig = Join-Path $WorkDir "ckms.toml"
    "[http_config]`nserver_url = `"$bootstrapUrl`"" | Set-Content -Path $CkmsConfig -Encoding ASCII
    function Invoke-Ckms { param([string[]]$Arguments) Invoke-Native $CkmsExe (@("--conf-path", $CkmsConfig) + $Arguments) "ckms $($Arguments -join ' ')" }

    $caExtensions = Join-Path $WorkDir "ca.ext"
    @('[ v3_ca ]', 'basicConstraints=critical,CA:TRUE', 'keyUsage=critical,keyCertSign,crlSign,digitalSignature') |
        Set-Content -Path $caExtensions -Encoding ASCII
    Invoke-Ckms @("certificates", "certify", "--certificate-id", $CaUid, "--generate-key-pair", "--algorithm", "rsa2048",
        "--subject-name", "CN=Windows EST Interop Test CA,O=Cosmian Test,C=FR", "--days", "3650",
        "--certificate-extensions", $caExtensions) | Out-Null
    $CaPem = Join-Path $WorkDir "est-ca.crt"
    Invoke-Ckms @("certificates", "export", $CaPem, "--certificate-id", $CaUid, "--format", "pem") | Out-Null
    $linksFile = Join-Path $WorkDir "ca-links.json"
    Invoke-Ckms @("attributes", "get", "-i", $CaUid, "-a", "LinkType", "-l", "private-key", "-o", $linksFile) | Out-Null
    $CaPrivateKeyUid = (Get-Content -Path $linksFile -Raw | ConvertFrom-Json).PrivateKeyLink
    if ([string]::IsNullOrWhiteSpace($CaPrivateKeyUid)) { Fail "CA PrivateKeyLink was not returned" }
    Invoke-Ckms @("access-rights", "grant", "[enrollment-service]", "-i", $CaUid, "certify") | Out-Null
    Invoke-Ckms @("access-rights", "grant", "[enrollment-service]", "-i", $CaPrivateKeyUid, "certify") | Out-Null
    Stop-Kms

    Write-Step "Generate local TLS server certificate"
    $TlsCaKey = Join-Path $WorkDir "tls-ca.key"
    $TlsCaPem = Join-Path $WorkDir "tls-ca.crt"
    $TlsKey = Join-Path $WorkDir "tls.key"
    $TlsCsr = Join-Path $WorkDir "tls.csr"
    $TlsPem = Join-Path $WorkDir "tls.crt"
    $TlsExtensions = Join-Path $WorkDir "tls.ext"
    'subjectAltName=IP:127.0.0.1,DNS:localhost' | Set-Content -Path $TlsExtensions -Encoding ASCII
    Invoke-Native $Openssl @("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", $env:OPENSSL_CONF,
        "-subj", "/CN=EST TLS CA", "-keyout", $TlsCaKey, "-out", $TlsCaPem) "failed to create TLS CA" | Out-Null
    Invoke-Native $Openssl @("req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", $env:OPENSSL_CONF,
        "-subj", "/CN=127.0.0.1", "-keyout", $TlsKey, "-out", $TlsCsr) "failed to create TLS server CSR" | Out-Null
    Invoke-Native $Openssl @("x509", "-req", "-in", $TlsCsr, "-CA", $TlsCaPem, "-CAkey", $TlsCaKey, "-CAcreateserial",
        "-days", "2", "-extfile", $TlsExtensions, "-out", $TlsPem) "failed to sign TLS server certificate" | Out-Null

    $tlsPort = Get-FreePort
    $tlsConfig = Join-Path $WorkDir "kms-est.toml"
    @(
        'default_username = "admin"', '',
        '[db]', 'database_type = "sqlite"', "sqlite_path = `"$tomlPath/db`"", 'clear_database = false', '',
        '[http]', 'hostname = "127.0.0.1"', "port = $tlsPort", '',
        '[tls]', "tls_cert_file = `"$($TlsPem.Replace('\', '/'))`"", "tls_key_file = `"$($TlsKey.Replace('\', '/'))`"", "clients_ca_cert_file = `"$($CaPem.Replace('\', '/'))`"", '',
        '[logging]', 'rust_log = "info,cosmian_kms=info"', 'ansi_colors = false', '',
        '[est]', 'est_enabled = true', "est_ca_uid = `"$CaUid`"", 'est_require_client_cert = false',
        "est_bootstrap_username = `"$BootstrapUser`"", "est_bootstrap_password = `"$BootstrapPassword`"", 'est_template = "windows_est_device"', '',
        '[templates.windows_est_device]', 'name = "windows_est_device"', 'min_rsa_key_bits = 2048', 'allowed_ekus = ["clientAuth"]',
        'max_validity_days = 365', 'default_validity_days = 90', 'subject_cn_regex = "[a-z0-9-]+\\.est\\.example"'
    ) | Set-Content -Path $tlsConfig -Encoding ASCII

    Write-Step "Start KMS over TLS with EST enabled"
    $KmsLog = Join-Path $WorkDir "kms.log"
    Start-Kms $KmsExe $tlsConfig $KmsLog
    Wait-ForTlsKms $Curl $TlsCaPem $tlsPort $KmsLog
    Write-Ok "KMS ready over TLS on 127.0.0.1:$tlsPort"
    $EstServer = "127.0.0.1:$tlsPort"
    function Invoke-Est {
        param([string[]]$Arguments, [switch]$AllowFail)
        Invoke-Native $EstClient $Arguments "estclient $($Arguments -join ' ')" -AllowFail:$AllowFail
    }

    Write-Step "Scenario 1: /cacerts"
    $CaCerts = Join-Path $WorkDir "cacerts.pem"
    Invoke-Est @("cacerts", "-server", $EstServer, "-explicit", $TlsCaPem, "-out", $CaCerts) | Out-Null
    $expectedFingerprint = (Invoke-Native $Openssl @("x509", "-in", $CaPem, "-noout", "-fingerprint", "-sha256") "failed to read EST CA fingerprint").Trim()
    $receivedFingerprint = (Invoke-Native $Openssl @("x509", "-in", $CaCerts, "-noout", "-fingerprint", "-sha256") "failed to read /cacerts fingerprint").Trim()
    Assert-That ($expectedFingerprint -eq $receivedFingerprint) "/cacerts returned the KMS EST CA" "/cacerts fingerprint differs from the KMS EST CA"

    Write-Step "Scenario 2: /csrattrs"
    $csrAttributes = Invoke-Est @("csrattrs", "-server", $EstServer, "-explicit", $TlsCaPem)
    Assert-That (-not [string]::IsNullOrWhiteSpace($csrAttributes)) "/csrattrs returned template attributes" "/csrattrs returned an empty response"

    Write-Step "Scenario 3: /simpleenroll with HTTP Basic bootstrap credentials"
    $DeviceOneCn = "win-est-01.est.example"
    $DeviceOneKey = Join-Path $WorkDir "win-est-01.key"
    $DeviceOneCsr = Join-Path $WorkDir "win-est-01.csr"
    $DeviceOneCert = Join-Path $WorkDir "win-est-01.crt"
    New-DeviceCsr $Openssl $env:OPENSSL_CONF $DeviceOneCn $DeviceOneKey $DeviceOneCsr
    Invoke-Est @("enroll", "-server", $EstServer, "-explicit", $TlsCaPem, "-user", $BootstrapUser, "-pass", $BootstrapPassword,
        "-csr", $DeviceOneCsr, "-key", $DeviceOneKey, "-out", $DeviceOneCert) | Out-Null
    Invoke-Native $Openssl @("verify", "-CAfile", $CaPem, $DeviceOneCert) "bootstrap certificate does not chain to EST CA" | Out-Null
    $deviceOne = [Security.Cryptography.X509Certificates.X509Certificate2]::new($DeviceOneCert)
    Assert-That ($deviceOne.Subject -match "CN=$([regex]::Escape($DeviceOneCn))(,|$)") "bootstrap certificate has CN=$DeviceOneCn" "unexpected bootstrap certificate subject: $($deviceOne.Subject)"
    $eku = Invoke-Native $Openssl @("x509", "-in", $DeviceOneCert, "-noout", "-ext", "extendedKeyUsage") "failed to read bootstrap certificate EKU"
    Assert-That ($eku -match "TLS Web Client Authentication|clientAuth|1\.3\.6\.1\.5\.5\.7\.3\.2") "bootstrap certificate includes clientAuth EKU" "bootstrap certificate is missing clientAuth EKU: $eku"
    $certificateText = Invoke-Native $Openssl @("x509", "-in", $DeviceOneCert, "-noout", "-text") "failed to inspect bootstrap certificate key"
    $keyBitsMatch = [regex]::Match($certificateText, "Public-Key: \((\d+) bit\)")
    Assert-That ($keyBitsMatch.Success -and [int]$keyBitsMatch.Groups[1].Value -ge 2048) "bootstrap certificate uses RSA >= 2048 bits" "bootstrap certificate key is weaker than RSA-2048"
    Assert-That (($deviceOne.NotAfter.ToUniversalTime() - $deviceOne.NotBefore.ToUniversalTime()).TotalDays -le 366) "bootstrap certificate validity is within 365-day template maximum" "bootstrap certificate validity exceeds 365 days"
    $initialSerial = Get-CertificateSerial $Openssl $DeviceOneCert
    Write-Ok "/simpleenroll issued a valid bootstrap certificate"

    Write-Step "Scenario 4: rejected enrollments"
    Invoke-Est @("enroll", "-server", $EstServer, "-explicit", $TlsCaPem, "-user", $BootstrapUser, "-pass", "wrong",
        "-csr", $DeviceOneCsr, "-key", $DeviceOneKey) -AllowFail | Out-Null
    $wrongBootstrapOutput = $script:LastNativeOutput
    Assert-That ($script:LastNativeExitCode -ne 0 -and $wrongBootstrapOutput -match "401|Unauthorized|EST client authentication required") "wrong bootstrap password rejected" "/simpleenroll wrong-password failure did not prove rejected authentication: $wrongBootstrapOutput"
    $EvilKey = Join-Path $WorkDir "evil.key"
    $EvilCsr = Join-Path $WorkDir "evil.csr"
    New-DeviceCsr $Openssl $env:OPENSSL_CONF "evil.example.com" $EvilKey $EvilCsr
    Invoke-Est @("enroll", "-server", $EstServer, "-explicit", $TlsCaPem, "-user", $BootstrapUser, "-pass", $BootstrapPassword,
        "-csr", $EvilCsr, "-key", $EvilKey) -AllowFail | Out-Null
    $templateViolationOutput = $script:LastNativeOutput
    Assert-That ($script:LastNativeExitCode -ne 0 -and $templateViolationOutput -match "does not match|422|Unprocessable") "out-of-template enrollment rejected" "/simpleenroll template failure was not an HTTP 422: $templateViolationOutput"

    Write-Step "Scenario 5: /simplereenroll over mutual TLS"
    $RenewedKey = Join-Path $WorkDir "win-est-01-renewed.key"
    $RenewedCsr = Join-Path $WorkDir "win-est-01-renewed.csr"
    $RenewedCert = Join-Path $WorkDir "win-est-01-renewed.crt"
    New-DeviceCsr $Openssl $env:OPENSSL_CONF $DeviceOneCn $RenewedKey $RenewedCsr
    Invoke-Est @("reenroll", "-server", $EstServer, "-explicit", $TlsCaPem, "-certs", $DeviceOneCert, "-key", $DeviceOneKey,
        "-csr", $RenewedCsr, "-out", $RenewedCert) | Out-Null
    Invoke-Native $Openssl @("verify", "-CAfile", $CaPem, $RenewedCert) "re-enrolled certificate does not chain to EST CA" | Out-Null
    $renewedSerial = Get-CertificateSerial $Openssl $RenewedCert
    Assert-That ($initialSerial -ne $renewedSerial) "/simplereenroll issued a certificate with a new serial" "/simplereenroll returned the bootstrap certificate serial"
    $DeviceTwoKey = Join-Path $WorkDir "device2.key"
    $DeviceTwoCsr = Join-Path $WorkDir "device2.csr"
    New-DeviceCsr $Openssl $env:OPENSSL_CONF "device2.est.example" $DeviceTwoKey $DeviceTwoCsr
    Invoke-Est @("reenroll", "-server", $EstServer, "-explicit", $TlsCaPem, "-certs", $DeviceOneCert, "-key", $DeviceOneKey,
        "-csr", $DeviceTwoCsr) -AllowFail | Out-Null
    $changedSubjectOutput = $script:LastNativeOutput
    Assert-That ($script:LastNativeExitCode -ne 0 -and $changedSubjectOutput -match "identical|400|Bad Request") "changed-subject re-enrollment rejected" "/simplereenroll changed-subject failure was not an HTTP 400: $changedSubjectOutput"
    Write-Ok "All EST interoperability scenarios passed"
} catch {
    $script:Failed = $true
    Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
    foreach ($log in (Join-Path $WorkDir "kms-bootstrap.log"), (Join-Path $WorkDir "kms.log")) {
        foreach ($file in $log, "$log.err") {
            if (Test-Path $file) { Write-Host "--- tail $file ---"; Get-Content -Path $file -Tail 25 }
        }
    }
} finally {
    Stop-Kms
    if ($KeepWork -or $script:Failed) { Write-Info "work dir kept: $WorkDir" }
    else { Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($script:Failed) { exit 1 }
