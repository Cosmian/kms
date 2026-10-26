# ============================================================================
# scep_windows_csp.ps1 -- Drives the Windows MDM SCEP client (ClientCertificateInstall
# CSP) through the WMI bridge. Must run as SYSTEM: test_scep_windows.ps1 launches it
# through a one-shot scheduled task. Writes a JSON result to -OutFile (last, atomically)
# and a trace to "$OutFile.log".
#
# Modes: enroll (create the SCEP node, trigger enrollment, wait), cleanup (delete nodes).
# ============================================================================
param(
    [Parameter(Mandatory)][ValidateSet("enroll", "cleanup")][string]$Mode,
    [Parameter(Mandatory)][string]$UniqueId,
    [Parameter(Mandatory)][string]$OutFile,
    [string]$ServerUrl,
    [string]$Challenge,
    [string]$SubjectName,
    [string]$CaThumbprint,
    [string]$HashAlgorithm = "SHA-2",
    [int]$KeyLength = 2048,
    [int]$KeyUsage = 160,   # digitalSignature (0x80) + keyEncipherment (0x20)
    [string]$Eku = "1.3.6.1.5.5.7.3.2",
    [int]$TimeoutSec = 120
)
$ErrorActionPreference = "Stop"

$ns = "root\cimv2\mdm\dmmap"
$installClass = "MDM_ClientCertificateInstall_Install03"
$statusClass = "MDM_ClientCertificateInstall_SCEP01_01"
$scepRoot = "./Vendor/MSFT/ClientCertificateInstall/SCEP"
$parent = "$scepRoot/$UniqueId"
$logFile = "$OutFile.log"
Remove-Item $logFile, $OutFile -Force -ErrorAction SilentlyContinue

function Log { param([string]$Msg) "$(Get-Date -Format o) $Msg" | Add-Content -Path $logFile -Encoding UTF8 }

function Get-Nodes {
    @(Get-CimInstance -Namespace $ns -ClassName $installClass -Filter "ParentID='$parent'" -ErrorAction SilentlyContinue)
    @(Get-CimInstance -Namespace $ns -ClassName $statusClass -Filter "ParentID='$scepRoot' AND InstanceID='$UniqueId'" -ErrorAction SilentlyContinue)
}

function Remove-Nodes {
    foreach ($n in (Get-Nodes)) {
        if ($n) {
            try { Remove-CimInstance -InputObject $n -ErrorAction Stop; Log "removed $($n.CimClass.CimClassName)" }
            catch { Log "remove $($n.CimClass.CimClassName) failed: $($_.Exception.Message)" }
        }
    }
}

function Get-Status {
    Get-CimInstance -Namespace $ns -ClassName $statusClass -Filter "ParentID='$scepRoot' AND InstanceID='$UniqueId'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

$result = [ordered]@{ mode = $Mode; ok = $false; error = $null; status = $null; errorCode = $null; thumbprint = $null; respondent = $null }
try {
    if ($Mode -eq "cleanup") {
        Remove-Nodes
        $result.ok = $true
    } else {
        Remove-Nodes
        $props = @{
            ParentID = $parent; InstanceID = "Install"
            ServerURL = $ServerUrl; Challenge = $Challenge; SubjectName = $SubjectName
            KeyLength = [int]$KeyLength; KeyUsage = [int]$KeyUsage; HashAlgorithm = $HashAlgorithm
            EKUMapping = $Eku; KeyProtection = [int]3   # 3 = software KSP
            RetryCount = [int]1; RetryDelay = [int]1
        }
        if ($CaThumbprint) { $props.CAThumbprint = $CaThumbprint }
        Log "creating $installClass at $parent"
        $inst = New-CimInstance -Namespace $ns -ClassName $installClass -Property $props
        Log "created; invoking EnrollMethod"
        Invoke-CimMethod -InputObject $inst -MethodName EnrollMethod | Out-Null
        Log "EnrollMethod returned"

        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while ((Get-Date) -lt $deadline) {
            $s = Get-Status
            if ($s) {
                $result.status = $s.Status; $result.errorCode = $s.ErrorCode
                $result.thumbprint = $s.CertThumbprint; $result.respondent = $s.RespondentServerUrl
                Log "poll status=$($s.Status) errorCode=$($s.ErrorCode) thumbprint=$($s.CertThumbprint)"
                if ($s.CertThumbprint) { $result.ok = $true; break }
                if ($s.ErrorCode -ne 0) { $result.error = "enrollment failed, ErrorCode=$($s.ErrorCode)"; break }
            } else {
                Log "poll: no status node yet"
            }
            Start-Sleep -Seconds 2
        }
        if (-not $result.ok -and -not $result.error) { $result.error = "timeout after ${TimeoutSec}s" }
    }
} catch {
    $result.error = $_.Exception.Message
    Log "ERROR: $($_.Exception.Message)"
}

$tmp = "$OutFile.tmp"
$result | ConvertTo-Json | Set-Content -Path $tmp -Encoding UTF8
Move-Item -Path $tmp -Destination $OutFile -Force
