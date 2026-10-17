# ============================================================================
# probe_mdm_scep.ps1 -- Read-only probe of the Windows MDM WMI bridge for the
# ClientCertificateInstall CSP (SCEP). Run from an ELEVATED Windows PowerShell.
#
# The bridge (root\cimv2\mdm\dmmap) only answers as SYSTEM, so the probe body is
# run through a one-shot scheduled task. Nothing is created or modified.
# Output is printed and saved to $env:TEMP\mdm-scep-probe.txt.
# ============================================================================
$ErrorActionPreference = "Stop"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell (Run as administrator)."
}

$out = Join-Path $env:TEMP "mdm-scep-probe.txt"
$body = Join-Path $env:TEMP "mdm-scep-probe-body.ps1"
Remove-Item $out -Force -ErrorAction SilentlyContinue

@'
$ErrorActionPreference = "Continue"
$out = '@@OUT@@'
& {
    "whoami: $(whoami)"
    $os = Get-CimInstance Win32_OperatingSystem
    "OS: $($os.Caption) build $($os.BuildNumber)"
    "--- Enrollments (HKLM) ---"
    Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -ErrorAction SilentlyContinue |
        ForEach-Object { $p = Get-ItemProperty $_.PSPath; "$($_.PSChildName) provider=$($p.ProviderID) upn=$($p.UPN) type=$($p.EnrollmentType)" }
    "--- ClientCertificateInstall classes in root\cimv2\mdm\dmmap ---"
    try {
        $classes = Get-CimClass -Namespace root\cimv2\mdm\dmmap -ClassName 'MDM_ClientCertificateInstall*' -ErrorAction Stop
        foreach ($c in $classes) {
            "CLASS $($c.CimClassName)"
            foreach ($p in $c.CimClassProperties) {
                $key = if ($p.Qualifiers['key']) { ' [key]' } else { '' }
                "    $($p.Name) : $($p.CimType)$key"
            }
            foreach ($m in $c.CimClassMethods) { "    METHOD $($m.Name)" }
        }
        "count=$(@($classes).Count)"
    } catch { "ERROR: $($_.Exception.Message)" }
    "--- Existing instances ---"
    try {
        Get-CimInstance -Namespace root\cimv2\mdm\dmmap -ClassName 'MDM_ClientCertificateInstall_Install01' -ErrorAction Stop |
            Format-List * | Out-String
    } catch { "none/err: $($_.Exception.Message)" }
} *>&1 | Out-File -FilePath $out -Encoding UTF8
'@.Replace('@@OUT@@', $out) | Set-Content -Path $body -Encoding UTF8

$taskName = "KmsMdmScepProbe"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$body`""
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
try {
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline -and (Get-ScheduledTask -TaskName $taskName).State -ne 'Ready') { Start-Sleep -Milliseconds 500 }
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $body -Force -ErrorAction SilentlyContinue
}

if (Test-Path $out) { Get-Content $out } else { Write-Host "No output produced." -ForegroundColor Red }
Write-Host "`nSaved to $out"
