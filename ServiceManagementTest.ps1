#requires -Version 5.1
<# M7 service-management contract tests. All read-only, NO real service state changes. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($file in @('ServiceManagement.ps1','ServiceBridge.ps1','ElevatedExecutor.ps1',
    'Installer.ps1','GuiV4.ps1','MemoryInspector.ps1','PrivilegeSecurity.ps1')) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $file),[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { throw ('M7 syntax failure in '+$file+': '+($errors | Out-String)) }
}
. (Join-Path $root 'PrivilegeSecurity.ps1')
. (Join-Path $root 'ServiceManagement.ps1')
foreach ($good in @('Spooler','TestService_123','Vendor.Agent-1','W32Time')) {
    if (-not (Test-MiServiceName $good)) { throw ('Valid service name rejected: '+$good) }
}
foreach ($bad in @('','../Bad','Name With Space',"Name';Remove-Item",('a' * 129))) {
    if (Test-MiServiceName $bad) { throw ('Unsafe service name allowed: '+$bad) }
}
foreach ($critical in @('RpcSs','WinDefend','SamSs','Schedule','BFE','PlugPlay','EventLog')) {
    if (-not (Test-MiServiceDenied $critical)) { throw ('Critical service not blocked: '+$critical) }
}
$id=[guid]::NewGuid().ToString('N')
if (-not (Test-MiPrivilegedOperation -Operation Probe -RequestId $id)) { throw 'M6 Probe broken.' }
foreach ($action in @('ApproveService','RevokeServiceApproval','StopApprovedService','StartPreviouslyStoppedService')) {
    if (-not (Test-MiPrivilegedOperation -Operation $action -RequestId $id -ServiceName 'Spooler')) {
        throw ('M7 operation rejected: '+$action)
    }
    if (Test-MiPrivilegedOperation -Operation $action -RequestId $id -ServiceName '../Injected') {
        throw 'Invalid service target passed.'
    }
    if (Test-MiPrivilegedOperation -Operation $action -RequestId 'invalid' -ServiceName 'Spooler') {
        throw 'Invalid request ID passed.'
    }
}
foreach ($action in @('ForceStop','StopProcess','sc.exe','powershell.exe','RunCommand')) {
    if (Test-MiPrivilegedOperation -Operation $action -RequestId $id -ServiceName 'Spooler') {
        throw ('Unexpected command allowed: '+$action)
    }
}
function Get-ItemProperty { param([string]$LiteralPath) return [pscustomobject]@{LaunchProtected=0} }
$svc=[pscustomobject]@{
    Name='Vendor.Test';PathName='C:\Program Files\Vendor\svc.exe -service'
    ServiceType='Own Process';StartName='LocalSystem';StartMode='Manual'
}
Assert-MiServiceEligible $svc
$approval=Get-MiServiceFingerprint $svc
if (-not (Test-MiServiceFingerprint $svc $approval)) { throw 'Identical service fingerprint rejected.' }
$changed=[pscustomobject]@{
    Name=$svc.Name;PathName='C:\Temp\changed.exe';ServiceType=$svc.ServiceType;StartName=$svc.StartName
}
if (Test-MiServiceFingerprint $changed $approval) { throw 'Changed executable fingerprint accepted.' }
function Get-ItemProperty { param([string]$LiteralPath) return [pscustomobject]@{LaunchProtected=1} }
try { Assert-MiServiceEligible $svc; throw 'LaunchProtected service allowed.' }
catch { if ($_.Exception.Message -eq 'LaunchProtected service allowed.') { throw } }
function Get-ItemProperty { param([string]$LiteralPath) return [pscustomobject]@{LaunchProtected=0} }
$blocked=[pscustomobject]@{
    Name='RpcSs';PathName='C:\Windows\System32\svchost.exe -k rpcss'
    ServiceType='Share Process';StartName='LocalSystem';StartMode='Auto'
}
try { Assert-MiServiceEligible $blocked; throw 'Protected service passed eligibility.' }
catch { if ($_.Exception.Message -eq 'Protected service passed eligibility.') { throw } }
$driver=[pscustomobject]@{
    Name='AcmeDriver';PathName='C:\Windows\drivers\test.sys'
    ServiceType='Kernel Driver';StartName='LocalSystem';StartMode='Manual'
}
try { Assert-MiServiceEligible $driver; throw 'Driver allowed.' }
catch { if ($_.Exception.Message -eq 'Driver allowed.') { throw } }
$code=[IO.File]::ReadAllText((Join-Path $root 'ServiceManagement.ps1'),[Text.Encoding]::UTF8)
if ($code -match '(?i)\b(Stop-Service|Start-Service|Stop-Process|Set-Service|Set-ItemProperty|Invoke-Expression|taskkill)\b') {
    throw 'Service implementation contains forbidden mutation interface.'
}
if ($code -notmatch 'Assert-MiServiceDependentsStopped' -or
    $code -notmatch 'Assert-MiServicePrerequisitesRunning' -or
    $code -notmatch 'WaitForStatus' -or $code -notmatch 'Write-MiRecoveryRecord' -or
    $code -notmatch 'Write-MiPrivilegedAudit') {
    throw 'Missing safety guards or audit/recovery controls.'
}
if ((Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim() -cne '0.0.8') {
    throw 'Expected version 0.0.8.'
}
Write-Host 'PASS: M7 syntax, allowlist contracts, protected service guard, fingerprints and recovery guards.' -ForegroundColor Green
