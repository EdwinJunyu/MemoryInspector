#requires -Version 5.1
<# M7 service-management regression tests. Dedicated file fixtures and simulated SCM only; NO real service state changes. #>
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
if ((Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim() -cne '0.0.9') {
    throw 'Expected version 0.0.9.'
}
Write-Host 'PASS: M7 syntax, allowlist contracts, protected service guard, fingerprints and recovery guards.' -ForegroundColor Green

# P1-03 / P1-05：仅使用项目内专用 JSON 和模拟 SCM，子进程不会查询或改变真实服务。
$fixture=Join-Path $root ('test-artifacts\ServiceManagement-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$script:TestPaths=[pscustomobject]@{
    PolicyFolder=$fixture;Policy=(Join-Path $fixture 'approved-services.json')
    Recovery=(Join-Path $fixture 'service-recovery.json');Audit=(Join-Path $fixture 'audit.jsonl')
}
function Get-MiSecurityPaths { return $script:TestPaths }
function Test-MiAdminToken { return $true }
# ACL 模拟只用于专用数据目录；生产逻辑的真实 ACL 验收仍由 disposable runner 承担。
function Test-MiNoReparse { param($Path) return $true }
function Test-MiAclRestricted { param($Path,$Protected) return $true }
function Set-MiProtectedFileAcl { param($Path,$AllowUsersRead) }
function Write-MiPrivilegedAudit {
    param($RequestId,$State,$Reason,$Action,$ServiceName)
    [IO.File]::AppendAllText($script:TestPaths.Audit,(@{RequestId=$RequestId;State=$State;ServiceName=$ServiceName;Reason=$Reason} | ConvertTo-Json -Compress)+[Environment]::NewLine)
}
function Reset-MiTestState {
    [IO.File]::WriteAllText($script:TestPaths.Policy,'{"SchemaVersion":1,"Services":[]}',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($script:TestPaths.Recovery,'{"SchemaVersion":1,"Records":[]}',[Text.UTF8Encoding]::new($false))
    $script:SvcState='Running';$script:ScCode=0;$script:ScThrows=$false;$script:WaitMode='Success';$script:ScCount=0
}
function Assert-MiTestRejected {
    param([scriptblock]$Body,[string]$Message)
    $rejected=$false
    try { & $Body | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw $Message }
}
$script:FakeService=[pscustomobject]@{
    Name='Vendor.P1Fixture';PathName='C:\Vendor\p1-fixture.exe';ServiceType='Own Process'
    StartName='LocalSystem';StartMode='Manual';State='Running';CanStop=$true;DisplayName='Simulated fixture';ProcessId=42424
}
function Get-MiServiceRecord { param($Name) $v=$script:FakeService.PSObject.Copy();$v.State=$script:SvcState;return $v }
function Assert-MiServiceEligible { param($Service) }
function Assert-MiServiceApproved { param($Service) return (Get-MiServiceFingerprint $Service) }
function Confirm-MiServiceAction { param($Operation,$Service) }
function Assert-MiServiceDependentsStopped { param($Name) }
function Assert-MiServicePrerequisitesRunning { param($Name) }
function Invoke-MiScControl {
    param($Verb,$Name)
    $script:ScCount++
    if ($script:ScThrows) { throw 'Simulated CIM transport failure after dispatch.' }
    return $script:ScCode
}
function Wait-MiServiceState {
    param($Name,$Desired)
    if ($script:WaitMode -eq 'Timeout') { throw [System.ServiceProcess.TimeoutException]::new('Simulated timeout') }
    if ($script:WaitMode -ne 'Mismatch') { $script:SvcState=[string]$Desired }
}
Reset-MiTestState
$stopId=[guid]::NewGuid().ToString('N')
if ((Invoke-MiServiceMutation StopApprovedService $script:FakeService.Name $stopId) -cne 'Confirmed') { throw 'Stop simulation failed.' }
$entry=Get-MiServiceRecoveryEntry $script:FakeService.Name
if ($entry.Status -cne 'StopConfirmed' -or -not (Test-MiRecoveryRestorable $script:FakeService $entry)) { throw 'Confirmed stop evidence unavailable.' }
$restoreId=[guid]::NewGuid().ToString('N')
if ((Invoke-MiServiceMutation StartPreviouslyStoppedService $script:FakeService.Name $restoreId) -cne 'Confirmed') { throw 'Restore simulation failed.' }
$entry=Get-MiServiceRecoveryEntry $script:FakeService.Name
if ($entry.Status -cne 'RestoreConfirmed' -or $entry.StopRequestId -cne $stopId -or $entry.LastRequestId -cne $restoreId) { throw 'Restore lost original stop identity or confirmed terminal state.' }
$states=@(Get-Content -LiteralPath $script:TestPaths.Audit | ForEach-Object { (ConvertFrom-Json -InputObject $_).State })
foreach ($expected in @('StopRequested','StopConfirmed','RestoreRequested','RestoreConfirmed')) {
    if ($states -cnotcontains $expected) { throw ('Missing transition audit: '+$expected) }
}
foreach ($failure in @('Declined','Timeout','Transport','Mismatch')) {
    Reset-MiTestState
    if ($failure -eq 'Declined') {$script:ScCode=5}
    if ($failure -eq 'Timeout') {$script:WaitMode='Timeout'}
    if ($failure -eq 'Transport') {$script:ScThrows=$true}
    if ($failure -eq 'Mismatch') {$script:WaitMode='Mismatch'}
    try { $outcome=Invoke-MiServiceMutation StopApprovedService $script:FakeService.Name ([guid]::NewGuid().ToString('N')) }
    catch { if ($failure -notin @('Transport','Mismatch')) {throw} }
    $entry=Get-MiServiceRecoveryEntry $script:FakeService.Name
    $expected=switch ($failure) {'Declined' {'StopFailed'} 'Timeout' {'TimedOut'} default {'UnknownOutcome'}}
    if ($entry.Status -cne $expected -or (Test-MiRecoveryRestorable $script:FakeService $entry)) { throw ('Unsafe failure evidence: '+$failure) }
    $script:SvcState='Stopped'
    Assert-MiTestRejected { Invoke-MiServiceMutation StartPreviouslyStoppedService $script:FakeService.Name ([guid]::NewGuid().ToString('N')) } 'Restore accepted unreliable stop evidence.'
    if ($script:ScCount -ne 1) { throw 'Rejected restore dispatched a second SCM request.' }
    if ($failure -ne 'Declined') {
        $script:SvcState='Running'
        Assert-MiTestRejected { Invoke-MiServiceMutation StopApprovedService $script:FakeService.Name ([guid]::NewGuid().ToString('N')) } 'Uncertain stop retried automatically.'
    }
}
Reset-MiTestState
Write-MiRecoveryRecord $script:FakeService ([guid]::NewGuid().ToString('N')) StopRequested
$script:SvcState='Stopped'
Assert-MiTestRejected { Invoke-MiServiceMutation StartPreviouslyStoppedService $script:FakeService.Name ([guid]::NewGuid().ToString('N')) } 'Legacy StopRequested became restoration evidence.'
$legacy=Get-MiServiceRecoveryEntry $script:FakeService.Name
$legacy.Status='Stopped'
if (-not (Test-MiRecoveryRestorable $script:FakeService $legacy)) {throw 'Legacy confirmed Stopped compatibility broken.'}
Reset-MiTestState
[void](Invoke-MiServiceMutation StopApprovedService $script:FakeService.Name ([guid]::NewGuid().ToString('N')))
$script:ScCode=5
if ((Invoke-MiServiceMutation StartPreviouslyStoppedService $script:FakeService.Name ([guid]::NewGuid().ToString('N'))) -ne 'Failed' -or
    (Get-MiServiceRecoveryEntry $script:FakeService.Name).Status -ne 'RestoreFailed') {throw 'Restore failure was not recorded.'}
Write-Host 'PASS: P1 simulated stop/restore success, declined, timeout, transport failure, unknown outcome and audited transitions.' -ForegroundColor Green

# 以下子进程共享真实 FileShare.None 锁；仅模拟管理员令牌和 ACL，不绕过被测同步实现。
$childSetup=@'
$ErrorActionPreference='Stop'
. (Join-Path $repo 'PrivilegeSecurity.ps1')
. (Join-Path $repo 'ServiceManagement.ps1')
$script:TestPaths=[pscustomobject]@{PolicyFolder=$fixture;Policy=(Join-Path $fixture 'approved-services.json');Recovery=(Join-Path $fixture 'service-recovery.json');Audit=(Join-Path $fixture 'audit.jsonl')}
function Get-MiSecurityPaths {return $script:TestPaths}
function Test-MiAdminToken {return $true}
function Test-MiNoReparse {param($Path) return $true}
function Test-MiAclRestricted {param($Path,$Protected) return $true}
function Set-MiProtectedFileAcl {param($Path,$AllowUsersRead)}
function Assert-MiServiceEligible {param($Service)}
function Write-MiPrivilegedAudit {param($RequestId,$State,$Reason,$Action,$ServiceName)}
$service=[pscustomobject]@{Name=$name;PathName='C:\Vendor\fixture.exe';ServiceType='Own Process';StartName='LocalSystem'}
'@
function Start-MiP1Child {
    param([string]$Name,[string]$Body)
    $q=[char]39
    $prefix='$repo='+$q+$root.Replace("'","''")+$q+';$fixture='+$q+$fixture.Replace("'","''")+$q+';$name='+$q+$Name+$q+';'
    $code=$prefix+[Environment]::NewLine+$childSetup+[Environment]::NewLine+$Body+[Environment]::NewLine+'exit 0'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $diagnostic=Join-Path $fixture ($Name+'-'+[guid]::NewGuid().ToString('N'))
    $child=Start-Process -FilePath $exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -WindowStyle Hidden -PassThru -RedirectStandardOutput ($diagnostic+'.out') -RedirectStandardError ($diagnostic+'.err')
    $null=$child.Handle
    $child | Add-Member -NotePropertyName DiagnosticPath -NotePropertyValue $diagnostic
    return $child
}
function Wait-MiP1Child {
    param($Process)
    try {
        if (-not $Process.WaitForExit(15000)) {throw 'P1 test child exceeded bounded deadline.'}
        if ($Process.ExitCode -ne 0) {throw ('P1 test child failed: '+$Process.ExitCode+'; '+[IO.File]::ReadAllText($Process.DiagnosticPath+'.err'))}
    } finally {$Process.Dispose()}
}
Reset-MiTestState
$held=Enter-MiServiceLock -Kind Target -Name 'Vendor.P1Fixture'
try {
    $child=Start-MiP1Child 'vendor.p1fixture' @'
function Get-MiServiceRecord {param($Name) throw 'BUG: target lookup occurred before acquiring target lock.'}
try {Invoke-MiServiceMutation StopApprovedService $name ([guid]::NewGuid().ToString('N'));exit 8}
catch {if ($_.Exception.Message -notlike '*lock unavailable*') {exit 9}}
'@
    Wait-MiP1Child $child
} finally {$held.Dispose()}
# 同名锁在异常进程退出时由 OS 释放；没有删除锁文件，也没有依据 PID 猜测锁是否有效。
$child=Start-MiP1Child 'Vendor.CrashFixture' '$lock=Enter-MiServiceLock -Kind Target -Name $name;[Environment]::Exit(0)'
Wait-MiP1Child $child
$released=Enter-MiServiceLock -Kind Target -Name 'vendor.crashfixture'
$released.Dispose()
foreach ($kind in @('Policy','Recovery')) {
    Reset-MiTestState
    $body=if ($kind -eq 'Policy') {
@'
$originalRead=${function:Read-MiServicePolicy}
function Read-MiServicePolicy {$value=& $originalRead;Start-Sleep -Milliseconds 150;return $value}
while (-not [IO.File]::Exists((Join-Path $fixture 'go-policy'))) {Start-Sleep -Milliseconds 10}
Update-MiServiceApproval ApproveService $service
'@
    } else {
@'
$originalRead=${function:Read-MiServiceRecovery}
function Read-MiServiceRecovery {$value=& $originalRead;Start-Sleep -Milliseconds 150;return $value}
while (-not [IO.File]::Exists((Join-Path $fixture 'go-recovery'))) {Start-Sleep -Milliseconds 10}
Write-MiRecoveryRecord $service ([guid]::NewGuid().ToString('N')) StopRequested
'@
    }
    $first=Start-MiP1Child 'Vendor.First' $body
    $second=Start-MiP1Child 'Vendor.Second' $body
    [IO.File]::WriteAllText((Join-Path $fixture ('go-'+$kind.ToLowerInvariant())),'start')
    Wait-MiP1Child $first
    Wait-MiP1Child $second
    if ($kind -eq 'Policy') {$count=@((Read-MiServicePolicy).Services).Count}
    else {$count=@((Read-MiServiceRecovery).Records).Count}
    if ($count -ne 2) {throw ('Concurrent '+$kind+' updates lost an entry.')}
}
Reset-MiTestState
$policyHeld=Enter-MiServiceLock -Kind Policy
try {
    Assert-MiTestRejected {Update-MiServiceApproval ApproveService $script:FakeService} 'Busy policy lock allowed an update.'
    if (@((Read-MiServicePolicy).Services).Count -ne 0) {throw 'Lock failure changed allowlist.'}
} finally {$policyHeld.Dispose()}
# 受保护审计失败时，不得派发 SCM，也不能把历史 Requested 洗成可恢复状态。
$originalAudit=${function:Write-MiPrivilegedAudit}
function Write-MiPrivilegedAudit {param($RequestId,$State,$Reason,$Action,$ServiceName) throw 'Simulated audit storage failure'}
try {
    Assert-MiTestRejected {Invoke-MiServiceMutation StopApprovedService $script:FakeService.Name ([guid]::NewGuid().ToString('N'))} 'Audit failure allowed service operation.'
    if ($script:ScCount -ne 0 -or @((Read-MiServiceRecovery).Records).Count -ne 0) {throw 'Audit failure dispatched SCM or rewrote ledger.'}
} finally {Set-Item -LiteralPath Function:Write-MiPrivilegedAudit -Value $originalAudit}
# 权限校验和锁争用失败必须发生在读取、写入或 SCM 调用之前。
function Test-MiAdminToken {return $false}
Assert-MiTestRejected {Enter-MiServiceLock Target 'Vendor.P1Fixture'} 'Non-admin lock accepted.'
function Test-MiAdminToken {return $true}
function Test-MiAclRestricted {param($Path,$Protected) return $false}
Assert-MiTestRejected {Enter-MiServiceLock Target 'Vendor.P1Fixture'} 'Untrusted lock path accepted.'
Write-Host ('PASS: P1 cross-process target exclusion, crash release, concurrent allowlist/ledger updates and fail-closed locks. Fixtures retained: '+$fixture) -ForegroundColor Green
