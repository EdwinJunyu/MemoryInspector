#requires -Version 5.1
<# Milestone 5 - validation, simulated actions and cross-process lock regression. Never terminates a real target process. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('ProcessActions.ps1','MemoryInspector.ps1','GuiV4.ps1','ProcessActionsTest.ps1')
foreach($file in $files) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $file),[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { throw ('PowerShell parse error: '+$file+' '+($errors|Out-String)) }
}
. (Join-Path $root 'ProcessActions.ps1')
$start=[datetime]::UtcNow.AddMinutes(-5)
$record=[pscustomobject]@{
    PID=42424;Name='M5-TestApp';StartUtcTicks=[long]$start.Ticks
    Status='Success';PrivateBytes=100MB
}
$sample=[pscustomobject]@{
    CaptureEndUtc=[datetime]::UtcNow
    Processes=[pscustomobject]@{Status='Success';Items=@($record)}
}
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'Pass') {throw 'Valid snapshot rejected.'}
$sample.CaptureEndUtc=[datetime]::UtcNow.AddSeconds(-91)
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'StaleSnapshot') {throw 'Stale snapshot accepted.'}
$sample.CaptureEndUtc=[datetime]::UtcNow
$record.Status='Partial'
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'IncompleteProcessData') {throw 'Incomplete data accepted.'}
$record.Status='Success'
$sample.Processes.Items=@()
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'IdentityNotInSnapshot') {throw 'Identity mismatch not rejected.'}
if (-not (Test-MiProtectedProcess -Name 'svchost' -Path 'C:\App\svchost.exe')) {throw 'Protected name not rejected.'}
if (-not (Test-MiProtectedProcess -Name 'normal' -Path '')) {throw 'Missing path not rejected.'}
$actionCode=Get-Content -LiteralPath (Join-Path $root 'ProcessActions.ps1') -Raw -Encoding UTF8
if ($actionCode -match '(?i)\b(Stop-Service|Start-Service|Invoke-Expression|Clear-StandbyList|EmptyWorkingSet)\b') { throw 'Forbidden action in M5 process module.' }
$guiCode=Get-Content -LiteralPath (Join-Path $root 'GuiV4.ps1') -Raw -Encoding UTF8
if ($guiCode -match '(?i)\.Kill\s*\(' -or $guiCode -match '(?i)\b(Stop-Process|Stop-Service)\b') { throw 'GUI directly performs destructive operations.' }
if ($actionCode -notmatch 'GetOwnerSid' -or $actionCode -notmatch 'Win32_Service' -or
    $actionCode -notmatch 'CloseMainWindow' -or $actionCode -notmatch 'Write-MiProcessAudit') {
    throw 'Missing process safety checks or audit.'
}
Write-Host 'PASS: M5 syntax, fail-closed snapshot, protected target, audit and separation.' -ForegroundColor Green

# The following checks use a fake in-memory process. No real PID is opened or terminated.
$script:FakeKills=0
$script:FakeCloses=0
$fake=[pscustomobject]@{
    HasExited=$false
    ProcessName=$record.Name
    StartTime=$start
}
$fake | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
$fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
$fake | Add-Member -MemberType ScriptMethod -Name CloseMainWindow -Value { $script:FakeCloses++; return $true }
$fake | Add-Member -MemberType ScriptMethod -Name Kill -Value { $script:FakeKills++ }
function Assert-MiProcessTarget { param($Item,$Snapshot) return $fake }
$logDir=Join-Path $root ('test-artifacts\ProcessActions-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($logDir)
try {
    $script:MiActions=[pscustomobject]@{
        CanAudit=$true;Busy=$false;Pending=$null
        AuditPath=(Join-Path $logDir 'actions.jsonl')
    }
    $sample.Processes.Items=@($record)
    $sample | Add-Member -NotePropertyName System -NotePropertyValue ([pscustomobject]@{
        Status='Success';CommittedBytes=[long](6GB);AvailablePhysicalBytes=[long](3GB)
    }) -Force
    $blocked=Invoke-MiProcessAction -Mode Force -Item $record -Snapshot $sample -DangerEnabled $false
    if ($blocked.Outcome -ne 'Rejected' -or $script:FakeKills -ne 0) {throw 'Danger-disabled force was not blocked.'}
    $allowed=Invoke-MiProcessAction -Mode Force -Item $record -Snapshot $sample -DangerEnabled $true
    if ($allowed.Outcome -ne 'Requested' -or $script:FakeKills -ne 1) {throw 'Fake test force path did not issue exactly one request.'}
    $again=Invoke-MiProcessAction -Mode Graceful -Item $record -Snapshot $sample -DangerEnabled $false
    if ($again.Outcome -ne 'Rejected' -or $script:FakeCloses -ne 0) {throw 'Pending action lock failed.'}
    # 另一个真正的 PowerShell 进程不能在观察期拿到同目标锁，RequestId/GUI 内存状态不参与判断。
    $q=[char]39
    $childCode='$ErrorActionPreference='+$q+'Stop'+$q+';. '+$q+(Join-Path $root 'ProcessActions.ps1').Replace("'","''")+$q+';'
    $childCode+='$script:MiActions=[pscustomobject]@{AuditPath='+$q+$script:MiActions.AuditPath.Replace("'","''")+$q+'};'
    $childCode+='$item=[pscustomobject]@{PID='+$record.PID+';StartUtcTicks='+$record.StartUtcTicks+'};'
    $childCode+='try {$h=Enter-MiProcessTargetLock $item Force;$h.Dispose();exit 7}catch {exit 0}'
    $childExe=Join-Path $env:WINDIR 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCode))
    $child=Start-Process -FilePath $childExe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -WindowStyle Hidden -PassThru
    try {
        $null=$child.Handle
        if (-not $child.WaitForExit(15000) -or $child.ExitCode -ne 0) {throw 'Another GUI bypassed process target lock.'}
    } finally {$child.Dispose()}
    $sample.CaptureEndUtc=$allowed.StartedUtc.AddSeconds(61)
    $sample.System.CommittedBytes=[long](5GB)
    $finished=Update-MiActionObservation -Snapshot $sample -NowUtc $allowed.StartedUtc.AddSeconds(62)
    if ($finished.State -ne 'Complete' -or $finished.NetCommitBytes -ne -[long](1GB)) {
        throw 'Release report net system commit calculation failed.'
    }
    if (@($allowed.Observations | Where-Object {$_.TargetStatus -eq 'MissingSample'}).Count -ne 3) {
        throw 'Delayed samples were incorrectly represented as timely measurements.'
    }
    if ($null -ne $script:MiActions.Pending) {throw 'Action observation lock was not released.'}
    $completedPath=Join-Path $logDir ('process-'+$record.PID+'-'+$record.StartUtcTicks+'.lock')
    $stateRows=@(Get-Content -LiteralPath $completedPath -Encoding UTF8 | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    foreach ($requiredState in @('RejectedBeforeDispatch','Dispatching','Requested','ObservationComplete')) {
        if (@($stateRows | Where-Object {$_.Status -ceq $requiredState}).Count -ne 1) {throw ('Append-only target state lost evidence: '+$requiredState)}
    }

    $logs=@(Get-Content -LiteralPath $script:MiActions.AuditPath -Encoding UTF8)
    if (@($logs | Where-Object {$_ -match 'OBSERVATION_COMPLETE'}).Count -ne 1) {
        throw 'Complete audit log record missing.'
    }
    $duplicate=Invoke-MiProcessAction -Mode Force -Item $record -Snapshot $sample -DangerEnabled $true
    if ($duplicate.Outcome -eq 'Requested' -or $script:FakeKills -ne 1) {throw 'Completed force request was sent twice for same instance.'}
    # 模拟发送前后崩溃：只释放 OS 句柄而不更新 Dispatching，下一实例必须拒绝未知结果。
    $crashRecord=$record.PSObject.Copy();$crashRecord.PID=42425
    $crashLock=Enter-MiProcessTargetLock $crashRecord Force
    Write-MiProcessTargetState $crashLock 'simulated-crash' Force Dispatching
    $crashLock.Dispose()
    $uncertain=Invoke-MiProcessAction -Mode Force -Item $crashRecord -Snapshot $sample -DangerEnabled $true
    if ($uncertain.Outcome -eq 'Requested' -or $script:FakeKills -ne 1) {throw 'Unknown request was resent after crash lock release.'}
    # 已有空锁可能由创建或历史状态更新中途崩溃产生，不能回退成首次请求。
    foreach ($fault in @('EmptyExisting','TruncatedTail','MalformedJson','InvalidUtf8')) {
        $faultRecord=$record.PSObject.Copy()
        $faultRecord.PID=42430+@('EmptyExisting','TruncatedTail','MalformedJson','InvalidUtf8').IndexOf($fault)
        $faultPath=Join-Path $logDir ('process-'+$faultRecord.PID+'-'+$faultRecord.StartUtcTicks+'.lock')
        if ($fault -eq 'EmptyExisting') {
            [IO.File]::WriteAllBytes($faultPath,[byte[]]@())
        } else {
            $faultLock=Enter-MiProcessTargetLock $faultRecord Graceful
            Write-MiProcessTargetState $faultLock 'simulated-sent' Graceful Dispatching
            # 先确认完整发送证据，再模拟状态更新中断：旧行必须仍在，尾部不完整也绝不回退到旧行。
            $beforeLength=$faultLock.Length
            $tail=if ($fault -eq 'TruncatedTail') { [Text.Encoding]::UTF8.GetBytes('{"Status":"ObservationComplete"') }
                elseif ($fault -eq 'MalformedJson') { [Text.Encoding]::UTF8.GetBytes('not-json'+[Environment]::NewLine) }
                else { [byte[]]@(255,13,10) }
            $faultLock.Position=$faultLock.Length
            $faultLock.Write($tail,0,$tail.Length);$faultLock.Flush($true)
            if ($faultLock.Length -le $beforeLength) {throw 'Append interrupted update lost prior sent evidence.'}
            $faultLock.Dispose()
        }
        $faultResult=Invoke-MiProcessAction Force $faultRecord $sample $true
        if ($faultResult.Outcome -eq 'Requested' -or $script:FakeKills -ne 1) {throw ('Corrupt target state permitted duplicate request: '+$fault)}
    }
    # Graceful 观察结束后，保留用户明确确认的 Force 升级功能；Force 仍不能重复发送。
    $gracefulRecord=$record.PSObject.Copy();$gracefulRecord.PID=42426
    $graceful=Invoke-MiProcessAction -Mode Graceful -Item $gracefulRecord -Snapshot $sample -DangerEnabled $false
    if ($graceful.Outcome -ne 'Requested' -or $script:FakeCloses -ne 1) {throw 'Graceful simulation failed.'}
    $sample.CaptureEndUtc=$graceful.StartedUtc.AddSeconds(61)
    [void](Update-MiActionObservation -Snapshot $sample -NowUtc $graceful.StartedUtc.AddSeconds(62))
    $escalated=Invoke-MiProcessAction -Mode Force -Item $gracefulRecord -Snapshot $sample -DangerEnabled $true
    if ($escalated.Outcome -ne 'Requested' -or $script:FakeKills -ne 2) {throw 'Explicit Force escalation compatibility broken.'}
} finally {
    Stop-MiActionObservation
    # 测试证据保留在项目 test-artifacts 中，不删除历史及锁状态文件。
}
Write-Host 'PASS: M5 simulated actions, cross-process target lock, append-only crash/corruption guards, explicit escalation, delayed samples and audit.' -ForegroundColor Green

