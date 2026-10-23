#requires -Version 5.1
<# Milestone 5 - pure validation and forbidden-command regression. Never terminates a process. #>
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
$logDir=Join-Path ([IO.Path]::GetTempPath()) ('MiM5Test-'+[guid]::NewGuid().ToString('N'))
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
    $logs=@(Get-Content -LiteralPath $script:MiActions.AuditPath -Encoding UTF8)
    if (@($logs | Where-Object {$_ -match 'OBSERVATION_COMPLETE'}).Count -ne 1) {
        throw 'Complete audit log record missing.'
    }
} finally {
    if (Test-Path -LiteralPath $logDir) {Remove-Item -LiteralPath $logDir -Recurse -Force}
}
Write-Host 'PASS: M5 simulated action, danger mode, pending lock, delayed samples and audit.' -ForegroundColor Green

