#requires -Version 5.1
<# Protected uninstall: verify all obligations, remove only the known task,
archive installed payload, retain histories and audits. No recursive deletion. #>
param([switch]$PurgeProtectedData)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'PrivilegeSecurity.ps1')
if (-not (Test-MiAdminToken)) { throw 'Administrator permission required.' }
$paths=Assert-MiTrustedInstallation
if ($PurgeProtectedData) { throw 'Protected data purge is disabled by the retention policy; no changes made.' }
$answer=Read-Host 'Type UNINSTALL MEMORYINSPECTOR to archive the protected program files'
if ($answer -cne 'UNINSTALL MEMORYINSPECTOR') { throw 'Uninstall cancelled.' }
$lease=Enter-MiDeploymentLease -Exclusive
$lock=$null
try {
    $lock=Enter-MiTraceLock
    $paths=Assert-MiTrustedInstallation
    $manifest=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json
    if ($manifest.TraceArchitectureVersion -ne 1) { throw 'Use the matching legacy uninstaller for a legacy installation.' }
    $j=Read-MiTraceJournal $lock; Assert-MiTraceQuiescent $j
    if ($j.Deployment -cne 'Ready') { throw 'Unfinished deployment blocks uninstall; use TraceRecovery.' }
    $watchdog=Assert-MiWatchdog
    $recovery=[IO.File]::ReadAllText($paths.Recovery)|ConvertFrom-Json
    if ($recovery.SchemaVersion -ne 1 -or $null -eq $recovery.Records -or
        @($recovery.Records|Where-Object {$_.Status -cnotin @('StopFailed','RestoreConfirmed')}).Count -gt 0) { throw 'Service recovery blocks uninstall.' }
    $actual=@(Get-ChildItem -LiteralPath $paths.Install -Force -File)
    if ($actual.Count -ne @($manifest.Files).Count -or @(Get-ChildItem -LiteralPath $paths.Install -Force -Directory).Count -ne 0) {
        throw 'Installation contains unexpected content; nothing archived.'
    }
    # 先持久化删除意图，任务删除返回未知时保留执行器，禁止自动再次删除。
    $j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='RecoveryRequired';Intent='UnregisterWatchdog'})
    (Get-MiTaskScheduler).GetFolder('\').DeleteTask('MemoryInspector.TraceWatchdog',0)
    $stillPresent=$null
    try { $stillPresent=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog') }
    catch { if ($_.Exception.HResult -ne -2147024894) { throw } }
    if ($null -ne $stillPresent) { throw 'Watchdog removal outcome unknown; executor retained.' }
    $retired=Join-Path $paths.Data 'retired'
    if ([IO.Directory]::Exists($retired)) { Assert-MiTracePath $retired }
    else { [void][IO.Directory]::CreateDirectory($retired); Set-MiAdminDirectoryAcl $retired }
    $destination=Join-Path $retired ('install-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::Move($paths.Install,$destination)
    [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Retired'}))
    Write-Host ('Program files archived at '+$destination) -ForegroundColor Green
    Write-Host ('User history, protected audit, policy and trace records retained at '+$paths.Data)
} finally { if ($null -ne $lock) { $lock.Dispose() }; $lease.Dispose() }
