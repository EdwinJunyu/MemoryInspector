#requires -Version 5.1
<# V3-M2 protected installer. Explicit elevated Windows PowerShell 5.1 only.
Registers one fixed SYSTEM watchdog. Does not start WPR or change Heap settings. #>
$ErrorActionPreference='Stop'
$source=Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $source 'PrivilegeSecurity.ps1')
if ($PSVersionTable.PSVersion.Major -ne 5 -or -not (Test-MiAdminToken)) { throw 'Run Installer.ps1 in elevated Windows PowerShell 5.1.' }
$paths=Get-MiSecurityPaths
$names=@('MemoryInspector.ps1','Collector.ps1','Worker.ps1','Persistence.ps1','Analyzer.ps1','GuiV4.ps1',
    'ProcessActions.ps1','PrivilegeSecurity.ps1','PrivilegeBridge.ps1','ServiceBridge.ps1','ServiceManagement.ps1',
    'ElevatedExecutor.ps1','Run_MemoryInspector.cmd','Installer.ps1','Uninstaller.ps1','VERSION')
foreach ($name in $names) {
    $file=Join-Path $source $name
    if (-not [IO.File]::Exists($file) -or -not (Test-MiNoReparse $file)) { throw ('Missing or reparse source: '+$name) }
}
$sourceVersion=[IO.File]::ReadAllText((Join-Path $source 'VERSION')).Trim()
if ($sourceVersion -cne '0.0.9') { throw 'Expected VERSION 0.0.9; installation canceled.' }
if (-not [IO.Directory]::Exists($paths.Data)) {
    [void][IO.Directory]::CreateDirectory($paths.Data); Set-MiAdminDirectoryAcl $paths.Data
}
Assert-MiTracePath $paths.Data
$lease=Enter-MiDeploymentLease -Exclusive
$lock=$null
$stage=$null; $backup=$null; $oldManifest=$null; $registrationAttempted=$false; $journalReady=$false
$swap=[pscustomobject]@{OldInstallMoved=$false;StageInstalled=$false;OldManifestMoved=$false;NewManifestInstalled=$false;Backup=$null;OldManifest=$null}
try {
    $lock=Enter-MiTraceLock
    $wasM2=$false
    if ([IO.Directory]::Exists($paths.Install)) {
        [void](Assert-MiTrustedInstallation -AllowedVersions @('0.0.7','0.0.8','0.0.9'))
        $old=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json
        $wasM2=$old.TraceArchitectureVersion -eq 1
    }
    if ([IO.File]::Exists($paths.Recovery)) {
        Assert-MiTracePath $paths.Recovery
        # 服务恢复义务也不能因升级或卸载后的重装丢失。
        $serviceRecovery=[IO.File]::ReadAllText($paths.Recovery)|ConvertFrom-Json
        if ($serviceRecovery.SchemaVersion -ne 1 -or $null -eq $serviceRecovery.Records -or
            @($serviceRecovery.Records|Where-Object {$_.Status -cnotin @('StopFailed','RestoreConfirmed')}).Count -gt 0) {
            throw 'Pending service recovery blocks upgrade.'
        }
    }
    if ($wasM2) {
        $j=Read-MiTraceJournal $lock; Assert-MiTraceQuiescent $j
        if ($j.Deployment -cne 'Ready') { throw 'Unfinished deployment blocks upgrade; use TraceRecovery.' }
        [void](Assert-MiWatchdog)
    } else {
        # 除明确的任务不存在外，其余查询错误都不能当成可覆盖。
        $folder=(Get-MiTaskScheduler).GetFolder('\')
        $existing=$null
        try { $existing=$folder.GetTask('MemoryInspector.TraceWatchdog') }
        catch { if ($_.Exception.HResult -ne -2147024894) { throw } }
        if ($null -ne $existing) { throw 'Unknown existing Watchdog task; installation refused.' }
        if ([IO.Directory]::Exists($paths.TraceRoot)) {
            $j=Read-MiTraceJournal $lock; Assert-MiTraceQuiescent $j
            # 仅允许已退休安装，或尚未进入注册阶段且旧安装已重新通过完整性核验的事务。
            if ($j.Deployment -cne 'Retired' -and -not ($j.Deployment -cin @('Pending','RecoveryRequired') -and
                $j.DeploymentRecord.Intent -cin @('PrepareInstallation','RolledBackBeforeTaskRegistration'))) {
                throw 'Unfinished trace deployment requires protected recovery.'
            }
        } else {
            if ([IO.File]::Exists($paths.Manifest)) {
                Assert-MiTracePath $paths.Manifest
                $retainedManifest=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json
                if ($retainedManifest.TraceArchitectureVersion -eq 1) { throw 'M2 journal missing; cannot initialize again.' }
            }
            $j=Initialize-MiTraceJournal $lock
        }
    }
    $journalReady=$true
    $j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Pending';Intent='PrepareInstallation'})
    $parent=Split-Path -Parent $paths.Install
    $stage=Join-Path $parent ('MemoryInspector.stage-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($stage); Set-MiAdminDirectoryAcl $stage $true
    $entries=New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $names) {
        $destination=Join-Path $stage $name
        [IO.File]::WriteAllBytes($destination,[IO.File]::ReadAllBytes((Join-Path $source $name)))
        Set-MiProtectedFileAcl $destination $true
        $entries.Add([pscustomobject]@{Name=$name;Sha256=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash})
    }
    foreach ($directory in @((Split-Path -Parent $paths.Audit),$paths.Replay,$paths.Results,$paths.PolicyFolder)) {
        if ([IO.Directory]::Exists($directory)) { Assert-MiTracePath $directory }
        else { [void][IO.Directory]::CreateDirectory($directory); Set-MiAdminDirectoryAcl $directory }
    }
    Set-MiAdminDirectoryAcl $paths.Data $true; Set-MiAdminDirectoryAcl $paths.PolicyFolder $true
    foreach ($item in @(@($paths.Policy,'{"SchemaVersion":1,"Services":[]}'),
            @($paths.Recovery,'{"SchemaVersion":1,"Records":[]}'),@($paths.Audit,''))) {
        if ([IO.File]::Exists($item[0])) { Assert-MiTracePath $item[0] }
        else { [IO.File]::WriteAllText($item[0],$item[1],[Text.UTF8Encoding]::new($false)); Set-MiProtectedFileAcl $item[0] }
    }
    Set-MiProtectedFileAcl $paths.Policy $true
    $manifest=[ordered]@{SchemaVersion=1;Version=$sourceVersion;TraceArchitectureVersion=1;
        InstalledUtc=[datetime]::UtcNow.ToString('o');Files=@($entries.ToArray())}
    $newManifest=Join-Path $paths.Data ('install-manifest-'+[guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::WriteAllText($newManifest,($manifest|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false)); Set-MiProtectedFileAcl $newManifest
    if ([IO.Directory]::Exists($paths.Install)) {
        $backup=Join-Path $parent ('MemoryInspector.retained-'+[guid]::NewGuid().ToString('N'))
        $swap.Backup=$backup
        Move-MiDeploymentEntry $paths.Install $backup; $swap.OldInstallMoved=$true
    }
    Move-MiDeploymentEntry $stage $paths.Install; $swap.StageInstalled=$true
    if ([IO.File]::Exists($paths.Manifest)) {
        $oldManifest=$paths.Manifest+'.retained-'+[guid]::NewGuid().ToString('N'); $swap.OldManifest=$oldManifest
        Move-MiDeploymentEntry $paths.Manifest $oldManifest; $swap.OldManifestMoved=$true
    }
    Move-MiDeploymentEntry $newManifest $paths.Manifest; $swap.NewManifestInstalled=$true
    [void](Assert-MiTrustedInstallation)
    # 记录注册意图后才调用任务计划程序。结果未知时保留这一整套匹配的执行器/清单/Journal。
    $j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Pending';Intent='RegisterWatchdog'})
    $registrationAttempted=$true
    Register-MiWatchdog $lock $j $wasM2
    $lock.Dispose(); $lock=$null
    $health=Invoke-MiTraceHealthCheck
    $lock=Enter-MiTraceLock; $j=Read-MiTraceJournal $lock
    if ($j.Revision -ne $health.Revision -or $j.Hash -cne $health.Hash -or $j.Deployment -cne 'Pending') { throw 'Installation changed during health check.' }
    Assert-MiTraceQuiescent $j; [void](Assert-MiWatchdog)
    [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Ready'}))
    Write-Host ('Installed MemoryInspector '+$sourceVersion+' with protected V3-M2 architecture at '+$paths.Install) -ForegroundColor Green
    Write-Host 'WPR recording remains disabled until M3 acceptance. Old payloads and audits retained; not a Stable v3 release.'
} catch {
    $failure=$_.Exception.Message
    # 注册前且无任何追踪副作用时可恢复旧文件；注册后禁止猜测回滚或重复注册。
    $rollbackVerified=$false
    if (-not $registrationAttempted) {
        try {
            Restore-MiInstallationSwap $paths $swap
            if ([IO.Directory]::Exists($paths.Install)) { [void](Assert-MiTrustedInstallation -AllowedVersions @('0.0.7','0.0.8','0.0.9')) }
            $rollbackVerified=$true
        } catch { $failure+='; rollback could not be verified: '+$_.Exception.Message }
    }
    if ($journalReady) {
        try {
            if ($null -eq $lock) { $lock=Enter-MiTraceLock }
            $j=Read-MiTraceJournal $lock
            $intent=if ($rollbackVerified) {'RolledBackBeforeTaskRegistration'} else {'ManualRecovery'}
            [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='RecoveryRequired';Intent=$intent;Error=$failure}))
        } catch { $failure+='; protected journal also requires manual inspection' }
    }
    throw ('Installation failed closed. Backups/staging preserved. '+$failure)
} finally { if ($null -ne $lock) { $lock.Dispose() }; $lease.Dispose() }
