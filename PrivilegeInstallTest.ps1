#requires -Version 5.1
<#
M6 disposable GitHub Actions Windows runner installation acceptance.
Must only be executed on a fresh, disposable runner; NEVER on a user machine.
Default mode is disposable CI only. -LiveM2 is the explicitly selected Windows 11
acceptance mode: retains this run's installation and never runs the uninstall loop.
No service/diagnostic-target actions. Requires an elevated Windows PowerShell 5.1 token.
#>
param([switch]$LiveM2,[switch]$ContinueLiveM2,[switch]$ProbeLiveM2Normal,[switch]$InspectLiveM2,[switch]$RepairLiveM2TaskAcl,[string]$RestoreTaskDefinitionAttempt='')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'PrivilegeSecurity.ps1')
function Show-MiM2LiveInspection {
    # 只读诊断失败安装；不设置任务权限、重注册、清空日志或写入产品目录。
    if ($PSVersionTable.PSEdition -cne 'Desktop' -or -not (Test-MiAdminToken)) {throw 'Inspection requires elevated Windows PowerShell 5.1.'}
    $paths=Get-MiSecurityPaths;$marker=Join-Path $paths.Data 'm2-win11-live-owner.json';Assert-MiTracePath $marker
    $claim=[IO.File]::ReadAllText($marker)|ConvertFrom-Json
    if ($claim.SchemaVersion -ne 1 -or $claim.SourceRoot -cne $root -or $claim.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or -not (Test-MiGuidN $claim.RunId)) {throw 'Inspection owner mismatch.'}
    $task=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog')
    $sddl=$task.GetSecurityDescriptor(7);$sd=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $journal=$null;Assert-MiTracePath $paths.TraceLock
    $lock=[IO.File]::Open($paths.TraceLock,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {$journal=Read-MiTraceJournal $lock} finally {$lock.Dispose()}
    $result=[ordered]@{SchemaVersion=1;Utc=[datetime]::UtcNow.ToString('o');Mode='ReadOnlyInspection';RunId=$claim.RunId;Sddl=$sddl;
        Owner=$sd.Owner.Value;ControlFlags=$sd.ControlFlags.ToString();Aces=@($sd.DiscretionaryAcl|ForEach-Object {
            [pscustomobject]@{Sid=$_.SecurityIdentifier.Value;Mask=$_.AccessMask;Flags=$_.AceFlags.ToString();Type=$_.AceType.ToString()}});
        Xml=$task.Xml;LastTaskResult=$task.LastTaskResult;Deployment=$journal.Deployment;DeploymentRecord=$journal.DeploymentRecord;
        Revision=$journal.Revision;Hash=$journal.Hash;ManifestHash=(Get-FileHash $paths.Manifest -Algorithm SHA256).Hash}
    $folder=Join-Path $root 'test-artifacts\v3-m2-win11';[void][IO.Directory]::CreateDirectory($folder)
    [IO.File]::WriteAllText((Join-Path $folder 'live-inspection.json'),($result|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    $result|ConvertTo-Json -Depth 6
}
function Repair-MiM2LiveTaskAcl {
    # 仅修复本次首次注册失败的固定任务 ACL；不改 payload/hash/policy，不宣告部署 Ready。
    if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not (Test-MiAdminToken)) {throw 'ACL repair requires elevated Windows PowerShell 5.1.'}
    $paths=Assert-MiTrustedInstallation;$marker=Join-Path $paths.Data 'm2-win11-live-owner.json';Assert-MiTracePath $marker
    $claim=[IO.File]::ReadAllText($marker)|ConvertFrom-Json
    if ($claim.SchemaVersion -ne 1 -or $claim.SourceRoot -cne $root -or $claim.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or -not (Test-MiGuidN $claim.RunId)) {throw 'ACL repair owner mismatch.'}
    $runLockPath=Join-Path $paths.Data 'm2-win11-live.lock';Assert-MiTracePath $runLockPath
    $runLock=[IO.File]::Open($runLockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $lease=$null;$lock=$null
    try {
        $lease=Enter-MiDeploymentLease -Exclusive;$lock=Enter-MiTraceLock;$j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
        if ($j.Deployment -cne 'RecoveryRequired' -or $j.DeploymentRecord.Intent -cne 'ManualRecovery' -or
            $j.DeploymentRecord.Error -cne 'Untrusted Watchdog task ACL.' -or $j.Sessions.Count -ne 0 -or $j.HeapTransactions.Count -ne 0 -or
            [IO.File]::Exists($paths.WatchdogPolicy)) {throw 'ACL repair only supports this pristine first-registration failure; no automatic general recovery.'}
        $task=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog');Assert-MiWatchdogConfiguration $task
        $before=$task.GetSecurityDescriptor(7);$sd=[Security.AccessControl.RawSecurityDescriptor]::new($before)
        if ($sd.Owner.Value -cne 'S-1-5-32-544' -or $null -eq $sd.DiscretionaryAcl -or
            $task.Definition.RegistrationInfo.SecurityDescriptor -cne 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)') {throw 'Unexpected task origin; ACL repair refused.'}
        foreach ($ace in $sd.DiscretionaryAcl) {
            if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.AceFlags -ne 0 -or
                $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
                $ace.SecurityIdentifier.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $ace.AccessMask -notin @(2032127,1179785)) {throw 'Unexpected task ACL; no overwrite.'}
        }
        $path=Join-Path $paths.Results ('m2-acl-repair-'+[guid]::NewGuid().ToString('N')+'.jsonl')
        $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {
            Set-MiProtectedFileAcl $path
            $intent=[ordered]@{SchemaVersion=1;State='Intent';RunId=$claim.RunId;BeforeSddl=$before;BeforeXml=$task.Xml;JournalRevision=$j.Revision;JournalHash=$j.Hash;Utc=[datetime]::UtcNow.ToString('o')}
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($intent|ConvertTo-Json -Compress)+"`n");$file.Write($bytes,0,$bytes.Length);$file.Flush($true)
            $task.SetSecurityDescriptor('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',16)
            $after=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog')
            $observed=[ordered]@{SchemaVersion=1;State='ObservedAfterSet';Sddl=$after.GetSecurityDescriptor(7);Utc=[datetime]::UtcNow.ToString('o')}
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($observed|ConvertTo-Json -Compress)+"`n");$file.Write($bytes,0,$bytes.Length);$file.Flush($true)
            $folder=Join-Path $root 'test-artifacts\v3-m2-win11'
            [IO.File]::WriteAllText((Join-Path $folder 'acl-set-observation.json'),($observed|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
            Assert-MiWatchdogDefinition $after
        } finally {$file.Dispose()}
        Write-Host 'Exact task ACL verified. Deployment remains RecoveryRequired; installed payload/policy are unchanged.'
    } finally {if ($null -ne $lock) {$lock.Dispose()};if ($null -ne $lease) {$lease.Dispose()};$runLock.Dispose()}
}
function Read-MiM2LiveAccessRoster {param($Paths)
    # 工作区 JSON 仅选择 GUID；实际存在性快照必须来自受保护目录并绑定当前用户/启动会话。
    $summary=[IO.File]::ReadAllText((Join-Path $root 'test-artifacts\v3-m2-win11\live-summary.json'))|ConvertFrom-Json
    if (-not (Test-MiGuidN $summary.AttemptId) -or $summary.Status -cne 'ChecksPassedWithPendingAcceptance') {throw 'No completed administrator acceptance snapshot.'}
    $rosterPath=Join-Path $Paths.Data ('m2-win11-access-'+$summary.AttemptId+'.json');Assert-MiTracePath $rosterPath
    $roster=[IO.File]::ReadAllText($rosterPath)|ConvertFrom-Json
    $age=[datetime]::UtcNow-(ConvertTo-MiTraceUtc $roster.Utc)
    if ($roster.SchemaVersion -ne 1 -or $roster.AttemptId -cne $summary.AttemptId -or -not (Test-MiGuidN $roster.RunId) -or
        $roster.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or $roster.BootSessionId -cne (Get-MiBootSessionId) -or
        $age.TotalSeconds -lt 0 -or $age.TotalMinutes -gt 15) {throw 'Stale or mismatched administrator existence snapshot.'}
    return $roster
}
function Invoke-MiM2NormalAccessProbe {
    # 只申请 OPEN_EXISTING 句柄，不写字节、不删除、不更改 ACL；缺失对象不能算权限拒绝。
    if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or (Test-MiAdminToken)) {
        throw 'Normal access probe requires non-elevated Windows PowerShell 5.1.'
    }
    $paths=Get-MiSecurityPaths
    if (-not [IO.File]::Exists($paths.Executor)) {throw 'Installed executor is missing; no access acceptance possible.'}
    # 普通令牌只持既有只读部署租约；它只阻止采样期间部署变更，不能追溯证明历史快照仍为当前部署。
    Assert-MiTracePath $paths.DeploymentLease
    $lease=[IO.File]::Open($paths.DeploymentLease,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
    [void][IO.File]::ReadAllText($paths.Executor)
    if (-not ('MiM2AccessProbeNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class MiM2AccessProbeNative {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr handle);
}
'@
    }
    $checks=@();$roster=$null
    foreach ($target in @($paths.Install,$paths.Executor,$paths.Data,$paths.Manifest,$paths.TraceRoot,$paths.TraceJournal,$paths.WatchdogPolicy)) {
        # 先用零访问权句柄证明对象存在；不能把父目录拒绝遍历造成的 ACCESS_DENIED 当作目标已受保护。
        $handle=[MiM2AccessProbeNative]::CreateFileW($target,0,7,[IntPtr]::Zero,3,33554432,[IntPtr]::Zero)
        $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $proof='NormalTokenMetadataHandle'
        if ($handle.ToInt64() -eq -1) {
            if ($errorCode -ne 5) {throw ('Cannot establish live object existence: '+$target+'; Win32 error '+$errorCode)}
            if ($null -eq $roster) {
                $roster=Read-MiM2LiveAccessRoster $paths
            }
            if (@($roster.Paths|Where-Object {$_ -ceq $target}).Count -ne 1) {throw 'Denied metadata has no bound administrator existence evidence.'}
            $proof='HistoricalProtectedAdministratorSnapshot_CurrentExistencePending'
        } else {[void][MiM2AccessProbeNative]::CloseHandle($handle)}
        foreach ($right in @(@('WriteData',2),@('WriteDacl',262144),@('Delete',65536))) {
            $handle=[MiM2AccessProbeNative]::CreateFileW($target,[uint32]$right[1],7,[IntPtr]::Zero,3,33554432,[IntPtr]::Zero)
            $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($handle.ToInt64() -ne -1) {[void][MiM2AccessProbeNative]::CloseHandle($handle);throw ('Normal user obtained '+$right[0]+' on '+$target)}
            if ($errorCode -ne 5) {throw ('Access probe returned unexpected Win32 error '+$errorCode+' on '+$target)}
            $checks+=,[pscustomobject]@{Path=$target;Right=$right[0];Win32Error=$errorCode;ExistenceProof=$proof}
        }
    }
    $handle=[MiM2AccessProbeNative]::CreateFileW($paths.TraceJournal,1,7,[IntPtr]::Zero,3,33554432,[IntPtr]::Zero)
    $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($handle.ToInt64() -ne -1) {[void][MiM2AccessProbeNative]::CloseHandle($handle);throw 'Normal user read protected Journal.'}
    if ($errorCode -ne 5) {throw 'Journal read did not return ACCESS_DENIED.'}
    # 查找被拒绝和 setter 被拒绝分别记账；查找失败时不能声称已实际调用写接口。
    $task=$null;$taskAccess=[ordered]@{Lookup='NotReached';ReadEnabled='NotReached';Write='NotReached';HResult=$null}
    try {$task=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog');$taskAccess.Lookup='Succeeded'}
    catch {if ($_.Exception.HResult -ne -2147024891) {throw};$taskAccess.Lookup='Denied';$taskAccess.HResult=$_.Exception.HResult}
    if ($null -ne $task) {
        try {$enabled=$task.Enabled;$taskAccess.ReadEnabled='Succeeded'}
        catch {if ($_.Exception.HResult -ne -2147024891) {throw};$taskAccess.ReadEnabled='Denied';$taskAccess.HResult=$_.Exception.HResult}
    }
    if ($taskAccess.ReadEnabled -ceq 'Succeeded') {
        $denied=$false
        try {$task.Enabled=$enabled}
        catch {if ($_.Exception.HResult -ne -2147024891) {throw};$denied=$true;$taskAccess.Write='Denied';$taskAccess.HResult=$_.Exception.HResult}
        if (-not $denied) {throw 'Normal user accessed task write interface.'}
    }
    $folder=Join-Path $root 'test-artifacts\v3-m2-win11';[void][IO.Directory]::CreateDirectory($folder)
    $report=[ordered]@{SchemaVersion=1;Mode='NonElevatedAccessProbe';Utc=[datetime]::UtcNow.ToString('o');
        OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Administrator=$false;Status=$(if ($null -eq $roster) {'Passed'} else {'AccessDeniedObservedCurrentExistencePending'});
        Checks=$checks;JournalReadWin32Error=$errorCode;TaskAccess=$taskAccess;AdministratorSnapshot=$roster}
    [IO.File]::WriteAllText((Join-Path $folder 'normal-access.json'),($report|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    if ($null -ne $roster) {throw 'Access denials observed and recorded; historical administrator snapshot cannot prove current inaccessible objects exist. Normal access acceptance remains Pending.'}
    Write-Host 'PASS: real non-elevated file write/DACL/delete and Journal read refused; fixed task access denial stage recorded.'
    } finally {$lease.Dispose()}
}
function Complete-MiM2LiveInitialRegistration {
    # 仅在外层已核验本次 owner/run 并持验收独占锁后调用；绝不重建未知任务或覆盖策略。
    $paths=Assert-MiTrustedInstallation;$lease=Enter-MiDeploymentLease -Exclusive;$lock=$null
    try {
        $lock=Enter-MiTraceLock;$j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
        if ($j.Revision -ne 4 -or $j.Deployment -cne 'RecoveryRequired' -or $j.DeploymentRecord.Intent -cne 'ManualRecovery' -or
            $j.DeploymentRecord.Error -cne 'Untrusted Watchdog task ACL.' -or $j.Sessions.Count -ne 0 -or $j.HeapTransactions.Count -ne 0 -or
            $j.Artifacts.Count -ne 0 -or [IO.File]::Exists($paths.WatchdogPolicy)) {throw 'Initial registration completion requires exact pristine failed transaction and absent policy.'}
        $records=@([IO.File]::ReadAllLines($paths.TraceJournal)|ForEach-Object {$_|ConvertFrom-Json})
        if ($records.Count -ne 4 -or $records[0].Kind -cne 'Initialize' -or $records[1].Kind -cne 'Deployment' -or $records[2].Kind -cne 'Deployment' -or
            ($records[1].Payload|ConvertFrom-Json).Intent -cne 'PrepareInstallation' -or ($records[2].Payload|ConvertFrom-Json).Intent -cne 'RegisterWatchdog') {throw 'Initial registration provenance mismatch.'}
        $task=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog');Assert-MiWatchdogDefinition $task
        $hash=Get-MiTraceHash $task.Xml
        [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='RecoveryRequired';Intent='LiveM2CompleteInitialRegistration';DefinitionHash=$hash}))
        $policy=[ordered]@{SchemaVersion=1;InstallationId=$j.InstallationId;DefinitionHash=$hash}
        $file=[IO.File]::Open($paths.WatchdogPolicy,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            Set-MiProtectedFileAcl $paths.WatchdogPolicy
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($policy|ConvertTo-Json -Compress));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)
        } finally {$file.Dispose()}
        [void](Assert-MiWatchdog)
    } finally {if ($null -ne $lock) {$lock.Dispose()};$lease.Dispose()}
    # 正式恢复仍要求新的真实 SYSTEM challenge/response；策略落盘不等于 Ready。
    Invoke-MiTraceDeploymentRecovery
}
function Restore-MiM2LiveTaskDefinition {param([string]$RunId,[string]$AttemptId)
    # 只消费受保护故障证据；备份必须逐字节匹配现有策略指纹，绝不修改策略来接纳新 XML。
    if (-not (Test-MiGuidN $RunId) -or -not (Test-MiGuidN $AttemptId)) {throw 'Invalid definition restore identity.'}
    $paths=Assert-MiTrustedInstallation;$lease=Enter-MiDeploymentLease -Exclusive;$lock=$null
    try {
        $lock=Enter-MiTraceLock;$j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
        $reportPath=Join-Path $paths.Results ('m2-win11-'+$AttemptId+'.json');Assert-MiTracePath $reportPath
        $prior=[IO.File]::ReadAllText($reportPath)|ConvertFrom-Json
        $failed=@($prior.Checks|Where-Object {$_.State -ceq 'Failed'})
        if ($prior.SchemaVersion -ne 1 -or $prior.RunId -cne $RunId -or $prior.AttemptId -cne $AttemptId -or $prior.Mode -cne 'Windows11LiveM2' -or
            $prior.Status -cne 'Failed' -or $failed.Count -ne 1 -or $failed[0].Name -cne 'TaskDefinitionTamperRefusedAndRestored' -or
            $failed[0].Error -cne 'Watchdog definition fingerprint mismatch.') {throw 'No bound task-definition fault report.'}
        $case=Join-Path (Join-Path (Join-Path $paths.Results 'm2-win11-fault-evidence') $AttemptId) 'TaskXml'
        $backup=Join-Path $case 'original.bin';$stages=Join-Path $case 'stages.jsonl'
        foreach ($path in @($case,$backup,$stages,$paths.WatchdogPolicy)) {Assert-MiTracePath $path}
        $intent=[IO.File]::ReadAllLines($stages)[0]|ConvertFrom-Json
        if ($intent.SchemaVersion -ne 1 -or $intent.RunId -cne $RunId -or $intent.AttemptId -cne $AttemptId -or $intent.Kind -cne 'TaskXml' -or
            $intent.State -cne 'CapturedBeforeMutation' -or $intent.OriginalSha256 -cne (Get-FileHash $backup -Algorithm SHA256).Hash) {throw 'Untrusted original task evidence.'}
        $original=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($backup))
        $policy=[IO.File]::ReadAllText($paths.WatchdogPolicy)|ConvertFrom-Json
        if ($policy.SchemaVersion -ne 1 -or $policy.InstallationId -cne $j.InstallationId -or (Get-MiTraceHash $original) -cne $policy.DefinitionHash) {throw 'Original XML does not match existing protected policy.'}
        $folder=(Get-MiTaskScheduler).GetFolder('\');$task=$folder.GetTask('MemoryInspector.TraceWatchdog');Assert-MiWatchdogDefinition $task
        $actual=$task.Xml;$sd=$task.GetSecurityDescriptor(7)
        $registrationSd='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        $normalized=$actual.Replace('<SecurityDescriptor>O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)</SecurityDescriptor>',('<SecurityDescriptor>'+$registrationSd+'</SecurityDescriptor>'))
        if ((Get-MiTraceHash $normalized) -cne $policy.DefinitionHash) {throw 'Task has changes beyond the observed descriptor serialization; no overwrite.'}
        $evidence=Join-Path $paths.Results ('m2-definition-restore-'+[guid]::NewGuid().ToString('N')+'.jsonl')
        $file=[IO.File]::Open($evidence,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {
            Set-MiProtectedFileAcl $evidence
            $record=[ordered]@{SchemaVersion=1;State='RestoreIntent';RunId=$RunId;AttemptId=$AttemptId;BeforeXml=$actual;BeforeSddl=$sd;ExpectedHash=$policy.DefinitionHash;JournalHash=$j.Hash;Utc=[datetime]::UtcNow.ToString('o')}
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress)+"`n");$file.Write($bytes,0,$bytes.Length);$file.Flush($true)
            $restored=$folder.RegisterTask('MemoryInspector.TraceWatchdog',$original,20,'S-1-5-18',$null,5,$registrationSd)
            $restored.SetSecurityDescriptor($sd,16);[void](Assert-MiWatchdog)
            $record=[ordered]@{SchemaVersion=1;State='Restored';RunId=$RunId;AttemptId=$AttemptId;Utc=[datetime]::UtcNow.ToString('o')}
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress)+"`n");$file.Write($bytes,0,$bytes.Length);$file.Flush($true)
        } finally {$file.Dispose()}
    } finally {if ($null -ne $lock) {$lock.Dispose()};$lease.Dispose()}
}
function Invoke-MiM2LiveAcceptance {
    # 普通终端不能跳过为 PASS；本模式只针对本次明确创建的产品资源，不覆盖未知安装。
    if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not (Test-MiAdminToken) -or
        [Environment]::OSVersion.Version.Build -lt 22000) {throw 'Live M2 requires elevated Windows PowerShell 5.1 on Windows 11.'}
    $paths=Get-MiSecurityPaths;$folder=Join-Path $root 'test-artifacts\v3-m2-win11'
    [void][IO.Directory]::CreateDirectory($folder)
    $marker=Join-Path $paths.Data 'm2-win11-live-owner.json';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($ContinueLiveM2) {
        Assert-MiTracePath $marker;$claim=[IO.File]::ReadAllText($marker)|ConvertFrom-Json
        if ($claim.SchemaVersion -ne 1 -or $claim.OwnerSid -cne $sid -or $claim.SourceRoot -cne $root -or -not (Test-MiGuidN $claim.RunId)) {throw 'Existing paths are not bound to this live acceptance.'}
    } else {
        if ([IO.Directory]::Exists($paths.Install) -or [IO.Directory]::Exists($paths.Data)) {throw 'Existing product paths refused; -ContinueLiveM2 only resumes this test-owned installation.'}
        $existing=$null
        try {$existing=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog')}
        catch {if ($_.Exception.HResult -ne -2147024894) {throw}}
        if ($null -ne $existing) {throw 'Unknown pre-existing Watchdog task refused.'}
        [void][IO.Directory]::CreateDirectory($paths.Data);Set-MiAdminDirectoryAcl $paths.Data
        $claim=[pscustomobject]@{SchemaVersion=1;RunId=[guid]::NewGuid().ToString('N');OwnerSid=$sid;SourceRoot=$root;CreatedUtc=[datetime]::UtcNow.ToString('o');BootBefore=(Get-MiBootSessionId)}
        $file=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($claim|ConvertTo-Json -Compress));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
        Set-MiProtectedFileAcl $marker
    }
    $runLockPath=Join-Path $paths.Data 'm2-win11-live.lock'
    if ([IO.File]::Exists($runLockPath)) {Assert-MiTracePath $runLockPath}
    $acceptanceLock=[IO.File]::Open($runLockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {Set-MiProtectedFileAcl $runLockPath} catch {$acceptanceLock.Dispose();throw}
    $report=[pscustomobject]@{SchemaVersion=1;RunId=$claim.RunId;AttemptId=[guid]::NewGuid().ToString('N');Mode='Windows11LiveM2';StartedUtc=[datetime]::UtcNow.ToString('o');
        OS=[Environment]::OSVersion.VersionString;PowerShell=$PSVersionTable.PSVersion.ToString();BootBefore=$claim.BootBefore;Status='Running';Checks=@();
        Pending=@('Real Windows restart/boot-trigger recovery','Windows 10 acceptance','Non-elevated access probe');Error=$null;ProtectedEvidence=$null;DefinitionRestoreAttempt=$RestoreTaskDefinitionAttempt}
    function Save-MiM2LiveReport {
        [IO.File]::WriteAllText((Join-Path $folder 'live-summary.json'),($report|ConvertTo-Json -Depth 9),[Text.UTF8Encoding]::new($false))
    }
    function Invoke-MiM2LiveCheck {param([string]$Name,[scriptblock]$Action)
        $clock=[Diagnostics.Stopwatch]::StartNew();$deploymentLease=$null
        try {
            if ($Name -cin @('DisabledTaskRefusedAndRestored','TaskDefinitionTamperRefusedAndRestored','TaskDaclTamperRefusedAndRestored','InstalledPayloadTamperRefusedAndRestored','OwnWatchdogInterruption','FinalProtectedStateAndAudit')) {
                $deploymentLease=Enter-MiDeploymentLease
            }
            $detail=& $Action;$report.Checks+=,[pscustomobject]@{Name=$Name;State='Passed';ElapsedMs=$clock.ElapsedMilliseconds;Detail=$detail};Save-MiM2LiveReport
        }
        catch {$report.Checks+=,[pscustomobject]@{Name=$Name;State='Failed';ElapsedMs=$clock.ElapsedMilliseconds;Error=$_.Exception.Message};Save-MiM2LiveReport;throw}
        finally {if ($null -ne $deploymentLease) {$deploymentLease.Dispose()}}
    }
    function Invoke-MiM2LiveChild {param([string]$Operation,[string]$Id)
        $exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $args='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+'" -Operation '+$Operation+' -RequestId '+$Id
        $process=Start-Process -FilePath $exe -ArgumentList $args -WindowStyle Hidden -PassThru -ErrorAction Stop
        try {if (-not $process.WaitForExit(60000)) {throw 'Executor outcome unknown; not killed or retried.'};return [int]$process.ExitCode} finally {$process.Dispose()}
    }
    function Save-MiM2LiveFaultBackup {param([ValidateSet('TaskEnabled','TaskXml','TaskDacl','Payload')][string]$Kind,[byte[]]$Original)
        # 故障注入前先保留受保护原值和意图。崩溃时不依赖 finally，更不从普通用户 JSON 恢复。
        $base=Join-Path $paths.Results 'm2-win11-fault-evidence';$attempt=Join-Path $base $report.AttemptId;$case=Join-Path $attempt $Kind
        foreach ($directory in @($base,$attempt,$case)) {
            if (-not [IO.Directory]::Exists($directory)) {[void][IO.Directory]::CreateDirectory($directory);Set-MiAdminDirectoryAcl $directory}
            Assert-MiTracePath $directory
        }
        $backup=Join-Path $case 'original.bin';$file=[IO.File]::Open($backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$file.Write($Original,0,$Original.Length);$file.Flush($true)} finally {$file.Dispose()}
        Set-MiProtectedFileAcl $backup
        $intent=[pscustomobject]@{SchemaVersion=1;RunId=$report.RunId;AttemptId=$report.AttemptId;Kind=$Kind;State='CapturedBeforeMutation';
            OriginalSha256=(Get-FileHash $backup -Algorithm SHA256).Hash;Utc=[datetime]::UtcNow.ToString('o');
            Guidance='Preserve original.bin and this protected record. If interrupted, compare the fixed owned task/payload and original hash before administrator repair. ContinueLiveM2 never overwrites an untrusted current state.'}
        $file=[IO.File]::Open((Join-Path $case 'stages.jsonl'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($intent|ConvertTo-Json -Compress)+"`n");$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
        Set-MiProtectedFileAcl (Join-Path $case 'stages.jsonl')
        return $case
    }
    function Add-MiM2LiveFaultStage {param([string]$Case,[ValidateSet('MutationApplied','Restored')][string]$State)
        $expected=Join-Path (Join-Path $paths.Results 'm2-win11-fault-evidence') $report.AttemptId
        if ([IO.Path]::GetDirectoryName($Case) -cne $expected -or [IO.Path]::GetFileName($Case) -cnotin @('TaskEnabled','TaskXml','TaskDacl','Payload')) {throw 'Unbound fault evidence directory.'}
        Assert-MiTracePath $Case;$path=Join-Path $Case 'stages.jsonl';Assert-MiTracePath $path
        $file=[IO.File]::Open($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(([ordered]@{SchemaVersion=1;State=$State;Utc=[datetime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress)+"`n");$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
    }
    function Invoke-MiM2LiveIntentProcess {param([ValidateSet('RecoveryIntent','RequestedIntent','VerifyRecovery')][string]$Kind,[string]$Id='')
        if ($Kind -ceq 'RequestedIntent' -and -not (Test-MiGuidN $Id)) {throw 'Invalid acceptance intent identity.'}
        $code=@'
$ErrorActionPreference='Stop'
. 'INSTALL_ROOT\PrivilegeSecurity.ps1'
if ('FIXED_KIND' -ceq 'VerifyRecovery') {Invoke-MiTraceDeploymentRecovery;exit 0}
$lock=Enter-MiTraceLock
try {
 $j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
 if ('FIXED_KIND' -ceq 'RecoveryIntent') {
  [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='RecoveryRequired';Intent='LiveM2VerifyOnly'}))
 } else {
  $id='INTENT_ID'
  $intent=[pscustomobject]@{SchemaVersion=1;TraceSessionId=$id;WprInstanceName=('MemoryInspector-'+$id);OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;BootSessionId=(Get-MiBootSessionId);
   RequestedTraceType='VirtualAlloc';ProfileId=$null;ProfileFingerprint=$null;WprExecutableIdentity=$null;RecordingMode='Memory';RequestedDuration=300;
   StartedUtc=$null;DeadlineUtc=$null;TraceWorkingBudget=0;State='Requested';CleanupState='NotRequired';OutputArtifactId=$null;LastVerifiedUtc=[datetime]::UtcNow.ToString('o');ErrorCode=$null;
   JournalRevision=1;StopState='NotStarted';SaveState='NotStarted';AnalysisState='NotStarted';ActiveReferences=0;AuthorizationId=$null}
  [void](Add-MiTraceJournalRecord $lock $j.Revision 'Session' $intent)
 }
} finally {$lock.Dispose()}
'@
        $code=$code.Replace('INSTALL_ROOT',$paths.Install.Replace("'","''")).Replace('FIXED_KIND',$Kind).Replace('INTENT_ID',$Id)
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $child=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -EncodedCommand '+$encoded) -PassThru -WindowStyle Hidden -ErrorAction Stop
        try {if (-not $child.WaitForExit(60000) -or $child.ExitCode -ne 0) {throw 'Live intent/recovery child failed or unknown; no automatic retry.'}} finally {$child.Dispose()}
    }
    try {
        Invoke-MiM2LiveCheck 'ProtectedInstallation' {
            if (-not [IO.Directory]::Exists($paths.Install)) {& (Join-Path $root 'Installer.ps1')}
            elseif ($ContinueLiveM2) {
                if (-not [string]::IsNullOrEmpty($RestoreTaskDefinitionAttempt)) {Restore-MiM2LiveTaskDefinition $claim.RunId $RestoreTaskDefinitionAttempt}
                if (-not [IO.File]::Exists($paths.WatchdogPolicy)) {Complete-MiM2LiveInitialRegistration}
                $current=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json;$changed=$false
                foreach ($entry in $current.Files) {
                    if ((Get-FileHash -LiteralPath (Join-Path $root $entry.Name) -Algorithm SHA256).Hash -cne $entry.Sha256) {$changed=$true}
                }
                # 安装源码修复只经过原安装器事务，不直接覆盖已安装文件或伪造 manifest hash。
                if ($changed) {& (Join-Path $root 'Installer.ps1')}
            }
            [void](Assert-MiTrustedInstallation)
            $manifest=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json
            if ($manifest.TraceArchitectureVersion -ne 1) {throw 'M2 architecture missing.'}
            [pscustomobject]@{Install=$paths.Install;Files=@($manifest.Files).Count;ManifestHash=(Get-FileHash $paths.Manifest -Algorithm SHA256).Hash}
        }
        # 从已安装副本加载真正部署的安全实现，不能用源代码替身假冒 SYSTEM 或 Journal。
        . (Join-Path $paths.Install 'PrivilegeSecurity.ps1')
        Invoke-MiM2LiveCheck 'ProtectedAclsAndFixedSystemTask' {
            foreach ($path in @($paths.Install,$paths.Data,$paths.TraceRoot,$paths.TraceJournal,$paths.WatchdogPolicy,$paths.Executor,$paths.Manifest)) {
                Assert-MiTracePath $path
            }
            $watchdog=Assert-MiWatchdog
            [pscustomobject]@{DefinitionHash=$watchdog.Policy.DefinitionHash;Sddl=$watchdog.Task.GetSecurityDescriptor(7);Xml=$watchdog.Task.Xml}
        }
        Invoke-MiM2LiveCheck 'ActualSystemHealthResponse' {
            $j=Invoke-MiTraceHealthCheck
            if ($j.Response.ExecutorSid -cne 'S-1-5-18' -or $j.Response.Nonce -cne $j.Challenge.Nonce) {throw 'No bound actual SYSTEM response.'}
            [pscustomobject]@{InstallationId=$j.InstallationId;Challenge=$j.Challenge;Response=$j.Response;Revision=$j.Revision;Hash=$j.Hash}
        }
        Invoke-MiM2LiveCheck 'DisabledTaskRefusedAndRestored' {
            $watchdog=Assert-MiWatchdog;$evidence=Save-MiM2LiveFaultBackup 'TaskEnabled' ([Text.Encoding]::UTF8.GetBytes($watchdog.Task.Xml))
            try {$watchdog.Task.Enabled=$false;Add-MiM2LiveFaultStage $evidence 'MutationApplied';$denied=$false;try {[void](Invoke-MiTraceHealthCheck)} catch {$denied=$true};if (-not $denied) {throw 'Disabled Watchdog accepted.'}}
            finally {$watchdog.Task.Enabled=$true}
            [void](Invoke-MiTraceHealthCheck);Add-MiM2LiveFaultStage $evidence 'Restored';return $evidence
        }
        Invoke-MiM2LiveCheck 'TaskDefinitionTamperRefusedAndRestored' {
            $watchdog=Assert-MiWatchdog;$original=$watchdog.Task.Xml;$sd=$watchdog.Task.GetSecurityDescriptor(7)
            $registrationSd=[string]$watchdog.Task.Definition.RegistrationInfo.SecurityDescriptor
            $evidence=Save-MiM2LiveFaultBackup 'TaskXml' ([Text.Encoding]::UTF8.GetBytes($original))
            $scheduler=Get-MiTaskScheduler;$taskFolder=$scheduler.GetFolder('\');$definition=$watchdog.Task.Definition
            $definition.Settings.ExecutionTimeLimit='PT44S'
            try {
                $changed=$taskFolder.RegisterTaskDefinition('MemoryInspector.TraceWatchdog',$definition,20,'S-1-5-18',$null,5,$registrationSd)
                $changed.SetSecurityDescriptor($sd,16)
                Add-MiM2LiveFaultStage $evidence 'MutationApplied'
                $denied=$false;try {[void](Assert-MiWatchdog)} catch {$denied=$true};if (-not $denied) {throw 'Changed task definition accepted.'}
            } finally {$restored=$taskFolder.RegisterTask('MemoryInspector.TraceWatchdog',$original,20,'S-1-5-18',$null,5,$registrationSd);$restored.SetSecurityDescriptor($sd,16)}
            [void](Assert-MiWatchdog);[void](Invoke-MiTraceHealthCheck);Add-MiM2LiveFaultStage $evidence 'Restored';return $evidence
        }
        Invoke-MiM2LiveCheck 'TaskDaclTamperRefusedAndRestored' {
            $watchdog=Assert-MiWatchdog;$original=$watchdog.Task.GetSecurityDescriptor(7)
            $evidence=Save-MiM2LiveFaultBackup 'TaskDacl' ([Text.Encoding]::UTF8.GetBytes($original))
            try {
                $watchdog.Task.SetSecurityDescriptor('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)',16)
                Add-MiM2LiveFaultStage $evidence 'MutationApplied'
                $denied=$false;try {[void](Assert-MiWatchdog)} catch {$denied=$true};if (-not $denied) {throw 'Changed task DACL accepted.'}
            } finally {$watchdog.Task.SetSecurityDescriptor($original,16)}
            [void](Assert-MiWatchdog);Add-MiM2LiveFaultStage $evidence 'Restored';return $evidence
        }
        Invoke-MiM2LiveCheck 'InstalledPayloadTamperRefusedAndRestored' {
            $target=Join-Path $paths.Install 'PrivilegeBridge.ps1';$before=[IO.File]::ReadAllBytes($target)
            $evidence=Save-MiM2LiveFaultBackup 'Payload' $before
            try {
                [IO.File]::WriteAllBytes($target,($before+[byte[]]@(10)))
                Add-MiM2LiveFaultStage $evidence 'MutationApplied'
                if ((Invoke-MiM2LiveChild 'Probe' ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Tampered payload accepted.'}
            } finally {[IO.File]::WriteAllBytes($target,$before);Set-MiProtectedFileAcl $target $true}
            [void](Assert-MiTrustedInstallation);Add-MiM2LiveFaultStage $evidence 'Restored';return $evidence
        }
        Invoke-MiM2LiveCheck 'RealProbeReplayAndIndependentGates' {
            $id=[guid]::NewGuid().ToString('N')
            if ((Invoke-MiM2LiveChild 'Probe' $id) -ne 0 -or (Invoke-MiM2LiveChild 'Probe' $id) -eq 0) {throw 'Probe/replay contract failed.'}
            if ((Invoke-MiM2LiveChild 'TraceWatchdog' 'Scheduled') -eq 0) {throw 'Administrator impersonated SYSTEM.'}
            if ((Invoke-MiM2LiveChild 'TraceStart' ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Unaccepted tracing enabled.'}
            if ((Get-MiWprReleaseStatus).Enabled -or (Get-MiHeapReleaseStatus).Enabled -or (Get-MiExportReleaseStatus).Enabled) {throw 'Release gate opened.'}
            return 'Actual child processes: Probe succeeded once; replay/SYSTEM impersonation/TraceStart refused.'
        }
        Invoke-MiM2LiveCheck 'DeploymentRecoveryPersistsAcrossControllerExit' {
            Invoke-MiM2LiveIntentProcess 'RecoveryIntent'
            $before=Get-MiTraceRecoveryReport
            if (-not $before.UpgradeBlocked) {throw 'Pending recovery did not block deployment.'}
            # 此处不修改 WPR/Heap；生产恢复函数只复核完整安装和新的 SYSTEM 扫描后再记 Ready。
            Invoke-MiM2LiveIntentProcess 'VerifyRecovery'
            $after=Get-MiTraceRecoveryReport
            if ($after.Deployment -cne 'Ready' -or $after.DeploymentBlocked) {throw 'Recovery did not verify readiness.'}
            [pscustomobject]@{Before=$before.Deployment;After=$after.Deployment;JournalRevision=$after.JournalRevision}
        }
        Invoke-MiM2LiveCheck 'OwnWatchdogInterruption' {
            $watchdog=Assert-MiWatchdog;$lock=Enter-MiTraceLock
            try {
                $j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
                # 仅中断本工具固定任务，且无活跃追踪；不按 PID 终止任何系统/目标进程。
                [void]$watchdog.Task.Run($null);$watchdog.Task.Stop(0)
            } finally {$lock.Dispose()}
            $clock=[Diagnostics.Stopwatch]::StartNew()
            do {Start-Sleep -Milliseconds 100;$task=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog')} while ($task.State -eq 4 -and $clock.Elapsed.TotalSeconds -lt 10)
            if ($task.State -eq 4 -or $task.LastTaskResult -ne 267014) {throw 'Task interruption not confirmed as SCHED_S_TASK_TERMINATED.'}
            [pscustomobject]@{TaskState=$task.State;LastTaskResult=$task.LastTaskResult;AutomaticRecovery='Pending following periodic intent check'}
        }
        Invoke-MiM2LiveCheck 'PeriodicWatchdogRecoversUnapprovedIntent' {
            $id=[guid]::NewGuid().ToString('N');Invoke-MiM2LiveIntentProcess 'RequestedIntent' $id
            # 不调用 Task.Run/UpdateSupervision，等待真实每分钟触发；没有伪造授权、录制或停止证据。
            $clock=[Diagnostics.Stopwatch]::StartNew();$observed=$null
            while ($clock.Elapsed.TotalSeconds -lt 100) {
                Start-Sleep -Milliseconds 500;$lock=$null
                try {$lock=Enter-MiTraceLock} catch [IO.IOException] {continue}
                try {$j=Read-MiTraceJournal $lock;$observed=$j.Sessions[$id];if ($observed.State -ceq 'AuthorizationDenied') {break}} finally {$lock.Dispose()}
            }
            if ($observed.State -cne 'AuthorizationDenied' -or $observed.ErrorCode -cne 'PreflightInterrupted') {throw 'No periodic recovery within observed 100-second window.'}
            [void](Invoke-MiTraceHealthCheck)
            [pscustomobject]@{TraceSessionId=$id;State=$observed.State;ErrorCode=$observed.ErrorCode;ElapsedMs=$clock.ElapsedMilliseconds;LastVerifiedUtc=$observed.LastVerifiedUtc}
        }
        Invoke-MiM2LiveCheck 'FinalProtectedStateAndAudit' {
            [void](Assert-MiTrustedInstallation);[void](Assert-MiWatchdog);$j=Invoke-MiTraceHealthCheck
            if ($j.Deployment -cne 'Ready') {throw 'Deployment not Ready at end.'}
            Assert-MiTraceQuiescent $j
            if ([IO.File]::ReadAllText($paths.Audit) -notmatch 'CONFIRMED') {throw 'Protected audit missing.'}
            $snapshotPaths=@($paths.Install,$paths.Executor,$paths.Data,$paths.Manifest,$paths.TraceRoot,$paths.TraceJournal,$paths.WatchdogPolicy)
            foreach ($path in $snapshotPaths) {Assert-MiTracePath $path}
            $snapshot=[ordered]@{SchemaVersion=1;RunId=$report.RunId;AttemptId=$report.AttemptId;OwnerSid=$claim.OwnerSid;InstallationId=$j.InstallationId;
                Utc=[datetime]::UtcNow.ToString('o');BootSessionId=(Get-MiBootSessionId);ManifestHash=(Get-FileHash $paths.Manifest -Algorithm SHA256).Hash;Paths=$snapshotPaths}
            $snapshotPath=Join-Path $paths.Data ('m2-win11-access-'+$report.AttemptId+'.json')
            $file=[IO.File]::Open($snapshotPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {Set-MiProtectedFileAcl $snapshotPath $true;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($snapshot|ConvertTo-Json -Depth 4));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
            [pscustomobject]@{Revision=$j.Revision;JournalHash=$j.Hash;BootSessionId=(Get-MiBootSessionId);AdvancedFeaturesEnabled=$false;AccessSnapshot=$snapshotPath}
        }
        $report.Status='ChecksPassedWithPendingAcceptance'
    } catch {$report.Status='Failed';$report.Error=$_.Exception.Message;throw}
    finally {
        try {
        # 报告只是验收证据，不是可编辑的解锁配置；任何失败均不修改生产发布门。
        if ([IO.Directory]::Exists($paths.Results)) {
            $protected=Join-Path $paths.Results ('m2-win11-'+$report.AttemptId+'.json')
            $report.ProtectedEvidence=$protected
            $file=[IO.File]::Open($protected,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 9));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
            Set-MiProtectedFileAcl $protected $true
        }
        } finally {try {Save-MiM2LiveReport} finally {$acceptanceLock.Dispose()}}
    }
    Write-Host 'M2 Windows 11 live checks completed; boot/Windows 10/non-elevated acceptance remain explicit pending. Installation retained.'
}
if (-not [string]::IsNullOrEmpty($RestoreTaskDefinitionAttempt) -and (-not $LiveM2 -or -not $ContinueLiveM2 -or -not (Test-MiGuidN $RestoreTaskDefinitionAttempt))) {throw 'Definition restore requires -LiveM2 -ContinueLiveM2 and an exact prior attempt GUID.'}
if ($RepairLiveM2TaskAcl -and ($LiveM2 -or $ContinueLiveM2 -or $ProbeLiveM2Normal -or $InspectLiveM2)) {throw 'ACL repair and other modes are mutually exclusive.'}
if ($RepairLiveM2TaskAcl) {Repair-MiM2LiveTaskAcl;return}
if ($InspectLiveM2 -and ($LiveM2 -or $ContinueLiveM2 -or $ProbeLiveM2Normal)) {throw 'Inspection and acceptance modes are mutually exclusive.'}
if ($InspectLiveM2) {Show-MiM2LiveInspection;return}
if ($ProbeLiveM2Normal -and ($LiveM2 -or $ContinueLiveM2)) {throw 'Normal probe and elevated live modes are mutually exclusive.'}
if ($ContinueLiveM2 -and -not $LiveM2) {throw '-ContinueLiveM2 requires -LiveM2.'}
if ($ProbeLiveM2Normal) {Invoke-MiM2NormalAccessProbe;return}
if ($LiveM2) {Invoke-MiM2LiveAcceptance;return}
if (-not (Test-MiAdminToken)) {
    Write-Host 'SKIP: CI runner is not elevated; cannot exercise protected installation.'
    return
}
$paths=Get-MiSecurityPaths
if ([IO.Directory]::Exists($paths.Install) -or [IO.Directory]::Exists($paths.Data)) {
    throw 'CI installation fixture requires fresh paths. Refusing to overwrite existing installation.'
}
function Invoke-MiTestExecutor {
    param([string]$Operation,[string]$RequestId,[ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType='VirtualAlloc')
    $exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+'" -Operation '+$Operation+' -RequestId '+$RequestId
    if ($Operation -ceq 'TraceStart') {$args+=' -TraceType '+$TraceType}
    if ($Operation -ceq 'TraceExportPrepare') {$args+=' -ArtifactId '+[guid]::NewGuid().ToString('N')}
    $process=Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    try { return [int]$process.ExitCode } finally { $process.Dispose() }
}
& (Join-Path $root 'Installer.ps1')
[void](Assert-MiTrustedInstallation)
$watchdog=Assert-MiWatchdog
[void](Invoke-MiTraceHealthCheck)
if ((Invoke-MiTestExecutor 'TracePreflight' ([guid]::NewGuid().ToString('N'))) -eq 0) { throw 'M2 unexpectedly enabled WPR.' }
if ((Invoke-MiTestExecutor 'TraceStart' ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Unaccepted M3 launch escaped code-level gate.'}
if ((Invoke-MiTestExecutor 'TraceStart' ([guid]::NewGuid().ToString('N')) 'Heap') -eq 0) {throw 'Unaccepted M4 Heap request escaped code-level gate.'}
if ((Invoke-MiTestExecutor 'TraceExportPrepare' ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Unaccepted M5 export escaped code-level gate.'}
if ((Invoke-MiTestExecutor 'TraceWatchdog' 'Scheduled') -eq 0) { throw 'Administrator impersonated SYSTEM watchdog.' }
$lock=Enter-MiTraceLock
try {
    $j=Read-MiTraceJournal $lock; Assert-MiTraceQuiescent $j
    if ($j.HeapTransactions.Count -ne 0) {throw 'Disabled Heap request created a transaction.'}
    if (@($j.Sessions.Values).Count -ne 1 -or @($j.Sessions.Values)[0].ErrorCode -cne 'TraceBackendUnavailable') {throw 'Preflight did not persist explicit M3 gate.'}
} finally {$lock.Dispose()}
# 真实任务被禁用后必须拒绝高权限请求，恢复原值仅用于本次隔离测试。
$watchdog.Task.Enabled=$false
try {
    if ((Invoke-MiTestExecutor Probe ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Disabled watchdog escaped gate.'}
} finally {$watchdog.Task.Enabled=$true}
[void](Invoke-MiTraceHealthCheck)
Write-Host 'PASS: real SYSTEM health handshake, exact fixed task gate, M3 recording disabled.'
# P1-03：仅 disposable runner，验证真实受保护目录内持有独占句柄时的 ACL 设置及锁释放。
# 不请求任何 SCM 变更，不删除锁文件；该部分覆盖单元测试中模拟 ACL 无法验证的 Windows 行为。
. (Join-Path $paths.Install 'ServiceManagement.ps1')
foreach ($kind in @('Target','Policy','Recovery')) {
    $held=Enter-MiServiceLock -Kind $kind -Name 'MemoryInspector.P1DedicatedFixture'
    try {
        $leaf=if ($kind -eq 'Target') {'service-memoryinspector.p1dedicatedfixture.lock'} else {$kind.ToLowerInvariant()+'.lock'}
        $lockPath=Join-Path $paths.PolicyFolder $leaf
        if (-not (Test-MiAclRestricted $lockPath $true) -or -not (Test-MiNoReparse $lockPath)) {
            throw 'Protected operation lock ACL/path check failed.'
        }
        $refused=$false
        try {$unexpected=Enter-MiServiceLock -Kind $kind -Name 'memoryinspector.p1dedicatedfixture' -TimeoutMilliseconds 0}
        catch {$refused=$true}
        if (-not $refused) {$unexpected.Dispose();throw 'Held protected lock was acquired twice.'}
    } finally {$held.Dispose()}
    $reopened=Enter-MiServiceLock -Kind $kind -Name 'memoryinspector.p1dedicatedfixture'
    $reopened.Dispose()
}
Write-Host 'PASS: protected target/policy/recovery lock ACLs, exclusion and release.' -ForegroundColor Green
$id=[guid]::NewGuid().ToString('N')
if ((Invoke-MiTestExecutor -Operation Probe -RequestId $id) -ne 0) {
    throw 'Real protected Probe failed.'
}
if ((Invoke-MiTestExecutor -Operation Probe -RequestId $id) -eq 0) {
    throw 'Replay request was accepted.'
}
if ((Invoke-MiTestExecutor -Operation StopApprovedService -RequestId ([guid]::NewGuid().ToString('N'))) -eq 0) {
    throw 'Service control was unexpectedly accepted.'
}
$audit=Get-Content -LiteralPath $paths.Audit -Raw -Encoding UTF8 -ErrorAction Stop
if ($audit -notmatch 'REQUESTED' -or $audit -notmatch 'CONFIRMED') {
    throw 'Protected audit records missing.'
}
# M7 protected defaults: no services approved and recovery record empty.
$policy=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Policy,[Text.Encoding]::UTF8)) -ErrorAction Stop
$recovery=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Recovery,[Text.Encoding]::UTF8)) -ErrorAction Stop
if (@($policy.Services).Count -ne 0 -or @($recovery.Records).Count -ne 0) { throw 'Unsafe nonempty initial service state.' }
if (-not (Test-MiAclRestricted $paths.Policy $true) -or -not (Test-MiAclRestricted $paths.Recovery $true)) { throw 'Unprotected service state.' }
$svcExe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$svcId=[guid]::NewGuid().ToString('N')
$svcArgs='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+
    '" -Operation StopApprovedService -RequestId '+$svcId+' -ServiceName RpcSs'
$svcProc=Start-Process -FilePath $svcExe -ArgumentList $svcArgs -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
try { if ($svcProc.ExitCode -eq 0) { throw 'Critical service stop should be rejected.' } }
finally { $svcProc.Dispose() }
# Modify one installed file as administrator, verify manifest check rejects the next probe,
# then restore identical bytes. This does NOT run any service operations.
$target=Join-Path $paths.Install 'PrivilegeBridge.ps1'
$before=[IO.File]::ReadAllBytes($target)
try {
    [IO.File]::WriteAllBytes($target,($before + [byte[]]@(10)))
    if ((Invoke-MiTestExecutor -Operation Probe -RequestId ([guid]::NewGuid().ToString('N'))) -eq 0) {
        throw 'Modified installed file escaped SHA256 manifest validation.'
    }
} finally {
    [IO.File]::WriteAllBytes($target,$before)
    Set-MiProtectedFileAcl -Path $target -AllowUsersRead $true
}
[void](Assert-MiTrustedInstallation)
Write-Host 'PASS: actual M6 protected install, UAC execution contract, replay denial, audit, and SHA256 rejection.' -ForegroundColor Green

# M8 disposable-runner uninstall test: no production installation involved.
function Read-Host { param([string]$Prompt) return 'UNINSTALL MEMORYINSPECTOR' }
& (Join-Path $root 'Uninstaller.ps1')
if ([IO.Directory]::Exists($paths.Install)) { throw 'Protected uninstall left the application files behind.' }
if (-not [IO.File]::Exists($paths.Audit) -or -not [IO.File]::Exists($paths.Policy)) {
    throw 'Uninstall unexpectedly removed protected audit / allowlist records.'
}
Write-Host 'PASS: M8 protected uninstall retained privileged audit and policy data.' -ForegroundColor Green
# 保留 Journal 的正常卸载必须允许安全重装，不得删除日志才能再次安装。
& (Join-Path $root 'Installer.ps1')
[void](Invoke-MiTraceHealthCheck)
& (Join-Path $root 'Uninstaller.ps1')
Write-Host 'PASS: M2 retired journal reused after verified uninstall/reinstall; task and payload removed from active paths.'
