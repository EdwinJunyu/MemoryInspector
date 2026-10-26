#requires -Version 5.1
<# M6 regression: source parsing, secure pure contracts, and disposable ACL fixture.
No UAC prompt, service modification, process termination, or install performed. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('PrivilegeSecurity.ps1','PrivilegeBridge.ps1','ElevatedExecutor.ps1',
    'Installer.ps1','Uninstaller.ps1','MemoryInspector.ps1','GuiV4.ps1',
    'ServiceManagement.ps1','ServiceBridge.ps1','PrivilegeInstallTest.ps1')
foreach ($f in $files) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $f),[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { throw ('M6 parse failure '+$f+': '+($errors|Out-String)) }
}
. (Join-Path $root 'PrivilegeSecurity.ps1')
# 实机验收辅助函数使用真实临时文件回归；仅 ACL/部署租约为夹具，不安装、不发 UAC。
& {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'PrivilegeInstallTest.ps1'),[ref]$tokens,[ref]$errors)
    foreach ($name in @('Invoke-MiM2LiveAcceptance','Invoke-MiM2NormalAccessProbe','Show-MiM2LiveInspection','Repair-MiM2LiveTaskAcl','Save-MiM2LiveFaultBackup','Add-MiM2LiveFaultStage','Invoke-MiM2LiveCheck')) {
        $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -ceq $name},$true)
        if ($null -eq $node) {throw ('Missing live acceptance helper '+$name)}
        . ([scriptblock]::Create($node.Extent.Text))
    }
    function Assert-LiveHarnessRejected {param([scriptblock]$Action)
        $denied=$false;try {& $Action|Out-Null} catch {$denied=$true};if (-not $denied) {throw 'Unsafe live harness condition accepted.'}
    }
    function Test-MiAdminToken {return $false}
    Assert-LiveHarnessRejected {Invoke-MiM2LiveAcceptance}
    Assert-LiveHarnessRejected {Show-MiM2LiveInspection}
    Assert-LiveHarnessRejected {Repair-MiM2LiveTaskAcl}
    $fixture=Join-Path $root ('test-artifacts\M2-LiveHarness-'+[guid]::NewGuid().ToString('N'))
    $paths=[pscustomobject]@{Results=$fixture;Executor=(Join-Path $fixture 'missing-executor.ps1')}
    function Get-MiSecurityPaths {return $paths}
    Assert-LiveHarnessRejected {Invoke-MiM2NormalAccessProbe}
    $report=[pscustomobject]@{RunId=[guid]::NewGuid().ToString('N');AttemptId=[guid]::NewGuid().ToString('N');Checks=@()}
    [void][IO.Directory]::CreateDirectory($fixture)
    $writable=Join-Path $fixture 'readable-executor.ps1';[IO.File]::WriteAllText($writable,'unchanged')
    $paths|Add-Member NoteProperty DeploymentLease (Join-Path $fixture 'deployment.lock');[IO.File]::WriteAllText($paths.DeploymentLease,'')
    function Assert-MiTracePath {param($Path)
        if (-not (Test-Path -LiteralPath $Path) -or -not [IO.Path]::GetFullPath($Path).StartsWith($fixture+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unbound live fixture path.'}
    }
    $paths.Executor=$writable;$paths|Add-Member NoteProperty Install (Join-Path $fixture 'missing-object')
    $missingObjectRejected=$false
    try {Invoke-MiM2NormalAccessProbe} catch {$missingObjectRejected=$_.Exception.Message.StartsWith('Cannot establish live object existence: ')}
    if (-not $missingObjectRejected) {throw 'Native normal probe counted missing/inaccessible metadata as accepted ACL.'}
    $paths.Install=$writable
    $unexpectedAccessRejected=$false
    try {Invoke-MiM2NormalAccessProbe} catch {$unexpectedAccessRejected=$_.Exception.Message -ceq ('Normal user obtained WriteData on '+$writable)}
    if (-not $unexpectedAccessRejected -or [IO.File]::ReadAllText($writable) -cne 'unchanged') {throw 'Native normal probe failed to reject writable file without changing its bytes.'}
    function Set-MiAdminDirectoryAcl {param($Path)}
    function Set-MiProtectedFileAcl {param($Path)}
    function Assert-MiTracePath {param($Path)
        if (-not (Test-Path -LiteralPath $Path) -or -not [IO.Path]::GetFullPath($Path).StartsWith($fixture+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unbound live fixture path.'}
    }
    foreach ($kind in @('TaskEnabled','TaskXml','TaskDacl','Payload')) {
        $original=[Text.Encoding]::UTF8.GetBytes('original '+$kind)
        $case=Save-MiM2LiveFaultBackup $kind $original
        $backup=Join-Path $case 'original.bin';$stages=Join-Path $case 'stages.jsonl'
        $intent=[IO.File]::ReadAllLines($stages)[0]|ConvertFrom-Json
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($backup)) -cne [Convert]::ToBase64String($original) -or
            $intent.State -cne 'CapturedBeforeMutation' -or $intent.AttemptId -cne $report.AttemptId -or
            $intent.OriginalSha256 -cne (Get-FileHash $backup -Algorithm SHA256).Hash) {throw 'Fault backup lost original bytes/intent binding.'}
        Assert-LiveHarnessRejected {Save-MiM2LiveFaultBackup $kind ([byte[]]@(0))}
        Add-MiM2LiveFaultStage $case 'MutationApplied';Add-MiM2LiveFaultStage $case 'Restored'
        $states=@([IO.File]::ReadAllLines($stages)|ForEach-Object {($_|ConvertFrom-Json).State})
        if (($states -join ',') -cne 'CapturedBeforeMutation,MutationApplied,Restored') {throw 'Fault evidence ordering failed.'}
    }
    Assert-LiveHarnessRejected {Add-MiM2LiveFaultStage (Join-Path $fixture 'Payload') 'Restored'}
    $leases=[Collections.Generic.List[object]]::new();$saved=0
    function Enter-MiDeploymentLease {$lease=[IO.MemoryStream]::new();$leases.Add($lease);return $lease}
    function Save-MiM2LiveReport {$script:liveHarnessSaved++}
    $script:liveHarnessSaved=0
    Invoke-MiM2LiveCheck 'DisabledTaskRefusedAndRestored' {'successful fixture'}
    Assert-LiveHarnessRejected {Invoke-MiM2LiveCheck 'InstalledPayloadTamperRefusedAndRestored' {throw 'injected check failure'}}
    if ($leases.Count -ne 2 -or $leases[0].CanRead -or $leases[1].CanRead -or $script:liveHarnessSaved -ne 2 -or
        $report.Checks[0].State -cne 'Passed' -or $report.Checks[1].State -cne 'Failed') {throw 'Live check lost failure evidence or deployment lease release.'}
    Write-Host 'PASS: M2 live harness denies nonadmin/missing install, preserves CreateNew fault originals and ordered evidence, releases leases on success/failure (ACL mocked).'
}
$id=[guid]::NewGuid().ToString('N')
if (-not (Test-MiGuidN $id)) { throw 'Valid GUID rejected.' }
foreach ($bad in @('', '00000000000000000000000000000000','../evil','xxxx',('a'*33))) {
    if (Test-MiGuidN $bad) { throw 'Invalid request ID accepted.' }
}
if (-not (Test-MiPrivilegedOperation -Operation 'Probe' -RequestId $id)) {
    throw 'Allowed harmless M6 probe was rejected.'
}
foreach ($forbidden in @('StopApprovedService','StartPreviouslyStoppedService','ApproveService',
    'RevokeServiceApproval','TerminateApprovedUserProcess','RunCommand','probe','')) {
    if (Test-MiPrivilegedOperation -Operation $forbidden -RequestId $id) {
        throw ('M6 unexpectedly unlocked an operation: '+$forbidden)
    }
}
$executor=Get-Content -LiteralPath (Join-Path $root 'ElevatedExecutor.ps1') -Raw -Encoding UTF8
if ($executor -match '(?i)\b(Stop-Service|Start-Service|Stop-Process|Invoke-Expression|Invoke-Command|Set-Service|sc\.exe|taskkill)\b') {
    throw 'Executor contains forbidden service/process commands.'
}
if ($executor -notmatch 'CreateNew' -or $executor -notmatch 'Assert-MiTrustedInstallation' -or
    $executor -notmatch 'Write-MiPrivilegedAudit' -or $executor -notmatch 'Test-MiPrivilegedOperation') {
    throw 'Executor lacks request replay/integrity/audit safeguards.'
}
$bridge=Get-Content -LiteralPath (Join-Path $root 'PrivilegeBridge.ps1') -Raw -Encoding UTF8
if ($bridge -notmatch 'Start-Process' -or $bridge -notmatch 'RunAs' -or
    $bridge -notmatch 'Test-MiPrivilegeBridgeInstalled') { throw 'GUI bridge is not limited to protected UAC installation.' }
$install=Get-Content -LiteralPath (Join-Path $root 'Installer.ps1') -Raw -Encoding UTF8
if ($install -notmatch 'Set-MiAdminDirectoryAcl' -or $install -notmatch 'Set-MiProtectedFileAcl' -or
    $install -notmatch 'Assert-MiTrustedInstallation') { throw 'Protected installer safeguards missing.' }
if ((Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim() -cne '0.0.10') {
    throw 'VERSION mismatch.'
}
# 版本升级必须执行真实信任函数，而非仅比较源码字符串。夹具仅模拟本目录的ACL，
# 不安装、不提权；文件/清单/哈希和M7必需项实际验证，不能替代管理员部署验收。
& {
    $fixture=Join-Path (Join-Path $root 'test-artifacts') ('VersionTrust-'+[guid]::NewGuid().ToString('N'))
    $versionPaths=[pscustomobject]@{
        Install=(Join-Path $fixture 'install');Data=(Join-Path $fixture 'data')
        Replay=(Join-Path $fixture 'data\replay');Results=(Join-Path $fixture 'data\results')
        PolicyFolder=(Join-Path $fixture 'data\policy');Policy=(Join-Path $fixture 'data\policy\approved.json')
        Audit=(Join-Path $fixture 'data\audit\audit.jsonl');Manifest=(Join-Path $fixture 'data\manifest.json')
        Recovery=(Join-Path $fixture 'data\policy\recovery.json')
        Executor=(Join-Path $fixture 'install\ElevatedExecutor.ps1')
        WatchdogPolicy=(Join-Path $fixture 'data\watchdog-policy.json')
    }
    foreach($directory in @($versionPaths.Install,$versionPaths.Data,$versionPaths.Replay,$versionPaths.Results,$versionPaths.PolicyFolder,(Split-Path -Parent $versionPaths.Audit))){[void][IO.Directory]::CreateDirectory($directory)}
    foreach($file in @($versionPaths.Policy,$versionPaths.Audit,$versionPaths.Recovery)){[IO.File]::WriteAllText($file,'fixture',[Text.UTF8Encoding]::new($false))}
    function Get-MiSecurityPaths {return $versionPaths}
    function Test-MiAclRestricted {
        param([string]$Path,[bool]$Directory=$false)
        return [IO.Path]::GetFullPath($Path).StartsWith($fixture+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
    }
    # 某些PS5.1执行环境没有自动加载Get-FileHash；测试适配器仍对真实夹具字节计算SHA-256。
    function Get-FileHash {
        param([string]$LiteralPath,[string]$Algorithm)
        if($Algorithm -cne 'SHA256'){throw 'Unexpected hash algorithm.'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try{return [pscustomobject]@{Hash=([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($LiteralPath)))).Replace('-','')}}finally{$sha.Dispose()}
    }
    $versionEntries=New-Object 'System.Collections.Generic.List[object]'
    foreach($name in @('ElevatedExecutor.ps1','PrivilegeSecurity.ps1','ServiceManagement.ps1','ServiceBridge.ps1','VERSION','Collector.ps1','GuiV4.ps1','Worker.ps1','Analyzer.ps1')){
        $file=Join-Path $versionPaths.Install $name
        [IO.File]::WriteAllText($file,'fixture',[Text.UTF8Encoding]::new($false))
        $versionEntries.Add([pscustomobject]@{Name=$name;Sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash})
    }
    function Write-VersionManifest {
        param([string]$Version,$Files)
        $manifest=[pscustomobject]@{SchemaVersion=1;Version=$Version;Files=@($Files);TraceArchitectureVersion=1}
        [IO.File]::WriteAllText($versionPaths.Manifest,($manifest|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    }
    function Assert-VersionTrustRejected {
        param([string]$ExpectedMessage,[string[]]$AllowedVersions=@('0.0.10'))
        $rejected=$false
        try{[void](Assert-MiTrustedInstallation -AllowedVersions $AllowedVersions)}catch{
            if(-not $_.Exception.Message.Contains($ExpectedMessage)){throw}
            $rejected=$true
        }
        if(-not $rejected){throw ('Version trust unexpectedly accepted: '+$ExpectedMessage)}
    }
    $allEntries=$versionEntries.ToArray()
    # 版本升级同时核验真实 Watchdog 信任入口：只模拟任务对象读取，不跳过固定定义/ACL 校验。
    $realScheduler=Get-MiTaskScheduler;$definition=Get-MiWatchdogDefinition $realScheduler
    $versionTask=[pscustomobject]@{Definition=$definition;Enabled=$true;State=3;Xml='fixed version-trust task fixture'}
    $versionTask|Add-Member ScriptMethod GetSecurityDescriptor {param($Flags) return 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
    $versionFolder=[pscustomobject]@{};$versionFolder|Add-Member ScriptMethod GetTask {param($Name)
        if ($Name -cne 'MemoryInspector.TraceWatchdog') {throw 'Unexpected task name.'};return $versionTask
    }
    $versionScheduler=[pscustomobject]@{};$versionScheduler|Add-Member ScriptMethod GetFolder {param($Path) return $versionFolder}
    function Get-MiTaskScheduler {return $versionScheduler}
    $policy=[ordered]@{SchemaVersion=1;InstallationId=[guid]::NewGuid().ToString('N');DefinitionHash=(Get-MiTraceHash $versionTask.Xml)}
    [IO.File]::WriteAllText($versionPaths.WatchdogPolicy,($policy|ConvertTo-Json -Compress))
    Write-VersionManifest '0.0.10' $allEntries
    [void](Assert-MiTrustedInstallation)
    [void](Assert-MiWatchdog)
    $upgradeVersions=@('0.0.7','0.0.8','0.0.9','0.0.10')
    foreach($oldVersion in @('0.0.7','0.0.8','0.0.9')){
        Write-VersionManifest $oldVersion $allEntries
        Assert-VersionTrustRejected 'Invalid installation manifest/version.'
        [void](Assert-MiTrustedInstallation -AllowedVersions $upgradeVersions)
        $oldWatchdogDenied=$false
        try {[void](Assert-MiWatchdog)} catch {if ($_.Exception.Message -cne 'Invalid installation manifest/version.') {throw};$oldWatchdogDenied=$true}
        if (-not $oldWatchdogDenied) {throw 'Daily watchdog trust accepted old release implicitly.'}
        [void](Assert-MiWatchdog -AllowedVersions $upgradeVersions)
        Write-VersionManifest $oldVersion @($allEntries|Where-Object Name -cne 'ServiceManagement.ps1')
        Assert-VersionTrustRejected 'Missing M7 component: ServiceManagement.ps1' $upgradeVersions
    }
    foreach($unknownVersion in @('0.0.11','1.2.3','0.0.10.1','0.0.10 ')){
        Write-VersionManifest $unknownVersion $allEntries
        Assert-VersionTrustRejected 'Invalid installation manifest/version.'
    }
    foreach($essential in @('ElevatedExecutor.ps1','PrivilegeSecurity.ps1','ServiceManagement.ps1','ServiceBridge.ps1','VERSION')){
        Write-VersionManifest '0.0.10' @($allEntries|Where-Object Name -cne $essential)
        Assert-VersionTrustRejected ('Missing M7 component: '+$essential)
    }
    Write-VersionManifest '0.0.10' $allEntries
    $retainedLedger=Join-Path $versionPaths.PolicyFolder 'recovery.retained.json'
    [IO.File]::Move($versionPaths.Recovery,$retainedLedger)
    try{Assert-VersionTrustRejected 'Untrusted service recovery ledger.'}finally{[IO.File]::Move($retainedLedger,$versionPaths.Recovery)}
    [void](Assert-MiTrustedInstallation)
    [void](Assert-MiWatchdog)
    $versionTask.Definition.Actions.Item(1).Arguments+=' -Command rejected'
    $taskDenied=$false;try {[void](Assert-MiWatchdog -AllowedVersions $upgradeVersions)} catch {$taskDenied=$true}
    if (-not $taskDenied) {throw 'Upgrade version allowlist bypassed actual task definition validation.'}
}
Write-Host 'PASS: 0.0.10 exact trust pin, explicit 0.0.7/0.0.8/0.0.9 upgrade, unknown-version rejection and unchanged M7 component/ledger requirements (ACL mocked only in fixture).'
# Lightweight ACL smoke test in a uniquely named throwaway temp directory.
# This is deliberately NOT an installation and never changes Windows services.
if (Test-MiAdminToken) {
    # 管理员测试只保护本次唯一夹具，保留证据；不安装应用或修改项目根目录的 ACL。
    $dir=Join-Path (Join-Path $root 'test-artifacts') ('MiM6AclTest-'+[guid]::NewGuid().ToString('N'))
    try {
        [void][IO.Directory]::CreateDirectory($dir)
        Set-MiAdminDirectoryAcl -Path $dir -AllowUsersRead $true
        if (-not (Test-MiAclRestricted $dir $true)) { throw 'Protected fixture directory is not restricted.' }
        $f=Join-Path $dir 'fixture.txt'
        [IO.File]::WriteAllText($f,'fixture',[Text.Encoding]::UTF8)
        Set-MiProtectedFileAcl -Path $f -AllowUsersRead $true
        if (-not (Test-MiAclRestricted $f $true)) { throw 'Protected fixture file is not restricted.' }
        if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -eq '') {
            throw 'SHA256 fixture failed.'
        }
    } finally {
        Write-Host ('ACL fixture retained: '+$dir)
    }
} else {
    Write-Host 'INFO: non-admin CI host; disposable ACL fixture skipped.'
}
Write-Host 'PASS: M6 safeguards retained and M7 service scope gated by exact target name.' -ForegroundColor Green

# V3-M2：真实文件与独占句柄，只有本次夹具的身份和 ACL 被模拟。
& {
    $fixture=Join-Path (Join-Path $root 'test-artifacts') ('TraceArchitecture-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($fixture)
    $p=[pscustomobject]@{Data=$fixture;TraceRoot=(Join-Path $fixture 'trace');TraceJournal=(Join-Path $fixture 'trace\journal.jsonl');
        TraceLock=(Join-Path $fixture 'trace.lock');TraceWorkspace=(Join-Path $fixture 'trace\workspace');DeploymentLease=(Join-Path $fixture 'deployment.lock')}
    function Get-MiSecurityPaths { return $p }
    function Test-MiAdminToken { return $true }
    function Test-MiAclRestricted { param($Path,$RequireProtectedDacl) return ([IO.Path]::GetFullPath($Path)).StartsWith($fixture,[StringComparison]::OrdinalIgnoreCase) }
    function Set-MiProtectedFileAcl { param($Path,$AllowUsersRead) }
    function Set-MiAdminDirectoryAcl { param($Path,$AllowUsersRead) }
    function Assert-TraceRejected { param([scriptblock]$Action,[string]$Label)
        $rejected=$false; try { & $Action } catch { $rejected=$true }
        if (-not $rejected) { throw ('Trace test unexpectedly accepted: '+$Label) }
    }
    foreach ($operation in @('TracePreflight','TraceHealth','TraceRecovery')) {
        if (-not (Test-MiPrivilegedOperation $operation $id)) { throw 'Fixed trace operation rejected.' }
        if (Test-MiPrivilegedOperation $operation $id 'RpcSs') { throw 'Trace accepted service payload.' }
    }
    if (-not (Test-MiPrivilegedOperation 'TraceWatchdog' 'Scheduled')) { throw 'Fixed task protocol rejected.' }
    foreach ($bad in @($id,'scheduled','Scheduled -Command evil','')) {
        if (Test-MiPrivilegedOperation 'TraceWatchdog' $bad) { throw 'Watchdog accepted arbitrary request payload.' }
    }
    $shared=Enter-MiDeploymentLease
    try { Assert-TraceRejected { $bad=Enter-MiDeploymentLease -Exclusive; $bad.Dispose() } 'upgrade during service lease' }
    finally { $shared.Dispose() }
    $exclusive=Enter-MiDeploymentLease -Exclusive
    try { Assert-TraceRejected { $bad=Enter-MiDeploymentLease; $bad.Dispose() } 'service during upgrade' }
    finally { $exclusive.Dispose() }
    $lock=Enter-MiTraceLock
    try {
        Assert-TraceRejected { $bad=Enter-MiTraceLock; $bad.Dispose() } 'simultaneous controller/watchdog'
        Assert-TraceRejected { Read-MiTraceJournal $lock } 'missing journal'
        $j=Initialize-MiTraceJournal $lock
        Assert-TraceRejected { Initialize-MiTraceJournal $lock } 'journal reinitialize'
        $session=[pscustomobject][ordered]@{SchemaVersion=1;TraceSessionId=[guid]::NewGuid().ToString('N');WprInstanceName='';
            OwnerSid='S-1-5-21-1-2-3-1001';BootSessionId='100';RequestedTraceType='VirtualAlloc';ProfileId=$null;
            ProfileFingerprint=$null;WprExecutableIdentity=$null;RecordingMode='Memory';RequestedDuration=300;StartedUtc=$null;
            DeadlineUtc=$null;TraceWorkingBudget=0;State='Requested';CleanupState='NotRequired';OutputArtifactId=$null;
            LastVerifiedUtc=[datetime]::UtcNow.ToString('o');ErrorCode=$null;JournalRevision=1;StopState='NotStarted';
            SaveState='NotStarted';AnalysisState='NotStarted';ActiveReferences=0;AuthorizationId=$null}
        $session.WprInstanceName='MemoryInspector-'+$session.TraceSessionId
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
        Assert-TraceRejected { Assert-MiTraceQuiescent $j } 'unfinished request upgrade'
        $before=[IO.File]::ReadAllText($p.TraceJournal)
        Assert-TraceRejected { Add-MiTraceJournalRecord $lock 1 'Session' $session } 'stale CAS'
        $another=$session|ConvertTo-Json -Depth 8|ConvertFrom-Json
        $another.TraceSessionId=[guid]::NewGuid().ToString('N'); $another.WprInstanceName='MemoryInspector-'+$another.TraceSessionId
        Assert-TraceRejected { Add-MiTraceJournalRecord $lock $j.Revision 'Session' $another } 'second active trace'
        $copy=$session|ConvertTo-Json -Depth 8|ConvertFrom-Json; $copy.State='Preflight'; $copy.OwnerSid='S-1-5-21-1-2-3-1002'
        Assert-TraceRejected { Add-MiTraceJournalRecord $lock $j.Revision 'Session' $copy } 'changed owner'
        if ([IO.File]::ReadAllText($p.TraceJournal) -cne $before) { throw 'Rejected request mutated journal.' }
        $session.State='Preflight'; $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
        $session.State='ResourcePreflightRejected'; $session.ErrorCode='TraceBackendUnavailable'
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
        Assert-MiTraceQuiescent $j
        Assert-TraceRejected { Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session } 'terminal replay'
        # 只测试生命周期数据契约，不执行 WPR；停止、保存、恢复及分析分别核验。
        $next=$another
        foreach ($state in @('Requested','Preflight','Authorized','Preparing','Recording','Stopping','Saving','Saved','Cleaning','Analyzing','Completed')) {
            $next.State=$state
            if ($state -ceq 'Authorized') { $next.AuthorizationId=[guid]::NewGuid().ToString('N');$next.ProfileId='FixtureOnly';$next.ProfileFingerprint='A'*64;$next.WprExecutableIdentity=[pscustomobject]@{Path='fixture';Sha256=('B'*64)} }
            if ($state -ceq 'Recording') { $start=[datetime]::UtcNow;$next.StartedUtc=$start.ToString('o');$next.DeadlineUtc=$start.AddSeconds(300).ToString('o') }
            if ($state -ceq 'Stopping') { $next.StopState='Pending' }
            if ($state -ceq 'Saving') { $next.StopState='Confirmed';$next.SaveState='Pending' }
            if ($state -ceq 'Saved') { $next.SaveState='Saved';$next.OutputArtifactId=[guid]::NewGuid().ToString('N');$next.CleanupState='Pending' }
            if ($state -ceq 'Analyzing') { $next.CleanupState='Restored';$next.AnalysisState='Pending' }
            if ($state -ceq 'Completed') {
                Assert-TraceRejected { Assert-MiTraceSession $next } 'analysis unfinished'
                $next.AnalysisState='Complete'
            }
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $next
            if ($state -ceq 'Saved') { Assert-TraceRejected {Assert-MiTraceQuiescent $j} 'saved is not completed' }
        }
        Assert-MiTraceQuiescent $j
        $bad=$next|ConvertTo-Json -Depth 8|ConvertFrom-Json; $bad.CleanupState='Pending'
        Assert-TraceRejected {Assert-MiTraceSession $bad} 'completed with pending cleanup'
        foreach ($duration in @(299,1801)) { $bad=$session|ConvertTo-Json -Depth 8|ConvertFrom-Json; $bad.RequestedDuration=$duration;Assert-TraceRejected {Assert-MiTraceSession $bad} 'duration outside bounds' }
        $valid=[IO.File]::ReadAllText($p.TraceJournal)
        foreach ($broken in @('', $valid.TrimEnd([char]10), $valid.Replace('"Revision":1,','"Revision":99,'),
                $valid.Replace('"SchemaVersion":1,','"SchemaVersion":1,"SchemaVersion":1,'), ($valid+'{}'+"`n"))) {
            [IO.File]::WriteAllText($p.TraceJournal,$broken,[Text.UTF8Encoding]::new($false))
            Assert-TraceRejected {Read-MiTraceJournal $lock} 'torn/corrupt/duplicate/unknown journal'
        }
        [IO.File]::WriteAllText($p.TraceJournal,$valid,[Text.UTF8Encoding]::new($false))
        $j=Read-MiTraceJournal $lock
        $challenge=[ordered]@{SchemaVersion=1;Nonce=[guid]::NewGuid().ToString('N');BootSessionId='100';InstallationId=$j.InstallationId;
            DefinitionHash=('A'*64);RequestedUtc=[datetime]::UtcNow.ToString('o');ExpiresUtc=[datetime]::UtcNow.AddSeconds(40).ToString('o')}
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'HealthChallenge' $challenge
        $response=[ordered]@{SchemaVersion=1;Nonce=$challenge.Nonce;BootSessionId='100';InstallationId=$j.InstallationId;
            DefinitionHash=('A'*64);Utc=[datetime]::UtcNow.ToString('o');ExecutorSid='S-1-5-18';ScannedHash=$j.Hash}
        $before=[IO.File]::ReadAllText($p.TraceJournal)
        foreach ($field in @('Nonce','BootSessionId','InstallationId','DefinitionHash','ExecutorSid','ScannedHash')) {
            $badResponse=$response|ConvertTo-Json -Compress|ConvertFrom-Json;$badResponse.$field='mismatch'
            Assert-TraceRejected {Add-MiTraceJournalRecord $lock $j.Revision 'HealthResponse' $badResponse} ('health binding '+$field)
        }
        $badResponse=$response|ConvertTo-Json -Compress|ConvertFrom-Json;$badResponse.Utc=[datetime]::UtcNow.AddMinutes(1).ToString('o')
        Assert-TraceRejected {Add-MiTraceJournalRecord $lock $j.Revision 'HealthResponse' $badResponse} 'health expiration'
        if ([IO.File]::ReadAllText($p.TraceJournal) -cne $before) {throw 'Rejected health response modified journal.'}
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'HealthResponse' $response
        Assert-TraceRejected {Add-MiTraceJournalRecord $lock $j.Revision 'HealthResponse' $response} 'health replay'
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Ready'})
        $readyJournal=[IO.File]::ReadAllText($p.TraceJournal)
        $unknown=$next|ConvertTo-Json -Depth 8|ConvertFrom-Json; $unknown.State='UnknownOutcome'
        $retry=$unknown|ConvertTo-Json -Depth 8|ConvertFrom-Json; $retry.State='Stopping'
        Assert-TraceRejected {Assert-MiTraceTransition $unknown $retry} 'unknown result retry'
        $retry.State='RecoveryRequired'; Assert-MiTraceTransition $unknown $retry
        if (-not (Test-MiTraceObligation $retry)) { throw 'RecoveryRequired lost obligation.' }
        $interrupted=$session|ConvertTo-Json -Depth 8|ConvertFrom-Json
        $interrupted.TraceSessionId=[guid]::NewGuid().ToString('N');$interrupted.WprInstanceName='MemoryInspector-'+$interrupted.TraceSessionId
        $interrupted.State='Requested';$interrupted.ErrorCode=$null
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $interrupted
        $j=Update-MiTraceSupervision $lock '200'
        if ($j.Sessions[$interrupted.TraceSessionId].State -cne 'AuthorizationDenied') {throw 'Interrupted preauthorization not recovered.'}
        Assert-MiTraceQuiescent $j
        $revision=$j.Revision;$j=Update-MiTraceSupervision $lock '200'
        if ($j.Revision -ne $revision) {throw 'Idle supervision rewrote journal.'}
        # 模拟已录制会话超时；M2 必须只登记截止及恢复，不能虚构停止/保存成功。
        $interrupted.TraceSessionId=[guid]::NewGuid().ToString('N');$interrupted.WprInstanceName='MemoryInspector-'+$interrupted.TraceSessionId
        foreach ($state in @('Requested','Preflight','Authorized','Preparing','Recording')) {
            $interrupted.State=$state
            if ($state -ceq 'Authorized') {$interrupted.AuthorizationId=[guid]::NewGuid().ToString('N');$interrupted.ProfileId='Fixture';$interrupted.ProfileFingerprint='A'*64;$interrupted.WprExecutableIdentity=[pscustomobject]@{Sha256=('B'*64)}}
            if ($state -ceq 'Recording') {$start=[datetime]::UtcNow.AddMinutes(-10);$interrupted.StartedUtc=$start.ToString('o');$interrupted.DeadlineUtc=$start.AddSeconds(300).ToString('o')}
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $interrupted
        }
        $recordingEvidence=[IO.File]::ReadAllText($p.TraceJournal)
        $j=Update-MiTraceSupervision $lock '200'
        if ($j.Sessions[$interrupted.TraceSessionId].ErrorCode -cne 'BootChanged') {throw 'Reboot identity was not enforced.'}
        [IO.File]::WriteAllText($p.TraceJournal,$recordingEvidence,[Text.UTF8Encoding]::new($false))
        $j=Update-MiTraceSupervision $lock '100';$supervised=$j.Sessions[$interrupted.TraceSessionId]
        if ($supervised.State -cne 'RecoveryRequired' -or $null -eq $supervised.DeadlineObservedUtc -or
            $supervised.StopState -cne 'NotStarted' -or $supervised.SaveState -cne 'NotStarted') {throw 'Unknown ownership dispatched or deadline lost.'}
        Assert-TraceRejected {Assert-MiTraceQuiescent $j} 'unresolved ownership blocks upgrade'
        $revision=$j.Revision;$j=Update-MiTraceSupervision $lock '200'
        if ($j.Revision -ne $revision) {throw 'Unknown recovery automatically retried.'}
    } finally { $lock.Dispose() }
    $reopened=Enter-MiTraceLock; $reopened.Dispose()
    # 恢复入口必须与部署实际门控一致；这里仅模拟已完成的安装/任务外层信任。
    $p|Add-Member NoteProperty Recovery (Join-Path $fixture 'service-recovery.json')
    [IO.File]::WriteAllText($p.Recovery,'{"SchemaVersion":1,"Records":[]}',[Text.UTF8Encoding]::new($false))
    function Assert-MiTrustedInstallation {return $p}
    $taskFault=$false
    function Assert-MiWatchdog {if ($taskFault) {throw 'Fixture task is not trusted.'}}
    $unfinishedJournal=[IO.File]::ReadAllText($p.TraceJournal)
    if (-not (Get-MiTraceRecoveryReport).UpgradeBlocked) {throw 'Recovery report omitted unfinished trace.'}
    [IO.File]::WriteAllText($p.TraceJournal,$readyJournal,[Text.UTF8Encoding]::new($false))
    if ((Get-MiTraceRecoveryReport).UpgradeBlocked) {throw 'Recovery report blocked clean verified fixture.'}
    $lock=Enter-MiTraceLock
    try {$j=Read-MiTraceJournal $lock;[void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='RecoveryRequired'}))}
    finally {$lock.Dispose()}
    $report=Get-MiTraceRecoveryReport
    if (-not $report.UpgradeBlocked -or -not $report.DeploymentBlocked) {throw 'Recovery report omitted deployment obligation.'}
    $taskFault=$true
    if (-not (Get-MiTraceRecoveryReport).TaskBlocked) {throw 'Recovery report omitted task trust failure.'}
    [IO.File]::WriteAllText($p.Recovery,'{"SchemaVersion":1,"Records":[{"Status":"StopConfirmed"}]}',[Text.UTF8Encoding]::new($false))
    if (-not (Get-MiTraceRecoveryReport).ServiceRecoveryBlocked) {throw 'Recovery report omitted service restoration.'}
    [IO.File]::WriteAllText($p.TraceJournal,'torn',[Text.UTF8Encoding]::new($false))
    $report=Get-MiTraceRecoveryReport
    if (-not $report.UpgradeBlocked -or $report.JournalStatus -cne 'UntrustedOrIncomplete') {throw 'Corrupt journal did not produce blocked diagnostic report.'}
    [IO.File]::WriteAllText($p.TraceJournal,$unfinishedJournal,[Text.UTF8Encoding]::new($false))
    Write-Host ('PASS: M2 journal/CAS/lifecycle/lease/exclusion/corruption; fixture retained: '+$fixture)
}

# 实际文件级回滚故障：分别中断新目录就位、旧清单备份和新清单就位。
& {
    foreach ($failurePoint in @('StageMove','OldManifestMove','NewManifestMove')) {
        $fixture=Join-Path (Join-Path $root 'test-artifacts') ('InstallRollback-'+$failurePoint+'-'+[guid]::NewGuid().ToString('N'))
        $p=[pscustomobject]@{Install=(Join-Path $fixture 'install');Manifest=(Join-Path $fixture 'manifest.json')}
        [void][IO.Directory]::CreateDirectory($p.Install)
        [IO.File]::WriteAllText((Join-Path $p.Install 'old.txt'),'old payload');[IO.File]::WriteAllText($p.Manifest,'old manifest')
        $stage=Join-Path $fixture 'stage';[void][IO.Directory]::CreateDirectory($stage)
        [IO.File]::WriteAllText((Join-Path $stage 'new.txt'),'new payload')
        $swap=[pscustomobject]@{OldInstallMoved=$false;StageInstalled=$false;OldManifestMoved=$false;NewManifestInstalled=$false;
            Backup=(Join-Path $fixture 'retained');OldManifest=(Join-Path $fixture 'old-manifest.json')}
        Move-MiDeploymentEntry $p.Install $swap.Backup;$swap.OldInstallMoved=$true
        $injected=$false
        try {
            if ($failurePoint -ceq 'StageMove') {Move-MiDeploymentEntry $stage ($stage+'.preserved')}
            Move-MiDeploymentEntry $stage $p.Install;$swap.StageInstalled=$true
            if ($failurePoint -ceq 'OldManifestMove') {[IO.File]::WriteAllText($swap.OldManifest,'occupied destination')}
            Move-MiDeploymentEntry $p.Manifest $swap.OldManifest;$swap.OldManifestMoved=$true
            Move-MiDeploymentEntry (Join-Path $fixture 'missing-new-manifest') $p.Manifest;$swap.NewManifestInstalled=$true
        } catch {$injected=$true}
        if (-not $injected) {throw 'Installation fault was not injected.'}
        Restore-MiInstallationSwap $p $swap
        if ([IO.File]::ReadAllText((Join-Path $p.Install 'old.txt')) -cne 'old payload' -or
            [IO.File]::ReadAllText($p.Manifest) -cne 'old manifest') {throw ('Rollback lost old install: '+$failurePoint)}
    }
    Write-Host 'PASS: real file-move fault injection at three installation swap boundaries; old payload and manifest retained.'
}

# 真正的 Task Scheduler COM 定义仅在内存构建；不注册任何任务。
& {
    # 确定性复现 IgnoreNew 的“已回应但仍在退出”边界；锁已释放才可派发下一次扫描。
    $context=@{Mode='Finishing';Polls=0;Runs=0;Published=$false;Respond=$false;Handles=[Collections.Generic.List[object]]::new();Journal=$null}
    $installId=[guid]::NewGuid().ToString('N');$policy=[pscustomobject]@{InstallationId=$installId;DefinitionHash=('C'*64)}
    $task=[pscustomobject]@{}
    $task|Add-Member ScriptProperty State { $context.Polls++;if ($context.Mode -ceq 'Finishing' -and $context.Polls -lt 3) {return 4};return 3 }
    $task|Add-Member ScriptMethod Run {param($Argument)
        if (-not $context.Published -or ($context.Mode -ceq 'Finishing' -and $context.Polls -lt 3) -or @($context.Handles|Where-Object {$_.CanRead}).Count -ne 0) {throw 'Watchdog dispatched before ready/challenge or while holding trace lock.'}
        $context.Runs++;$context.Respond=$true
    }
    function Assert-MiWatchdog {
        if ($context.Mode -ceq 'TaskChanged' -and $context.Published) {throw 'Actual task changed.'}
        return [pscustomobject]@{Task=$task;Policy=$policy}
    }
    function Get-MiBootSessionId {return '123'}
    function Enter-MiTraceLock {$handle=[IO.MemoryStream]::new();$context.Handles.Add($handle);return $handle}
    function Add-MiTraceJournalRecord {param($Lock,$Revision,$Kind,$Payload)
        if ($Kind -cne 'HealthChallenge') {throw 'Unexpected health fixture record.'}
        $context.Published=$true;$context.Journal.Challenge=$Payload;$context.Journal.Hash=('B'*64);return $context.Journal
    }
    function Read-MiTraceJournal {param($Lock)
        $j=$context.Journal
        if ($context.Published -and $context.Mode -ceq 'Superseded') {$j.Challenge.Nonce=[guid]::NewGuid().ToString('N')}
        if ($context.Published -and ($context.Respond -or $context.Mode -ceq 'ExistingResponds')) {
            $j.Response=[pscustomobject]@{Nonce=$j.Challenge.Nonce;DefinitionHash=$policy.DefinitionHash;InstallationId=$installId;BootSessionId='123';ScannedHash=$j.Hash;Utc=[datetime]::UtcNow.ToString('o')}
        }
        return $j
    }
    function Start-Sleep {param($Milliseconds)}
    foreach ($mode in @('Finishing','Ready','ExistingResponds','Superseded','TaskChanged')) {
        $context.Mode=$mode;$context.Polls=0;$context.Runs=0;$context.Published=$false;$context.Respond=$false;$context.Handles.Clear()
        $context.Journal=[pscustomobject]@{InstallationId=$installId;Deployment='Ready';Revision=1;Hash=('A'*64);Sessions=@{};HeapTransactions=@{};Artifacts=@{};Challenge=$null;Response=$null}
        $denied=$false;try {$result=Invoke-MiTraceHealthCheck} catch {$denied=$true}
        if ($mode -cin @('Superseded','TaskChanged')) {
            if (-not $denied -or $context.Runs -ne 0) {throw 'Changed health/task context dispatched or accepted.'}
        } elseif ($denied -or ($mode -ceq 'ExistingResponds' -and $context.Runs -ne 0) -or
            ($mode -cne 'ExistingResponds' -and $context.Runs -ne 1) -or $null -eq $result.Response) {throw ('Health dispatch contract failed for '+$mode)}
        if (@($context.Handles|Where-Object {$_.CanRead}).Count -ne 0) {throw 'Health check leaked a held trace lock.'}
    }
    Write-Host 'PASS: IgnoreNew finishing/ready health race, existing scan response, single dispatch after Flush/unlock and changed challenge/task refusal (scheduler/journal mocked).'
}

# 真正的 Task Scheduler COM 定义仅在内存构建；不注册任何任务。
& {
    $scheduler=Get-MiTaskScheduler
    $definition=Get-MiWatchdogDefinition $scheduler
    $fake=[pscustomobject]@{Definition=$definition;Enabled=$true;State=3;Sddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
    $fake|Add-Member ScriptMethod GetSecurityDescriptor {param($flags) return $this.Sddl}
    Assert-MiWatchdogDefinition $fake
    foreach ($badAcl in @('O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;SY)',
            'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)',
            'O:BAG:BAD:P(A;;FR;;;SY)(A;;FA;;;BA)','O:BAG:BAD:P(A;;FA;;;SY)')) {
        $fake.Sddl=$badAcl;$rejected=$false
        try {Assert-MiWatchdogDefinition $fake} catch {$rejected=$true}
        if (-not $rejected) {throw 'Unprotected/expanded/incomplete watchdog ACL accepted.'}
    }
    $fake.Sddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    $definition.Actions.Item(1).Arguments+=' -Command evil'
    $rejected=$false;try {Assert-MiWatchdogDefinition $fake}catch {$rejected=$true}
    if (-not $rejected) {throw 'Changed task action accepted.'}
    $fake.Definition=Get-MiWatchdogDefinition $scheduler
    $fake.Definition.Principal.UserId=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $rejected=$false;try {Assert-MiWatchdogDefinition $fake}catch {$rejected=$true}
    if (-not $rejected) {throw 'Changed task principal accepted.'}
    $fake.Definition=Get-MiWatchdogDefinition $scheduler
    $fake.Definition.Settings.ExecutionTimeLimit='PT0S'
    $rejected=$false;try {Assert-MiWatchdogDefinition $fake}catch {$rejected=$true}
    if (-not $rejected) {throw 'Unbounded watchdog accepted.'}
    Write-Host 'PASS: real COM task definition (not registered), exact action/principal/bounded runtime rejection.'
}

# 注册适配器必须禁止自动追加 ACE，并复读真实对象；不能用 XML 里的 D:P 当作已设置成功。
& {
    $realScheduler=Get-MiTaskScheduler;$state=@{Flags=0;SetFlags=0;Gets=0;DropProtection=$false}
    $fixture=Join-Path $root ('test-artifacts\M2-TaskRegistration-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
    $paths=[pscustomobject]@{Install=$fixture;Executor=(Join-Path $fixture 'ElevatedExecutor.ps1');WatchdogPolicy=(Join-Path $fixture 'policy.json')}
    function Get-MiSecurityPaths {return $paths}
    $definition=Get-MiWatchdogDefinition $realScheduler
    $task=[pscustomobject]@{Definition=$definition;Enabled=$true;State=3;Sddl='';Xml='actual registered XML fixture'}
    $task|Add-Member ScriptMethod GetSecurityDescriptor {param($flags) return $this.Sddl}
    $task|Add-Member ScriptMethod SetSecurityDescriptor {param($sddl,$flags)
        $state.SetFlags=$flags;$this.Sddl=$sddl
        if ($state.DropProtection) {$this.Sddl=$sddl.Replace('D:P','D:')}
    }
    $folder=[pscustomobject]@{}
    $folder|Add-Member ScriptMethod RegisterTaskDefinition {param($name,$definition,$flags,$sid,$password,$logon,$sddl)
        if ($name -cne 'MemoryInspector.TraceWatchdog' -or $sid -cne 'S-1-5-18' -or $logon -ne 5) {throw 'Unexpected registration scope.'}
        $state.Flags=$flags;$task.Sddl='O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;SY)';return $task
    }
    $folder|Add-Member ScriptMethod GetTask {param($name) $state.Gets++;return $task}
    $scheduler=[pscustomobject]@{};$scheduler|Add-Member ScriptMethod GetFolder {param($path) return $folder}
    function Get-MiTaskScheduler {return $scheduler}
    function Get-MiWatchdogDefinition {param($Scheduler) return $definition}
    function Assert-MiTraceLockHeld {param($Lock)}
    function Set-MiProtectedFileAcl {param($Path)}
    function Assert-MiTracePath {param($Path) if (-not [IO.File]::Exists($Path)) {throw 'Missing registration fixture.'}}
    $journal=[pscustomobject]@{InstallationId=[guid]::NewGuid().ToString('N');Sessions=@{};HeapTransactions=@{};Artifacts=@{}}
    Register-MiWatchdog $null $journal
    if ($state.Flags -ne 18 -or $state.SetFlags -ne 16 -or $state.Gets -ne 1 -or -not [IO.File]::Exists($paths.WatchdogPolicy)) {throw 'Registration failed exact ACL API/requery contract.'}
    Register-MiWatchdog $null $journal $true
    if ($state.Flags -ne 20) {throw 'Update omitted TASK_DONT_ADD_PRINCIPAL_ACE.'}
    $state.DropProtection=$true;$paths.WatchdogPolicy=Join-Path $fixture 'must-not-exist.json';$denied=$false
    try {Register-MiWatchdog $null $journal} catch {$denied=$true}
    if (-not $denied -or [IO.File]::Exists($paths.WatchdogPolicy)) {throw 'Unsupported actual task ACL was trusted or policy created.'}
    Write-Host 'PASS: registration/create-update flags, exact ACL setter/requery and missing protection refusal (registration/ACL mocked; COM definition real).'
}

# 初装续跑只补齐确切写前事务，已存在或部分写入的策略不能覆盖；正式健康恢复另行核验。
& {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'PrivilegeInstallTest.ps1'),[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -ceq 'Complete-MiM2LiveInitialRegistration'},$true)
    . ([scriptblock]::Create($node.Extent.Text))
    $fixture=Join-Path $root ('test-artifacts\M2-InitialRegistration-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
    $paths=[pscustomobject]@{Data=$fixture;TraceRoot=(Join-Path $fixture 'trace');TraceWorkspace=(Join-Path $fixture 'trace\workspace');
        TraceJournal=(Join-Path $fixture 'trace\journal.jsonl');TraceLock=(Join-Path $fixture 'trace.lock');WatchdogPolicy=(Join-Path $fixture 'policy.json')}
    $context=@{Recoveries=0;TaskDenied=$false}
    function Get-MiSecurityPaths {return $paths}
    function Assert-MiTrustedInstallation {return $paths}
    function Set-MiProtectedFileAcl {param($Path)}
    function Set-MiAdminDirectoryAcl {param($Path)}
    function Assert-MiTracePath {param($Path)
        if (-not (Test-Path -LiteralPath $Path) -or -not [IO.Path]::GetFullPath($Path).StartsWith($fixture,[StringComparison]::OrdinalIgnoreCase)) {throw 'Initial registration path invalid.'}
    }
    function Enter-MiDeploymentLease {param([switch]$Exclusive) return [IO.File]::Open((Join-Path $fixture 'deployment.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    function Enter-MiTraceLock {return [IO.File]::Open($paths.TraceLock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    $task=[pscustomobject]@{Xml='strict task identity fixture'}
    $folder=[pscustomobject]@{};$folder|Add-Member ScriptMethod GetTask {param($Name) return $task}
    $scheduler=[pscustomobject]@{};$scheduler|Add-Member ScriptMethod GetFolder {param($Path) return $folder}
    function Get-MiTaskScheduler {return $scheduler}
    function Assert-MiWatchdogDefinition {param($Task) if ($context.TaskDenied) {throw 'Invalid actual task fixture.'}}
    function Assert-MiWatchdog {
        $policy=[IO.File]::ReadAllText($paths.WatchdogPolicy)|ConvertFrom-Json
        if ($policy.DefinitionHash -cne (Get-MiTraceHash $task.Xml)) {throw 'Policy identity lost.'}
    }
    function Invoke-MiTraceDeploymentRecovery {$context.Recoveries++}
    $lock=Enter-MiTraceLock
    try {
        $j=Initialize-MiTraceJournal $lock
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Pending';Intent='PrepareInstallation'})
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Pending';Intent='RegisterWatchdog'})
    } finally {$lock.Dispose()}
    $denied=$false;try {Complete-MiM2LiveInitialRegistration} catch {$denied=$true}
    if (-not $denied -or [IO.File]::Exists($paths.WatchdogPolicy)) {throw 'Incomplete initial provenance accepted.'}
    $lock=Enter-MiTraceLock
    try {$j=Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='RecoveryRequired';Intent='ManualRecovery';Error='Untrusted Watchdog task ACL.'})} finally {$lock.Dispose()}
    $context.TaskDenied=$true;$denied=$false;try {Complete-MiM2LiveInitialRegistration} catch {$denied=$true}
    if (-not $denied -or [IO.File]::Exists($paths.WatchdogPolicy)) {throw 'Untrusted actual task received a policy.'}
    $context.TaskDenied=$false;Complete-MiM2LiveInitialRegistration
    $original=[IO.File]::ReadAllText($paths.WatchdogPolicy);$denied=$false
    try {Complete-MiM2LiveInitialRegistration} catch {$denied=$true}
    $lock=Enter-MiTraceLock
    try {$j=Read-MiTraceJournal $lock} finally {$lock.Dispose()}
    if (-not $denied -or [IO.File]::ReadAllText($paths.WatchdogPolicy) -cne $original -or $context.Recoveries -ne 1 -or
        $j.Deployment -cne 'RecoveryRequired' -or $j.Revision -ne 5) {throw 'Initial completion overwrote policy, repeated or bypassed actual health requirement.'}
    Write-Host 'PASS: exact initial-registration provenance, task refusal, CreateNew policy binding and no readiness without actual health (ACL/task/health mocked).'
}

# 已知 XML 序列化差异只允许从受保护备份恢复既有指纹；绝不采纳新 hash。
& {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'PrivilegeInstallTest.ps1'),[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -ceq 'Read-MiM2LiveAccessRoster'},$true)
    . ([scriptblock]::Create($node.Extent.Text))
    $fixture=Join-Path $root ('test-artifacts\M2-AccessRoster-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
    $root=$fixture;$folder=Join-Path $root 'test-artifacts\v3-m2-win11';[void][IO.Directory]::CreateDirectory($folder)
    $paths=[pscustomobject]@{Data=(Join-Path $root 'protected')};[void][IO.Directory]::CreateDirectory($paths.Data)
    $attempt=[guid]::NewGuid().ToString('N');$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $summary=[ordered]@{AttemptId=$attempt;Status='ChecksPassedWithPendingAcceptance'}
    $snapshot=[ordered]@{SchemaVersion=1;AttemptId=$attempt;RunId=[guid]::NewGuid().ToString('N');OwnerSid=$sid;BootSessionId='123';Utc=[datetime]::UtcNow.ToString('o');Paths=@('fixed fixture')}
    $context=@{Trusted=$true}
    function Get-MiBootSessionId {return '123'}
    function Assert-MiTracePath {param($Path)
        if (-not $context.Trusted -or -not $Path.StartsWith($paths.Data+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Untrusted access snapshot.'}
    }
    function Write-AccessRosterFixture {
        [IO.File]::WriteAllText((Join-Path $folder 'live-summary.json'),($summary|ConvertTo-Json -Compress))
        [IO.File]::WriteAllText((Join-Path $paths.Data ('m2-win11-access-'+$attempt+'.json')),($snapshot|ConvertTo-Json -Compress))
    }
    Write-AccessRosterFixture;$accepted=Read-MiM2LiveAccessRoster $paths
    if ($accepted.AttemptId -cne $attempt) {throw 'Protected existence snapshot lost binding.'}
    foreach ($failure in @('Acl','Schema','Attempt','Owner','Boot','Stale','Future','FailedSummary','PathSelection')) {
        $snapshot.SchemaVersion=1;$snapshot.AttemptId=$attempt;$snapshot.OwnerSid=$sid;$snapshot.BootSessionId='123';$snapshot.Utc=[datetime]::UtcNow.ToString('o')
        $summary.AttemptId=$attempt;$summary.Status='ChecksPassedWithPendingAcceptance';$context.Trusted=$true
        switch ($failure) {
            'Acl' {$context.Trusted=$false}
            'Schema' {$snapshot.SchemaVersion=2}
            'Attempt' {$snapshot.AttemptId=[guid]::NewGuid().ToString('N')}
            'Owner' {$snapshot.OwnerSid='S-1-5-21-1-2-3-999'}
            'Boot' {$snapshot.BootSessionId='456'}
            'Stale' {$snapshot.Utc=[datetime]::UtcNow.AddMinutes(-16).ToString('o')}
            'Future' {$snapshot.Utc=[datetime]::UtcNow.AddMinutes(1).ToString('o')}
            'FailedSummary' {$summary.Status='Failed'}
            'PathSelection' {$summary.AttemptId='../outside'}
        }
        Write-AccessRosterFixture;$denied=$false;try {Read-MiM2LiveAccessRoster $paths|Out-Null} catch {$denied=$true}
        if (-not $denied) {throw ('Invalid administrator snapshot accepted: '+$failure)}
    }
    Write-Host 'PASS: protected access snapshot binding rejects ACL/schema/identity/boot/time/failed-summary/path selection faults (ACL mocked).'
}

# 已知 XML 序列化差异只允许从受保护备份恢复既有指纹；绝不采纳新 hash。
& {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'PrivilegeInstallTest.ps1'),[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -ceq 'Restore-MiM2LiveTaskDefinition'},$true)
    . ([scriptblock]::Create($node.Extent.Text))
    $fixture=Join-Path $root ('test-artifacts\M2-DefinitionRestore-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
    $paths=[pscustomobject]@{Results=$fixture;WatchdogPolicy=(Join-Path $fixture 'policy.json')}
    $run=[guid]::NewGuid().ToString('N');$attempt=[guid]::NewGuid().ToString('N');$installId=[guid]::NewGuid().ToString('N')
    $sddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)';$actualSddl=$sddl.Replace('D:P','D:PAI')
    $original='<Task><SecurityDescriptor>'+$sddl+'</SecurityDescriptor><safe /></Task>'
    $task=[pscustomobject]@{Xml=$original.Replace($sddl,$actualSddl);Sddl=$actualSddl}
    $state=@{Registers=0;RegisterFlags=0;SetFlags=0};$journal=[pscustomobject]@{InstallationId=$installId;Hash=('A'*64);Sessions=@{};HeapTransactions=@{};Artifacts=@{}}
    $task|Add-Member ScriptMethod GetSecurityDescriptor {param($Flags) return $this.Sddl}
    $task|Add-Member ScriptMethod SetSecurityDescriptor {param($Sd,$Flags) $state.SetFlags=$Flags;$this.Sddl=$Sd}
    $folder=[pscustomobject]@{};$folder|Add-Member ScriptMethod GetTask {param($Name) return $task}
    $folder|Add-Member ScriptMethod RegisterTask {param($Name,$Xml,$Flags,$Sid,$Password,$Logon,$Sd)
        if ($Name -cne 'MemoryInspector.TraceWatchdog' -or $Sd -cne $sddl -or $Sid -cne 'S-1-5-18' -or $Logon -ne 5) {throw 'Unexpected task restore scope.'}
        $state.Registers++;$state.RegisterFlags=$Flags;$task.Xml=$Xml;return $task
    }
    $scheduler=[pscustomobject]@{};$scheduler|Add-Member ScriptMethod GetFolder {param($Path) return $folder}
    function Get-MiTaskScheduler {return $scheduler}
    function Assert-MiTrustedInstallation {return $paths}
    function Enter-MiDeploymentLease {param([switch]$Exclusive) return [IO.MemoryStream]::new()}
    function Enter-MiTraceLock {return [IO.MemoryStream]::new()}
    function Read-MiTraceJournal {param($Lock) return $journal}
    function Assert-MiWatchdogDefinition {param($Task)}
    function Assert-MiWatchdog {if ((Get-MiTraceHash $task.Xml) -cne (Get-MiTraceHash $original)) {throw 'Restore changed accepted fingerprint.'}}
    function Set-MiProtectedFileAcl {param($Path)}
    function Assert-MiTracePath {param($Path) if (-not (Test-Path -LiteralPath $Path) -or -not $Path.StartsWith($fixture,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unknown restore fixture.'}}
    $prior=[ordered]@{SchemaVersion=1;RunId=$run;AttemptId=$attempt;Mode='Windows11LiveM2';Status='Failed';
        Checks=@([ordered]@{State='Failed';Name='TaskDefinitionTamperRefusedAndRestored';Error='Watchdog definition fingerprint mismatch.'})}
    [IO.File]::WriteAllText((Join-Path $fixture ('m2-win11-'+$attempt+'.json')),($prior|ConvertTo-Json -Depth 4))
    $case=Join-Path (Join-Path (Join-Path $fixture 'm2-win11-fault-evidence') $attempt) 'TaskXml';[void][IO.Directory]::CreateDirectory($case)
    $backup=Join-Path $case 'original.bin';[IO.File]::WriteAllText($backup,$original,[Text.UTF8Encoding]::new($false))
    $intent=[ordered]@{SchemaVersion=1;RunId=$run;AttemptId=$attempt;Kind='TaskXml';State='CapturedBeforeMutation';OriginalSha256=(Get-FileHash $backup -Algorithm SHA256).Hash}
    [IO.File]::WriteAllText((Join-Path $case 'stages.jsonl'),($intent|ConvertTo-Json -Compress)+"`n")
    $policy=[ordered]@{SchemaVersion=1;InstallationId=$installId;DefinitionHash=(Get-MiTraceHash $original)}
    $policyText=$policy|ConvertTo-Json -Compress;[IO.File]::WriteAllText($paths.WatchdogPolicy,$policyText)
    foreach ($identities in @(@([guid]::NewGuid().ToString('N'),$attempt),@($run,[guid]::NewGuid().ToString('N')))) {
        $denied=$false;try {Restore-MiM2LiveTaskDefinition $identities[0] $identities[1]} catch {$denied=$true}
        if (-not $denied -or $state.Registers -ne 0) {throw 'Definition repair accepted wrong owner run or absent attempt evidence.'}
    }
    [IO.File]::WriteAllText($backup,$original+'changed',[Text.UTF8Encoding]::new($false));$denied=$false
    try {Restore-MiM2LiveTaskDefinition $run $attempt} catch {$denied=$true}
    if (-not $denied -or $state.Registers -ne 0) {throw 'Definition repair accepted backup SHA mismatch.'}
    [IO.File]::WriteAllText($backup,$original,[Text.UTF8Encoding]::new($false))
    $policy.DefinitionHash=('B'*64);[IO.File]::WriteAllText($paths.WatchdogPolicy,($policy|ConvertTo-Json -Compress));$denied=$false
    try {Restore-MiM2LiveTaskDefinition $run $attempt} catch {$denied=$true}
    if (-not $denied -or $state.Registers -ne 0) {throw 'Definition repair accepted original XML outside existing policy.'}
    [IO.File]::WriteAllText($paths.WatchdogPolicy,$policyText)
    $task.Xml+='unexpected';$denied=$false;try {Restore-MiM2LiveTaskDefinition $run $attempt} catch {$denied=$true}
    if (-not $denied -or $state.Registers -ne 0) {throw 'Definition repair overwrote extra task changes.'}
    $task.Xml=$original.Replace($sddl,$actualSddl)
    Restore-MiM2LiveTaskDefinition $run $attempt
    $evidence=@(Get-ChildItem -LiteralPath $fixture -Filter 'm2-definition-restore-*.jsonl')
    $stages=@([IO.File]::ReadAllLines($evidence[0].FullName)|ForEach-Object {($_|ConvertFrom-Json).State})
    if ($state.Registers -ne 1 -or $state.RegisterFlags -ne 20 -or $state.SetFlags -ne 16 -or
        [IO.File]::ReadAllText($paths.WatchdogPolicy) -cne $policyText -or ($stages -join ',') -cne 'RestoreIntent,Restored') {throw 'Definition restore lost exact XML/ACL/policy or intent ordering.'}
    Write-Host 'PASS: definition restore rejects unrelated changes and restores only protected original fingerprint with separate registration/actual ACL (task/ACL mocked).'
}


# V3-M3：真实 Journal/文件移动，WPR/ACL/健康边界在夹具中模拟；绝不录制本机。
& {
    function Assert-M3Rejected {param([scriptblock]$Action,[string]$Label)
        $rejected=$false;try {& $Action|Out-Null} catch {$rejected=$true}
        if (-not $rejected) {throw ('M3 unexpectedly accepted: '+$Label)}
    }
    if ((Get-MiWprReleaseStatus).Enabled -or (Get-MiWprReleaseStatus).M2Accepted -or (Get-MiWprReleaseStatus).FileAccepted) {throw 'Unaccepted M2/M3 released.'}
    Assert-M3Rejected {Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))} 'actual release gate'
    Assert-M3Rejected {Invoke-MiWprStop ([guid]::NewGuid().ToString('N'))} 'actual stop release gate'
    Assert-M3Rejected {Repair-MiWprSavedArtifacts} 'actual recovery release gate'
    foreach ($operation in @('TraceStart','TraceStop','TraceArtifacts','TraceExportPrepare')) {
        if (-not (Test-MiPrivilegedOperation $operation $id)) {throw 'Fixed M3 protocol rejected.'}
        if (Test-MiPrivilegedOperation $operation $id 'RpcSs') {throw 'M3 protocol accepted service payload.'}
    }
    if (-not (Test-MiWprResources 0 0 6442450944 1073741824)) {throw 'Valid independent budgets rejected.'}
    foreach ($values in @(@(-1,0,6442450944,1073741824),@(8589934592,0,6442450944,1073741824),
        @(0,4294967297,6442450944,1073741824),@(0,0,6442450943,1073741824),@(0,0,6442450944,1073741823))) {
        if (Test-MiWprResources $values[0] $values[1] $values[2] $values[3]) {throw 'Invalid resource budget accepted.'}
    }
    $profileFixture=Join-Path (Join-Path $root 'test-artifacts') ('WprProfiles-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($profileFixture)
    $parsedProfiles=0
    foreach ($type in @('VirtualAlloc','Pool','Heap')) {foreach ($mode in @('Memory','File')) {
        $profile=Get-MiWprProfile $type $mode
        if ((Get-MiTraceHash $profile.Xml) -cne $profile.Fingerprint -or $profile.BufferBytes -ne 134217728) {throw 'Profile fingerprint/buffer budget mismatch.'}
        $path=Join-Path $profileFixture ($type+'-'+$mode+'.wprp');[IO.File]::WriteAllText($path,$profile.Xml)
        if ([IO.File]::Exists((Join-Path $env:WINDIR 'System32\wpr.exe'))) {
            & (Join-Path $env:WINDIR 'System32\wpr.exe') -profiles $path | Out-Null
            if ($LASTEXITCODE -ne 0) {throw 'Real read-only WPR profile parser rejected fixed profile.'}
            $parsedProfiles++
        }
    }}
    Assert-M3Rejected {Invoke-MiWprStart ([guid]::NewGuid().ToString('N')) 'Heap' 'Memory' 300 'C:\fixture.exe'} 'M4 actual release gate'
    Assert-M3Rejected {Repair-MiHeapTransactions} 'M4 actual recovery release gate'
    Assert-M3Rejected {Set-MiHeapConfiguration $null $null} 'M4 actual registry write release gate'
    Assert-M3Rejected {Initialize-MiArtifactExport ([guid]::NewGuid().ToString('N'))} 'M5 actual descriptor gate'
    if ((Get-MiExportReleaseStatus).Enabled -or (Get-MiExportReleaseStatus).OfflineAccepted -or (Get-MiExportReleaseStatus).NormalizationAccepted -or
        (Get-MiExportReleaseStatus).OnlineAccepted) {throw 'M5 actual acceptance gate opened.'}
    if ((Get-MiHeapReleaseStatus).Enabled -or (Get-MiHeapReleaseStatus).ConfigurationAccepted -or (Get-MiHeapReleaseStatus).RecoveryAccepted) {throw 'Heap acceptance gate opened.'}
    foreach ($badName in @('..\evil.exe','evil.exe\child','evil.exe:stream','*.exe','fixture.EXE','a..exe')) {
        Assert-M3Rejected {Assert-MiHeapImageName $badName} 'registry image scope'
    }
    foreach ($badPath in @('fixture.exe','\\server\share\fixture.exe','C:\fixture.exe:stream')) {
        Assert-M3Rejected {Get-MiHeapTargetIdentity $badPath} 'local executable scope'
    }
    # 原生只读查询与 PE/哈希检查，不创建测试键，更不启用系统 Heap。
    $nativeImage=Get-MiHeapTargetIdentity (Join-Path $env:WINDIR 'System32\cmd.exe')
    if ($nativeImage.Machine -cne 'NativeX64' -or $nativeImage.Sha256 -cnotmatch '^[A-F0-9]{64}$') {throw 'Native PE identity invalid'}
    $probe=Get-MiHeapConfiguration ('MiReadOnlyProbe-'+[guid]::NewGuid().ToString('N')+'.exe')
    if ($probe.KeyExists -or $probe.ValueExists -or -not $probe.ScopeSupported) {throw 'Read-only registry probe changed configuration'}
    Initialize-MiTraceNative
    $badEtl=Join-Path $profileFixture 'invalid.etl';[IO.File]::WriteAllText($badEtl,'not an ETL')
    Assert-M3Rejected {Test-MiEtlArtifact $badEtl} 'real native ETL parser'
    if (-not (Test-MiAdminToken)) {Assert-M3Rejected {Get-MiEtwSessions} 'permission filtered ETW query'}
    Write-Host ('PASS: actual disabled release gates, independent budgets and native invalid ETL rejection; real WPR profile parses='+$parsedProfiles)
    if ($parsedProfiles -eq 0) {Write-Host 'SKIP: WPR missing; profile syntax not verified by actual WPR.'}

    $realAppend=${function:Add-MiTraceJournalRecord}
    $realTransport=${function:Start-MiWprProcess}
    $test=@{}
    function Get-MiSecurityPaths {return $test.Paths}
    function Test-MiAdminToken {return $true}
    function Test-MiAclRestricted {param($Path,$Protected) if ($test.PathFault) {return $false};return [IO.Path]::GetFullPath($Path).StartsWith($test.Paths.Data+'\',[StringComparison]::OrdinalIgnoreCase) -or $Path -eq $test.Paths.Data}
    function Set-MiProtectedFileAcl {param($Path,$AllowUsersRead)}
    function Set-MiAdminDirectoryAcl {param($Path,$AllowUsersRead)}
    function Set-MiDiagnosticAccess {param($Path,$OwnerSid,[switch]$Directory)}
    function Get-MiWprReleaseStatus {return [pscustomobject]@{Enabled=$true;M2Accepted=$true;MemoryAccepted=$true;FileAccepted=$true}}
    function Get-MiBootSessionId {return '100'}
    function Assert-MiWatchdog {}
    function Invoke-MiTraceHealthCheck {if ($test.HealthFault) {throw 'Fixture health failure'}}
    function Read-Host {param($Prompt) if ($test.Cancel) {return ''};if ($Prompt -match 'Type START ([a-f0-9]{32}) ') {return 'START '+$matches[1]};throw 'Unexpected prompt'}
    function Get-MiWprIdentity {return [pscustomobject]@{SchemaVersion=1;Path='C:\Windows\System32\wpr.exe';Sha256=('A'*64);Version='Fixture';Signer='Fixture'}}
    function Get-MiEtwSessions {return $test.Observed}
    function Get-MiWprResources {
        if ($test.ResourceFault) {throw 'Fixture disk query failed'}
        return [pscustomobject]@{ArtifactBytes=0;WorkingBytes=$test.WorkingBytes;FreeBytes=10737418240;AvailableMemoryBytes=4294967296}
    }
    function Start-MiWprProcess {param($Verb,$Session)
        if ($Verb -ceq 'Start') {
            $test.Starts++
            if ($test.StartFault) {throw 'Fixture start result unknown'}
            $profile=Get-MiWprProfile $Session.RequestedTraceType $Session.RecordingMode
            $temporary=(Get-MiWprSessionPaths $Session).Temporary
            $test.Observed=@($test.Observed)+[pscustomobject]@{Name=('WPR_initiated_'+$Session.WprInstanceName+'_'+$profile.CollectorSuffix);
                Guid=[guid]::NewGuid().ToString();Handle='0000000000000123';ThreadId=123;ThreadCreated=[datetime]::UtcNow.ToFileTimeUtc();
                Mode=if ($Session.RequestedTraceType -ceq 'Heap') {0} else {0x02000000};FileName=(Join-Path $temporary 'fixture.etl');BufferKB=1024;MaximumBuffers=128}
        } else {$test.Stops++;if ($test.StopFault) {throw 'Fixture stop dispatch outcome unknown'}}
        $time=if ($test.Expired) {[datetime]::UtcNow.AddMinutes(-10)} else {[datetime]::UtcNow}
        return [pscustomobject]@{SchemaVersion=1;Pid=123;StartUtcTicks=123456;DispatchedUtc=$time.ToString('o');Operation=$Verb}
    }
    function Test-MiWprProcessRunning {param($Identity) return $test.WriterLive}
    function Test-MiEtlArtifact {param($Path)
        $file=Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.Length -eq 0) {throw 'Empty fixture ETL'}
        return [pscustomobject]@{SizeBytes=$file.Length;Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;EventCount=3;EventsLost=1;BuffersLost=0;
            StartUtc='2026-10-25T00:00:00.0000000Z';EndUtc='2026-10-25T00:05:00.0000000Z'}
    }
    function Add-MiTraceJournalRecord {param($Lock,$ExpectedRevision,$Kind,$Payload)
        if ($Kind -ceq 'Artifact' -and $Payload.State -ceq 'Saving' -and $test.AgeArtifact) {
            $Payload.CreatedUtc=[datetime]::UtcNow.AddDays(-8).ToString('o');$Payload.RetainUntilUtc=(ConvertTo-MiTraceUtc $Payload.CreatedUtc).AddDays(7).ToString('o')
        }
        $state=if ($Kind -ceq 'HeapTransaction') {$Payload.RestoreState} else {$Payload.State}
        if ($test.Fault -ceq ($Kind+':'+$state)) {$test.Fault='';throw 'Injected append boundary failure'}
        return & $realAppend $Lock $ExpectedRevision $Kind $Payload
    }
    function New-M3Fixture {
        $test.Clear();$test.Starts=0;$test.Stops=0;$test.WorkingBytes=0;$test.Observed=@();$test.WriterLive=$true
        $directory=Join-Path (Join-Path $root 'test-artifacts') ('WprCore-'+[guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($directory)
        $test.Paths=[pscustomobject]@{Data=$directory;TraceRoot=(Join-Path $directory 'trace');TraceJournal=(Join-Path $directory 'trace\journal.jsonl');
            TraceLock=(Join-Path $directory 'trace.lock');TraceWorkspace=(Join-Path $directory 'trace\workspace');DeploymentLease=(Join-Path $directory 'deployment.lock');TraceArtifacts=(Join-Path $directory 'diagnostics')}
        $lock=Enter-MiTraceLock
        try {
            $j=Initialize-MiTraceJournal $lock
            $challenge=[ordered]@{SchemaVersion=1;Nonce=[guid]::NewGuid().ToString('N');BootSessionId='100';InstallationId=$j.InstallationId;
                DefinitionHash=('A'*64);RequestedUtc=[datetime]::UtcNow.ToString('o');ExpiresUtc=[datetime]::UtcNow.AddSeconds(40).ToString('o')}
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'HealthChallenge' $challenge
            $response=[ordered]@{SchemaVersion=1;Nonce=$challenge.Nonce;BootSessionId='100';InstallationId=$j.InstallationId;
                DefinitionHash=('A'*64);Utc=[datetime]::UtcNow.ToString('o');ExecutorSid='S-1-5-18';ScannedHash=$j.Hash}
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'HealthResponse' $response
            [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Ready'}))
        } finally {$lock.Dispose()}
    }
    New-M3Fixture;$test.Cancel=$true
    if ((Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))).State -cne 'AuthorizationDenied' -or $test.Starts -ne 0) {throw 'Cancelled start dispatched.'}
    New-M3Fixture;$test.HealthFault=$true
    Assert-M3Rejected {Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))} 'missing watchdog response'
    if ($test.Starts -ne 0) {throw 'Unhealthy watchdog dispatched.'}
    New-M3Fixture;$test.StartFault=$true;$request=[guid]::NewGuid().ToString('N')
    Assert-M3Rejected {Invoke-MiWprStart $request} 'unknown start'
    $lock=Enter-MiTraceLock
    try {
        $j=Update-MiTraceSupervision $lock '100';$j=Update-MiTraceSupervision $lock '100'
        if ($test.Starts -ne 1 -or $test.Stops -ne 0 -or $j.Sessions[$request].State -cne 'RecoveryRequired') {throw 'Unknown start automatically retried or stopped.'}
    } finally {$lock.Dispose()}
    foreach ($mode in @('Memory','File')) {
        New-M3Fixture;$session=Invoke-MiWprStart ([guid]::NewGuid().ToString('N')) 'Pool' $mode 300
        $arguments=Get-MiWprArguments Start $session
        if (-not $arguments.EndsWith('-instancename '+$session.WprInstanceName) -or ($mode -ceq 'File' -and $arguments -notmatch '-filemode') -or
            ($mode -ceq 'Memory' -and $arguments -match '-filemode')) {throw 'Wrong mode or instance command binding.'}
        Assert-M3Rejected {Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))} 'single active trace'
        Assert-MiWprOwnership $session $test.Observed
        $test.PathFault=$true
        Assert-M3Rejected {& $realTransport 'Start' $session} 'untrusted actual transport workspace'
        $test.PathFault=$false
        $paths=Get-MiWprSessionPaths $session;$profileText=[IO.File]::ReadAllText($paths.Profile)
        [IO.File]::WriteAllText($paths.Profile,'changed profile')
        Assert-M3Rejected {& $realTransport 'Start' $session} 'changed actual transport profile'
        [IO.File]::WriteAllText($paths.Profile,$profileText)
        $original=$test.Observed[0]|ConvertTo-Json -Depth 10|ConvertFrom-Json
        foreach ($field in @('Guid','Handle','ThreadId','ThreadCreated','Mode','FileName')) {
            $bad=$original|ConvertTo-Json -Depth 10|ConvertFrom-Json
            if ($field -cin @('ThreadId','ThreadCreated','Mode')) {$bad.$field=1} else {$bad.$field='replaced'}
            Assert-M3Rejected {Assert-MiWprOwnership $session @($bad)} ('ownership '+$field)
        }
        if ($test.Stops -ne 0) {throw 'Ownership rejection dispatched stop.'}
    }
    foreach ($reason in @('Deadline','ResourceFailure','Budget','FileMergeReserve','UnknownStop')) {
        New-M3Fixture;$test.Expired=$reason -ceq 'Deadline'
        $mode=if ($reason -ceq 'FileMergeReserve') {'File'} else {'Memory'}
        $session=Invoke-MiWprStart ([guid]::NewGuid().ToString('N')) 'VirtualAlloc' $mode
        $test.ResourceFault=$reason -cin @('Deadline','ResourceFailure');$test.StopFault=$reason -ceq 'UnknownStop'
        if ($reason -ceq 'Budget') {$test.WorkingBytes=4294967297}
        if ($reason -ceq 'FileMergeReserve') {$test.WorkingBytes=2147483648}
        $lock=Enter-MiTraceLock
        try {
            if ($reason -ceq 'UnknownStop') {Assert-M3Rejected {Request-MiWprStop $lock $session} 'unknown stop'}
            else {$j=Update-MiTraceSupervision $lock '100'}
            $j=Read-MiTraceJournal $lock
            if ($test.Stops -ne 1) {throw ('Missing single stop: '+$reason)}
            if ($reason -ceq 'Deadline' -and $j.Sessions[$session.TraceSessionId].StopReason -cne 'DeadlineExceeded') {throw 'Resource error masked deadline.'}
            Assert-M3Rejected {Request-MiWprStop $lock $session} 'stale or replayed stop'
            $j=Update-MiTraceSupervision $lock '100'
            if ($test.Stops -ne 1) {throw 'Stop automatically repeated.'}
        } finally {$lock.Dispose()}
    }
    foreach ($fault in @('','Artifact:Ready','Session:Cleaning','Session:Analyzing','Session:Completed','MissingOutput')) {
        New-M3Fixture;$session=Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))
        $lock=Enter-MiTraceLock
        try {
            $j=Request-MiWprStop $lock $session;$test.Observed=@()
            $j=Update-MiTraceSupervision $lock '100';$current=$j.Sessions[$session.TraceSessionId]
            if ($current.State -cne 'Saving' -or $current.StopState -cne 'Confirmed' -or $current.SaveState -ceq 'Saved') {throw 'Stop/save outcomes conflated.'}
            $paths=Get-MiWprSessionPaths $session
            if ($fault -cne 'MissingOutput') {[IO.File]::WriteAllText($paths.Output,'fixture ETL bytes')}
            $test.WriterLive=$false;$test.Fault=$fault
            $j=Update-MiTraceSupervision $lock '100';$current=$j.Sessions[$session.TraceSessionId]
            if ($fault -ceq 'MissingOutput') {
                if ($current.State -cne 'TraceNotSaved' -or $current.StopState -cne 'Confirmed') {throw 'Missing ETL erased confirmed stop.'}
                continue
            }
            if ($fault -ne '') {
                if ($current.State -cne 'RecoveryRequired') {throw ('Fault not retained: '+$fault)}
                if ($fault.StartsWith('Session:') -and $current.SaveState -cne 'Saved') {throw 'Saved result lost on later failure.'}
                $j=Complete-MiWprArtifact $lock $current
            }
            $current=$j.Sessions[$session.TraceSessionId];$artifact=$j.Artifacts[$current.OutputArtifactId]
            if ($current.State -cne 'Completed' -or $artifact.State -cne 'Ready' -or $artifact.MeasurementQuality -cne 'Partial' -or
                -not [IO.File]::Exists((Get-MiTraceArtifactPath $artifact)) -or [IO.File]::Exists($paths.Output)) {throw 'Save/recovery did not preserve verified artifact.'}
            Assert-MiTraceQuiescent $j
            $artifact.ActiveReferences=1;$j=Add-MiTraceJournalRecord $lock $j.Revision 'Artifact' $artifact
            Assert-M3Rejected {Assert-MiTraceQuiescent $j} 'active analysis deployment'
            $artifact.ActiveReferences=0;$j=Add-MiTraceJournalRecord $lock $j.Revision 'Artifact' $artifact
            if ($test.Stops -ne 1) {throw 'Save recovery repeated WPR stop.'}
        } finally {$lock.Dispose()}
    }
    # 停止确认后、首次 Artifact 意图前重启：只恢复已知文件，不补发 WPR。
    New-M3Fixture;$session=Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))
    $lock=Enter-MiTraceLock
    try {
        $j=Request-MiWprStop $lock $session;$test.Observed=@();$j=Update-MiTraceSupervision $lock '100'
        [IO.File]::WriteAllText((Get-MiWprSessionPaths $session).Output,'ETL written before reboot')
        $test.WriterLive=$false;$j=Update-MiTraceSupervision $lock '200'
        if ($j.Sessions[$session.TraceSessionId].State -cne 'RecoveryRequired' -or $j.Artifacts.Count -ne 0) {throw 'Reboot fixture failed.'}
    } finally {$lock.Dispose()}
    Repair-MiWprSavedArtifacts
    $lock=Enter-MiTraceLock
    try {
        $j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
        if ($j.Sessions[$session.TraceSessionId].State -cne 'Completed' -or $test.Stops -ne 1) {throw 'Pre-intent reboot recovery failed.'}
    } finally {$lock.Dispose()}
    # 7 天归档：先验证活跃读句柄与引用保护，再模拟移动成功/记账失败后的重入。
    New-M3Fixture;$test.AgeArtifact=$true;$session=Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))
    $lock=Enter-MiTraceLock
    try {
        $j=Request-MiWprStop $lock $session;$test.Observed=@();$j=Update-MiTraceSupervision $lock '100'
        [IO.File]::WriteAllText((Get-MiWprSessionPaths $session).Output,'retained ETL')
        $test.WriterLive=$false;$j=Update-MiWprSession $lock $j.Sessions[$session.TraceSessionId]
        $artifact=@($j.Artifacts.Values)[0];$source=Get-MiTraceArtifactPath $artifact
        $artifact.ActiveReferences=1;$j=Add-MiTraceJournalRecord $lock $j.Revision 'Artifact' $artifact
        $j=Invoke-MiTraceRetention $lock
        if ($j.Artifacts[$artifact.ArtifactId].State -cne 'Ready') {throw 'Active reference archived.'}
        $artifact.ActiveReferences=0;$j=Add-MiTraceJournalRecord $lock $j.Revision 'Artifact' $artifact
        $reader=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {$j=Invoke-MiTraceRetention $lock;if ($j.Artifacts[$artifact.ArtifactId].State -cne 'Ready') {throw 'Active reader archived.'}} finally {$reader.Dispose()}
        $test.Fault='Artifact:Retained';Assert-M3Rejected {Invoke-MiTraceRetention $lock} 'retention append interruption'
        $j=Read-MiTraceJournal $lock;Assert-M3Rejected {Assert-MiTraceQuiescent $j} 'unfinished retention blocks deployment'
        $j=Invoke-MiTraceRetention $lock
        if ($j.Artifacts[$artifact.ArtifactId].State -cne 'Retained' -or -not [IO.File]::Exists((Get-MiTraceArtifactPath $artifact -Retained)) -or
            (Measure-MiProtectedTree $test.Paths.TraceArtifacts) -ne $artifact.SizeBytes) {throw 'Retention lost bytes or misreported storage.'}
    } finally {$lock.Dispose()}
    Write-Host 'PASS: M3 start/cancel/health/gates, modes/ownership/replay, resource/deadline stops, independent outcomes and four save crash boundaries (WPR and ACL mocked).'
    # M4 复用真实 Journal/文件与 M3 生命周期；仅注册表、目标身份、WPR 和健康边界使用夹具。
    & {
        function Get-MiHeapReleaseStatus {return [pscustomobject]@{Enabled=$true;ConfigurationAccepted=$true;RecoveryAccepted=$true}}
        function Get-MiHeapTargetIdentity {param($Path)
            $test.TargetReads++
            if ($test.TargetFault -or $test.TargetReads -eq $test.TargetFailAt) {throw 'Injected target replacement'}
            return [pscustomobject][ordered]@{Path='C:\fixture.exe';ImageName='fixture.exe';Sha256=('B'*64);Machine='NativeX64'}
        }
        function Get-MiHeapConfiguration {param($ImageName)
            if ($ImageName -cne 'fixture.exe') {throw 'Unbounded registry target'}
            $test.RegistryReads++
            if ($test.RegistryReadFault -or $test.RegistryReads -eq $test.RegistryFailAt) {throw 'Registry read unavailable'}
            return $test.Registry|ConvertTo-Json -Compress|ConvertFrom-Json
        }
        function Test-MiWprProcessRunning {param($Identity)
            if ($Identity.Operation -ceq 'Start') {return $false};return $test.WriterLive
        }
        function Set-MiHeapConfiguration {param($Lock,$Transaction,[switch]$Restore)
            $j=Read-MiTraceJournal $Lock;$tx=$j.HeapTransactions[$Transaction.TransactionId]
            if ($null -eq $tx -or $tx.ConfigOwner -cne 'MemoryInspector' -or
                ($tx|ConvertTo-Json -Depth 10 -Compress) -cne ($Transaction|ConvertTo-Json -Depth 10 -Compress) -or
                $tx.RestoreState -cne $(if ($Restore) {'Restoring'} else {'Intent'})) {throw 'Fixture write lacks protected intent'}
            $expected=if ($Restore) {$tx.ExpectedModifiedConfig} else {$tx.OriginalConfig}
            if (-not (Test-MiHeapConfigEqual $test.Registry $expected)) {throw 'Fixture compare-before-write conflict'}
            if ($test.RegistryWriteFault -ceq 'Before') {$test.RegistryWriteFault='';throw 'Registry write failed before mutation'}
            if ($Restore) {$test.Restores++;$test.Registry=$tx.OriginalConfig|ConvertTo-Json -Compress|ConvertFrom-Json}
            else {$test.Enables++;$test.Registry=$tx.ExpectedModifiedConfig|ConvertTo-Json -Compress|ConvertFrom-Json}
            if ($test.RegistryWriteFault -ceq 'After') {$test.RegistryWriteFault='';throw 'Registry result lost after mutation'}
            return Get-MiHeapConfiguration 'fixture.exe'
        }
        function New-M4Fixture {
            New-M3Fixture
            $test.Enables=0;$test.Restores=0
            $test.Registry=[pscustomobject][ordered]@{KeyExists=$false;ValueExists=$false;Kind='';Value=$null;ContextFingerprint=('C'*64);ScopeSupported=$true}
        }
        function Stop-M4Fixture {
            param($Lock,$Session,[switch]$MissingOutput)
            $j=Request-MiWprStop $Lock $Session;$test.Observed=@()
            $j=Update-MiWprSession $Lock $j.Sessions[$Session.TraceSessionId]
            if (-not $MissingOutput) {[IO.File]::WriteAllText((Get-MiWprSessionPaths $Session).Output,'Heap fixture ETL')}
            $test.WriterLive=$false
            return Update-MiWprSession $Lock $j.Sessions[$Session.TraceSessionId]
        }
        # M2/M3 即使被测试替身开放，M4 自己的未验收门仍须先拒绝。
        $openGate=${function:Get-MiHeapReleaseStatus}
        function Get-MiHeapReleaseStatus {return [pscustomobject]@{Enabled=$false;ConfigurationAccepted=$false;RecoveryAccepted=$false}}
        New-M4Fixture
        Assert-M3Rejected {Invoke-MiWprStart ([guid]::NewGuid().ToString('N')) 'Heap' 'Memory' 300 'C:\fixture.exe'} 'independent M4 gate'
        if ($test.Enables -ne 0 -or $test.Starts -ne 0) {throw 'Closed Heap gate had a side effect'}
        ${function:Get-MiHeapReleaseStatus}=$openGate
        foreach ($original in @('Absent','Zero','Compatible','UnknownBits','WrongType','Filtered','ReadFailure','Cancelled','TargetChanged')) {
            New-M4Fixture
            if ($original -cin @('Zero','Compatible','UnknownBits','WrongType')) {
                $test.Registry.KeyExists=$true;$test.Registry.ValueExists=$true;$test.Registry.Kind='DWord'
                $test.Registry.Value=if ($original -ceq 'Compatible') {1} elseif ($original -ceq 'UnknownBits') {3} else {0}
            }
            if ($original -ceq 'WrongType') {$test.Registry.Kind='String';$test.Registry.Value=$null}
            if ($original -ceq 'Filtered') {$test.Registry.ScopeSupported=$false}
            $test.RegistryReadFault=$original -ceq 'ReadFailure';$test.Cancel=$original -ceq 'Cancelled';$test.TargetFault=$original -ceq 'TargetChanged'
            $id=[guid]::NewGuid().ToString('N')
            if ($original -cin @('UnknownBits','WrongType','Filtered','ReadFailure','TargetChanged')) {
                Assert-M3Rejected {Invoke-MiWprStart $id 'Heap' 'Memory' 300 'C:\fixture.exe'} $original
                if ($test.Enables -ne 0 -or $test.Starts -ne 0) {throw 'Rejected Heap request modified configuration'}
                continue
            }
            $session=Invoke-MiWprStart $id 'Heap' 'Memory' 300 'C:\fixture.exe'
            if ($original -ceq 'Cancelled') {if ($test.Enables -ne 0 -or $test.Starts -ne 0) {throw 'Cancel wrote configuration'};continue}
            $lock=Enter-MiTraceLock
            try {
                $j=Read-MiTraceJournal $lock
                Assert-M3Rejected {Assert-MiTraceQuiescent $j} 'Heap active obligation'
                $forged=$j.HeapTransactions[$session.HeapTransactionId]|ConvertTo-Json -Depth 10|ConvertFrom-Json
                $forged.OriginalConfig.Value=99
                Assert-M3Rejected {Add-MiTraceJournalRecord $lock $j.Revision 'HeapTransaction' $forged} 'immutable original value'
                $j=Stop-M4Fixture $lock $session
                if ($j.Sessions[$id].State -cne 'Completed' -or $j.Sessions[$id].CleanupState -cne 'Restored') {throw 'Heap normal completion failed'}
                $tx=$j.HeapTransactions[$session.HeapTransactionId]
                if (-not (Test-MiHeapConfigEqual $test.Registry $tx.OriginalConfig)) {throw 'Original Heap value not restored'}
                $writes=if ($original -ceq 'Compatible') {0} else {1}
                if ($test.Enables -ne $writes -or $test.Restores -ne $writes) {throw 'Compatible configuration was modified or owned change not restored'}
                Assert-MiTraceQuiescent $j
                Assert-M3Rejected {Add-MiTraceJournalRecord $lock $j.Revision 'HeapTransaction' $tx} 'terminal transaction replay'
            } finally {$lock.Dispose()}
        }
        foreach ($fault in @('HeapTransaction:Intent','HeapTransaction:Applied','WriteBefore','WriteAfter','LateTargetRead','LateConfigRead')) {
            New-M4Fixture
            if ($fault.StartsWith('HeapTransaction:')) {$test.Fault=$fault}
            elseif ($fault -ceq 'LateTargetRead') {$test.TargetFailAt=3}
            elseif ($fault -ceq 'LateConfigRead') {$test.RegistryFailAt=2}
            else {$test.RegistryWriteFault=if ($fault -ceq 'WriteBefore') {'Before'} else {'After'}}
            $id=[guid]::NewGuid().ToString('N')
            Assert-M3Rejected {Invoke-MiWprStart $id 'Heap' 'Memory' 300 'C:\fixture.exe'} $fault
            $lock=Enter-MiTraceLock
            try {
                $j=Read-MiTraceJournal $lock
                if ($test.Starts -ne 0 -or $test.Enables -gt 1) {throw 'Heap preparation retried/dispatched after failure'}
                Assert-M3Rejected {Assert-MiTraceQuiescent $j} 'interrupted Heap preparation blocks deployment'
                $j=Update-MiTraceSupervision $lock '100'
                if ($j.HeapTransactions.Count -gt 0 -and @($j.HeapTransactions.Values)[0].RestoreState -cne 'Restored') {throw 'Heap write-intent crash recovery failed'}
                Assert-MiTraceQuiescent $j
                $resolved=$j.Sessions[$id]
                if ($resolved.PreStartResolution.Outcome -cne 'NoTraceDispatched' -or $resolved.State -ceq 'Completed') {throw 'Pre-start failure was not honestly resolved'}
                if ($j.HeapTransactions.Count -eq 0 -and ($resolved.PreStartResolution.ConfigOutcome -cne 'NoWriteIntent' -or $test.Enables -ne 0)) {throw 'No-intent failure did not resolve without a configuration write'}
                Assert-M3Rejected {Add-MiTraceJournalRecord $lock $j.Revision 'Session' $resolved} 'resolved pre-start replay'
                Assert-M3Rejected {& $realTransport 'Start' $resolved} 'resolved pre-start dispatch'
                $forged=$resolved|ConvertTo-Json -Depth 12|ConvertFrom-Json
                $forged.PreStartResolution.ConfigOutcome=if ($j.HeapTransactions.Count -eq 0) {'Restored'} else {'NoWriteIntent'}
                Assert-M3Rejected {Assert-MiHeapSessionBinding $forged $j} 'forged pre-start configuration outcome'
                $before=$j.Revision;$j=Update-MiTraceSupervision $lock '100'
                if ($j.Revision -ne $before) {throw 'Resolved pre-start repeatedly journaled'}
                if ($test.Enables -gt 1 -or $test.Stops -ne 0) {throw 'Preparation recovery retried WPR or enable'}
            } finally {$lock.Dispose()}
        }
        foreach ($fault in @('ExternalBits','ExternalContext','RestoreBefore','RestoreAfter','RestoreRecord','ReadFailure','MissingEtl','BootChanged','UnknownStart')) {
            New-M4Fixture;$id=[guid]::NewGuid().ToString('N')
            $session=Invoke-MiWprStart $id 'Heap' 'Memory' 300 'C:\fixture.exe'
            $lock=Enter-MiTraceLock
            try {
                if ($fault -ceq 'UnknownStart') {
                    $j=Read-MiTraceJournal $lock;$current=$j.Sessions[$id];$current.State='UnknownOutcome';$j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $current
                    $j=Update-MiTraceSupervision $lock '100'
                    if ($test.Restores -ne 0 -or $test.Stops -ne 0) {throw 'Unknown active trace caused speculative cleanup'}
                    continue
                }
                if ($fault -ceq 'ExternalBits') {$test.Registry.Value=3}
                if ($fault -ceq 'ExternalContext') {$test.Registry.ContextFingerprint=('D'*64)}
                if ($fault -ceq 'RestoreBefore') {$test.RegistryWriteFault='Before'}
                if ($fault -ceq 'RestoreAfter') {$test.RegistryWriteFault='After'}
                if ($fault -ceq 'RestoreRecord') {$test.Fault='HeapTransaction:Restored'}
                if ($fault -ceq 'ReadFailure') {$test.RegistryReadFault=$true}
                if ($fault -ceq 'BootChanged') {
                    $test.Observed=@();$test.WriterLive=$false
                    function Get-MiBootSessionId {return '200'}
                    $j=Update-MiTraceSupervision $lock '200'
                    if ($j.HeapTransactions[$session.HeapTransactionId].RestoreState -cne 'Restored' -or $test.Stops -ne 0) {throw 'Boot recovery failed'}
                    function Get-MiBootSessionId {return '100'}
                    continue
                }
                $j=Stop-M4Fixture $lock $session -MissingOutput:($fault -ceq 'MissingEtl')
                $j=Update-MiTraceSupervision $lock '100';$current=$j.Sessions[$id];$tx=$j.HeapTransactions[$session.HeapTransactionId]
                if ($fault -cin @('ExternalBits','ExternalContext')) {
                    if ($tx.RestoreState -cne 'Conflict' -or $test.Restores -ne 0 -or $current.State -ceq 'Completed' -or $current.SaveState -cne 'Saved') {throw 'External Heap conflict overwritten or hidden'}
                    Assert-M3Rejected {Assert-MiTraceQuiescent $j} 'external conflict blocks deployment'
                    $j=Update-MiHeapCleanup $lock -RetryPending
                    if ($test.Restores -ne 0) {throw 'Explicit conflict recovery overwrote external values'}
                    $test.Registry=$tx.OriginalConfig|ConvertTo-Json -Compress|ConvertFrom-Json
                    $j=Update-MiHeapCleanup $lock -RetryPending
                    if ($j.HeapTransactions[$tx.TransactionId].RestoreState -cne 'Restored') {throw 'Administrator repair not reconciled'}
                } elseif ($fault -ceq 'MissingEtl') {
                    if ($current.SaveState -cne 'Failed' -or $current.StopState -cne 'Confirmed' -or $tx.RestoreState -cne 'Restored') {throw 'ETL failure erased independent Heap restoration'}
                } elseif ($fault -cin @('RestoreAfter','RestoreRecord')) {
                    if ($tx.RestoreState -cne 'Restored' -or $test.Restores -ne 1) {throw 'Restore acknowledgement crash repeated/lost mutation'}
                } else {
                    if ($tx.RestoreState -cne 'CleanupPending' -or $current.State -ceq 'Completed') {throw 'Restore failure not tracked'}
                    $test.RegistryReadFault=$false
                    $j=Update-MiHeapCleanup $lock -RetryPending
                    if ($j.HeapTransactions[$tx.TransactionId].RestoreState -cne 'Restored' -or $test.Restores -ne 1) {throw 'Explicit pending recovery failed'}
                }
                if ($test.Starts -ne 1 -or $test.Stops -ne 1) {throw 'Heap recovery replayed WPR'}
            } finally {$lock.Dispose()}
        }
        # 不依赖额外 Watchdog 的显式恢复闭环：先核验配置，再核验已保存 ETL。
        New-M4Fixture;$id=[guid]::NewGuid().ToString('N')
        $session=Invoke-MiWprStart $id 'Heap' 'Memory' 300 'C:\fixture.exe';$lock=Enter-MiTraceLock
        try {
            $test.RegistryWriteFault='Before';$j=Stop-M4Fixture $lock $session
            if ($j.Sessions[$id].State -cne 'CleanupPending') {throw 'Direct cleanup failure fixture invalid'}
            $j=Update-MiHeapCleanup $lock -RetryPending
            if ($j.Sessions[$id].State -cne 'RecoveryRequired') {throw 'Explicit config recovery cannot enter saved artifact recovery'}
        } finally {$lock.Dispose()}
        Repair-MiWprSavedArtifacts
        $lock=Enter-MiTraceLock
        try {
            $j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
            if ($j.Sessions[$id].State -cne 'Completed' -or $test.Restores -ne 1 -or $test.Stops -ne 1) {throw 'Explicit recovery closure failed'}
        } finally {$lock.Dispose()}
        foreach ($uncertain in @('StartMarker','StopMarker','WorkspaceReadFailure','EtwPresent')) {
            New-M4Fixture;$test.Fault='HeapTransaction:Applied';$id=[guid]::NewGuid().ToString('N')
            Assert-M3Rejected {Invoke-MiWprStart $id 'Heap' 'Memory' 300 'C:\fixture.exe'} 'interrupted enable for dispatch-proof test'
            $lock=Enter-MiTraceLock
            try {
                $j=Read-MiTraceJournal $lock;$session=$j.Sessions[$id];$paths=Get-MiWprSessionPaths $session
                if ($uncertain -cin @('StartMarker','StopMarker')) {
                    [void][IO.Directory]::CreateDirectory($paths.Workspace)
                    $marker=if ($uncertain -ceq 'StartMarker') {$paths.StartMarker} else {$paths.StopMarker}
                    [IO.File]::WriteAllText($marker,'DispatchIntent')
                }
                if ($uncertain -ceq 'WorkspaceReadFailure') {$test.PathFault=$true}
                if ($uncertain -ceq 'EtwPresent') {$test.Observed=@([pscustomobject]@{Name=('WPR_initiated_'+$session.WprInstanceName+'_unknown')})}
                if ($uncertain -ceq 'WorkspaceReadFailure') {
                    Assert-M3Rejected {Update-MiHeapCleanup $lock} 'unreadable journal/workspace'
                    $test.PathFault=$false;$j=Read-MiTraceJournal $lock
                } else {$j=Update-MiHeapCleanup $lock}
                if ($null -ne $j.Sessions[$id].PreStartResolution -or $test.Restores -ne 0) {throw 'Uncertain dispatch was cleared/restored'}
                Assert-M3Rejected {Assert-MiTraceQuiescent $j} 'uncertain dispatch remains blocked'
            } finally {$lock.Dispose()}
        }
        Write-Host 'PASS: M4 owned config transactions, compatible/unknown original values, intent/write/restore crashes, external conflicts, boot recovery and independent ETL/cleanup outcomes (registry/WPR mocked).'
    }
    & {
        function Get-MiExportReleaseStatus {return [pscustomobject]@{Enabled=$true;OfflineAccepted=$true;NormalizationAccepted=$true;OnlineAccepted=$false}}
        function Get-MiHeapReleaseStatus {return [pscustomobject]@{Enabled=$true;ConfigurationAccepted=$true;RecoveryAccepted=$true}}
        function Assert-MiTrustedInstallation {return $test.Paths}
        function Set-MiExportDirectoryAccess {param($Path,$OwnerSid)}
        New-M3Fixture;$session=Invoke-MiWprStart ([guid]::NewGuid().ToString('N'))
        $test.Paths|Add-Member NoteProperty Install (Join-Path $test.Paths.Data 'install')
        [void][IO.Directory]::CreateDirectory($test.Paths.Install)
        [IO.File]::WriteAllBytes((Join-Path $test.Paths.Install 'Analyzer.ps1'),[IO.File]::ReadAllBytes((Join-Path $root 'Analyzer.ps1')))
        $lock=Enter-MiTraceLock
        try {
            $j=Request-MiWprStop $lock $session;$test.Observed=@();$j=Update-MiWprSession $lock $j.Sessions[$session.TraceSessionId]
            [IO.File]::WriteAllText((Get-MiWprSessionPaths $session).Output,'Export descriptor source ETL')
            $test.WriterLive=$false;$j=Update-MiWprSession $lock $j.Sessions[$session.TraceSessionId]
            $artifact=$j.Artifacts[$session.PlannedArtifactId]
        } finally {$lock.Dispose()}
        Assert-M3Rejected {Initialize-MiArtifactExport ([guid]::NewGuid().ToString('N'))} 'unknown export artifact'
        $prepared=Initialize-MiArtifactExport $artifact.ArtifactId
        if ($prepared.State -cne 'Prepared' -or $test.Starts -ne 1 -or $test.Stops -ne 1) {throw 'Export preparation launched extra trace/process'}
        $folder=Split-Path -Parent (Get-MiTraceArtifactPath $artifact);$path=Join-Path $folder ($artifact.ArtifactId+'.export.json')
        $bytes=[IO.File]::ReadAllBytes($path);$metadata=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
        if ($metadata.Sha256 -cne $artifact.Sha256 -or $metadata.EventLossStatus -cne 'LossReported' -or
            -not [IO.Directory]::Exists((Join-Path $folder ($artifact.ArtifactId+'.export')))) {throw 'Export metadata lost source quality/identity'}
        [void](Initialize-MiArtifactExport $artifact.ArtifactId)
        [IO.File]::WriteAllText($path,'corrupt')
        Assert-M3Rejected {Initialize-MiArtifactExport $artifact.ArtifactId} 'corrupt descriptor not overwritten'
        [IO.File]::WriteAllBytes($path,$bytes)
        $lock=Enter-MiTraceLock
        try {
            $j=Read-MiTraceJournal $lock;$forged=$j.Artifacts[$artifact.ArtifactId]|ConvertTo-Json -Depth 12|ConvertFrom-Json
            $forged.ExportDescriptor.OwnerSid='S-1-5-21-1-2-3-999'
            Assert-M3Rejected {Add-MiTraceJournalRecord $lock $j.Revision 'Artifact' $forged} 'forged export descriptor owner'
        } finally {$lock.Dispose()}
        [IO.File]::WriteAllText((Join-Path $folder ($artifact.ArtifactId+'.export\result.txt')),'counted user output')
        if ((Measure-MiProtectedTree $test.Paths.TraceArtifacts) -lt ($artifact.SizeBytes+$bytes.Length+19)) {throw 'Export data omitted from diagnostic budget'}
        Write-Host 'PASS: M5 protected descriptor intent/source binding, idempotent preparation, corruption refusal and user-output budget (ACL/ETL boundary mocked).'
    }
}

# V3-M7：真实请求报告文件和请求者上下文；受保护 ACL/Journal 获取由夹具提供。
& {
    . (Join-Path $root 'PrivilegeSecurity.ps1')
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$sessionId=[int](Get-Process -Id $PID).SessionId
    function Assert-M7Denied {param([scriptblock]$Action,[string]$Label)
        $denied=$false;try {& $Action|Out-Null} catch {$denied=$true};if (-not $denied) {throw ('M7 accepted '+$Label)}
    }
    Assert-MiGuiRequesterContext 'TraceStatus' $owner $sessionId
    Assert-M7Denied {Assert-MiGuiRequesterContext 'TraceStatus' 'S-1-5-21-1-2-3-4' $sessionId} 'another UAC account'
    Assert-M7Denied {Assert-MiGuiRequesterContext 'TraceStatus' $owner ($sessionId+1)} 'another UAC session'
    Assert-M7Denied {Assert-MiGuiRequesterContext 'StopApprovedService' $owner $sessionId} 'service request as trace'
    $fixture=Join-Path $root ('test-artifacts\M7-Report-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
    $context=@{Untrusted=$false}
    function Get-MiSecurityPaths {return [pscustomobject]@{TraceArtifacts=$fixture}}
    function Enter-MiDeploymentLease {return [IO.File]::Open((Join-Path $fixture 'lease'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)}
    function Get-MiTraceRecoveryReport {
        if ($context.Untrusted) {return [pscustomobject]@{JournalStatus='UntrustedOrIncomplete';UpgradeBlocked=$true;Sessions=@();Guidance='Preserve evidence'}}
        return [pscustomobject]@{UpgradeBlocked=$true;DeploymentBlocked=$false;TaskBlocked=$true;Guidance='Do not clear pending recovery';
            Sessions=@([pscustomobject]@{OwnerSid=$owner;TraceSessionId=('1'*32);State='CleanupPending'},[pscustomobject]@{OwnerSid='S-1-5-21-1-2-3-4';TraceSessionId=('3'*32)});
            Artifacts=@([pscustomobject]@{OwnerSid=$owner;ArtifactId=('2'*32)});
            HeapTransactions=@([pscustomobject]@{TraceSessionId=('1'*32);RestoreState='CleanupPending'})}
    }
    function Measure-MiProtectedTree {return 0L}
    function Set-MiDiagnosticAccess {param($Path,$OwnerSid,[switch]$Directory)}
    function Assert-MiTracePath {param($Path) if (-not (Test-Path -LiteralPath $Path) -or -not $Path.StartsWith($fixture,[StringComparison]::OrdinalIgnoreCase)) {throw 'Fixture path trust refused'}}
    $id=[guid]::NewGuid().ToString('N');Write-MiTraceRequestReport $id 'TraceStatus' $owner
    $path=Join-Path (Join-Path (Join-Path $fixture $owner) 'requests') ($id+'.json')
    $report=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true))|ConvertFrom-Json
    if ($report.RequestId -cne $id -or $report.Sessions.Count -ne 1 -or $report.Sessions[0].OwnerSid -cne $owner -or
        $report.HeapTransactions[0].RestoreState -cne 'CleanupPending' -or -not $report.UpgradeBlocked -or -not $report.TaskBlocked) {throw 'Report ownership/independent obligation binding failed'}
    Assert-M7Denied {Write-MiTraceRequestReport $id 'TraceStatus' $owner} 'report overwrite'
    $context.Untrusted=$true;$id=[guid]::NewGuid().ToString('N');Write-MiTraceRequestReport $id 'TraceStatus' $owner
    $path=Join-Path (Split-Path -Parent $path) ($id+'.json');$report=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if ($report.JournalStatus -cne 'UntrustedOrIncomplete' -or -not $report.DeploymentBlocked -or -not $report.TaskBlocked -or -not $report.UpgradeBlocked) {throw 'Unknown recovery report became permissive'}
    Write-Host 'PASS: V3-M7 actual requester SID/session refusal, owner-scoped CreateNew reports, immutable request IDs and unknown-journal blocking (protected ACL/Journal mocked).'
}
