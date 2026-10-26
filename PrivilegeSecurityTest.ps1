#requires -Version 5.1
<# M6 regression: source parsing, secure pure contracts, and disposable ACL fixture.
No UAC prompt, service modification, process termination, or install performed. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('PrivilegeSecurity.ps1','PrivilegeBridge.ps1','ElevatedExecutor.ps1',
    'Installer.ps1','Uninstaller.ps1','MemoryInspector.ps1','GuiV4.ps1',
    'ServiceManagement.ps1','ServiceBridge.ps1')
foreach ($f in $files) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $f),[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { throw ('M6 parse failure '+$f+': '+($errors|Out-String)) }
}
. (Join-Path $root 'PrivilegeSecurity.ps1')
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
if ((Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim() -cne '0.0.9') {
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
        $manifest=[pscustomobject]@{SchemaVersion=1;Version=$Version;Files=@($Files)}
        [IO.File]::WriteAllText($versionPaths.Manifest,($manifest|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    }
    function Assert-VersionTrustRejected {
        param([string]$ExpectedMessage)
        $rejected=$false
        try{[void](Assert-MiTrustedInstallation)}catch{
            if(-not $_.Exception.Message.Contains($ExpectedMessage)){throw}
            $rejected=$true
        }
        if(-not $rejected){throw ('Version trust unexpectedly accepted: '+$ExpectedMessage)}
    }
    $allEntries=$versionEntries.ToArray()
    Write-VersionManifest '0.0.9' $allEntries
    [void](Assert-MiTrustedInstallation)
    foreach($oldVersion in @('0.0.7','0.0.8')){
        Write-VersionManifest $oldVersion $allEntries
        Assert-VersionTrustRejected 'Invalid installation manifest/version.'
        [void](Assert-MiTrustedInstallation -AllowedVersions @('0.0.7','0.0.8','0.0.9'))
    }
    foreach($unknownVersion in @('0.0.10','1.2.3','0.0.9.1','0.0.9 ')){
        Write-VersionManifest $unknownVersion $allEntries
        Assert-VersionTrustRejected 'Invalid installation manifest/version.'
    }
    foreach($essential in @('ElevatedExecutor.ps1','PrivilegeSecurity.ps1','ServiceManagement.ps1','ServiceBridge.ps1','VERSION')){
        Write-VersionManifest '0.0.9' @($allEntries|Where-Object Name -cne $essential)
        Assert-VersionTrustRejected ('Missing M7 component: '+$essential)
    }
    Write-VersionManifest '0.0.9' $allEntries
    $retainedLedger=Join-Path $versionPaths.PolicyFolder 'recovery.retained.json'
    [IO.File]::Move($versionPaths.Recovery,$retainedLedger)
    try{Assert-VersionTrustRejected 'Untrusted service recovery ledger.'}finally{[IO.File]::Move($retainedLedger,$versionPaths.Recovery)}
    [void](Assert-MiTrustedInstallation)
}
Write-Host 'PASS: 0.0.9 exact trust pin, explicit old-version upgrade, unknown-version rejection and unchanged M7 component/ledger requirements (ACL mocked only in fixture).'
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
    $scheduler=Get-MiTaskScheduler
    $definition=Get-MiWatchdogDefinition $scheduler
    $fake=[pscustomobject]@{Definition=$definition;Enabled=$true;State=3}
    $fake|Add-Member ScriptMethod GetSecurityDescriptor {param($flags) return 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
    Assert-MiWatchdogDefinition $fake
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
