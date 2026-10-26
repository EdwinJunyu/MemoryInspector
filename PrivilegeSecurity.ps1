#requires -Version 5.1
<#
Milestone 6: shared, conservative installation and privileged-protocol checks.
Only the elevated installer/executor may WRITE protected state.
No service or target-process mutations; Heap configuration writes require protected transactions.
#>
function Get-MiSecurityPaths {
    $pf = $env:ProgramW6432
    if ([string]::IsNullOrWhiteSpace($pf)) { $pf = $env:ProgramFiles }
    if ([string]::IsNullOrWhiteSpace($pf)) { throw 'Program Files path unavailable.' }
    $pd = [Environment]::GetFolderPath('CommonApplicationData')
    if ([string]::IsNullOrWhiteSpace($pd)) { throw 'ProgramData path unavailable.' }
    $install = Join-Path $pf 'MemoryInspector'
    $data = Join-Path $pd 'MemoryInspector'
    return [pscustomobject]@{
        Install=$install; Data=$data
        Manifest=(Join-Path $data 'install-manifest.json')
        Audit=(Join-Path $data 'audit\privileged.jsonl')
        Replay=(Join-Path $data 'replay')
        Results=(Join-Path $data 'results')
        PolicyFolder=(Join-Path $data 'policy')
        Policy=(Join-Path $data 'policy\approved-services.json')
        Recovery=(Join-Path $data 'policy\service-recovery.json')
        Executor=(Join-Path $install 'ElevatedExecutor.ps1')
        TraceRoot=(Join-Path $data 'trace')
        TraceJournal=(Join-Path $data 'trace\journal.jsonl')
        TraceLock=(Join-Path $data 'trace.lock')
        DeploymentLease=(Join-Path $data 'deployment.lock')
        TraceWorkspace=(Join-Path $data 'trace\workspace')
        WatchdogPolicy=(Join-Path $data 'trace\watchdog-policy.json')
        TraceArtifacts=(Join-Path $data 'diagnostics')
    }
}
function Test-MiAdminToken {
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=[Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function Test-MiGuidN {
    param([string]$Value)
    return -not [string]::IsNullOrWhiteSpace($Value) -and
        $Value -cmatch '^[0-9a-fA-F]{32}$' -and
        $Value -cne '00000000000000000000000000000000'
}
function Test-MiPrivilegedOperation {
    param([string]$Operation,[string]$RequestId,[string]$ServiceName='')
    # 定时任务只有一个固定入口；禁止借用它携带请求、服务名或自由命令。
    if ($Operation -ceq 'TraceWatchdog') { return $RequestId -ceq 'Scheduled' -and $ServiceName -ceq '' }
    if (-not (Test-MiGuidN $RequestId)) { return $false }
    if ($Operation -cin @('TracePreflight','TraceHealth','TraceRecovery','TraceStart','TraceStop','TraceArtifacts')) { return $ServiceName -ceq '' }
    if ($Operation -ceq 'Probe') { return [string]::IsNullOrWhiteSpace($ServiceName) }
    if ($Operation -cnotin @('ApproveService','RevokeServiceApproval','StopApprovedService','StartPreviouslyStoppedService')) {
        return $false
    }
    return (-not [string]::IsNullOrWhiteSpace($ServiceName) -and
        $ServiceName -cmatch '^[A-Za-z0-9_.-]{1,128}$')
}
function Test-MiNoReparse {
    param([string]$Path)
    try {
        $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return -not (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch { return $false }
}
function Test-MiAclRestricted {
    param([string]$Path,[bool]$RequireProtectedDacl=$false)
    try {
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        if ($RequireProtectedDacl -and -not $acl.AreAccessRulesProtected) { return $false }
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if (@('S-1-5-18','S-1-5-32-544') -cnotcontains $owner) { return $false }
        $danger=[int64]([Security.AccessControl.FileSystemRights]::Write -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
        foreach ($ace in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
            if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid=$ace.IdentityReference.Value
            if (@('S-1-5-18','S-1-5-32-544') -ccontains $sid) { continue }
            if (([int64]$ace.FileSystemRights -band $danger) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}
function Assert-MiTrustedInstallation {
    # 当前执行器只接受本发行版；旧版本仅由安装器显式指定，用于验证升级来源。
    param([string[]]$AllowedVersions=@('0.0.9'))
    $paths=Get-MiSecurityPaths
    foreach ($folder in @($paths.Install,$paths.Data,$paths.Replay,(Split-Path -Parent $paths.Audit),$paths.Results,$paths.PolicyFolder)) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container) -or
            -not (Test-MiNoReparse $folder) -or -not (Test-MiAclRestricted $folder $true)) {
            throw ('Untrusted installation directory or ACL: '+$folder)
        }
    }
    foreach ($protectedFile in @($paths.Audit,$paths.Policy)) {
        if (-not (Test-Path -LiteralPath $protectedFile -PathType Leaf) -or
            -not (Test-MiNoReparse $protectedFile) -or
            -not (Test-MiAclRestricted $protectedFile $true)) { throw ('Untrusted protected state: '+$protectedFile) }
    }
    if (-not (Test-Path -LiteralPath $paths.Manifest -PathType Leaf) -or
        -not (Test-MiNoReparse $paths.Manifest) -or
        -not (Test-MiAclRestricted $paths.Manifest $true)) { throw 'Missing or untrusted protected manifest.' }
    $manifest=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Manifest,[Text.Encoding]::UTF8)) -ErrorAction Stop
    if ($manifest.SchemaVersion -ne 1 -or $AllowedVersions -cnotcontains [string]$manifest.Version -or
        $null -eq $manifest.Files -or @($manifest.Files).Count -lt 8) { throw 'Invalid installation manifest/version.' }
    if ($manifest.Version -cin @('0.0.7','0.0.8','0.0.9')) {
        $names=@($manifest.Files | ForEach-Object { [string]$_.Name })
        foreach ($essential in @('ElevatedExecutor.ps1','PrivilegeSecurity.ps1','ServiceManagement.ps1','ServiceBridge.ps1','VERSION')) {
            if ($names -cnotcontains $essential) { throw ('Missing M7 component: '+$essential) }
        }
        if (-not (Test-Path -LiteralPath $paths.Recovery -PathType Leaf) -or
            -not (Test-MiNoReparse $paths.Recovery) -or
            -not (Test-MiAclRestricted $paths.Recovery $true)) { throw 'Untrusted service recovery ledger.' }
    }
    foreach ($entry in @($manifest.Files)) {
        $name=[string]$entry.Name
        if ($name -cnotmatch '^[A-Za-z0-9_-]+\.(ps1|cmd)$' -and $name -cne 'VERSION') {
            throw 'Manifest includes an unexpected path.'
        }
        $file=Join-Path $paths.Install $name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or -not (Test-MiNoReparse $file) -or
            -not (Test-MiAclRestricted $file $true)) { throw ('Untrusted installed file: '+$name) }
        $hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($hash -cne [string]$entry.Sha256) { throw ('Installed file hash mismatch: '+$name) }
    }
    if ($null -ne $manifest.TraceArchitectureVersion -and $manifest.TraceArchitectureVersion -ne 1) {
        throw 'Unsupported trace architecture version.'
    }
    return $paths
}
function Set-MiAdminDirectoryAcl {
    param([string]$Path,[bool]$AllowUsersRead=$false)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'Cannot secure missing directory.' }
    if (-not (Test-MiNoReparse $Path)) { throw 'Reparse directory refused.' }
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
        $sid=[Security.Principal.SecurityIdentifier]::new($sidText)
        $rule=[Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    if ($AllowUsersRead) {
        $users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $read=[Security.AccessControl.FileSystemAccessRule]::new(
            $users,[Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($read)
    }
    $dir=Get-Item -LiteralPath $Path -ErrorAction Stop
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $dir.SetAccessControl($acl)
    if (-not (Test-MiAclRestricted $Path $true)) { throw 'Directory ACL verification failed.' }
}
function Set-MiProtectedFileAcl {
    param([string]$Path,[bool]$AllowUsersRead=$false)
    if (-not (Test-MiNoReparse $Path)) { throw 'Untrusted protected file.' }
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($admin)
    foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
        $sid=[Security.Principal.SecurityIdentifier]::new($sidText)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    if ($AllowUsersRead) {
        $sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    (Get-Item -LiteralPath $Path -ErrorAction Stop).SetAccessControl($acl)
    if (-not (Test-MiAclRestricted $Path $true)) { throw 'Protected file ACL verification failed.' }
}
function Write-MiPrivilegedAudit {
    param([string]$RequestId,[string]$State,[string]$Reason,
        [string]$Action='Probe',[string]$ServiceName='')
    $paths=Get-MiSecurityPaths
    $obj=[ordered]@{
        SchemaVersion=1; Utc=[datetime]::UtcNow.ToString('o'); RequestId=$RequestId
        Action=$Action; ServiceName=$ServiceName; State=$State; Reason=$Reason
        ExecutorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }
    $line=($obj | ConvertTo-Json -Compress -Depth 4)+[Environment]::NewLine
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($line)
    $fs=[IO.File]::Open($paths.Audit,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $fs.Write($bytes,0,$bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

# V3-M2：所有路径由受保护安装计算，调用者不能指定 Journal、输出目录或任务动作。
function Assert-MiTracePath {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path) -or -not (Test-MiNoReparse $Path) -or
        -not (Test-MiAclRestricted $Path $true)) { throw 'Untrusted trace path or ACL.' }
    # 验证整条祖先链，不能只检查最终文件而遗漏被替换的父目录。
    $parent=Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    while (-not [string]::IsNullOrEmpty($parent)) {
        if (-not (Test-MiNoReparse $parent)) { throw 'Reparse trace ancestor refused.' }
        $next=Split-Path -Parent $parent
        if ($next -eq $parent) { break }; $parent=$next
    }
}
function Enter-MiTraceLock {
    if (-not (Test-MiAdminToken)) { throw 'Protected trace context required.' }
    $p=Get-MiSecurityPaths
    Assert-MiTracePath $p.Data
    if ([IO.File]::Exists($p.TraceLock)) { Assert-MiTracePath $p.TraceLock }
    # 文件不删除；跨进程持有独占句柄，崩溃后由 OS 释放。锁争用直接拒绝，不重复操作。
    $handle=[IO.File]::Open($p.TraceLock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { Set-MiProtectedFileAcl $p.TraceLock; Assert-MiTracePath $p.TraceLock; return $handle }
    catch { $handle.Dispose(); throw }
}
function Enter-MiDeploymentLease {
    param([switch]$Exclusive)
    if (-not (Test-MiAdminToken)) { throw 'Protected deployment context required.' }
    $p=Get-MiSecurityPaths; Assert-MiTracePath $p.Data
    if (-not [IO.File]::Exists($p.DeploymentLease)) {
        # 首次创建竞争由 CreateNew 拒绝，不能删除/替换另一进程的锁。
        $created=[IO.File]::Open($p.DeploymentLease,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { Set-MiProtectedFileAcl $p.DeploymentLease } finally { $created.Dispose() }
    }
    Assert-MiTracePath $p.DeploymentLease
    if ($Exclusive) { return [IO.File]::Open($p.DeploymentLease,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
    # 服务确认可能很久：共享部署租约阻止升级，但不占用 Watchdog 的全局状态锁。
    return [IO.File]::Open($p.DeploymentLease,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
function Assert-MiTraceLockHeld {
    param($Lock)
    $p=Get-MiSecurityPaths
    if ($Lock -isnot [IO.FileStream] -or -not $Lock.CanWrite -or
        -not [string]::Equals($Lock.Name,$p.TraceLock,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Exclusive trace lock required.'
    }
}
function Get-MiTraceHash {
    param([string]$Text)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Text)))).Replace('-','') }
    finally { $sha.Dispose() }
}
function Get-MiBootSessionId {
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $os.LastBootUpTime) { throw 'Boot identity unavailable.' }
    return ([datetime]$os.LastBootUpTime).ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
function ConvertTo-MiTraceUtc {
    param($Value)
    $parsed=[datetimeoffset]::MinValue
    if ($Value -isnot [string] -or $Value -cnotmatch 'Z$' -or
        -not [datetimeoffset]::TryParseExact($Value,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,[ref]$parsed)) { throw 'Invalid trace UTC timestamp.' }
    return $parsed.UtcDateTime
}
function Assert-MiTraceSession {
    param($Session)
    $required=@('SchemaVersion','TraceSessionId','WprInstanceName','OwnerSid','BootSessionId','RequestedTraceType',
        'ProfileId','ProfileFingerprint','WprExecutableIdentity','RecordingMode','RequestedDuration','StartedUtc',
        'DeadlineUtc','TraceWorkingBudget','State','CleanupState','OutputArtifactId','LastVerifiedUtc','ErrorCode',
        'JournalRevision','StopState','SaveState','AnalysisState','ActiveReferences','AuthorizationId')
    foreach ($name in $required) { if ($Session.PSObject.Properties.Name -cnotcontains $name) { throw ('Missing TraceSession field: '+$name) } }
    if ($Session.SchemaVersion -ne 1 -or -not (Test-MiGuidN $Session.TraceSessionId) -or
        $Session.WprInstanceName -cne ('MemoryInspector-'+$Session.TraceSessionId) -or
        $Session.OwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or
        $Session.BootSessionId -cnotmatch '^\d{1,19}$' -or
        $Session.RequestedTraceType -cnotin @('VirtualAlloc','Pool','Heap') -or
        $Session.RecordingMode -cnotin @('Memory','File') -or
        $Session.RequestedDuration -lt 300 -or $Session.RequestedDuration -gt 1800 -or
        $Session.TraceWorkingBudget -lt 0 -or $Session.ActiveReferences -lt 0 -or
        $Session.JournalRevision -lt 1) { throw 'Invalid TraceSession identity or limits.' }
    $states=@('Requested','Preflight','Authorized','Preparing','Recording','Stopping','Saving','Saved','Cleaning',
        'Analyzing','Completed','ConflictBlocked','AuthorizationDenied','ResourcePreflightRejected','UnknownOutcome',
        'DeadlineExceeded','TraceNotSaved','CleanupPending','AnalysisPartial','RecoveryRequired')
    if ($Session.State -cnotin $states -or $Session.CleanupState -cnotin @('NotRequired','Pending','Restored','Conflict') -or
        $Session.StopState -cnotin @('NotStarted','Pending','Confirmed','Unknown') -or
        $Session.SaveState -cnotin @('NotStarted','Pending','Saved','Failed','Unknown') -or
        $Session.AnalysisState -cnotin @('NotStarted','Pending','Complete','Partial','Unavailable')) { throw 'Unknown trace result state.' }
    [void](ConvertTo-MiTraceUtc $Session.LastVerifiedUtc)
    if ($null -ne $Session.StartedUtc) {
        $start=ConvertTo-MiTraceUtc $Session.StartedUtc; $deadline=ConvertTo-MiTraceUtc $Session.DeadlineUtc
        if (($deadline-$start).TotalSeconds -ne $Session.RequestedDuration) { throw 'Invalid trace deadline.' }
    } elseif ($null -ne $Session.DeadlineUtc) { throw 'Deadline without start.' }
    if ($Session.State -cin @('Authorized','Preparing','Recording','Stopping','Saving','Saved','Cleaning','Analyzing','Completed')) {
        if (-not (Test-MiGuidN $Session.AuthorizationId) -or $Session.ProfileFingerprint -cnotmatch '^[A-F0-9]{64}$' -or
            [string]::IsNullOrWhiteSpace($Session.ProfileId) -or $null -eq $Session.WprExecutableIdentity) { throw 'Trace authorization or profile identity missing.' }
    }
    if ($Session.State -cin @('Recording','Stopping','Saving','Saved','Cleaning','Analyzing','Completed') -and $null -eq $Session.StartedUtc) { throw 'Recorded trace has no start.' }
    if ($Session.SaveState -ceq 'Saved' -and -not (Test-MiGuidN $Session.OutputArtifactId)) { throw 'Saved trace lacks artifact identity.' }
    if ($Session.State -ceq 'Completed' -and ($Session.StopState -cne 'Confirmed' -or $Session.SaveState -cne 'Saved' -or
        $Session.CleanupState -cnotin @('NotRequired','Restored') -or $Session.AnalysisState -cnotin @('Complete','Unavailable') -or
        $Session.ActiveReferences -ne 0)) { throw 'Unfinished trace cannot be Completed.' }
    if ($null -ne $Session.PreStartResolution) {
        $resolution=$Session.PreStartResolution
        if ($Session.State -cne 'RecoveryRequired' -or $Session.RequestedTraceType -cne 'Heap' -or
            -not (Test-MiGuidN $Session.AuthorizationId) -or -not (Test-MiGuidN $Session.HeapTransactionId) -or
            $Session.CleanupState -cne 'Restored' -or $null -ne $Session.StartedUtc -or $null -ne $Session.StartProcess -or
            $null -ne $Session.OwnershipEvidence -or $null -ne $Session.StopOperationId -or $null -ne $Session.StopProcess -or $null -ne $Session.OutputArtifactId -or
            $Session.StopState -cne 'NotStarted' -or $Session.SaveState -cne 'NotStarted' -or $Session.ActiveReferences -ne 0 -or
            $resolution.SchemaVersion -ne 1 -or $resolution.Outcome -cne 'NoTraceDispatched' -or
            $resolution.ConfigOutcome -cnotin @('Restored','NoWriteIntent') -or $resolution.BootSessionId -cnotmatch '^\d{1,19}$') {throw 'Invalid pre-start recovery resolution.'}
        [void](ConvertTo-MiTraceUtc $resolution.VerifiedUtc)
    }
}
function Test-MiTraceObligation {
    param($Session)
    Assert-MiTraceSession $Session
    if ($Session.CleanupState -cnotin @('NotRequired','Restored') -or $Session.ActiveReferences -ne 0) { return $true }
    if ($null -ne $Session.PreStartResolution) {return $false}
    if ($Session.State -ceq 'Completed') { return $false }
    # 只有尚未授权、未发生外部副作用的拒绝请求才无需恢复；Saved 从来不是完成。
    return -not ($Session.State -cin @('ConflictBlocked','AuthorizationDenied','ResourcePreflightRejected') -and
        $null -eq $Session.StartedUtc -and $null -eq $Session.AuthorizationId -and
        $Session.StopState -ceq 'NotStarted' -and $Session.SaveState -ceq 'NotStarted')
}
function Assert-MiTraceTransition {
    param($Previous,$Next)
    Assert-MiTraceSession $Next
    if ($null -eq $Previous) {
        if ($Next.State -cne 'Requested') { throw 'Trace must begin at Requested.' }; return
    }
    if ($null -ne $Previous.PreStartResolution) {throw 'Resolved pre-start session cannot be reopened or replayed.'}
    foreach ($field in @('TraceSessionId','WprInstanceName','OwnerSid','BootSessionId','RequestedTraceType','RecordingMode','RequestedDuration')) {
        if ($Previous.$field -cne $Next.$field) { throw 'Immutable trace identity changed.' }
    }
    foreach ($field in @('StartedUtc','DeadlineUtc','AuthorizationId','ProfileId','ProfileFingerprint','WprExecutableIdentity')) {
        if ($null -ne $Previous.$field -and ($Previous.$field|ConvertTo-Json -Compress -Depth 6) -cne ($Next.$field|ConvertTo-Json -Compress -Depth 6)) { throw 'Bound trace authorization changed.' }
    }
    $edges=@{
        Requested=@('Preflight','AuthorizationDenied','RecoveryRequired'); Preflight=@('Authorized','ConflictBlocked','AuthorizationDenied','ResourcePreflightRejected','RecoveryRequired')
        Authorized=@('Preparing','RecoveryRequired'); Preparing=@('Recording','UnknownOutcome','RecoveryRequired')
        Recording=@('Recording','Stopping','DeadlineExceeded','UnknownOutcome','RecoveryRequired'); DeadlineExceeded=@('Stopping','RecoveryRequired')
        Stopping=@('Stopping','Saving','UnknownOutcome','TraceNotSaved','RecoveryRequired'); Saving=@('Saving','Saved','TraceNotSaved','UnknownOutcome','RecoveryRequired')
        Saved=@('Saved','Cleaning','RecoveryRequired'); Cleaning=@('Cleaning','Analyzing','CleanupPending','RecoveryRequired')
        Analyzing=@('Analyzing','Completed','AnalysisPartial','RecoveryRequired'); AnalysisPartial=@('Analyzing','RecoveryRequired')
        CleanupPending=@('CleanupPending','RecoveryRequired'); UnknownOutcome=@('UnknownOutcome','RecoveryRequired'); TraceNotSaved=@('TraceNotSaved','RecoveryRequired')
        RecoveryRequired=@('RecoveryRequired','Saving')
    }
    if (-not $edges.ContainsKey([string]$Previous.State) -or $Next.State -cnotin $edges[[string]$Previous.State]) { throw 'Illegal trace transition or replay.' }
    if ($Previous.State -ceq 'RecoveryRequired' -and $Next.State -ceq 'Saving' -and
        ($Previous.StopState -cne 'Confirmed' -or -not (Test-MiGuidN $Previous.PlannedArtifactId))) {throw 'Recovery cannot invent stop or artifact ownership.'}
    if ($Previous.CleanupState -cin @('Pending','Conflict') -and $Next.CleanupState -ceq 'NotRequired') { throw 'Cleanup obligation cannot disappear.' }
    foreach ($field in @('StartOperationId','StopOperationId','StartProcess','StopProcess','OwnershipEvidence','WorkspaceId','PlannedArtifactId','StartIntentUtc','StopRequestedUtc','ExternalSessions','HeapTransactionId','PreStartResolution')) {
        if ($null -ne $Previous.$field -and ($Previous.$field|ConvertTo-Json -Compress -Depth 12) -cne ($Next.$field|ConvertTo-Json -Compress -Depth 12)) {throw 'Bound WPR operation identity changed.'}
    }
}
function Read-MiTraceJournal {
    param($Lock)
    Assert-MiTraceLockHeld $Lock
    $p=Get-MiSecurityPaths
    Assert-MiTracePath $p.TraceRoot; Assert-MiTracePath $p.TraceJournal; Assert-MiTracePath $p.TraceWorkspace
    $text=[IO.File]::ReadAllText($p.TraceJournal,[Text.UTF8Encoding]::new($false,$true))
    if ([string]::IsNullOrWhiteSpace($text) -or -not $text.EndsWith("`n")) { throw 'Empty or torn trace journal; recovery required.' }
    $result=[pscustomobject]@{Revision=0;Hash=('0'*64);Sessions=@{};Artifacts=@{};HeapTransactions=@{};Challenge=$null;Response=$null;Deployment=$null;DeploymentRecord=$null;InstallationId=$null}
    foreach ($line in $text.Split([char]10)) {
        if ($line.Length -eq 0) { continue }
        $entry=$line|ConvertFrom-Json -ErrorAction Stop
        # 写入器使用规范 JSON；重复键、额外格式及非规范转义都拒绝，避免解析器覆盖字段。
        if (($entry|ConvertTo-Json -Compress -Depth 3) -cne $line.TrimEnd([char]13)) { throw 'Noncanonical trace journal record.' }
        if ($entry.SchemaVersion -ne 1 -or $entry.Revision -ne ($result.Revision+1) -or
            $entry.PreviousHash -cne $result.Hash -or $entry.Payload -isnot [string] -or
            $entry.Hash -cne (Get-MiTraceHash ($entry.Revision.ToString()+'|'+$entry.PreviousHash+'|'+$entry.Kind+'|'+$entry.Payload))) { throw 'Invalid trace journal chain.' }
        $payload=$entry.Payload|ConvertFrom-Json -ErrorAction Stop
        if (($payload|ConvertTo-Json -Compress -Depth 12) -cne $entry.Payload) { throw 'Noncanonical trace payload.' }
        if ($payload.SchemaVersion -ne 1) { throw 'Unknown trace payload schema.' }
        if ($entry.Kind -cin @('Deployment','HealthChallenge','HealthResponse')) { Assert-MiTraceControlRecord $entry.Kind $payload $result }
        switch -CaseSensitive ($entry.Kind) {
            'Initialize' {
                if ($result.Revision -ne 0 -or $payload.SchemaVersion -ne 1 -or -not (Test-MiGuidN $payload.InstallationId)) { throw 'Invalid trace genesis.' }
                $result.InstallationId=$payload.InstallationId; $result.Deployment='Pending'
            }
            'Session' {
                if ($result.Revision -eq 0 -or $payload.JournalRevision -ne $entry.Revision) { throw 'Invalid trace session revision.' }
                $old=$result.Sessions[$payload.TraceSessionId]
                Assert-MiTraceTransition $old $payload
                Assert-MiHeapSessionBinding $payload $result
                $result.Sessions[$payload.TraceSessionId]=$payload
            }
            'Artifact' {
                Assert-MiTraceArtifactTransition $result.Artifacts[$payload.ArtifactId] $payload $result
                $result.Artifacts[$payload.ArtifactId]=$payload
            }
            'HeapTransaction' {
                if ($payload.JournalRevision -ne $entry.Revision) {throw 'Invalid Heap transaction revision.'}
                Assert-MiHeapTransactionTransition $result.HeapTransactions[$payload.TransactionId] $payload $result
                $result.HeapTransactions[$payload.TransactionId]=$payload
            }
            'Deployment' {
                if ($result.Revision -eq 0 -or $payload.State -cnotin @('Pending','Ready','RecoveryRequired','Retired')) { throw 'Invalid deployment state.' }
                $result.Deployment=$payload.State
                $result.DeploymentRecord=$payload
            }
            'HealthChallenge' {
                if ($result.Revision -eq 0 -or $payload.SchemaVersion -ne 1 -or -not (Test-MiGuidN $payload.Nonce) -or
                    $payload.InstallationId -cne $result.InstallationId -or $payload.BootSessionId -cnotmatch '^\d{1,19}$') { throw 'Invalid health challenge.' }
                [void](ConvertTo-MiTraceUtc $payload.RequestedUtc); [void](ConvertTo-MiTraceUtc $payload.ExpiresUtc)
                $result.Challenge=$payload; $result.Response=$null
            }
            'HealthResponse' {
                if ($null -eq $result.Challenge -or $payload.SchemaVersion -ne 1 -or $payload.Nonce -cne $result.Challenge.Nonce -or
                    $payload.BootSessionId -cne $result.Challenge.BootSessionId -or $payload.ExecutorSid -cne 'S-1-5-18') { throw 'Invalid health response.' }
                [void](ConvertTo-MiTraceUtc $payload.Utc); $result.Response=$payload
            }
            default { throw 'Unknown trace journal record.' }
        }
        $result.Revision=[long]$entry.Revision; $result.Hash=$entry.Hash
    }
    if ($null -eq $result.InstallationId) { throw 'Missing trace genesis.' }
    # 不允许两个活跃实例；未恢复的旧实例也不能被下一次请求挤掉。
    if (@($result.Sessions.Values|Where-Object { Test-MiTraceObligation $_ }).Count -gt 1) { throw 'Concurrent trace obligations detected.' }
    return $result
}
function Add-MiTraceJournalRecord {
    param($Lock,[long]$ExpectedRevision,[string]$Kind,$Payload)
    Assert-MiTraceLockHeld $Lock
    $p=Get-MiSecurityPaths; $current=Read-MiTraceJournal $Lock
    if ($current.Revision -ne $ExpectedRevision) { throw 'Stale trace journal revision.' }
    if ($Kind -ceq 'Session') {
        $Payload.JournalRevision=$ExpectedRevision+1
        Assert-MiTraceTransition $current.Sessions[$Payload.TraceSessionId] $Payload
        Assert-MiHeapSessionBinding $Payload $current
        if (-not $current.Sessions.ContainsKey($Payload.TraceSessionId) -and
            @($current.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -ne 0) { throw 'Existing trace requires recovery.' }
    } elseif ($Kind -ceq 'Artifact') {Assert-MiTraceArtifactTransition $current.Artifacts[$Payload.ArtifactId] $Payload $current}
    elseif ($Kind -ceq 'HeapTransaction') {
        $Payload.JournalRevision=$ExpectedRevision+1
        Assert-MiHeapTransactionTransition $current.HeapTransactions[$Payload.TransactionId] $Payload $current
    }
    elseif ($Kind -cin @('Deployment','HealthChallenge','HealthResponse')) { Assert-MiTraceControlRecord $Kind $Payload $current }
    else { throw 'Unsupported journal operation.' }
    $json=$Payload|ConvertTo-Json -Compress -Depth 12
    $record=[ordered]@{SchemaVersion=1;Revision=($ExpectedRevision+1);PreviousHash=$current.Hash;Kind=$Kind;Payload=$json}
    $record.Hash=Get-MiTraceHash ($record.Revision.ToString()+'|'+$record.PreviousHash+'|'+$Kind+'|'+$json)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress -Depth 3)+"`n")
    $stream=[IO.File]::Open($p.TraceJournal,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    return Read-MiTraceJournal $Lock
}
function Assert-MiTraceControlRecord {
    param([string]$Kind,$Payload,$Journal)
    if ($Payload.SchemaVersion -ne 1 -or $Journal.Revision -lt 1) { throw 'Invalid trace control record.' }
    if ($Kind -ceq 'Deployment') {
        if ($Payload.State -cnotin @('Pending','Ready','RecoveryRequired','Retired')) { throw 'Invalid deployment state.' }
        if ($Payload.State -cin @('Ready','Retired')) { Assert-MiTraceQuiescent $Journal }
        if ($Payload.State -ceq 'Ready' -and $null -eq $Journal.Response) { throw 'Deployment readiness requires a health response.' }
    } elseif ($Kind -ceq 'HealthChallenge') {
        if (-not (Test-MiGuidN $Payload.Nonce) -or $Payload.InstallationId -cne $Journal.InstallationId -or
            $Payload.DefinitionHash -cnotmatch '^[A-F0-9]{64}$' -or $Payload.BootSessionId -cnotmatch '^\d{1,19}$') { throw 'Invalid health identity.' }
        $duration=((ConvertTo-MiTraceUtc $Payload.ExpiresUtc)-(ConvertTo-MiTraceUtc $Payload.RequestedUtc)).TotalSeconds
        if ($duration -le 0 -or $duration -gt 41) { throw 'Invalid health challenge lifetime.' }
    } elseif ($Kind -ceq 'HealthResponse') {
        $challenge=$Journal.Challenge
        if ($null -eq $challenge -or $null -ne $Journal.Response -or $Payload.Nonce -cne $challenge.Nonce -or
            $Payload.InstallationId -cne $Journal.InstallationId -or $Payload.DefinitionHash -cne $challenge.DefinitionHash -or
            $Payload.BootSessionId -cne $challenge.BootSessionId -or $Payload.ExecutorSid -cne 'S-1-5-18' -or
            $Payload.ScannedHash -cne $Journal.Hash) { throw 'Unbound or replayed health response.' }
        $utc=ConvertTo-MiTraceUtc $Payload.Utc
        if ($utc -lt (ConvertTo-MiTraceUtc $challenge.RequestedUtc) -or $utc -gt (ConvertTo-MiTraceUtc $challenge.ExpiresUtc)) { throw 'Expired health response.' }
    } else { throw 'Unknown trace control kind.' }
}
function Initialize-MiTraceJournal {
    param($Lock)
    Assert-MiTraceLockHeld $Lock
    $p=Get-MiSecurityPaths
    # 仅安装器在已核验的旧版迁移/全新安装中调用；绝不在运行时重建丢失日志。
    foreach ($dir in @($p.TraceRoot,$p.TraceWorkspace)) {
        if ([IO.Directory]::Exists($dir)) { Assert-MiTracePath $dir }
        else { [void][IO.Directory]::CreateDirectory($dir); Set-MiAdminDirectoryAcl $dir }
    }
    $json=[ordered]@{SchemaVersion=1;InstallationId=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress
    $record=[ordered]@{SchemaVersion=1;Revision=1;PreviousHash=('0'*64);Kind='Initialize';Payload=$json}
    $record.Hash=Get-MiTraceHash ('1|'+$record.PreviousHash+'|Initialize|'+$json)
    $stream=[IO.File]::Open($p.TraceJournal,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress)+"`n"); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Set-MiProtectedFileAcl $p.TraceJournal
    return Read-MiTraceJournal $Lock
}
function Assert-MiTraceQuiescent {
    param($Journal)
    if (@($Journal.HeapTransactions.Values|Where-Object {$_.RestoreState -cnotin @('Restored','Unchanged')}).Count -gt 0) {throw 'Unfinished Heap configuration transaction blocks deployment.'}
    if (@($Journal.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -gt 0) { throw 'Unfinished trace or cleanup blocks deployment; use TraceRecovery.' }
    if ($null -ne $Journal.Artifacts -and @($Journal.Artifacts.Values|Where-Object {$_.State -cin @('Saving','Retiring') -or $_.ActiveReferences -gt 0}).Count -gt 0) {throw 'Artifact transaction or reference blocks deployment.'}
}
function Get-MiWatchdogDefinition {
    param($Scheduler)
    $p=Get-MiSecurityPaths
    $definition=$Scheduler.NewTask(0)
    $definition.RegistrationInfo.Description='MemoryInspector V3-M2 protected trace supervision'
    $definition.Principal.UserId='S-1-5-18'; $definition.Principal.LogonType=5; $definition.Principal.RunLevel=1
    $definition.Settings.Enabled=$true; $definition.Settings.AllowDemandStart=$true
    $definition.Settings.StartWhenAvailable=$true; $definition.Settings.MultipleInstances=2
    $definition.Settings.DisallowStartIfOnBatteries=$false; $definition.Settings.StopIfGoingOnBatteries=$false
    $definition.Settings.ExecutionTimeLimit='PT45S'
    [void]$definition.Triggers.Create(8) # TASK_TRIGGER_BOOT
    $timer=$definition.Triggers.Create(1) # TASK_TRIGGER_TIME，永久每分钟重复。
    $timer.StartBoundary='2020-01-01T00:00:00Z'; $timer.Repetition.Interval='PT1M'
    $action=$definition.Actions.Create(0)
    $action.Path=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action.Arguments='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$p.Executor+'" -Operation TraceWatchdog -RequestId Scheduled'
    $action.WorkingDirectory=$p.Install
    return $definition
}
function Get-MiTaskScheduler {
    $scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect(); return $scheduler
}
function Assert-MiWatchdogDefinition {
    param($Task)
    $p=Get-MiSecurityPaths; $d=$Task.Definition
    $exe=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$p.Executor+'" -Operation TraceWatchdog -RequestId Scheduled'
    $sid=if ([string]$d.Principal.UserId -cmatch '^S-1-') { ([Security.Principal.SecurityIdentifier]::new([string]$d.Principal.UserId)).Value }
        else { ([Security.Principal.NTAccount]::new([string]$d.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value }
    # 部分系统直接返回 SID；不把本地化显示名称当成固定账户身份。
    if ($sid -cne 'S-1-5-18' -or $d.Principal.LogonType -ne 5 -or $d.Principal.RunLevel -ne 1 -or
        $d.Actions.Count -ne 1 -or $d.Actions.Item(1).Type -ne 0 -or
        -not [string]::Equals($d.Actions.Item(1).Path,$exe,[StringComparison]::OrdinalIgnoreCase) -or
        $d.Actions.Item(1).Arguments -cne $args -or $d.Actions.Item(1).WorkingDirectory -cne $p.Install -or
        $d.Triggers.Count -ne 2 -or $d.Triggers.Item(1).Type -ne 8 -or $d.Triggers.Item(2).Type -ne 1 -or
        -not $d.Triggers.Item(1).Enabled -or -not $d.Triggers.Item(2).Enabled -or
        $d.Triggers.Item(2).Repetition.Interval -cne 'PT1M' -or
        -not [string]::IsNullOrEmpty($d.Triggers.Item(2).Repetition.Duration) -or
        -not $Task.Enabled -or $Task.State -notin @(3,4) -or
        $d.Settings.MultipleInstances -ne 2 -or $d.Settings.ExecutionTimeLimit -cne 'PT45S' -or
        -not $d.Settings.AllowDemandStart -or -not $d.Settings.StartWhenAvailable -or
        $d.Settings.DisallowStartIfOnBatteries -or $d.Settings.StopIfGoingOnBatteries) { throw 'Watchdog task definition changed or not runnable.' }
    $sd=[Security.AccessControl.RawSecurityDescriptor]::new($Task.GetSecurityDescriptor(7))
    if ($sd.Owner.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $null -eq $sd.DiscretionaryAcl -or
        ($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) { throw 'Untrusted Watchdog task ACL.' }
    $allowed=@{}
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.SecurityIdentifier.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $ace.IsCallback -or
            $ace.AccessMask -ne 2032127) { throw 'Unexpected Watchdog task access.' }
        $allowed[$ace.SecurityIdentifier.Value]=$true
    }
    if ($allowed.Count -ne 2) { throw 'Watchdog administrator/SYSTEM access missing.' }
    if (-not (Test-MiNoReparse $exe) -or -not [IO.File]::Exists($exe)) { throw 'Fixed Windows PowerShell missing.' }
}
function Assert-MiWatchdog {
    $p=Assert-MiTrustedInstallation
    $manifest=[IO.File]::ReadAllText($p.Manifest)|ConvertFrom-Json
    if ($manifest.TraceArchitectureVersion -ne 1) { throw 'M2 installation required.' }
    Assert-MiTracePath $p.WatchdogPolicy
    $policy=[IO.File]::ReadAllText($p.WatchdogPolicy)|ConvertFrom-Json
    if ($policy.SchemaVersion -ne 1 -or -not (Test-MiGuidN $policy.InstallationId)) { throw 'Invalid watchdog policy.' }
    $task=(Get-MiTaskScheduler).GetFolder('\').GetTask('MemoryInspector.TraceWatchdog')
    Assert-MiWatchdogDefinition $task
    if ((Get-MiTraceHash $task.Xml) -cne $policy.DefinitionHash) { throw 'Watchdog definition fingerprint mismatch.' }
    return [pscustomobject]@{Task=$task;Policy=$policy}
}
function Register-MiWatchdog {
    param($Lock,$Journal,[bool]$Replace=$false)
    Assert-MiTraceLockHeld $Lock; Assert-MiTraceQuiescent $Journal
    $p=Get-MiSecurityPaths; $scheduler=Get-MiTaskScheduler; $folder=$scheduler.GetFolder('\')
    # 仅 CREATE 或已核验的 UPDATE；不得覆盖恰好同名的未知任务。
    $flags=if ($Replace) {4} else {2}
    $task=$folder.RegisterTaskDefinition('MemoryInspector.TraceWatchdog',(Get-MiWatchdogDefinition $scheduler),
        $flags,'S-1-5-18',$null,5,'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Assert-MiWatchdogDefinition $task
    $policy=[ordered]@{SchemaVersion=1;InstallationId=$Journal.InstallationId;DefinitionHash=(Get-MiTraceHash $task.Xml)}
    if ([IO.File]::Exists($p.WatchdogPolicy)) {
        Assert-MiTracePath $p.WatchdogPolicy
        [IO.File]::Move($p.WatchdogPolicy,($p.WatchdogPolicy+'.retained-'+[guid]::NewGuid().ToString('N')))
    }
    [IO.File]::WriteAllText($p.WatchdogPolicy,($policy|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    Set-MiProtectedFileAcl $p.WatchdogPolicy
}
function Invoke-MiTraceWatchdog {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'Watchdog requires LocalSystem.' }
    $watchdog=Assert-MiWatchdog; $boot=Get-MiBootSessionId; $lock=Enter-MiTraceLock
    try {
        $j=Read-MiTraceJournal $lock
        if ($j.InstallationId -cne $watchdog.Policy.InstallationId -or $j.Deployment -ceq 'Retired') { throw 'Watchdog installation identity mismatch or retired.' }
        $j=Update-MiTraceSupervision $lock $boot
        $challenge=$j.Challenge; $now=[datetime]::UtcNow
        if ($null -ne $challenge -and $null -eq $j.Response -and $challenge.BootSessionId -ceq $boot -and
            $challenge.DefinitionHash -ceq $watchdog.Policy.DefinitionHash -and
            $now -ge (ConvertTo-MiTraceUtc $challenge.RequestedUtc) -and $now -le (ConvertTo-MiTraceUtc $challenge.ExpiresUtc)) {
            # 扫描完成后才回应，绑定扫描到的链头，不把任务“存在”当成健康证据。
            $response=[ordered]@{SchemaVersion=1;Nonce=$challenge.Nonce;BootSessionId=$boot;ExecutorSid='S-1-5-18';
                Utc=$now.ToString('o');DefinitionHash=$watchdog.Policy.DefinitionHash;InstallationId=$j.InstallationId;ScannedHash=$j.Hash}
            [void](Add-MiTraceJournalRecord $lock $j.Revision 'HealthResponse' $response)
        }
    } finally { $lock.Dispose() }
}
function Update-MiTraceSupervision {
    param($Lock,[string]$BootSessionId)
    $j=Read-MiTraceJournal $Lock
    foreach ($session in @($j.Sessions.Values)) {
        if (-not (Test-MiTraceObligation $session) -or $session.State -ceq 'RecoveryRequired') { continue }
        if ((Get-MiWprReleaseStatus).Enabled -and $null -ne $session.StartOperationId -and $session.BootSessionId -ceq $BootSessionId -and
            $session.State -cin @('Recording','DeadlineExceeded','Stopping','Saving','Saved','Cleaning','Analyzing')) {
            $j=Update-MiWprSession $Lock $session;continue
        }
        $now=[datetime]::UtcNow
        if ($session.State -cin @('Requested','Preflight') -and $null -eq $session.AuthorizationId -and
            $null -eq $session.StartedUtc -and $session.CleanupState -ceq 'NotRequired') {
            # 写前意图证明尚未授权、更未派发外部副作用，可以安全结束中断的预检查。
            $session.State='AuthorizationDenied'; $session.ErrorCode='PreflightInterrupted'
        } else {
            if ($session.State -ceq 'Recording' -and $session.BootSessionId -ceq $BootSessionId -and
                $now -ge (ConvertTo-MiTraceUtc $session.DeadlineUtc)) {
                $session.State='DeadlineExceeded'
                $session|Add-Member NoteProperty DeadlineObservedUtc $now.ToString('o') -Force
                $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $session
            }
            # M2 不具备实际 WPR 归属适配器；名称匹配仍不足以停止，不产生 StopConfirmed。
            $session.State='RecoveryRequired'
            $session.ErrorCode=if ($session.BootSessionId -cne $BootSessionId) {'BootChanged'} else {'WprOwnershipVerifierUnavailable'}
        }
        $session.LastVerifiedUtc=$now.ToString('o')
        $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $session
    }
    if ((Get-MiHeapReleaseStatus).Enabled) {$j=Update-MiHeapCleanup $Lock}
    if ((Get-MiWprReleaseStatus).Enabled -and @($j.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -eq 0) {$j=Invoke-MiTraceRetention $Lock}
    return $j
}
function Invoke-MiTraceHealthCheck {
    $watchdog=Assert-MiWatchdog; $boot=Get-MiBootSessionId; $nonce=[guid]::NewGuid().ToString('N')
    $lock=Enter-MiTraceLock
    try {
        $j=Read-MiTraceJournal $lock
        if ($j.InstallationId -cne $watchdog.Policy.InstallationId -or $j.Deployment -cnotin @('Pending','Ready','RecoveryRequired')) { throw 'Trace deployment not ready for health check.' }
        Assert-MiTraceQuiescent $j
        $challenge=[ordered]@{SchemaVersion=1;Nonce=$nonce;BootSessionId=$boot;InstallationId=$j.InstallationId;
            DefinitionHash=$watchdog.Policy.DefinitionHash;RequestedUtc=[datetime]::UtcNow.ToString('o');ExpiresUtc=[datetime]::UtcNow.AddSeconds(40).ToString('o')}
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'HealthChallenge' $challenge
    } finally { $lock.Dispose() }
    [void]$watchdog.Task.Run($null)
    # 不持锁等待另一个进程；使用单调计时，系统时钟变化不能延长等待。
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 40) {
        Start-Sleep -Milliseconds 250
        $lock=$null
        try { $lock=Enter-MiTraceLock } catch [IO.IOException] { continue }
        try {
            $current=Read-MiTraceJournal $lock
            if ($current.Challenge.Nonce -cne $nonce) { throw 'Health challenge superseded.' }
            if ($null -ne $current.Response) {
                $r=$current.Response; $verified=Assert-MiWatchdog
                if ($r.DefinitionHash -cne $verified.Policy.DefinitionHash -or $r.InstallationId -cne $j.InstallationId -or
                    $r.BootSessionId -cne (Get-MiBootSessionId) -or $r.ScannedHash -cne $j.Hash -or
                    (ConvertTo-MiTraceUtc $r.Utc) -lt (ConvertTo-MiTraceUtc $challenge.RequestedUtc) -or
                    [datetime]::UtcNow -gt (ConvertTo-MiTraceUtc $challenge.ExpiresUtc)) { throw 'Stale or mismatched Watchdog health response.' }
                Assert-MiTraceQuiescent $current
                return $current
            }
        } finally { $lock.Dispose() }
    }
    throw 'Watchdog health response timed out; advanced tracing disabled.'
}
function Invoke-MiTracePreflight {
    param([string]$RequestId)
    # 此阶段只有固定 VirtualAlloc / Memory / 5 分钟预检查，不接受命令、Profile 或输出路径。
    # OwnerSid 是实际确认本次提权请求的账户；M3 开放 GUI 发起前还必须绑定原发起者。
    [void](Invoke-MiTraceHealthCheck)
    $lock=Enter-MiTraceLock
    try {
        $j=Read-MiTraceJournal $lock
        if ($j.Deployment -cne 'Ready') { throw 'Trace architecture deployment incomplete.' }
        Assert-MiTraceQuiescent $j
        $session=[pscustomobject][ordered]@{
            SchemaVersion=1;TraceSessionId=$RequestId;WprInstanceName=('MemoryInspector-'+$RequestId)
            OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;BootSessionId=(Get-MiBootSessionId)
            RequestedTraceType='VirtualAlloc';ProfileId=$null;ProfileFingerprint=$null;WprExecutableIdentity=$null
            RecordingMode='Memory';RequestedDuration=300;StartedUtc=$null;DeadlineUtc=$null;TraceWorkingBudget=0
            State='Requested';CleanupState='NotRequired';OutputArtifactId=$null;LastVerifiedUtc=[datetime]::UtcNow.ToString('o')
            ErrorCode=$null;JournalRevision=1;StopState='NotStarted';SaveState='NotStarted';AnalysisState='NotStarted'
            ActiveReferences=0;AuthorizationId=$null
        }
        $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
        $session.State='Preflight'; $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
        $session.State='ResourcePreflightRejected'; $session.ErrorCode='TraceBackendUnavailable'
        [void](Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session)
        Write-MiPrivilegedAudit -RequestId $RequestId -Action 'TracePreflight' -State 'REJECTED' -Reason 'M2 architecture only; M3 WPR backend not enabled.'
        return $session
    } finally { $lock.Dispose() }
}
function Get-MiTraceRecoveryReport {
    $p=Assert-MiTrustedInstallation; $lock=Enter-MiTraceLock
    try {
        try { $j=Read-MiTraceJournal $lock }
        catch {
            return [pscustomobject]@{SchemaVersion=1;Utc=[datetime]::UtcNow.ToString('o');UpgradeBlocked=$true;
                JournalStatus='UntrustedOrIncomplete';Error=$_.Exception.Message;Sessions=@();
                Guidance='Preserve journal and installation backups. Do not truncate or recreate state. Restore verified evidence with administrator assistance before any deployment or trace action.'}
        }
        $taskStatus=try { [void](Assert-MiWatchdog); 'DefinitionVerified' } catch { $_.Exception.Message }
        $serviceLedger=[IO.File]::ReadAllText($p.Recovery)|ConvertFrom-Json
        $serviceBlocked=$serviceLedger.SchemaVersion -ne 1 -or $null -eq $serviceLedger.Records -or
            @($serviceLedger.Records|Where-Object {$_.Status -cnotin @('StopFailed','RestoreConfirmed')}).Count -gt 0
        return [pscustomobject]@{SchemaVersion=1;Utc=[datetime]::UtcNow.ToString('o');InstallationId=$j.InstallationId;
            Deployment=$j.Deployment;JournalRevision=$j.Revision;Watchdog=$taskStatus;Sessions=@($j.Sessions.Values);
            UpgradeBlocked=($serviceBlocked -or $j.Deployment -cne 'Ready' -or $taskStatus -cne 'DefinitionVerified' -or
                @($j.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -gt 0 -or
                @($j.HeapTransactions.Values|Where-Object {$_.RestoreState -cnotin @('Restored','Unchanged')}).Count -gt 0 -or
                @($j.Artifacts.Values|Where-Object {$_.State -cin @('Saving','Retiring') -or $_.ActiveReferences -gt 0}).Count -gt 0);
            DeploymentBlocked=($j.Deployment -cne 'Ready');TaskBlocked=($taskStatus -cne 'DefinitionVerified');
            ServiceRecoveryBlocked=$serviceBlocked;
            WprState='ReleaseAcceptancePending';WprRelease=(Get-MiWprReleaseStatus);Artifacts=@($j.Artifacts.Values);
            HeapRelease=(Get-MiHeapReleaseStatus);HeapTransactions=@($j.HeapTransactions.Values);
            Guidance='Preserve protected journal and artifacts. Unknown WPR outcomes are never retried. Saved artifact recovery requires confirmed stop, no active writer and verified byte identity. Release gates remain closed until Windows acceptance.'}
    } finally { $lock.Dispose() }
}
function Invoke-MiTraceDeploymentRecovery {
    # 只允许重新验证已有的完整安装；不重新注册未知任务，也不清除 TraceSession。
    $lease=Enter-MiDeploymentLease -Exclusive
    try {
        $health=Invoke-MiTraceHealthCheck; $lock=Enter-MiTraceLock
        try {
            $j=Read-MiTraceJournal $lock; Assert-MiTraceQuiescent $j
            if ($j.Revision -ne $health.Revision -or $j.Hash -cne $health.Hash -or $j.Deployment -ceq 'Retired') { throw 'Recovery evidence changed.' }
            [void](Assert-MiWatchdog)
            [void](Add-MiTraceJournalRecord $lock $j.Revision 'Deployment' ([ordered]@{SchemaVersion=1;State='Ready';Reason='Existing installation and fresh SYSTEM scan verified'}))
        } finally { $lock.Dispose() }
    } finally { $lease.Dispose() }
}
function Move-MiDeploymentEntry {
    param([string]$Source,[string]$Destination)
    # 安装器只传入它计算并核验的固定产品目录；独立封装便于实际文件移动故障注入。
    if (-not (Test-MiNoReparse $Source)) { throw 'Reparse deployment entry refused.' }
    if ([IO.Directory]::Exists($Source)) { [IO.Directory]::Move($Source,$Destination) }
    else { [IO.File]::Move($Source,$Destination) }
}
function Restore-MiInstallationSwap {
    param($Paths,$Swap)
    # 按成功完成的步骤回滚，路径变量已赋值不代表对应 Move 已经成功。
    if ($Swap.NewManifestInstalled) { Move-MiDeploymentEntry $Paths.Manifest ($Paths.Manifest+'.failed-'+[guid]::NewGuid().ToString('N')) }
    if ($Swap.OldManifestMoved) { Move-MiDeploymentEntry $Swap.OldManifest $Paths.Manifest }
    if ($Swap.StageInstalled) { Move-MiDeploymentEntry $Paths.Install ($Paths.Install+'.failed-'+[guid]::NewGuid().ToString('N')) }
    if ($Swap.OldInstallMoved) { Move-MiDeploymentEntry $Swap.Backup $Paths.Install }
}

# V3-M3 发布门：不是 GUI 设置，也不读取可编辑的“已验收”JSON。
# 只有隔离 Win10/11 的 M2、所有权、保存/资源故障验收完成后，后续受审阅发行版才可开放。
function Get-MiWprReleaseStatus {
    return [pscustomobject]@{SchemaVersion=1;Enabled=$false;M2Accepted=$false;MemoryAccepted=$false;FileAccepted=$false;
        Reason='M2ProtectedDeploymentAndM3WindowsAcceptancePending'}
}
function Get-MiHeapReleaseStatus {
    # M4 独立验收，不允许通过用户设置/Journal/参数解锁；M2/M3 也必须先通过。
    return [pscustomobject]@{SchemaVersion=1;Enabled=$false;ConfigurationAccepted=$false;RecoveryAccepted=$false;
        Reason='M2M3AndM4WindowsHeapAcceptancePending'}
}
function Assert-MiHeapReleaseAccepted {
    Assert-MiWprReleaseAccepted
    $gate=Get-MiHeapReleaseStatus
    if (-not $gate.Enabled -or -not $gate.ConfigurationAccepted -or -not $gate.RecoveryAccepted) {throw ('Heap diagnosis disabled: '+$gate.Reason)}
}
function Assert-MiWprReleaseAccepted {
    $gate=Get-MiWprReleaseStatus
    if (-not $gate.Enabled -or -not $gate.M2Accepted -or -not $gate.MemoryAccepted) {throw ('Advanced tracing disabled: '+$gate.Reason)}
}
# V3-M4：只管理固定 IFEO/TracingFlags 的完整 DWORD，不能接受注册表路径或默认清理命令。
function Assert-MiHeapImageName {
    param([string]$ImageName)
    if ($ImageName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.exe$' -or $ImageName.Contains('..')) {throw 'Unsupported Heap image name.'}
}
function Get-MiHeapTargetIdentity {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '["\r\n]' -or $Path.Substring(2).Contains(':')) {throw 'Heap requires an absolute local executable path.'}
    $full=[IO.Path]::GetFullPath($Path);$name=[IO.Path]::GetFileName($full)
    Assert-MiHeapImageName $name
    $ancestor=$full
    while (-not [string]::IsNullOrEmpty($ancestor)) {
        if (-not (Test-MiNoReparse $ancestor)) {throw 'Heap target or ancestor is missing/reparse.'}
        $ancestor=[IO.Path]::GetDirectoryName($ancestor)
    }
    # 同一只读句柄同时验证 PE 与摘要；读取期间不允许文件被改写/替换。
    $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 256 -or $stream.Length -gt 1073741824) {throw 'Unsupported Heap executable size.'}
        $reader=[IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {throw 'Heap target is not a PE image.'}
        $stream.Position=60;$offset=$reader.ReadInt32()
        if ($offset -lt 64 -or $offset+256 -gt $stream.Length) {throw 'Invalid PE header.'}
        $stream.Position=$offset
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {throw 'Heap MVP supports native x64 desktop images only.'}
        $stream.Position=$offset+24
        if ($reader.ReadUInt16() -ne 0x20B) {throw 'Unsupported PE optional header.'}
        $stream.Position=$offset+24+224
        if ($reader.ReadUInt32() -ne 0) {throw 'Managed Heap compatibility is not accepted.'}
        $stream.Position=0;$sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')} finally {$sha.Dispose()}
        return [pscustomobject][ordered]@{Path=$full;ImageName=$name;Sha256=$hash;Machine='NativeX64'}
    } finally {$stream.Dispose()}
}
function Assert-MiHeapRegistryAcl {
    param($Key,[switch]$Ancestor)
    $acl=$Key.GetAccessControl();$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($owner -cnotin $trusted) {throw 'Untrusted IFEO registry owner.'}
    $danger=[long]([Security.AccessControl.RegistryRights]::Delete -bor [Security.AccessControl.RegistryRights]::ChangePermissions -bor [Security.AccessControl.RegistryRights]::TakeOwnership) -bor 268435456 -bor 1073741824
    if (-not $Ancestor) {$danger=$danger -bor [long][Security.AccessControl.RegistryRights]::SetValue -bor [long][Security.AccessControl.RegistryRights]::CreateSubKey}
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        # CREATOR OWNER 是所有者占位符，不是 Everyone；实际所有者已经单独核验。
        $sid=if ($ace.IdentityReference.Value -ceq 'S-1-3-0') {$owner} else {$ace.IdentityReference.Value}
        if (($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            $ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $sid -cnotin $trusted -and ([long]$ace.RegistryRights -band $danger) -ne 0) {throw 'IFEO registry is writable by an untrusted principal.'}
    }
}
function Open-MiHeapRegistryRoot {
    param([switch]$Writable)
    # 不使用 PSDrive、32 位重定向或调用者提供的键。每层都检查普通用户无法改写。
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $path=''
        foreach ($part in @('SOFTWARE','Microsoft','Windows NT','CurrentVersion','Image File Execution Options')) {
            $path=if ($path -eq '') {$part} else {$path+'\'+$part}
            $key=$base.OpenSubKey($path)
            if ($null -eq $key) {throw 'Fixed IFEO parent is unavailable.'}
            try {Assert-MiHeapRegistryAcl $key -Ancestor:($part -cne 'Image File Execution Options')} finally {$key.Dispose()}
        }
        return $base.OpenSubKey($path,[bool]$Writable)
    } finally {$base.Dispose()}
}
function Read-MiHeapRegistryKey {
    param($Key)
    $others=@();$children=@();$exists=$false;$kind='';$value=$null
    if ($null -ne $Key) {
        Assert-MiHeapRegistryAcl $Key
        foreach ($name in @($Key.GetValueNames()|Sort-Object)) {
            if ($name -ieq 'TracingFlags') {
                $exists=$true;$kind=$Key.GetValueKind($name).ToString()
                if ($kind -ceq 'DWord') {$value=([long]$Key.GetValue($name) -band 4294967295)}
            } else {
                $others+=,[ordered]@{Name=$name;Kind=$Key.GetValueKind($name).ToString();Value=$Key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
            }
        }
        $children=@($Key.GetSubKeyNames()|Sort-Object)
    }
    $context=Get-MiTraceHash (([ordered]@{Values=@($others);Children=@($children)})|ConvertTo-Json -Compress -Depth 8)
    $supported=$children.Count -eq 0 -and @($others|Where-Object Name -ieq 'UseFilter').Count -eq 0
    return [pscustomobject][ordered]@{KeyExists=($null -ne $Key);ValueExists=$exists;Kind=$kind;Value=$value;ContextFingerprint=$context;ScopeSupported=$supported}
}
function Get-MiHeapConfiguration {
    param([string]$ImageName)
    Assert-MiHeapImageName $ImageName
    $parent=Open-MiHeapRegistryRoot
    try {
        $key=$parent.OpenSubKey($ImageName)
        try {return Read-MiHeapRegistryKey $key} finally {if ($null -ne $key) {$key.Dispose()}}
    } finally {$parent.Dispose()}
}
function Test-MiHeapConfigEqual {
    param($Left,$Right)
    # 不删除新建的空 IFEO 键；只比较本工具拥有的值和旁侧配置，键存在本身不是配置位。
    return $null -ne $Left -and $null -ne $Right -and $Left.ValueExists -eq $Right.ValueExists -and
        $Left.Kind -ceq $Right.Kind -and $Left.Value -ceq $Right.Value -and $Left.ContextFingerprint -ceq $Right.ContextFingerprint -and $Left.ScopeSupported -eq $Right.ScopeSupported
}
function Get-MiHeapConfigDisposition {
    param($Config)
    if (-not $Config.ScopeSupported) {throw 'Filtered/packaged IFEO configuration compatibility unknown.'}
    if (-not $Config.ValueExists -or ($Config.Kind -ceq 'DWord' -and $Config.Value -eq 0)) {return 'Modify'}
    if ($Config.Kind -ceq 'DWord' -and $Config.Value -eq 1) {return 'Compatible'}
    throw 'Existing Heap configuration compatibility unknown; no modification allowed.'
}
function Assert-MiHeapSessionBinding {
    param($Session,$Journal)
    if ($Session.RequestedTraceType -cne 'Heap' -or $null -eq $Session.AuthorizationId) {return}
    if (-not (Test-MiGuidN $Session.HeapTransactionId) -or $Session.CleanupState -ceq 'NotRequired') {throw 'Authorized Heap session lacks a cleanup obligation.'}
    $tx=$Journal.HeapTransactions[$Session.HeapTransactionId]
    if ($null -ne $tx -and $tx.TraceSessionId -cne $Session.TraceSessionId) {throw 'Heap transaction belongs to another trace.'}
    $noIntent=$null -ne $Session.PreStartResolution -and $Session.PreStartResolution.ConfigOutcome -ceq 'NoWriteIntent' -and $null -eq $tx -and
        @($Journal.HeapTransactions.Values|Where-Object TraceSessionId -ceq $Session.TraceSessionId).Count -eq 0
    if ($null -ne $Session.PreStartResolution -and $Session.PreStartResolution.ConfigOutcome -ceq 'NoWriteIntent' -and -not $noIntent) {throw 'NoWriteIntent conflicts with recorded Heap intent.'}
    if ($Session.CleanupState -ceq 'Restored' -and -not $noIntent -and ($null -eq $tx -or $tx.RestoreState -cne 'Restored')) {throw 'Heap cleanup has no verified transaction outcome.'}
    if ($null -ne $Session.PreStartResolution -and -not $noIntent -and ($null -eq $tx -or $tx.RestoreState -cne 'Restored')) {throw 'Unproven pre-start Heap outcome.'}
}
function Assert-MiHeapTransactionTransition {
    param($Previous,$Next,$Journal)
    $fields=@('SchemaVersion','TransactionId','TraceSessionId','TargetImageIdentity','OriginalConfig','ExpectedModifiedConfig','ConfigOwner',
        'ChangeUtc','CurrentConfig','RestoreState','ConflictDetected','ErrorCode','JournalRevision')
    if (@($Next.PSObject.Properties).Count -ne $fields.Count) {throw 'Unexpected Heap transaction structure.'}
    foreach ($field in $fields) {if ($Next.PSObject.Properties.Name -cnotcontains $field) {throw 'Missing Heap transaction field.'}}
    $session=$Journal.Sessions[$Next.TraceSessionId]
    if ($Next.SchemaVersion -ne 1 -or -not (Test-MiGuidN $Next.TransactionId) -or $null -eq $session -or
        $session.RequestedTraceType -cne 'Heap' -or $session.HeapTransactionId -cne $Next.TransactionId -or
        $null -eq $session.AuthorizationId -or $Next.ConfigOwner -cnotin @('MemoryInspector','External') -or
        $Next.ConflictDetected -isnot [bool]) {throw 'Unbound Heap transaction.'}
    Assert-MiHeapImageName $Next.TargetImageIdentity.ImageName
    if ($Next.TargetImageIdentity.Path -notmatch '^[A-Za-z]:\\' -or
        [IO.Path]::GetFileName($Next.TargetImageIdentity.Path) -cne $Next.TargetImageIdentity.ImageName -or
        $Next.TargetImageIdentity.Sha256 -cnotmatch '^[A-F0-9]{64}$' -or $Next.TargetImageIdentity.Machine -cne 'NativeX64') {throw 'Invalid Heap target identity.'}
    [void](ConvertTo-MiTraceUtc $Next.ChangeUtc)
    if ($null -eq $Next.OriginalConfig -or $null -eq $Next.ExpectedModifiedConfig) {throw 'Missing Heap change snapshots.'}
    foreach ($config in @($Next.OriginalConfig,$Next.ExpectedModifiedConfig,$Next.CurrentConfig)) {
        if ($null -eq $config) {continue}
        if (@($config.PSObject.Properties).Count -ne 6 -or $config.KeyExists -isnot [bool] -or $config.ValueExists -isnot [bool] -or $config.ScopeSupported -isnot [bool] -or
            $config.ContextFingerprint -cnotmatch '^[A-F0-9]{64}$' -or
            (-not $config.ValueExists -and ($config.Kind -cne '' -or $null -ne $config.Value)) -or
            ($config.ValueExists -and (-not $config.KeyExists -or $config.Kind -cnotin @('DWord','String','ExpandString','Binary','MultiString','QWord','None','Unknown'))) -or
            ($config.Kind -ceq 'DWord' -and (($config.Value -isnot [int] -and $config.Value -isnot [long]) -or $config.Value -lt 0 -or $config.Value -gt 4294967295))) {throw 'Invalid Heap configuration snapshot.'}
    }
    $disposition=Get-MiHeapConfigDisposition $Next.OriginalConfig
    if ($Next.ExpectedModifiedConfig.ValueExists -ne $true -or $Next.ExpectedModifiedConfig.Kind -cne 'DWord' -or
        $Next.ExpectedModifiedConfig.Value -ne 1 -or $Next.OriginalConfig.ContextFingerprint -cne $Next.ExpectedModifiedConfig.ContextFingerprint -or
        ($Next.ConfigOwner -ceq 'External') -ne ($disposition -ceq 'Compatible')) {throw 'Heap change exceeds the owned configuration scope.'}
    if ($Next.RestoreState -cnotin @('Intent','Applied','Unchanged','Restoring','Restored','CleanupPending','Conflict') -or
        ($Next.ConflictDetected -ne ($Next.RestoreState -ceq 'Conflict'))) {throw 'Invalid Heap restore state.'}
    if ($Next.RestoreState -ceq 'Restored' -and -not (Test-MiHeapConfigEqual $Next.CurrentConfig $Next.OriginalConfig)) {throw 'Heap restoration is not verified.'}
    if ($Next.RestoreState -cin @('Applied','Unchanged') -and -not (Test-MiHeapConfigEqual $Next.CurrentConfig $Next.ExpectedModifiedConfig)) {throw 'Heap configuration result is not verified.'}
    if ($null -eq $Previous) {
        if ($session.State -cne 'Preparing' -or $Next.RestoreState -cne $(if ($disposition -ceq 'Compatible') {'Unchanged'} else {'Intent'})) {throw 'Heap transaction must begin before modification.'}
        if (@($Journal.HeapTransactions.Values|Where-Object TraceSessionId -ceq $Next.TraceSessionId).Count -gt 0) {throw 'Duplicate Heap transaction.'}
        return
    }
    foreach ($field in @('TransactionId','TraceSessionId','TargetImageIdentity','OriginalConfig','ExpectedModifiedConfig','ConfigOwner','ChangeUtc')) {
        if (($Previous.$field|ConvertTo-Json -Compress -Depth 8) -cne ($Next.$field|ConvertTo-Json -Compress -Depth 8)) {throw 'Immutable Heap change intent altered.'}
    }
    $edges=@{Intent=@('Applied','Restoring','Restored','CleanupPending','Conflict');Applied=@('Restoring','Restored','CleanupPending','Conflict');
        Restoring=@('Restored','CleanupPending','Conflict');CleanupPending=@('Restoring','Restored','CleanupPending','Conflict');
        Unchanged=@('Restored','CleanupPending','Conflict');Conflict=@('Restored')}
    if (-not $edges.ContainsKey([string]$Previous.RestoreState) -or $Next.RestoreState -cnotin $edges[[string]$Previous.RestoreState]) {throw 'Illegal Heap transaction transition; conflict needs administrator repair.'}
}
function Set-MiHeapConfiguration {
    param($Lock,$Transaction,[switch]$Restore)
    Assert-MiHeapReleaseAccepted
    $j=Read-MiTraceJournal $Lock;$bound=$j.HeapTransactions[$Transaction.TransactionId]
    if ($null -eq $bound -or ($bound|ConvertTo-Json -Compress -Depth 10) -cne ($Transaction|ConvertTo-Json -Compress -Depth 10) -or
        $bound.ConfigOwner -cne 'MemoryInspector' -or $bound.RestoreState -cne $(if ($Restore) {'Restoring'} else {'Intent'})) {throw 'Registry write lacks a current protected intent.'}
    $expected=if ($Restore) {$bound.ExpectedModifiedConfig} else {$bound.OriginalConfig}
    $desired=if ($Restore) {$bound.OriginalConfig} else {$bound.ExpectedModifiedConfig}
    $parent=Open-MiHeapRegistryRoot -Writable
    try {
        $key=$parent.OpenSubKey($bound.TargetImageIdentity.ImageName,$true)
        try {
            if (-not (Test-MiHeapConfigEqual (Read-MiHeapRegistryKey $key) $expected)) {throw 'Heap compare-before-write conflict.'}
            if ($null -eq $key) {$key=$parent.CreateSubKey($bound.TargetImageIdentity.ImageName)}
            # 创建后再读；发现其他修改便拒绝。外部管理员不受本工具互斥约束，写后仍需核验。
            if (-not (Test-MiHeapConfigEqual (Read-MiHeapRegistryKey $key) $expected)) {throw 'Heap configuration changed before write.'}
            if ($desired.ValueExists) {$key.SetValue('TracingFlags',[int]$desired.Value,[Microsoft.Win32.RegistryValueKind]::DWord)}
            else {$key.DeleteValue('TracingFlags',$false)}
            $key.Flush()
            return Read-MiHeapRegistryKey $key
        } finally {if ($null -ne $key) {$key.Dispose()}}
    } finally {$parent.Dispose()}
}
function Initialize-MiHeapTransaction {
    param($Lock,$Session,$Target)
    Assert-MiHeapReleaseAccepted
    $j=Read-MiTraceJournal $Lock
    $fresh=Get-MiHeapTargetIdentity $Target.Path
    if (($fresh|ConvertTo-Json -Compress) -cne ($Target|ConvertTo-Json -Compress)) {throw 'Heap executable identity changed.'}
    $original=Get-MiHeapConfiguration $Target.ImageName;$disposition=Get-MiHeapConfigDisposition $original
    $expected=[pscustomobject][ordered]@{KeyExists=$true;ValueExists=$true;Kind='DWord';Value=1;ContextFingerprint=$original.ContextFingerprint;ScopeSupported=$true}
    $tx=[pscustomobject][ordered]@{SchemaVersion=1;TransactionId=$Session.HeapTransactionId;TraceSessionId=$Session.TraceSessionId;TargetImageIdentity=$Target;
        OriginalConfig=$original;ExpectedModifiedConfig=$expected;ConfigOwner=if ($disposition -ceq 'Compatible') {'External'} else {'MemoryInspector'};
        ChangeUtc=[datetime]::UtcNow.ToString('o');CurrentConfig=$original;RestoreState=if ($disposition -ceq 'Compatible') {'Unchanged'} else {'Intent'};
        ConflictDetected=$false;ErrorCode=$null;JournalRevision=1}
    $j=Add-MiTraceJournalRecord $Lock $j.Revision 'HeapTransaction' $tx
    if ($tx.ConfigOwner -ceq 'External') {return $j}
    # 只有 Flush 成功的 Intent 才有写入资格；失败/崩溃不会重复执行 Enable。
    $tx.CurrentConfig=Set-MiHeapConfiguration $Lock $j.HeapTransactions[$tx.TransactionId]
    if (-not (Test-MiHeapConfigEqual $tx.CurrentConfig $expected)) {throw 'Heap enable verification failed.'}
    $tx.RestoreState='Applied'
    return Add-MiTraceJournalRecord $Lock $j.Revision 'HeapTransaction' $tx
}
function Test-MiWprNotDispatched {
    param($Session,$Journal)
    if ($null -ne $Session.StartProcess -or $null -ne $Session.StartedUtc -or $null -ne $Session.DeadlineUtc -or
        $null -ne $Session.OwnershipEvidence -or $null -ne $Session.StopOperationId -or $null -ne $Session.StopProcess -or
        $null -ne $Session.OutputArtifactId -or $Session.StopState -cne 'NotStarted' -or $Session.SaveState -cne 'NotStarted' -or
        @($Journal.Artifacts.Values|Where-Object TraceSessionId -ceq $Session.TraceSessionId).Count -gt 0) {return $false}
    $paths=Get-MiWprSessionPaths $Session;$parent=(Get-MiSecurityPaths).TraceWorkspace
    Assert-MiTracePath $parent
    # File.Exists 会把访问错误吞成 false；枚举必须成功，才能把“没有持久化派发标记”作为证据。
    $entries=@([IO.Directory]::GetFileSystemEntries($parent))
    if ($entries -icontains $paths.Workspace) {
        Assert-MiTracePath $paths.Workspace
        $entries=@([IO.Directory]::GetFileSystemEntries($paths.Workspace))
        if ($entries -icontains $paths.StartMarker -or $entries -icontains $paths.StopMarker) {return $false}
    }
    $observed=@(Get-MiEtwSessions)
    return @($observed|Where-Object {$_.Name.StartsWith(('WPR_initiated_'+$Session.WprInstanceName+'_'),[StringComparison]::Ordinal)}).Count -eq 0
}
function Restore-MiHeapTransaction {
    param($Lock,[string]$TransactionId,[switch]$RetryPending)
    Assert-MiHeapReleaseAccepted
    $j=Read-MiTraceJournal $Lock;$tx=$j.HeapTransactions[$TransactionId]
    if ($null -eq $tx) {throw 'Unknown Heap transaction; no speculative cleanup.'}
    if ($tx.RestoreState -ceq 'Restored' -or ($tx.RestoreState -ceq 'Conflict' -and -not $RetryPending)) {return $j}
    $session=$j.Sessions[$tx.TraceSessionId]
    try {
        # 即使是配置恢复，也不能在未知追踪/仍在运行的启动或保存进程旁猜测性写注册表。
        $bootChanged=$session.BootSessionId -cne (Get-MiBootSessionId)
        $observed=@(Get-MiEtwSessions)
        if (@($observed|Where-Object {$_.Name.StartsWith(('WPR_initiated_'+$session.WprInstanceName+'_'),[StringComparison]::Ordinal)}).Count -ne 0) {throw 'Known trace may still be recording.'}
        if (-not $bootChanged) {
            foreach ($process in @($session.StartProcess,$session.StopProcess)) {
                if ($null -ne $process -and (Test-MiWprProcessRunning $process)) {throw 'Known WPR writer may still be running.'}
            }
            if ($session.StopState -cne 'Confirmed') {
                if (-not (Test-MiWprNotDispatched $session $j)) {throw 'Unconfirmed WPR dispatch blocks Heap restore.'}
            }
        }
        $tx.CurrentConfig=Get-MiHeapConfiguration $tx.TargetImageIdentity.ImageName
        if (Test-MiHeapConfigEqual $tx.CurrentConfig $tx.OriginalConfig) {
            $tx.RestoreState='Restored';$tx.ConflictDetected=$false;$tx.ErrorCode=$null
        } elseif ($tx.RestoreState -ceq 'Conflict') {
            return $j # 管理员须先在系统中恢复原值；本工具不覆盖已报告的外部变化。
        } elseif (-not (Test-MiHeapConfigEqual $tx.CurrentConfig $tx.ExpectedModifiedConfig)) {
            $tx.RestoreState='Conflict';$tx.ConflictDetected=$true;$tx.ErrorCode='ExternalConfigurationChanged'
        } else {
            if ($tx.RestoreState -cin @('Restoring','CleanupPending') -and -not $RetryPending) {throw 'Prior restore outcome requires explicit recovery after a fresh read; no automatic retry.'}
            # Restoring 是写前意图；重入先查询真实值，恢复已完成时只补记结果。
            if ($tx.RestoreState -cne 'Restoring') {
                $tx.RestoreState='Restoring';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'HeapTransaction' $tx
            }
            $tx.CurrentConfig=Set-MiHeapConfiguration $Lock $j.HeapTransactions[$TransactionId] -Restore
            if (-not (Test-MiHeapConfigEqual $tx.CurrentConfig $tx.OriginalConfig)) {throw 'Heap restore verification failed.'}
            $tx.RestoreState='Restored';$tx.ErrorCode=$null
        }
        return Add-MiTraceJournalRecord $Lock $j.Revision 'HeapTransaction' $tx
    } catch {
        $failure=$_.Exception.Message;$j=Read-MiTraceJournal $Lock;$tx=$j.HeapTransactions[$TransactionId]
        if ($tx.RestoreState -cin @('Restored','Conflict')) {return $j}
        $tx.RestoreState='CleanupPending';$tx.ErrorCode=$failure
        return Add-MiTraceJournalRecord $Lock $j.Revision 'HeapTransaction' $tx
    }
}
function Repair-MiHeapTransactions {
    # 控制器恢复与 SYSTEM 启动/周期恢复共享同一条限定路径，绝不派发 Start/Stop。
    Assert-MiHeapReleaseAccepted
    $lease=Enter-MiDeploymentLease
    try {
        [void](Assert-MiWatchdog);$lock=Enter-MiTraceLock
        try {[void](Update-MiHeapCleanup $lock -RetryPending)} finally {$lock.Dispose()}
    } finally {$lease.Dispose()}
}
function Update-MiHeapCleanup {
    param($Lock,[switch]$RetryPending)
    $j=Read-MiTraceJournal $Lock
    foreach ($tx in @($j.HeapTransactions.Values)) {
        $session=$j.Sessions[$tx.TraceSessionId]
        if ($tx.RestoreState -ceq 'Restored' -and $session.CleanupState -ceq 'Restored') {continue}
        if ($session.State -cin @('Recording','DeadlineExceeded','Stopping','Saving')) {continue}
        $j=Restore-MiHeapTransaction $Lock $tx.TransactionId -RetryPending:$RetryPending
        $fresh=$j.HeapTransactions[$tx.TransactionId];$session=$j.Sessions[$tx.TraceSessionId]
        $cleanup=if ($fresh.RestoreState -cin @('Restored','Unchanged')) {'Restored'} elseif ($fresh.RestoreState -ceq 'Conflict') {'Conflict'} else {'Pending'}
        if ($session.CleanupState -cne $cleanup) {
            $session.CleanupState=$cleanup
            # 配置恢复本身不验证 ETL；显式进入已有保存恢复入口，不依赖额外一次 Watchdog 才能继续。
            if ($cleanup -ceq 'Restored' -and $session.State -ceq 'CleanupPending') {$session.State='RecoveryRequired'}
            $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $session
        }
    }
    # 完整且可信的 Journal 中没有写前意图，意味着本协议从未授予配置写入资格；
    # 这与整个 Journal 丢失/截断不同（Read-MiTraceJournal 会在此之前拒绝）。
    foreach ($session in @($j.Sessions.Values)) {
        if ($session.RequestedTraceType -cne 'Heap' -or $session.State -cnotin @('UnknownOutcome','RecoveryRequired') -or
            $null -ne $session.PreStartResolution -or $null -ne $session.StartProcess -or $null -ne $session.StartedUtc -or
            $null -ne $session.OwnershipEvidence -or $null -ne $session.StopOperationId -or $session.StopState -cne 'NotStarted') {continue}
        $tx=$j.HeapTransactions[$session.HeapTransactionId]
        if ($null -ne $tx -and $tx.RestoreState -cne 'Restored') {continue}
        try {if (-not (Test-MiWprNotDispatched $session $j)) {continue}} catch {continue} # 读取失败不是“没有派发”的证据。
        $resolution=[pscustomobject][ordered]@{SchemaVersion=1;Outcome='NoTraceDispatched';VerifiedUtc=[datetime]::UtcNow.ToString('o');
            BootSessionId=(Get-MiBootSessionId);ConfigOutcome=if ($null -eq $tx) {'NoWriteIntent'} else {'Restored'}}
        $session.State='RecoveryRequired';$session.CleanupState='Restored'
        Set-MiTraceMember $session 'PreStartResolution' $resolution
        $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $session
    }
    return $j
}
function Get-MiWprProfile {
    param([ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType,[ValidateSet('Memory','File')][string]$Mode='Memory')
    if ($TraceType -ceq 'Heap') {
        # Heap collector 只读取已按 IFEO 配置启用的映像；没有 Snapshot 或任意 provider 输入。
        $xml='<?xml version="1.0" encoding="utf-8"?><WindowsPerformanceRecorder Version="1.0"><Profiles>'+
            '<HeapEventCollector Id="MiHeapCollector" Name="MemoryInspector Heap Collector"><BufferSize Value="1024"/><Buffers Value="128"/></HeapEventCollector>'+
            '<HeapEventProvider Id="MiHeapProvider"/><Profile Id="MiHeap.Verbose.'+$Mode+'" Name="MiHeap" Description="MemoryInspector heap diagnosis" LoggingMode="'+$Mode+'" DetailLevel="Verbose">'+
            '<Collectors><HeapEventCollectorId Value="MiHeapCollector"><HeapEventProviders><HeapEventProviderId Value="MiHeapProvider"/></HeapEventProviders></HeapEventCollectorId></Collectors></Profile></Profiles></WindowsPerformanceRecorder>'
        return [pscustomobject]@{SchemaVersion=1;Name='MiHeap';Id=('MiHeap.Verbose.'+$Mode);Xml=$xml;Fingerprint=(Get-MiTraceHash $xml);
            BufferBytes=[long]134217728;CollectorSuffix='MemoryInspector Heap Collector'}
    }
    $name=if ($TraceType -ceq 'VirtualAlloc') {'MiVirtualAlloc'} else {'MiPool'}
    $keywords=if ($TraceType -ceq 'VirtualAlloc') {'<Keyword Value="VirtualAllocation"/>'} else {'<Keyword Value="Pool"/>'}
    $stacks=if ($TraceType -ceq 'VirtualAlloc') {'<Stack Value="VirtualAllocation"/>'} else {'<Stack Value="PoolAllocation"/><Stack Value="PoolFree"/>'}
    # 审核过的固定 XML 在受保护工作区生成；不加载用户 Profile，也不使用机器相关的大型内置默认配置。
    $xml='<?xml version="1.0" encoding="utf-8"?><WindowsPerformanceRecorder Version="1.0"><Profiles>'+
        '<SystemCollector Id="MiCollector" Name="MemoryInspector System Collector"><BufferSize Value="1024"/><Buffers Value="128"/></SystemCollector>'+
        '<SystemProvider Id="MiProvider"><Keywords><Keyword Value="ProcessThread"/><Keyword Value="Loader"/>'+$keywords+
        '</Keywords><Stacks>'+$stacks+'</Stacks></SystemProvider><Profile Id="'+$name+'.Verbose.'+$Mode+'" Name="'+$name+
        '" Description="MemoryInspector bounded memory diagnosis" LoggingMode="'+$Mode+'" DetailLevel="Verbose">'+
        '<Collectors><SystemCollectorId Value="MiCollector"><SystemProviderId Value="MiProvider"/></SystemCollectorId></Collectors></Profile></Profiles></WindowsPerformanceRecorder>'
    return [pscustomobject]@{SchemaVersion=1;Name=$name;Id=($name+'.Verbose.'+$Mode);Xml=$xml;Fingerprint=(Get-MiTraceHash $xml);
        BufferBytes=[long]134217728;CollectorSuffix='MemoryInspector System Collector'}
}
function Get-MiWprIdentity {
    $exe=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\wpr.exe'
    if (-not [Environment]::Is64BitProcess -or -not [IO.File]::Exists($exe) -or -not (Test-MiNoReparse $exe)) {throw 'WPR x64 binary unavailable.'}
    $signature=Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {throw 'WPR Microsoft signature not verified.'}
    return [pscustomobject]@{SchemaVersion=1;Path=$exe;Sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash;
        Version=(Get-Item -LiteralPath $exe).VersionInfo.FileVersion;Signer=$signature.SignerCertificate.Thumbprint}
}
function Get-MiWprSessionPaths {
    param($Session)
    if (-not (Test-MiGuidN $Session.TraceSessionId)) {throw 'Invalid trace path identity.'}
    $p=Get-MiSecurityPaths;$workspace=Join-Path $p.TraceWorkspace $Session.TraceSessionId
    return [pscustomobject]@{Workspace=$workspace;Profile=(Join-Path $workspace 'profile.wprp');Temporary=(Join-Path $workspace 'recording');
        Output=(Join-Path $workspace 'result.etl');StartMarker=(Join-Path $workspace 'start.dispatch.json');StopMarker=(Join-Path $workspace 'stop.dispatch.json')}
}
function Measure-MiProtectedTree {
    param([string]$Root)
    Assert-MiTracePath $Root
    $total=[long]0;$pending=New-Object 'System.Collections.Generic.Queue[string]';$pending.Enqueue($Root);$visited=0
    while ($pending.Count -gt 0) {
        $directory=$pending.Dequeue()
        foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (++$visited -gt 10000) {throw 'Trace storage enumeration limit exceeded.'}
            # WPR 生成的数据继承受保护父目录；控制文件仍要求独立受保护 DACL。
            if (-not (Test-MiNoReparse $entry.FullName) -or -not (Test-MiAclRestricted $entry.FullName $false)) {throw 'Untrusted generated trace data.'}
            if ($entry.PSIsContainer) {$pending.Enqueue($entry.FullName)} else {
                if ($entry.Length -gt ([long]::MaxValue-$total)) {throw 'Trace storage size overflow.'};$total+=$entry.Length
            }
        }
    }
    return $total
}
function Test-MiWprResources {
    param([long]$ArtifactBytes,[long]$WorkingBytes,[long]$FreeBytes,[long]$AvailableMemoryBytes,
        [long]$WorkingBudget=4294967296,[long]$ArtifactBudget=8589934592,[long]$Reserve=2147483648)
    # 三个预算独立。工作预算含录制、合并、保存；磁盘剩余不能只和 8 GiB 成品预算比较。
    if ($ArtifactBytes -lt 0 -or $WorkingBytes -lt 0 -or $FreeBytes -lt 0 -or $AvailableMemoryBytes -lt 0 -or
        $WorkingBudget -le 0 -or $ArtifactBudget -le 0 -or $Reserve -le 0) {return $false}
    return $ArtifactBytes -le ($ArtifactBudget-134217728) -and $WorkingBytes -le $WorkingBudget -and
        $FreeBytes -ge ([decimal]$Reserve+[decimal]$WorkingBudget) -and $AvailableMemoryBytes -ge 1073741824
}
function Get-MiWprResources {
    param($Session)
    $p=Get-MiSecurityPaths;$paths=Get-MiWprSessionPaths $Session
    Assert-MiTracePath $p.TraceWorkspace
    # 所有路径固定在本产品同一磁盘卷；重解析点和挂载点在路径检查时被拒绝。
    $volume=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($p.TraceWorkspace))
    if (-not $volume.IsReady -or $volume.DriveType -ne [IO.DriveType]::Fixed) {throw 'Trace volume unavailable or not local fixed storage.'}
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $os.FreePhysicalMemory) {throw 'Available physical memory unavailable.'}
    $artifactBytes=if ([IO.Directory]::Exists($p.TraceArtifacts)) {Measure-MiProtectedTree $p.TraceArtifacts} else {0}
    $workingBytes=Measure-MiProtectedTree $p.TraceWorkspace
    return [pscustomobject]@{ArtifactBytes=[long]$artifactBytes;WorkingBytes=[long]$workingBytes;FreeBytes=[long]$volume.AvailableFreeSpace;
        AvailableMemoryBytes=([long]$os.FreePhysicalMemory*1024);Volume=$volume.Name}
}
function Get-MiWprArguments {
    param([ValidateSet('Start','Stop')][string]$Verb,$Session)
    Assert-MiTraceSession $Session
    $paths=Get-MiWprSessionPaths $Session
    foreach ($path in @($paths.Profile,$paths.Temporary,$paths.Output)) {
        if ($path -match '["\r\n]' -or $path.EndsWith('\')) {throw 'Unsafe fixed WPR argument.'}
    }
    $profile=Get-MiWprProfile $Session.RequestedTraceType $Session.RecordingMode
    if ($Session.ProfileFingerprint -cne $profile.Fingerprint -or $Session.ProfileId -cne $profile.Id) {throw 'WPR profile binding mismatch.'}
    if ($Verb -ceq 'Start') {
        $arguments='-start "'+$paths.Profile+'!'+$profile.Name+'.Verbose"'
        if ($Session.RecordingMode -ceq 'File') {$arguments+=' -filemode'}
        $arguments+=' -recordtempto "'+$paths.Temporary+'"'
    } else {$arguments='-stop "'+$paths.Output+'" -skipPdbGen'}
    # 实例参数必须是最后一项；没有任何全局 stop/cancel 或任意命令分支。
    return $arguments+' -instancename '+$Session.WprInstanceName
}
function Start-MiWprProcess {
    param([ValidateSet('Start','Stop')][string]$Verb,$Session)
    Assert-MiWprReleaseAccepted
    Assert-MiTraceSession $Session
    if ($null -ne $Session.PreStartResolution) {throw 'Resolved pre-start trace cannot be dispatched.'}
    if ($Session.RequestedTraceType -ceq 'Heap') {Assert-MiHeapReleaseAccepted}
    $identity=Get-MiWprIdentity
    if (($identity|ConvertTo-Json -Compress) -cne ($Session.WprExecutableIdentity|ConvertTo-Json -Compress)) {throw 'WPR executable identity changed.'}
    $paths=Get-MiWprSessionPaths $Session
    Assert-MiTracePath $paths.Workspace;Assert-MiTracePath $paths.Temporary;Assert-MiTracePath $paths.Profile
    if ((Get-MiTraceHash ([IO.File]::ReadAllText($paths.Profile,[Text.Encoding]::UTF8))) -cne $Session.ProfileFingerprint) {throw 'WPR profile bytes changed.'}
    if ($Verb -ceq 'Stop' -and [IO.File]::Exists($paths.Output)) {throw 'WPR output already exists; no overwrite.'}
    $marker=if ($Verb -ceq 'Start') {$paths.StartMarker} else {$paths.StopMarker}
    $claim=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.Encoding]::UTF8.GetBytes('{"SchemaVersion":1,"State":"DispatchIntent"}');$claim.Write($bytes,0,$bytes.Length);$claim.Flush($true)} finally {$claim.Dispose()}
    Set-MiProtectedFileAcl $marker
    # WPR 为独立短期子进程；GUI 不等候保存，Watchdog 后续按精确 PID/创建时间观察，不 Kill/重试。
    Initialize-MiTraceNative
    # BREAKAWAY 防止计划任务的 45 秒作业限制终止正在合并的 WPR；系统不允许脱离时拒绝，绝不降级。
    return [MemoryInspector.TraceNative]::Launch($identity.Path,(Get-MiWprArguments $Verb $Session),$paths.Workspace,$paths.Temporary,($Verb -ceq 'Start'))

}
function Test-MiWprProcessRunning {
    param($Identity)
    if ($null -eq $Identity -or $Identity.Pid -le 0 -or $Identity.StartUtcTicks -le 0) {throw 'WPR process identity missing.'}
    $process=Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
    if ($null -eq $process) {return $false}
    try {return $process.StartTime.ToUniversalTime().Ticks -eq $Identity.StartUtcTicks -and -not $process.HasExited}
    finally {$process.Dispose()}
}
function Initialize-MiTraceNative {
    if ('MemoryInspector.TraceNative' -as [type]) {return}
    if (-not [Environment]::Is64BitProcess) {throw 'ETW adapter requires x64.'}
    # 原生层查询 ETW、消费 ETL 并派发已核验 WPR；不导入全局 StopTrace/ControlTrace 修改接口。
    $source=@"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
namespace MemoryInspector {
 public static class TraceNative {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
   public uint Size; public string Reserved,Desktop,Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
   public ushort Show,ReservedSize;public IntPtr ReservedPointer,Input,Output,Error;
  }
  [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr Process,Thread;public uint Id,ThreadId;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool CreateProcessW(
   string application,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,
   IntPtr environment,string directory,ref Startup startup,out ProcessInfo result);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
  public sealed class Dispatch {public int SchemaVersion=1;public uint Pid;public long StartUtcTicks;public string DispatchedUtc,Operation;}
  public static Dispatch Launch(string exe,string arguments,string directory,string temporary,bool starting) {
   // 固定最小环境，不继承用户的符号服务器、DLL 搜索路径或任意命令配置。
   string system=Environment.GetFolderPath(Environment.SpecialFolder.System),windows=System.IO.Directory.GetParent(system).FullName;
   string block="PATH="+system+"\0SystemRoot="+windows+"\0TEMP="+temporary+"\0TMP="+temporary+"\0WINDIR="+windows+"\0\0";
   IntPtr environment=Marshal.StringToHGlobalUni(block);ProcessInfo pi=new ProcessInfo();
   Startup startup=new Startup();startup.Size=(uint)Marshal.SizeOf(typeof(Startup));
   try {
    if(!CreateProcessW(exe,new StringBuilder("\""+exe+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,false,
      0x01000000|0x08000000|0x00000400,environment,directory,ref startup,out pi))throw new Win32Exception(Marshal.GetLastWin32Error());
    long created,exit,kernel,user;if(!GetProcessTimes(pi.Process,out created,out exit,out kernel,out user))throw new Win32Exception(Marshal.GetLastWin32Error());
    Dispatch token=new Dispatch {Pid=pi.Id,StartUtcTicks=DateTime.FromFileTimeUtc(created).Ticks,
      DispatchedUtc=DateTime.FromFileTimeUtc(created).ToString("o"),Operation=starting?"Start":"Stop"};
    if(starting) {
     uint code;if(WaitForSingleObject(pi.Process,5000)!=0 || !GetExitCodeProcess(pi.Process,out code) || code!=0)
      throw new InvalidOperationException("WPR start outcome uncertain or failed; no retry");
    }return token;
   }finally{if(pi.Thread!=IntPtr.Zero)CloseHandle(pi.Thread);if(pi.Process!=IntPtr.Zero)CloseHandle(pi.Process);Marshal.FreeHGlobal(environment);}
  }
  [StructLayout(LayoutKind.Sequential)] struct Wnode {
   public uint BufferSize,ProviderId; public ulong HistoricalContext,TimeStamp; public Guid Guid; public uint ClientContext,Flags;
  }
  [StructLayout(LayoutKind.Sequential)] struct Properties {
   public Wnode Wnode; public uint BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags,AgeLimit;
   public uint NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost;
   public IntPtr LoggerThreadId; public uint LogFileNameOffset,LoggerNameOffset;
  }
  public sealed class Session {
   public string Name,FileName,Guid,Handle; public long ThreadId,ThreadCreated;
   public uint Mode,BufferKB,MaximumBuffers,EventsLost,BuffersWritten,LogBuffersLost;
  }
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint QueryAllTracesW([In,Out]IntPtr[] items,uint count,out uint returned);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint id);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetThreadTimes(IntPtr thread,out long creation,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  static long Created(long id) {
   if(id<=0 || id>uint.MaxValue)return 0;
   IntPtr h=OpenThread(0x0800,false,(uint)id);if(h==IntPtr.Zero)return 0;
   try {long c,e,k,u;return GetThreadTimes(h,out c,out e,out k,out u)?c:0;}finally{CloseHandle(h);}
  }
  public static Session[] Query() {
   int size=Marshal.SizeOf(typeof(Properties)),capacity=size+8192;IntPtr[] blocks=new IntPtr[256];
   try {
    for(int i=0;i<blocks.Length;i++) {
     blocks[i]=Marshal.AllocHGlobal(capacity);Marshal.Copy(new byte[capacity],0,blocks[i],capacity);
     Properties p=new Properties();p.Wnode.BufferSize=(uint)capacity;p.LoggerNameOffset=(uint)size;p.LogFileNameOffset=(uint)(size+4096);
     Marshal.StructureToPtr(p,blocks[i],false);
    }
    uint count;uint error=QueryAllTracesW(blocks,(uint)blocks.Length,out count);
    if(error!=0 || count>blocks.Length)throw new Win32Exception((int)(error==0?234:error));
    List<Session> output=new List<Session>();
    for(int i=0;i<count;i++) {
     Properties p=(Properties)Marshal.PtrToStructure(blocks[i],typeof(Properties));
     if(p.LoggerNameOffset<size || p.LoggerNameOffset>=capacity || p.LogFileNameOffset>=capacity)throw new InvalidOperationException("Invalid ETW offsets");
     long thread=p.LoggerThreadId.ToInt64();
     output.Add(new Session {Name=Marshal.PtrToStringUni(IntPtr.Add(blocks[i],(int)p.LoggerNameOffset)),
      FileName=p.LogFileNameOffset==0?"":Marshal.PtrToStringUni(IntPtr.Add(blocks[i],(int)p.LogFileNameOffset)),
      Guid=p.Wnode.Guid.ToString("D"),Handle=p.Wnode.HistoricalContext.ToString("X16"),ThreadId=thread,ThreadCreated=Created(thread),
      Mode=p.LogFileMode,BufferKB=p.BufferSize,MaximumBuffers=p.MaximumBuffers,EventsLost=p.EventsLost,
      BuffersWritten=p.BuffersWritten,LogBuffersLost=p.LogBuffersLost});
    }return output.ToArray();
   }finally{foreach(IntPtr block in blocks)if(block!=IntPtr.Zero)Marshal.FreeHGlobal(block);}
  }
  // x64 EVENT_TRACE_LOGFILEW=448 bytes; embedded EVENT_TRACE=88 and TRACE_LOGFILE_HEADER=280.
  // 显式布局只暴露本阶段需要的字段，其余零初始化；来源为 Windows SDK evntrace.h。
  [StructLayout(LayoutKind.Explicit,Size=448)] struct TraceFile {
   [FieldOffset(0)] public IntPtr FileName;
   [FieldOffset(28)] public uint Mode;
   [FieldOffset(120)] public uint BufferSize;
   [FieldOffset(136)] public long EndTime;
   [FieldOffset(156)] public uint BuffersWritten;
   [FieldOffset(168)] public uint EventsLost;
   [FieldOffset(384)] public long StartTime;
   [FieldOffset(396)] public uint BuffersLost;
   [FieldOffset(400)] public IntPtr BufferCallback;
   [FieldOffset(424)] public IntPtr EventCallback;
  }
  [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate uint BufferCallback(IntPtr data);
  [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void EventCallback(IntPtr data);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern ulong OpenTraceW(ref TraceFile file);
  [DllImport("advapi32.dll",ExactSpelling=true)] static extern uint ProcessTrace([In]ulong[] handles,uint count,IntPtr start,IntPtr end);
  [DllImport("advapi32.dll",ExactSpelling=true)] static extern uint CloseTrace(ulong handle);
  public sealed class EtlResult {public long EventCount,StartTime,EndTime;public uint EventsLost,BuffersLost;}
  public static EtlResult ValidateEtl(string path) {
   TraceFile file=new TraceFile();file.FileName=Marshal.StringToHGlobalUni(path);file.Mode=0x100;
   long events=0;Stopwatch watch=Stopwatch.StartNew();
   BufferCallback buffer=delegate(IntPtr data){return watch.ElapsedMilliseconds<10000?1u:0u;};
   EventCallback callback=delegate(IntPtr data){events++;};
   file.BufferCallback=Marshal.GetFunctionPointerForDelegate(buffer);file.EventCallback=Marshal.GetFunctionPointerForDelegate(callback);
   ulong handle=ulong.MaxValue;
   try {
    handle=OpenTraceW(ref file);if(handle==ulong.MaxValue)throw new Win32Exception(Marshal.GetLastWin32Error());
    if(file.BufferSize==0 || file.BuffersWritten==0 || file.StartTime<=0 || file.EndTime<file.StartTime)throw new InvalidOperationException("Incomplete ETL header");
    uint error=ProcessTrace(new ulong[]{handle},1,IntPtr.Zero,IntPtr.Zero);
    if(error!=0 || watch.ElapsedMilliseconds>=10000)throw new InvalidOperationException("ETL validation incomplete: "+error);
    return new EtlResult {EventCount=events,StartTime=file.StartTime,EndTime=file.EndTime,EventsLost=file.EventsLost,BuffersLost=file.BuffersLost};
   }finally{if(handle!=ulong.MaxValue)CloseTrace(handle);Marshal.FreeHGlobal(file.FileName);GC.KeepAlive(buffer);GC.KeepAlive(callback);}
  }
 }
}
"@
    $compiler=[CodeDom.Compiler.CompilerParameters]::new()
    [void]$compiler.ReferencedAssemblies.Add('System.dll')
    if (Test-MiAdminToken) {
        $temporary=(Get-MiSecurityPaths).TraceWorkspace;Assert-MiTracePath $temporary
        $compiler.TempFiles=[CodeDom.Compiler.TempFileCollection]::new($temporary,$false)
    }
    Add-Type -TypeDefinition $source -CompilerParameters $compiler -ErrorAction Stop
}
function Get-MiEtwSessions {
    # 普通令牌只能看到部分公共会话，空查询不能证明系统没有外部追踪。
    if (-not (Test-MiAdminToken)) {throw 'Complete public ETW enumeration requires elevated context.'}
    Initialize-MiTraceNative
    return @([MemoryInspector.TraceNative]::Query())
}
function Get-MiWprOwnershipEvidence {
    param($Session,$Observed)
    $profile=Get-MiWprProfile $Session.RequestedTraceType $Session.RecordingMode
    $name='WPR_initiated_'+$Session.WprInstanceName+'_'+$profile.CollectorSuffix
    $own=@($Observed|Where-Object Name -ceq $name)
    if ($own.Count -ne 1 -or $own[0].Guid -eq [guid]::Empty.ToString() -or $own[0].Handle -ceq '0000000000000000' -or
        $own[0].ThreadId -le 0 -or $own[0].ThreadCreated -le 0 -or $own[0].BufferKB -ne 1024 -or $own[0].MaximumBuffers -ne 128 -or
        $own[0].ThreadCreated -lt (ConvertTo-MiTraceUtc $Session.StartIntentUtc).ToFileTimeUtc() -or
        @($Observed|Where-Object {$_.Name.StartsWith(('WPR_initiated_'+$Session.WprInstanceName+'_'),[StringComparison]::Ordinal)}).Count -ne 1) {throw 'ETW instance identity cannot be established.'}
    $paths=Get-MiWprSessionPaths $Session
    $systemCollector=($own[0].Mode -band 0x02000000) -ne 0
    if ($systemCollector -ne ($Session.RequestedTraceType -cne 'Heap')) {throw 'Unexpected collector mode.'}
    if ($Session.RecordingMode -ceq 'File') {
        if ([string]::IsNullOrWhiteSpace($own[0].FileName) -or -not [IO.Path]::GetFullPath($own[0].FileName).StartsWith(
            $paths.Temporary+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'ETW temporary file location differs from protected workspace.'}
    }
    return [pscustomobject][ordered]@{SchemaVersion=1;Name=$name;Guid=$own[0].Guid;Handle=$own[0].Handle;
        ThreadId=$own[0].ThreadId;ThreadCreated=$own[0].ThreadCreated;Mode=$own[0].Mode;FileName=$own[0].FileName;
        ProfileFingerprint=$profile.Fingerprint;BootSessionId=$Session.BootSessionId;StartOperationId=$Session.StartOperationId}
}
function Assert-MiWprOwnership {
    param($Session,$Observed)
    Assert-MiWprReleaseAccepted
    if ($Session.RequestedTraceType -ceq 'Heap') {Assert-MiHeapReleaseAccepted}
    if ($Session.BootSessionId -cne (Get-MiBootSessionId) -or -not (Test-MiGuidN $Session.StartOperationId) -or
        $null -eq $Session.StartProcess -or $null -eq $Session.OwnershipEvidence) {throw 'Protected WPR ownership evidence missing or wrong boot.'}
    $current=Get-MiWprOwnershipEvidence $Session $Observed
    if (($current|ConvertTo-Json -Compress) -cne ($Session.OwnershipEvidence|ConvertTo-Json -Compress)) {throw 'WPR session replaced or externally changed.'}
    $identity=Get-MiWprIdentity
    if (($identity|ConvertTo-Json -Compress) -cne ($Session.WprExecutableIdentity|ConvertTo-Json -Compress)) {throw 'WPR binary changed during recording.'}
}
function Set-MiTraceMember {
    param($Session,[string]$Name,$Value)
    $Session|Add-Member NoteProperty $Name $Value -Force
}
function New-MiWprSession {
    param([string]$Id,[ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType='VirtualAlloc',
        [ValidateSet('Memory','File')][string]$Mode='Memory',[ValidateRange(300,1800)][int]$DurationSeconds=300)
    if (-not (Test-MiGuidN $Id)) {throw 'Invalid trace request identity.'}
    return [pscustomobject][ordered]@{SchemaVersion=1;TraceSessionId=$Id;WprInstanceName=('MemoryInspector-'+$Id);
        OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;BootSessionId=(Get-MiBootSessionId);
        RequestedTraceType=$TraceType;ProfileId=$null;ProfileFingerprint=$null;WprExecutableIdentity=$null;RecordingMode=$Mode;
        RequestedDuration=$DurationSeconds;StartedUtc=$null;DeadlineUtc=$null;TraceWorkingBudget=[long]4294967296;
        State='Requested';CleanupState='NotRequired';OutputArtifactId=$null;LastVerifiedUtc=[datetime]::UtcNow.ToString('o');
        ErrorCode=$null;JournalRevision=1;StopState='NotStarted';SaveState='NotStarted';AnalysisState='NotStarted';ActiveReferences=0;AuthorizationId=$null}
}
function Invoke-MiWprStart {
    param([string]$RequestId,[ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType='VirtualAlloc',
        [ValidateSet('Memory','File')][string]$Mode='Memory',[ValidateRange(300,1800)][int]$DurationSeconds=300,[string]$HeapImagePath='')
    # 当前发行版在任何路径/任务/进程副作用之前拒绝未验收功能；没有强制开关。
    Assert-MiWprReleaseAccepted
    if ($TraceType -ceq 'Heap') {Assert-MiHeapReleaseAccepted}
    elseif ($HeapImagePath -cne '') {throw 'Heap image supplied to a non-Heap trace.'}
    if ($Mode -ceq 'File' -and -not (Get-MiWprReleaseStatus).FileAccepted) {throw 'File Mode acceptance pending.'}
    if (-not (Test-MiGuidN $RequestId)) {throw 'Invalid trace request identity.'}
    # 人工确认不持有全局锁；确认之后重新做健康、容量、冲突及身份核验。
    $heapTarget=$null
    if ($TraceType -ceq 'Heap') {
        $heapTarget=Get-MiHeapTargetIdentity $HeapImagePath
        Write-Host ('Heap configuration applies to ALL new processes named '+$heapTarget.ImageName+', including other paths/users. Target: '+$heapTarget.Path+' SHA256: '+$heapTarget.Sha256)
        Write-Host 'Existing instances may require a manual restart after configuration. MemoryInspector never starts, restarts or terminates the target. No Heap snapshot mode.'
    }
    $confirmation=Read-Host ('Type START '+$RequestId+' to authorize '+$TraceType+'/'+$Mode+' for '+$DurationSeconds+' seconds')
    if ($confirmation -cne ('START '+$RequestId)) {return [pscustomobject]@{State='AuthorizationDenied';TraceSessionId=$RequestId}}
    $lease=Enter-MiDeploymentLease
    try {
        [void](Invoke-MiTraceHealthCheck)
        $lock=Enter-MiTraceLock
        try {
            $j=Read-MiTraceJournal $lock;Assert-MiTraceQuiescent $j
            if ($j.Deployment -cne 'Ready') {throw 'M2 deployment not ready.'}
            $session=New-MiWprSession $RequestId $TraceType $Mode $DurationSeconds
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
            $session.State='Preflight';$j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
            try {
                $profile=Get-MiWprProfile $TraceType $Mode;$identity=Get-MiWprIdentity
                $resources=Get-MiWprResources $session
                if (-not (Test-MiWprResources $resources.ArtifactBytes $resources.WorkingBytes $resources.FreeBytes $resources.AvailableMemoryBytes)) {throw 'Trace resource preflight rejected.'}
                $before=@(Get-MiEtwSessions)
                $collector='WPR_initiated_'+$session.WprInstanceName+'_'+$profile.CollectorSuffix
                if (@($before|Where-Object Name -ceq $collector).Count -ne 0 -or
                    @($before|Where-Object {($_.Mode -band 0x02000000) -ne 0}).Count -ge 7) {throw 'ETW instance or system logger resources conflict.'}
                $paths=Get-MiWprSessionPaths $session
                if ([IO.Directory]::Exists($paths.Workspace)) {throw 'Trace workspace already exists.'}
                if ($TraceType -ceq 'Heap') {
                    $freshTarget=Get-MiHeapTargetIdentity $HeapImagePath
                    if (($freshTarget|ConvertTo-Json -Compress) -cne ($heapTarget|ConvertTo-Json -Compress)) {throw 'Heap target changed after authorization.'}
                    [void](Get-MiHeapConfigDisposition (Get-MiHeapConfiguration $heapTarget.ImageName))
                }
            } catch {
                $session.State='ResourcePreflightRejected';$session.ErrorCode=$_.Exception.Message
                [void](Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session);throw
            }
            $session.ProfileId=$profile.Id;$session.ProfileFingerprint=$profile.Fingerprint;$session.WprExecutableIdentity=$identity
            $session.AuthorizationId=[guid]::NewGuid().ToString('N');$session.State='Authorized'
            if ($TraceType -ceq 'Heap') {
                Set-MiTraceMember $session 'HeapTransactionId' ([guid]::NewGuid().ToString('N'))
                $session.CleanupState='Pending'
            }
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
            $session.State='Preparing';Set-MiTraceMember $session 'StartOperationId' ([guid]::NewGuid().ToString('N'))
            Set-MiTraceMember $session 'WorkspaceId' $session.TraceSessionId
            Set-MiTraceMember $session 'PlannedArtifactId' ([guid]::NewGuid().ToString('N'))
            Set-MiTraceMember $session 'ExternalSessions' @($before|Select-Object Name,Guid,Handle,ThreadId,ThreadCreated)
            Set-MiTraceMember $session 'StartIntentUtc' ([datetime]::UtcNow.ToString('o'))
            $j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session
            try {
                if ($TraceType -ceq 'Heap') {$j=Initialize-MiHeapTransaction $lock $session $heapTarget}
                foreach ($directory in @($paths.Workspace,$paths.Temporary)) {[void][IO.Directory]::CreateDirectory($directory);Set-MiAdminDirectoryAcl $directory}
                [IO.File]::WriteAllText($paths.Profile,$profile.Xml,[Text.UTF8Encoding]::new($false));Set-MiProtectedFileAcl $paths.Profile
                $process=Start-MiWprProcess 'Start' $session
                Set-MiTraceMember $session 'StartProcess' $process
                $after=@(Get-MiEtwSessions)
                foreach ($external in $before) {
                    $same=@($after|Where-Object {$_.Name -ceq $external.Name -and $_.Guid -ceq $external.Guid -and $_.Handle -ceq $external.Handle})
                    if ($same.Count -ne 1) {throw 'External ETW state changed during start; recovery required.'}
                }
                Set-MiTraceMember $session 'OwnershipEvidence' (Get-MiWprOwnershipEvidence $session $after)
                # 命令前已在日志中记录意图；命令成功且实际 ETW 身份建立后才能标记 Recording。
                $session.StartedUtc=$process.DispatchedUtc;$session.DeadlineUtc=(ConvertTo-MiTraceUtc $session.StartedUtc).AddSeconds($DurationSeconds).ToString('o')
                $session.State='Recording';$session.LastVerifiedUtc=[datetime]::UtcNow.ToString('o')
                [void](Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session)
                return $session
            } catch {
                $failure=$_.Exception.Message;$j=Read-MiTraceJournal $lock;$session=$j.Sessions[$session.TraceSessionId]
                $session.State='UnknownOutcome';$session.ErrorCode=$failure
                [void](Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session);throw
            }
        } finally {$lock.Dispose()}
    } finally {$lease.Dispose()}
}
function Assert-MiTraceArtifactTransition {
    param($Previous,$Next,$Journal)
    if ($Next.SchemaVersion -ne 1 -or -not (Test-MiGuidN $Next.ArtifactId) -or -not (Test-MiGuidN $Next.TraceSessionId) -or
        $Next.OwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $Next.ActiveReferences -lt 0 -or
        $Next.State -cnotin @('Saving','Ready','Retiring','Retained') -or $Next.SizeBytes -lt 0) {throw 'Invalid trace artifact.'}
    $session=$Journal.Sessions[$Next.TraceSessionId]
    if ($null -eq $session -or $session.OwnerSid -cne $Next.OwnerSid -or $session.PlannedArtifactId -cne $Next.ArtifactId) {throw 'Artifact has no protected session ownership.'}
    $created=ConvertTo-MiTraceUtc $Next.CreatedUtc;$retention=ConvertTo-MiTraceUtc $Next.RetainUntilUtc
    if (($retention-$created).TotalDays -ne 7) {throw 'Invalid artifact retention deadline.'}
    if ($Next.SizeBytes -le 0 -or $Next.SizeBytes -gt 8589934592 -or $Next.Sha256 -cnotmatch '^[A-F0-9]{64}$') {throw 'Artifact identity incomplete.'}
    if ($null -eq $Previous) {if ($Next.State -cne 'Saving') {throw 'Artifact must begin with save intent.'};return}
    foreach ($field in @('ArtifactId','TraceSessionId','OwnerSid','CreatedUtc','RetainUntilUtc')) {
        if ($Previous.$field -cne $Next.$field) {throw 'Artifact ownership changed.'}
    }
    if ($Previous.SizeBytes -ne $Next.SizeBytes -or $Previous.Sha256 -cne $Next.Sha256) {throw 'Artifact bytes changed.'}
    $edges=@{Saving=@('Ready');Ready=@('Ready','Retiring');Retiring=@('Retained');Retained=@()}
    if ($Next.State -cnotin $edges[[string]$Previous.State] -or ($Next.State -cin @('Retiring','Retained') -and $Next.ActiveReferences -ne 0)) {throw 'Artifact transition or active reference conflict.'}
}
function Get-MiTraceArtifactPath {
    param($Artifact,[switch]$Retained)
    if (-not (Test-MiGuidN $Artifact.ArtifactId) -or $Artifact.OwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {throw 'Invalid artifact path identity.'}
    $directory=Join-Path (Get-MiSecurityPaths).TraceArtifacts $Artifact.OwnerSid
    if ($Retained) {$directory=Join-Path $directory 'retained'}
    return Join-Path $directory ($Artifact.ArtifactId+'.etl')
}
function Set-MiDiagnosticAccess {
    param([string]$Path,[string]$OwnerSid,[switch]$Directory)
    if ($OwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {throw 'Unverified artifact recipient.'}
    if ($Directory) {Set-MiAdminDirectoryAcl $Path} else {Set-MiProtectedFileAcl $Path}
    $acl=Get-Acl -LiteralPath $Path
    $sid=[Security.Principal.SecurityIdentifier]::new($OwnerSid)
    if ($Directory) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    } else {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'Read','Allow'))}
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    Assert-MiTracePath $Path
}
function Test-MiEtlArtifact {
    param([string]$Path)
    if (-not (Test-MiNoReparse $Path)) {throw 'ETL path untrusted.'}
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -le 0 -or $file.Length -gt 8589934592) {throw 'ETL empty or exceeds artifact budget.'}
    Initialize-MiTraceNative
    $validation=[MemoryInspector.TraceNative]::ValidateEtl($Path)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $sha=[Security.Cryptography.SHA256]::Create();$clock=[Diagnostics.Stopwatch]::StartNew();$buffer=New-Object byte[] 1048576
    try {
        while (($count=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($clock.Elapsed.TotalSeconds -gt 10) {throw 'ETL hash validation time limit; retain for recovery.'}
            [void]$sha.TransformBlock($buffer,0,$count,$buffer,0)
        }
        [void]$sha.TransformFinalBlock($buffer,0,0)
        return [pscustomobject]@{SizeBytes=$stream.Length;Sha256=([BitConverter]::ToString($sha.Hash)).Replace('-','');
            EventCount=$validation.EventCount;EventsLost=$validation.EventsLost;BuffersLost=$validation.BuffersLost}
    } finally {$stream.Dispose();$sha.Dispose()}
}
function Complete-MiWprArtifact {
    param($Lock,$Session)
    $result=$null;$verified=$null # 不继承 PowerShell 调用者动态作用域的验证结果。
    $j=Read-MiTraceJournal $Lock;$Session=$j.Sessions[$Session.TraceSessionId]
    $paths=Get-MiWprSessionPaths $Session
    if ($Session.State -cnotin @('Saving','Saved','Cleaning','Analyzing','RecoveryRequired') -or $Session.StopState -cne 'Confirmed') {throw 'Saving requires independently confirmed trace stop.'}
    if ($null -eq $Session.StopProcess -or (Test-MiWprProcessRunning $Session.StopProcess)) {throw 'Save writer may still be running.'}
    if ($Session.State -ceq 'RecoveryRequired') {
        # 停止已确认，即使首次保存意图前重启，也可重新核验已知输出，不能补发停止。
        $Session.State='Saving';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
    }
    $artifact=$j.Artifacts[$Session.PlannedArtifactId]
    $p=Get-MiSecurityPaths
    if ($null -eq $artifact) {
        # 在移动前持久化已经验证的字节身份；崩溃后可区分“尚未移动”和“移动完成但未记账”。
        if ($Session.State -cne 'Saving') {throw 'Missing protected artifact save intent.'}
        Assert-MiGeneratedTraceData $paths.Output
        Set-MiProtectedFileAcl $paths.Output;$result=Test-MiEtlArtifact $paths.Output
        if (-not [IO.Directory]::Exists($p.TraceArtifacts)) {[void][IO.Directory]::CreateDirectory($p.TraceArtifacts);Set-MiAdminDirectoryAcl $p.TraceArtifacts $true}
        Assert-MiTracePath $p.TraceArtifacts
        if ((Measure-MiProtectedTree $p.TraceArtifacts)+[decimal]$result.SizeBytes -gt 8589934592) {throw 'Artifact budget exceeded; ETL retained in protected workspace.'}
        $created=[datetime]::UtcNow
        $artifact=[pscustomobject][ordered]@{SchemaVersion=1;ArtifactId=$Session.PlannedArtifactId;TraceSessionId=$Session.TraceSessionId;
            OwnerSid=$Session.OwnerSid;State='Saving';SizeBytes=$result.SizeBytes;Sha256=$result.Sha256;CreatedUtc=$created.ToString('o');RetainUntilUtc=$created.AddDays(7).ToString('o');
            ActiveReferences=0;EventLossStatus=if ($result.EventsLost -gt 0 -or $result.BuffersLost -gt 0) {'LossReported'} else {'NoLossReported'};
            MeasurementQuality=if ($result.EventsLost -gt 0 -or $result.BuffersLost -gt 0) {'Partial'} else {'Complete'}}
        $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Artifact' $artifact
    }
    $destination=Get-MiTraceArtifactPath $artifact;$directory=Split-Path -Parent $destination
    if ($artifact.State -ceq 'Saving') {
        $atSource=[IO.File]::Exists($paths.Output);$atDestination=[IO.File]::Exists($destination)
        if ($atSource -eq $atDestination) {throw 'Ambiguous or missing artifact; preserve both locations for recovery.'}
        $actual=if ($atSource) {$paths.Output} else {$destination}
        Assert-MiGeneratedTraceData $actual
        $verified=if ($null -ne $result -and $atSource) {$result} else {Test-MiEtlArtifact $actual}
        if ($verified.SizeBytes -ne $artifact.SizeBytes -or $verified.Sha256 -cne $artifact.Sha256) {throw 'Artifact save intent does not match actual bytes.'}
        if ($atSource) {
            if (-not [IO.Directory]::Exists($directory)) {[void][IO.Directory]::CreateDirectory($directory);Set-MiDiagnosticAccess $directory $Session.OwnerSid -Directory}
            Assert-MiTracePath $directory
            [IO.File]::Move($paths.Output,$destination)
        }
        Set-MiDiagnosticAccess $destination $Session.OwnerSid
        $artifact.State='Ready';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'Artifact' $artifact
    } elseif ($artifact.State -cne 'Ready') {throw 'Artifact is not available for save completion.'}
    # 即使 Ready 已记账也重新验证；管理员恢复不能凭 Journal 宣称文件仍在。
    Assert-MiTracePath $destination
    if ($null -eq $verified) {$verified=Test-MiEtlArtifact $destination}
    if ($verified.SizeBytes -ne $artifact.SizeBytes -or $verified.Sha256 -cne $artifact.Sha256) {throw 'Saved artifact identity changed.'}
    if ($Session.State -ceq 'RecoveryRequired') {
        $Session.State='Saving';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
    }
    if ($Session.State -ceq 'Saving') {
        $Session.SaveState='Saved';$Session.OutputArtifactId=$artifact.ArtifactId;$Session.State='Saved';$Session.ErrorCode=$null
        $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
    }
    # 已提交的阶段只向前推进；中断后不再重放文件移动或覆盖 SaveState。
    $next=@{Saved='Cleaning';Cleaning='Analyzing';Analyzing='Completed'}
    while ($next.ContainsKey([string]$Session.State)) {
        if ($Session.State -ceq 'Cleaning' -and $Session.RequestedTraceType -ceq 'Heap') {
            $j=Restore-MiHeapTransaction $Lock $Session.HeapTransactionId
            $tx=$j.HeapTransactions[$Session.HeapTransactionId]
            $Session=$j.Sessions[$Session.TraceSessionId]
            if ($tx.RestoreState -cnotin @('Restored','Unchanged')) {
                $Session.State='CleanupPending';$Session.CleanupState=if ($tx.ConflictDetected) {'Conflict'} else {'Pending'}
                $Session.ErrorCode=$tx.ErrorCode
                return Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
            }
            $Session.CleanupState='Restored'
        }
        $Session.State=$next[[string]$Session.State];$Session.AnalysisState='Unavailable'
        $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
    }
    return $j
}
function Assert-MiGeneratedTraceData {
    param([string]$Path)
    if (-not (Test-MiNoReparse $Path) -or -not (Test-MiAclRestricted $Path $false)) {throw 'Untrusted generated trace data.'}
    $parent=Split-Path -Parent $Path;Assert-MiTracePath $parent
}
function Repair-MiWprSavedArtifacts {
    # Recovery Wizard 仅恢复已经确认停止、具有保存意图的事务，不补发 Start/Stop。
    Assert-MiWprReleaseAccepted
    $lease=Enter-MiDeploymentLease
    try {
        [void](Assert-MiWatchdog);$lock=Enter-MiTraceLock
        try {
            $j=Read-MiTraceJournal $lock
            foreach ($session in @($j.Sessions.Values)) {
                if ($session.State -cin @('TraceNotSaved','RecoveryRequired','Saving','Saved','Cleaning','Analyzing') -and $session.StopState -ceq 'Confirmed' -and
                    (Test-MiGuidN $session.PlannedArtifactId)) {
                    if ($null -eq $session.StopProcess -or (Test-MiWprProcessRunning $session.StopProcess)) {throw 'Save writer may still be running.'}
                    if ($session.State -ceq 'TraceNotSaved') {$session.State='RecoveryRequired';$j=Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session}
                    try {$j=Complete-MiWprArtifact $lock $session} catch {
                        $failure=$_.Exception.Message;$j=Read-MiTraceJournal $lock;$session=$j.Sessions[$session.TraceSessionId]
                        $session.State='RecoveryRequired';$session.ErrorCode=$failure
                        [void](Add-MiTraceJournalRecord $lock $j.Revision 'Session' $session);throw
                    }
                }
            }
        } finally {$lock.Dispose()}
    } finally {$lease.Dispose()}
}
function Request-MiWprStop {
    param($Lock,$Session,[string]$Reason='UserRequested')
    $j=Read-MiTraceJournal $Lock
    $fresh=$j.Sessions[$Session.TraceSessionId]
    if ($null -eq $fresh -or ($fresh|ConvertTo-Json -Depth 16 -Compress) -cne ($Session|ConvertTo-Json -Depth 16 -Compress)) {throw 'Stale stop claim rejected.'}
    if ($Session.State -cnotin @('Recording','DeadlineExceeded') -or $null -ne $Session.StopOperationId) {throw 'Stop already claimed or state uncertain; no retry.'}
    $observed=@(Get-MiEtwSessions);Assert-MiWprOwnership $Session $observed
    $Session.State='Stopping';$Session.StopState='Pending';$Session.SaveState='Pending'
    Set-MiTraceMember $Session 'StopOperationId' ([guid]::NewGuid().ToString('N'))
    Set-MiTraceMember $Session 'StopRequestedUtc' ([datetime]::UtcNow.ToString('o'));Set-MiTraceMember $Session 'StopReason' $Reason
    $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
    try {
        Set-MiTraceMember $Session 'StopProcess' (Start-MiWprProcess 'Stop' $Session)
        return Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
    } catch {
        $Session.State='UnknownOutcome';$Session.StopState='Unknown';$Session.ErrorCode=$_.Exception.Message
        [void](Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session);throw
    }
}
function Update-MiWprSession {
    param($Lock,$Session)
    $j=Read-MiTraceJournal $Lock
    if ($Session.State -cin @('Recording','DeadlineExceeded')) {
        try {
            Assert-MiWprOwnership $Session @(Get-MiEtwSessions)
            if ([datetime]::UtcNow -ge (ConvertTo-MiTraceUtc $Session.DeadlineUtc)) {
                if ($Session.State -cne 'DeadlineExceeded') {$Session.State='DeadlineExceeded';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session}
                return Request-MiWprStop $Lock $Session 'DeadlineExceeded'
            }
            try {$resources=Get-MiWprResources $Session} catch {return Request-MiWprStop $Lock $Session 'ResourceMonitoringUnavailable'}
            # File 录制最多占工作预算的一半，为停止后的合并保留同等空间；周期监督不是硬配额。
            $recordingLimit=if ($Session.RecordingMode -ceq 'File') {[long]($Session.TraceWorkingBudget/2)} else {$Session.TraceWorkingBudget}
            $saveReserve=[decimal]2147483648+[Math]::Max([long]1073741824,[long]$resources.WorkingBytes)
            if ($resources.WorkingBytes -ge $recordingLimit -or $resources.FreeBytes -lt $saveReserve -or $resources.AvailableMemoryBytes -lt 536870912) {
                return Request-MiWprStop $Lock $Session 'ResourceProtection'
            }
            $Session.LastVerifiedUtc=[datetime]::UtcNow.ToString('o')
            return Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
        } catch {
            $fresh=Read-MiTraceJournal $Lock;$Session=$fresh.Sessions[$Session.TraceSessionId]
            if ($Session.State -cin @('Recording','DeadlineExceeded')) {
                $Session.State='RecoveryRequired';$Session.ErrorCode=$_.Exception.Message
                return Add-MiTraceJournalRecord $Lock $fresh.Revision 'Session' $Session
            }
            return $fresh
        }
    }
    if ($Session.State -cin @('Stopping','Saving')) {
        try {
            if ($null -eq $Session.StopProcess) {throw 'Stop dispatch outcome unknown.'}
            $live=Test-MiWprProcessRunning $Session.StopProcess
            $sessions=@(Get-MiEtwSessions)
            $matching=@($sessions|Where-Object Name -ceq $Session.OwnershipEvidence.Name)
            if ($matching.Count -eq 0 -and $Session.State -ceq 'Stopping') {
                $Session.StopState='Confirmed';$Session.State='Saving';Set-MiTraceMember $Session 'StoppedObservedUtc' ([datetime]::UtcNow.ToString('o'))
                $j=Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
            } elseif ($matching.Count -gt 0) {Assert-MiWprOwnership $Session $sessions}
            if ($live) {
                if (([datetime]::UtcNow-(ConvertTo-MiTraceUtc $Session.StopRequestedUtc)).TotalSeconds -gt 180) {throw 'Stop/save outcome unknown after bounded observation; no retry.'}
                return $j
            }
            if ($matching.Count -gt 0) {throw 'WPR exited but recording remains; no retry.'}
            return Complete-MiWprArtifact $Lock $Session
        } catch {
            $failure=$_.Exception.Message;$j=Read-MiTraceJournal $Lock;$Session=$j.Sessions[$Session.TraceSessionId]
            $Session.ErrorCode=$failure
            if ($Session.StopState -ceq 'Confirmed') {
                if ($Session.State -ceq 'Saving' -and $null -eq $j.Artifacts[$Session.PlannedArtifactId]) {$Session.State='TraceNotSaved';$Session.SaveState='Failed'}
                else {$Session.State='RecoveryRequired'}
            } else {$Session.State='UnknownOutcome';$Session.StopState='Unknown'}
            return Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
        }
    }
    if ($Session.State -cin @('Saved','Cleaning','Analyzing')) {
        try {return Complete-MiWprArtifact $Lock $Session} catch {
            $failure=$_.Exception.Message;$j=Read-MiTraceJournal $Lock;$Session=$j.Sessions[$Session.TraceSessionId]
            $Session.State='RecoveryRequired';$Session.ErrorCode=$failure
            return Add-MiTraceJournalRecord $Lock $j.Revision 'Session' $Session
        }
    }
    return $j
}
function Invoke-MiWprStop {
    param([string]$SessionId)
    Assert-MiWprReleaseAccepted
    if (-not (Test-MiGuidN $SessionId)) {throw 'Invalid trace session identity.'}
    $lease=Enter-MiDeploymentLease
    try {
    [void](Assert-MiWatchdog);$lock=Enter-MiTraceLock
    try {
        $j=Read-MiTraceJournal $lock;$session=$j.Sessions[$SessionId]
        if ($null -eq $session) {throw 'Unknown trace; not controlled by this tool.'}
        if ($session.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {throw 'Trace stop belongs to another authorizing user.'}
        [void](Request-MiWprStop $lock $session)
    } finally {$lock.Dispose()}
    } finally {$lease.Dispose()}
}
function Invoke-MiTraceRetention {
    param($Lock)
    $j=Read-MiTraceJournal $Lock
    foreach ($artifact in @($j.Artifacts.Values|Sort-Object CreatedUtc)) {
        if ($artifact.State -cnotin @('Ready','Retiring') -or $artifact.ActiveReferences -ne 0 -or [datetime]::UtcNow -lt (ConvertTo-MiTraceUtc $artifact.RetainUntilUtc)) {continue}
        $session=$j.Sessions[$artifact.TraceSessionId]
        if (Test-MiTraceObligation $session) {continue}
        $source=Get-MiTraceArtifactPath $artifact;$target=Get-MiTraceArtifactPath $artifact -Retained
        $atSource=[IO.File]::Exists($source);$atTarget=[IO.File]::Exists($target)
        if ($atSource -eq $atTarget -or ($artifact.State -ceq 'Ready' -and -not $atSource)) {throw 'Ambiguous retention transaction.'}
        $actual=if ($atSource) {$source} else {$target};Assert-MiTracePath $actual
        # 活跃读句柄不允许删除共享时不移动。真正 Move 仍受 OS 共享检查，失败保留 Retiring 意图。
        try {$probe=[IO.File]::Open($actual,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)} catch [IO.IOException] {continue}
        $probe.Dispose()
        $verified=Test-MiEtlArtifact $actual
        if ($verified.SizeBytes -ne $artifact.SizeBytes -or $verified.Sha256 -cne $artifact.Sha256) {throw 'Artifact changed; retention refused.'}
        $directory=Split-Path -Parent $target
        if (-not [IO.Directory]::Exists($directory)) {[void][IO.Directory]::CreateDirectory($directory);Set-MiDiagnosticAccess $directory $artifact.OwnerSid -Directory}
        Assert-MiTracePath $directory
        if ($artifact.State -ceq 'Ready') {$artifact.State='Retiring';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'Artifact' $artifact}
        if ($atSource) {[IO.File]::Move($source,$target)}
        $artifact.State='Retained';$j=Add-MiTraceJournalRecord $Lock $j.Revision 'Artifact' $artifact
        # 项目要求不实际删除：7 天后归档仍计入预算，不虚报释放空间。每轮最多处理一个。
        break
    }
    return $j
}
