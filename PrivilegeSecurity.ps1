#requires -Version 5.1
<#
Milestone 6: shared, conservative installation and privileged-protocol checks.
Only the elevated installer/executor may WRITE protected state.
There are no Windows service or process mutations in this module.
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
    if ($Operation -cin @('TracePreflight','TraceHealth','TraceRecovery')) { return $ServiceName -ceq '' }
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
}
function Test-MiTraceObligation {
    param($Session)
    Assert-MiTraceSession $Session
    if ($Session.CleanupState -cnotin @('NotRequired','Restored') -or $Session.ActiveReferences -ne 0) { return $true }
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
    foreach ($field in @('TraceSessionId','WprInstanceName','OwnerSid','BootSessionId','RequestedTraceType','RecordingMode','RequestedDuration')) {
        if ($Previous.$field -cne $Next.$field) { throw 'Immutable trace identity changed.' }
    }
    foreach ($field in @('StartedUtc','DeadlineUtc','AuthorizationId','ProfileId','ProfileFingerprint','WprExecutableIdentity')) {
        if ($null -ne $Previous.$field -and ($Previous.$field|ConvertTo-Json -Compress -Depth 6) -cne ($Next.$field|ConvertTo-Json -Compress -Depth 6)) { throw 'Bound trace authorization changed.' }
    }
    $edges=@{
        Requested=@('Preflight','AuthorizationDenied','RecoveryRequired'); Preflight=@('Authorized','ConflictBlocked','AuthorizationDenied','ResourcePreflightRejected','RecoveryRequired')
        Authorized=@('Preparing','RecoveryRequired'); Preparing=@('Recording','UnknownOutcome','RecoveryRequired')
        Recording=@('Stopping','DeadlineExceeded','UnknownOutcome','RecoveryRequired'); DeadlineExceeded=@('Stopping','RecoveryRequired')
        Stopping=@('Saving','UnknownOutcome','TraceNotSaved','RecoveryRequired'); Saving=@('Saved','TraceNotSaved','UnknownOutcome','RecoveryRequired')
        Saved=@('Cleaning','RecoveryRequired'); Cleaning=@('Analyzing','CleanupPending','RecoveryRequired')
        Analyzing=@('Completed','AnalysisPartial','RecoveryRequired'); AnalysisPartial=@('Analyzing','RecoveryRequired')
        CleanupPending=@('RecoveryRequired'); UnknownOutcome=@('RecoveryRequired'); TraceNotSaved=@('RecoveryRequired')
        RecoveryRequired=@('RecoveryRequired')
    }
    if (-not $edges.ContainsKey([string]$Previous.State) -or $Next.State -cnotin $edges[[string]$Previous.State]) { throw 'Illegal trace transition or replay.' }
    if ($Previous.CleanupState -cin @('Pending','Conflict') -and $Next.CleanupState -ceq 'NotRequired') { throw 'Cleanup obligation cannot disappear.' }
}
function Read-MiTraceJournal {
    param($Lock)
    Assert-MiTraceLockHeld $Lock
    $p=Get-MiSecurityPaths
    Assert-MiTracePath $p.TraceRoot; Assert-MiTracePath $p.TraceJournal; Assert-MiTracePath $p.TraceWorkspace
    $text=[IO.File]::ReadAllText($p.TraceJournal,[Text.UTF8Encoding]::new($false,$true))
    if ([string]::IsNullOrWhiteSpace($text) -or -not $text.EndsWith("`n")) { throw 'Empty or torn trace journal; recovery required.' }
    $result=[pscustomobject]@{Revision=0;Hash=('0'*64);Sessions=@{};Challenge=$null;Response=$null;Deployment=$null;DeploymentRecord=$null;InstallationId=$null}
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
                $result.Sessions[$payload.TraceSessionId]=$payload
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
        if (-not $current.Sessions.ContainsKey($Payload.TraceSessionId) -and
            @($current.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -ne 0) { throw 'Existing trace requires recovery.' }
    } elseif ($Kind -cin @('Deployment','HealthChallenge','HealthResponse')) { Assert-MiTraceControlRecord $Kind $Payload $current }
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
    if (@($Journal.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -gt 0) { throw 'Unfinished trace or cleanup blocks deployment; use TraceRecovery.' }
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
                @($j.Sessions.Values|Where-Object {Test-MiTraceObligation $_}).Count -gt 0);
            DeploymentBlocked=($j.Deployment -cne 'Ready');TaskBlocked=($taskStatus -cne 'DefinitionVerified');
            ServiceRecoveryBlocked=$serviceBlocked;
            WprState='UnavailableInM2';HeapTransactions='NotSupportedInM2';
            Guidance='M2 cannot establish actual WPR ownership. Preserve this report and protected journal; do not cancel unknown traces or clear records. Recovery remains blocked until a supported verifier proves real system state.'}
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
