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
    if (-not (Test-MiGuidN $RequestId)) { return $false }
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
