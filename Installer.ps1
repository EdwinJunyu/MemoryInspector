#requires -Version 5.1
<#
Milestone 6 protected installer. Run explicitly from an elevated Windows PowerShell 5.1
after reviewing the downloaded source. No service changes, no scheduled tasks,
no automatic startup, and no privilege escalation inside this installer.
#>
$ErrorActionPreference='Stop'
if (-not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) { throw 'Windows only.' }
$source=Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $source 'PrivilegeSecurity.ps1')
if (-not (Test-MiAdminToken)) { throw 'Run Installer.ps1 in an explicitly elevated Windows PowerShell.' }
$paths=Get-MiSecurityPaths
$names=@(
    'MemoryInspector.ps1','Collector.ps1','Worker.ps1','Persistence.ps1',
    'Analyzer.ps1','GuiV4.ps1','ProcessActions.ps1','PrivilegeSecurity.ps1',
    'PrivilegeBridge.ps1','ServiceBridge.ps1','ServiceManagement.ps1',
    'ElevatedExecutor.ps1','Run_MemoryInspector.cmd',
    'Installer.ps1','Uninstaller.ps1','VERSION'
)
foreach ($name in $names) {
    $f=Join-Path $source $name
    if (-not [IO.File]::Exists($f) -or -not (Test-MiNoReparse $f)) { throw ('Missing or reparse source: '+$name) }
}
if (([IO.File]::ReadAllText((Join-Path $source 'VERSION'))).Trim() -cne '0.0.8') {
    throw 'Expected VERSION 0.0.8; installation canceled.'
}
# Never replace an untrusted directory: refuse to overwrite arbitrary existing files.
if ([IO.Directory]::Exists($paths.Install)) {
    [void](Assert-MiTrustedInstallation -AllowedVersions @('0.0.7','0.0.8'))
}
$parent=Split-Path -Parent $paths.Install
if (-not [IO.Directory]::Exists($parent)) { throw 'Program Files parent folder missing.' }
$stage=Join-Path $parent ('MemoryInspector.stage-'+[guid]::NewGuid().ToString('N'))
$backup=$null; $swapped=$false; $dataReady=$false
try {
    [void][IO.Directory]::CreateDirectory($stage)
    Set-MiAdminDirectoryAcl -Path $stage -AllowUsersRead $true
    $entries=New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $names) {
        $src=Join-Path $source $name
        $dst=Join-Path $stage $name
        # Byte-copy into a newly created file; no hardlinks/symlinks.
        $bytes=[IO.File]::ReadAllBytes($src)
        [IO.File]::WriteAllBytes($dst,$bytes)
        Set-MiProtectedFileAcl -Path $dst -AllowUsersRead $true
        $entries.Add([pscustomobject]@{
            Name=$name
            Sha256=(Get-FileHash -LiteralPath $dst -Algorithm SHA256 -ErrorAction Stop).Hash
        })
    }
    if (-not [IO.Directory]::Exists($paths.Data)) {
        [void][IO.Directory]::CreateDirectory($paths.Data)
        Set-MiAdminDirectoryAcl -Path $paths.Data
    } elseif (-not (Test-MiNoReparse $paths.Data) -or -not (Test-MiAclRestricted $paths.Data $true)) {
        throw 'Existing ProgramData directory is not protected; refusing to reuse it.'
    }
    foreach ($folder in @((Split-Path -Parent $paths.Audit),$paths.Replay,$paths.Results,$paths.PolicyFolder)) {
        if (-not [IO.Directory]::Exists($folder)) {
            [void][IO.Directory]::CreateDirectory($folder)
            Set-MiAdminDirectoryAcl -Path $folder
        } elseif (-not (Test-MiNoReparse $folder) -or -not (Test-MiAclRestricted $folder $true)) {
            throw 'Untrusted existing protected subdirectory.'
        }
    }
    # Read/traverse access only for standard users; all protected writes remain admin-only.
    Set-MiAdminDirectoryAcl -Path $paths.Data -AllowUsersRead $true
    Set-MiAdminDirectoryAcl -Path $paths.PolicyFolder -AllowUsersRead $true
    # Create empty administrator-approved service allowlist and recovery ledger.
    if (-not [IO.File]::Exists($paths.Policy)) {
        [IO.File]::WriteAllText($paths.Policy,'{"SchemaVersion":1,"Services":[]}',[Text.UTF8Encoding]::new($false))
        Set-MiProtectedFileAcl -Path $paths.Policy -AllowUsersRead $true
    } elseif (-not (Test-MiNoReparse $paths.Policy) -or -not (Test-MiAclRestricted $paths.Policy $true)) {
        throw 'Service policy is untrusted.'
    }
    # Standard users may read the allowlist for UI only; writes stay administrator-only.
    Set-MiProtectedFileAcl -Path $paths.Policy -AllowUsersRead $true
    if (-not [IO.File]::Exists($paths.Recovery)) {
        [IO.File]::WriteAllText($paths.Recovery,'{"SchemaVersion":1,"Records":[]}',[Text.UTF8Encoding]::new($false))
        Set-MiProtectedFileAcl -Path $paths.Recovery
    } elseif (-not (Test-MiNoReparse $paths.Recovery) -or -not (Test-MiAclRestricted $paths.Recovery $true)) {
        throw 'Service recovery ledger is untrusted.'
    }
    if (-not [IO.File]::Exists($paths.Audit)) {
        [IO.File]::WriteAllText($paths.Audit,'',[Text.UTF8Encoding]::new($false))
        Set-MiProtectedFileAcl -Path $paths.Audit
    } elseif (-not (Test-MiNoReparse $paths.Audit) -or -not (Test-MiAclRestricted $paths.Audit $true)) {
        throw 'Existing privileged audit is untrusted.'
    }
    $dataReady=$true
    $manifest=[pscustomobject]@{
        SchemaVersion=1; Version='0.0.8'; InstalledUtc=[datetime]::UtcNow.ToString('o')
        Files=@($entries.ToArray())
    }
    $newManifest=Join-Path $paths.Data ('install-manifest-'+[guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::WriteAllText($newManifest,($manifest | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false))
    Set-MiProtectedFileAcl -Path $newManifest
    if ([IO.Directory]::Exists($paths.Install)) {
        $backup=Join-Path $parent ('MemoryInspector.backup-'+[guid]::NewGuid().ToString('N'))
        [IO.Directory]::Move($paths.Install,$backup)
    }
    [IO.Directory]::Move($stage,$paths.Install); $swapped=$true
    # The manifest is written last. Validate the entire new install before success.
    if ([IO.File]::Exists($paths.Manifest)) {
        # Existing manifest may be retained if an upgrade fails later.
        $oldManifest=Join-Path $paths.Data ('install-manifest-backup-'+[guid]::NewGuid().ToString('N')+'.tmp')
        [IO.File]::Move($paths.Manifest,$oldManifest)
    }
    [IO.File]::Move($newManifest,$paths.Manifest)
    [void](Assert-MiTrustedInstallation)
    if ($null -ne $backup -and [IO.Directory]::Exists($backup)) {
        [IO.Directory]::Delete($backup,$true)
    }
    if ($null -ne $oldManifest -and [IO.File]::Exists($oldManifest)) { [IO.File]::Delete($oldManifest) }
    Write-Host ('Installed MemoryInspector 0.0.8 in '+$paths.Install) -ForegroundColor Green
    Write-Host 'M8 release-candidate: run complete acceptance before stable release.'
    Write-Host ('Launch the protected GUI using: '+(Join-Path $paths.Install 'Run_MemoryInspector.cmd'))
} catch {
    $err=$_.Exception.Message
    # Do not erase the previous install if restoration is unsafe or uncertain.
    if ($swapped -and [IO.Directory]::Exists($paths.Install)) {
        try { [IO.Directory]::Delete($paths.Install,$true) } catch {}
    }
    if ($null -ne $backup -and [IO.Directory]::Exists($backup) -and
        -not [IO.Directory]::Exists($paths.Install)) {
        try { [IO.Directory]::Move($backup,$paths.Install) } catch {}
    }
    if ($null -ne $oldManifest -and [IO.File]::Exists($oldManifest)) {
        try {
            if ([IO.File]::Exists($paths.Manifest)) { [IO.File]::Delete($paths.Manifest) }
            [IO.File]::Move($oldManifest,$paths.Manifest)
        } catch {}
    }
    throw ('Installation failed (fail-closed). '+$err)
} finally {
    if ([IO.Directory]::Exists($stage)) {
        try { [IO.Directory]::Delete($stage,$true) } catch {}
    }
}
