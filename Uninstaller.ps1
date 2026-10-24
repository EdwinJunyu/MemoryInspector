#requires -Version 5.1
<# Controlled uninstall; leaves user monitoring history and protected audits by default.
Requires an elevated shell and a verified M6 installation. #>
param([switch]$PurgeProtectedData)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'PrivilegeSecurity.ps1')
if (-not (Test-MiAdminToken)) { throw 'Administrator permission required.' }
$paths=Assert-MiTrustedInstallation
$answer=Read-Host 'Type UNINSTALL MEMORYINSPECTOR to remove the protected program files'
if ($answer -cne 'UNINSTALL MEMORYINSPECTOR') { throw 'Uninstall cancelled.' }
$manifest=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Manifest,[Text.Encoding]::UTF8))
foreach ($entry in @($manifest.Files)) {
    $name=[string]$entry.Name
    if ($name -cnotmatch '^[A-Za-z0-9_-]+\.(ps1|cmd)$' -and $name -cne 'VERSION') {
        throw 'Unexpected installed file; aborting.'
    }
    $f=Join-Path $paths.Install $name
    if (-not (Test-MiNoReparse $f)) { throw 'Unexpected reparse point; aborting.' }
}
# Fail rather than recursively deleting unknown files.
$actual=@(Get-ChildItem -LiteralPath $paths.Install -Force -File)
if ($actual.Count -ne @($manifest.Files).Count -or
    @(Get-ChildItem -LiteralPath $paths.Install -Force -Directory).Count -ne 0) {
    throw 'Installation contains unexpected content. No files removed.'
}
foreach ($entry in @($manifest.Files)) {
    [IO.File]::Delete((Join-Path $paths.Install ([string]$entry.Name)))
}
[IO.Directory]::Delete($paths.Install,$false)
Write-Host 'Program files removed. Per-user monitoring history was preserved.' -ForegroundColor Green
if ($PurgeProtectedData) {
    $sure=Read-Host 'Type PURGE AUDIT to irreversibly remove protected M6 audit and replay history'
    if ($sure -cne 'PURGE AUDIT') { Write-Warning 'Protected data retained.'; return }
    # This is admin-only and verified against known protected paths, never a caller-supplied directory.
    if (-not (Test-MiAclRestricted $paths.Data $true) -or -not (Test-MiNoReparse $paths.Data)) {
        throw 'Protected data directory no longer trusted; manual inspection required.'
    }
    foreach ($folder in @($paths.Replay,$paths.Results,(Split-Path -Parent $paths.Audit))) {
        if (-not (Test-MiAclRestricted $folder $true) -or -not (Test-MiNoReparse $folder)) {
            throw 'Unsafe protected data subdirectory; manual inspection required.'
        }
    }
    [IO.Directory]::Delete($paths.Data,$true)
    Write-Host 'Protected M6 data was explicitly purged.'
} else {
    Write-Host ('Protected audit and replay data retained at '+$paths.Data)
}
