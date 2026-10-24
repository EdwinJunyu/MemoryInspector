#requires -Version 5.1
<# M6 regression: source parsing, secure pure contracts, and disposable ACL fixture.
No UAC prompt, service modification, process termination, or install performed. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('PrivilegeSecurity.ps1','PrivilegeBridge.ps1','ElevatedExecutor.ps1',
    'Installer.ps1','Uninstaller.ps1','MemoryInspector.ps1','GuiV4.ps1')
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
if ((Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim() -cne '0.0.6') {
    throw 'VERSION mismatch.'
}
# Lightweight ACL smoke test in a uniquely named throwaway temp directory.
# This is deliberately NOT an installation and never changes Windows services.
if (Test-MiAdminToken) {
    $dir=Join-Path ([IO.Path]::GetTempPath()) ('MiM6AclTest-'+[guid]::NewGuid().ToString('N'))
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
        if ([IO.Directory]::Exists($dir)) { [IO.Directory]::Delete($dir,$true) }
    }
} else {
    Write-Host 'INFO: non-admin CI host; disposable ACL fixture skipped.'
}
Write-Host 'PASS: M6 protected installer, allow-only Probe, anti-replay and ACL contract.' -ForegroundColor Green
