#requires -Version 5.1
<#
M6 disposable GitHub Actions Windows runner installation acceptance.
Must only be executed on a fresh, disposable runner; NEVER on a user machine.
No service/process modifications. Requires an elevated runner token.
#>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'PrivilegeSecurity.ps1')
if (-not (Test-MiAdminToken)) {
    Write-Host 'SKIP: CI runner is not elevated; cannot exercise protected installation.'
    return
}
$paths=Get-MiSecurityPaths
if ([IO.Directory]::Exists($paths.Install) -or [IO.Directory]::Exists($paths.Data)) {
    throw 'CI installation fixture requires fresh paths. Refusing to overwrite existing installation.'
}
function Invoke-MiTestExecutor {
    param([string]$Operation,[string]$RequestId)
    $exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+'" -Operation '+$Operation+' -RequestId '+$RequestId
    $process=Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
    try { return [int]$process.ExitCode } finally { $process.Dispose() }
}
& (Join-Path $root 'Installer.ps1')
[void](Assert-MiTrustedInstallation)
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
