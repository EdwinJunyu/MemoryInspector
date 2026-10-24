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
# M7 protected defaults: no services approved and recovery record empty.
$policy=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Policy,[Text.Encoding]::UTF8)) -ErrorAction Stop
$recovery=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Recovery,[Text.Encoding]::UTF8)) -ErrorAction Stop
if (@($policy.Services).Count -ne 0 -or @($recovery.Records).Count -ne 0) { throw 'Unsafe nonempty initial service state.' }
if (-not (Test-MiAclRestricted $paths.Policy $true) -or -not (Test-MiAclRestricted $paths.Recovery $true)) { throw 'Unprotected service state.' }
$svcExe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$svcId=[guid]::NewGuid().ToString('N')
$svcArgs='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+
    '" -Operation StopApprovedService -RequestId '+$svcId+' -ServiceName RpcSs'
$svcProc=Start-Process -FilePath $svcExe -ArgumentList $svcArgs -PassThru -Wait -ErrorAction Stop
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
