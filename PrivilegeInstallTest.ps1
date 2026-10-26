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
    param([string]$Operation,[string]$RequestId,[ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType='VirtualAlloc')
    $exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+'" -Operation '+$Operation+' -RequestId '+$RequestId
    if ($Operation -ceq 'TraceStart') {$args+=' -TraceType '+$TraceType}
    if ($Operation -ceq 'TraceExportPrepare') {$args+=' -ArtifactId '+[guid]::NewGuid().ToString('N')}
    $process=Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    try { return [int]$process.ExitCode } finally { $process.Dispose() }
}
& (Join-Path $root 'Installer.ps1')
[void](Assert-MiTrustedInstallation)
$watchdog=Assert-MiWatchdog
[void](Invoke-MiTraceHealthCheck)
if ((Invoke-MiTestExecutor 'TracePreflight' ([guid]::NewGuid().ToString('N'))) -eq 0) { throw 'M2 unexpectedly enabled WPR.' }
if ((Invoke-MiTestExecutor 'TraceStart' ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Unaccepted M3 launch escaped code-level gate.'}
if ((Invoke-MiTestExecutor 'TraceStart' ([guid]::NewGuid().ToString('N')) 'Heap') -eq 0) {throw 'Unaccepted M4 Heap request escaped code-level gate.'}
if ((Invoke-MiTestExecutor 'TraceExportPrepare' ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Unaccepted M5 export escaped code-level gate.'}
if ((Invoke-MiTestExecutor 'TraceWatchdog' 'Scheduled') -eq 0) { throw 'Administrator impersonated SYSTEM watchdog.' }
$lock=Enter-MiTraceLock
try {
    $j=Read-MiTraceJournal $lock; Assert-MiTraceQuiescent $j
    if ($j.HeapTransactions.Count -ne 0) {throw 'Disabled Heap request created a transaction.'}
    if (@($j.Sessions.Values).Count -ne 1 -or @($j.Sessions.Values)[0].ErrorCode -cne 'TraceBackendUnavailable') {throw 'Preflight did not persist explicit M3 gate.'}
} finally {$lock.Dispose()}
# 真实任务被禁用后必须拒绝高权限请求，恢复原值仅用于本次隔离测试。
$watchdog.Task.Enabled=$false
try {
    if ((Invoke-MiTestExecutor Probe ([guid]::NewGuid().ToString('N'))) -eq 0) {throw 'Disabled watchdog escaped gate.'}
} finally {$watchdog.Task.Enabled=$true}
[void](Invoke-MiTraceHealthCheck)
Write-Host 'PASS: real SYSTEM health handshake, exact fixed task gate, M3 recording disabled.'
# P1-03：仅 disposable runner，验证真实受保护目录内持有独占句柄时的 ACL 设置及锁释放。
# 不请求任何 SCM 变更，不删除锁文件；该部分覆盖单元测试中模拟 ACL 无法验证的 Windows 行为。
. (Join-Path $paths.Install 'ServiceManagement.ps1')
foreach ($kind in @('Target','Policy','Recovery')) {
    $held=Enter-MiServiceLock -Kind $kind -Name 'MemoryInspector.P1DedicatedFixture'
    try {
        $leaf=if ($kind -eq 'Target') {'service-memoryinspector.p1dedicatedfixture.lock'} else {$kind.ToLowerInvariant()+'.lock'}
        $lockPath=Join-Path $paths.PolicyFolder $leaf
        if (-not (Test-MiAclRestricted $lockPath $true) -or -not (Test-MiNoReparse $lockPath)) {
            throw 'Protected operation lock ACL/path check failed.'
        }
        $refused=$false
        try {$unexpected=Enter-MiServiceLock -Kind $kind -Name 'memoryinspector.p1dedicatedfixture' -TimeoutMilliseconds 0}
        catch {$refused=$true}
        if (-not $refused) {$unexpected.Dispose();throw 'Held protected lock was acquired twice.'}
    } finally {$held.Dispose()}
    $reopened=Enter-MiServiceLock -Kind $kind -Name 'memoryinspector.p1dedicatedfixture'
    $reopened.Dispose()
}
Write-Host 'PASS: protected target/policy/recovery lock ACLs, exclusion and release.' -ForegroundColor Green
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
$svcProc=Start-Process -FilePath $svcExe -ArgumentList $svcArgs -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
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
# 保留 Journal 的正常卸载必须允许安全重装，不得删除日志才能再次安装。
& (Join-Path $root 'Installer.ps1')
[void](Invoke-MiTraceHealthCheck)
& (Join-Path $root 'Uninstaller.ps1')
Write-Host 'PASS: M2 retired journal reused after verified uninstall/reinstall; task and payload removed from active paths.'
