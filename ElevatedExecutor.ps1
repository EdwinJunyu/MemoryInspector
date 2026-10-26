#requires -Version 5.1
<#
M7 / V3-M3 protected, short-lived executor. Fixed service and trace operations only.
Unaccepted WPR features remain disabled by the code-level release policy. Unknown identity, invalid ACL, changed binary, missing audit or
running dependents always fails closed. Never kills a service host process.
#>
param(
    [Parameter(Mandatory=$true)][string]$Operation,
    [Parameter(Mandatory=$true)][string]$RequestId,
    [string]$ServiceName='',
    [ValidateSet('VirtualAlloc','Pool')][string]$TraceType='VirtualAlloc',
    [ValidateSet('Memory','File')][string]$RecordingMode='Memory',
    [ValidateRange(300,1800)][int]$DurationSeconds=300,
    [string]$TraceSessionId=''
)
$ErrorActionPreference='Stop'
$exitCode=2
$trusted=$false
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or
        -not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
        throw 'Unsupported Windows PowerShell host.'
    }
    if ($MyInvocation.UnboundArguments.Count -gt 0) { throw 'Unexpected arguments.' }
    $root=Split-Path -Parent $MyInvocation.MyCommand.Path
    . (Join-Path $root 'PrivilegeSecurity.ps1')
    if (-not (Test-MiAdminToken)) { throw 'Elevated administrator token required.' }
    if (-not (Test-MiPrivilegedOperation -Operation $Operation -RequestId $RequestId -ServiceName $ServiceName)) {
        throw 'Unsupported operation, invalid request ID, or invalid service name.'
    }
    # 每种命令只接受其自身的固定参数，不静默忽略跨操作参数。
    foreach ($parameter in @('TraceType','RecordingMode','DurationSeconds')) {
        if ($PSBoundParameters.ContainsKey($parameter) -and $Operation -cne 'TraceStart') {throw 'Unexpected trace start parameter.'}
    }
    if (($PSBoundParameters.ContainsKey('TraceSessionId') -and $Operation -cne 'TraceStop') -or
        ($Operation -ceq 'TraceStop' -and -not (Test-MiGuidN $TraceSessionId))) {throw 'Unexpected or invalid trace session parameter.'}
    if ($Operation -cin @('TraceStart','TraceStop')) {Assert-MiWprReleaseAccepted}
    $paths=Assert-MiTrustedInstallation
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath($root).TrimEnd('\'),
        [IO.Path]::GetFullPath($paths.Install).TrimEnd('\'),
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Executor must run from verified protected installation.'
    }
    $trusted=$true
    $installationManifest=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json
    if ($installationManifest.TraceArchitectureVersion -eq 1 -and $Operation -cne 'TraceRecovery') {
        [void](Assert-MiWatchdog)
    }
    if ($Operation -ceq 'TraceWatchdog') {
        # 定时任务不使用普通请求的 nonce；SYSTEM 身份、固定任务与完整安装均另行核验。
        Invoke-MiTraceWatchdog
        exit 0
    }
    # Atomic CreateNew claim prevents replay, including concurrent elevated processes.
    $marker=Join-Path $paths.Replay ($RequestId.ToLowerInvariant()+'.nonce')
    $stream=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $content=[Text.UTF8Encoding]::new($false).GetBytes([datetime]::UtcNow.ToString('o'))
        $stream.Write($content,0,$content.Length);$stream.Flush($true)
    } finally { $stream.Dispose() }
    Set-MiProtectedFileAcl -Path $marker
    if ($Operation -ceq 'Probe') {
        Write-MiPrivilegedAudit -RequestId $RequestId -State 'REQUESTED' -Reason 'UAC readiness probe'
        Write-MiPrivilegedAudit -RequestId $RequestId -State 'CONFIRMED' -Reason 'Protected install/replay/audit checks passed'
        $exitCode=0
    } elseif ($Operation -ceq 'TraceHealth') {
        [void](Invoke-MiTraceHealthCheck)
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -State 'CONFIRMED' -Reason 'Fresh SYSTEM scan and challenge response verified'
        $exitCode=0
    } elseif ($Operation -ceq 'TracePreflight') {
        Invoke-MiTracePreflight $RequestId | Format-List
        $exitCode=2 # M2 不开放实际 WPR，拒绝不能伪装成成功启动。
    } elseif ($Operation -ceq 'TraceStart') {
        $trace=Invoke-MiWprStart $RequestId $TraceType $RecordingMode $DurationSeconds
        $trace|Format-List
        $exitCode=if ($trace.State -ceq 'Recording') {0} else {2}
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -State $trace.State -Reason 'Fixed profile trace request'
    } elseif ($Operation -ceq 'TraceStop') {
        Invoke-MiWprStop $TraceSessionId
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -State 'DISPATCHED' -Reason ('Asynchronous stop for '+$TraceSessionId)
        $exitCode=0
    } elseif ($Operation -ceq 'TraceArtifacts') {
        $lock=Enter-MiTraceLock
        try {@((Read-MiTraceJournal $lock).Artifacts.Values)|ConvertTo-Json -Depth 12|Write-Output} finally {$lock.Dispose()}
        $exitCode=0
    } elseif ($Operation -ceq 'TraceRecovery') {
        Get-MiTraceRecoveryReport | ConvertTo-Json -Depth 12 | Write-Output
        $answer=Read-Host 'Type VERIFY DEPLOYMENT or RECOVER SAVED ARTIFACTS; Enter only keeps the report'
        if ($answer -ceq 'VERIFY DEPLOYMENT') {
            Invoke-MiTraceDeploymentRecovery
            Get-MiTraceRecoveryReport | ConvertTo-Json -Depth 12 | Write-Output
        }
        if ($answer -ceq 'RECOVER SAVED ARTIFACTS') {
            Repair-MiWprSavedArtifacts
            Get-MiTraceRecoveryReport|ConvertTo-Json -Depth 12|Write-Output
        }
        $exitCode=0 # 仅表示生成报告；报告明确独立列出恢复阻断。
    } else {
        $lease=Enter-MiDeploymentLease
        try {
            $paths=Assert-MiTrustedInstallation
            $manifest=[IO.File]::ReadAllText($paths.Manifest)|ConvertFrom-Json
            if ($manifest.TraceArchitectureVersion -eq 1) {
                $stateLock=Enter-MiTraceLock
                try { if ((Read-MiTraceJournal $stateLock).Deployment -cne 'Ready') { throw 'Deployment recovery required.' } }
                finally { $stateLock.Dispose() }
            }
            . (Join-Path $root 'ServiceManagement.ps1')
            $outcome=Invoke-MiServiceMutation -Operation $Operation -ServiceName $ServiceName -RequestId $RequestId
        } finally { $lease.Dispose() }
        $exitCode=if ($outcome -eq 'Confirmed') {0} elseif ($outcome -eq 'TimedOut') {3} else {2}
    }
} catch {
    if ($trusted) {
        try {
            Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'FAILED_OR_CANCELLED' -Reason ([string]$_.Exception.Message)
        } catch {}
    }
    Write-Error ('Privileged operation refused: '+$_.Exception.Message) -ErrorAction Continue
    $exitCode=2
}
exit $exitCode
