#requires -Version 5.1
<#
M7 protected, short-lived executor. Probe plus explicitly approved Windows service
operations only. Unknown identity, invalid ACL, changed binary, missing audit or
running dependents always fails closed. Never kills a service host process.
#>
param(
    [Parameter(Mandatory=$true)][string]$Operation,
    [Parameter(Mandatory=$true)][string]$RequestId,
    [string]$ServiceName=''
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
    $paths=Assert-MiTrustedInstallation
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath($root).TrimEnd('\'),
        [IO.Path]::GetFullPath($paths.Install).TrimEnd('\'),
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Executor must run from verified protected installation.'
    }
    $trusted=$true
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
    } else {
        . (Join-Path $root 'ServiceManagement.ps1')
        $outcome=Invoke-MiServiceMutation -Operation $Operation -ServiceName $ServiceName -RequestId $RequestId
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
