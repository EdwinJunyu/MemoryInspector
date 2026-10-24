#requires -Version 5.1
<#
Milestone 6 privileged executor: PROBE ONLY.
Service STOP/START/APPROVE/REVOKE are intentionally NOT implemented here.
Never accepts arbitrary command text, a target executable or a service name.
#>
param(
    [Parameter(Mandatory=$true)][string]$Operation,
    [Parameter(Mandatory=$true)][string]$RequestId
)
$ErrorActionPreference='Stop'
$exitCode=1
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or
        -not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
        throw 'Unsupported host.'
    }
    if ($MyInvocation.UnboundArguments.Count -gt 0) { throw 'Unexpected arguments.' }
    . (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'PrivilegeSecurity.ps1')
    if (-not (Test-MiAdminToken)) { throw 'Elevated administrator token required.' }
    if (-not (Test-MiPrivilegedOperation -Operation $Operation -RequestId $RequestId)) {
        throw 'Denied operation or invalid request ID.'
    }
    $paths=Assert-MiTrustedInstallation
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path)).TrimEnd('\'),
        [IO.Path]::GetFullPath($paths.Install).TrimEnd('\'),
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Executor must run from the protected installation.'
    }
    # CreateNew is atomic and prevents replay even across concurrent processes.
    $marker=Join-Path $paths.Replay ($RequestId.ToLowerInvariant()+'.nonce')
    $fs=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes(([datetime]::UtcNow.ToString('o')))
        $fs.Write($bytes,0,$bytes.Length);$fs.Flush($true)
    } finally { $fs.Dispose() }
    Set-MiProtectedFileAcl -Path $marker
    # An audit failure blocks even the harmless probe.
    Write-MiPrivilegedAudit -RequestId $RequestId -State 'REQUESTED' -Reason 'M6 UAC readiness probe'
    Write-MiPrivilegedAudit -RequestId $RequestId -State 'CONFIRMED' -Reason 'Trusted installation / elevation / replay checks passed'
    $exitCode=0
} catch {
    # Fail closed. Reject reasons are not exposed as an instruction to retry destructively.
    Write-Error ('Privileged probe refused: '+$_.Exception.Message) -ErrorAction Continue
    $exitCode=2
}
exit $exitCode
