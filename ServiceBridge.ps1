#requires -Version 5.1
<# M7 GUI service bridge: only whitelisted operation names, explicit UAC, no SCM commands here. #>
$script:MiServiceRequest=$null
function Get-MiServiceApprovalMap {
    $map=@{}
    try {
        $paths=Get-MiSecurityPaths
        if (-not (Test-MiPrivilegeBridgeInstalled) -or -not (Test-MiNoReparse $paths.Policy) -or
            -not (Test-MiAclRestricted $paths.Policy $true)) { return $map }
        $policy=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Policy,[Text.Encoding]::UTF8)) -ErrorAction Stop
        if ([int]$policy.SchemaVersion -ne 1) { return $map }
        foreach ($s in @($policy.Services)) {
            if ([string]$s.Name -cmatch '^[A-Za-z0-9_.-]{1,128}$') { $map[[string]$s.Name]=$true }
        }
    } catch {} # UI display is advisory only; executor always enforces the real policy.
    return $map
}
function Start-MiServiceRequest {
    param([string]$Operation,[string]$ServiceName)
    if ($null -ne $script:MiServiceRequest -or $null -ne $script:MiPrivilegeProbe) {
        throw 'Another administrator request is still in progress.'
    }
    if (Test-MiElevated) { throw 'GUI must remain unelevated.' }
    $id=[guid]::NewGuid().ToString('N')
    if (-not (Test-MiPrivilegedOperation -Operation $Operation -RequestId $id -ServiceName $ServiceName)) {
        throw 'Unsupported operation or service name.'
    }
    if (-not (Test-MiPrivilegeBridgeInstalled)) { throw 'Run the protected 0.0.7 installation first.' }
    $paths=Get-MiSecurityPaths
    $exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not [IO.File]::Exists($exe)) { throw 'Windows PowerShell 5.1 missing.' }
    # Name regex excludes all spaces/quotes/shell metacharacters; no caller-supplied script path.
    $arguments='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+
        '" -Operation '+$Operation+' -RequestId '+$id+' -ServiceName '+$ServiceName
    try {
        $child=Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -PassThru -ErrorAction Stop
        if ($null -eq $child) { throw 'UAC child process failed to start.' }
        $script:MiServiceRequest=[pscustomobject]@{
            Id=$id;Name=$ServiceName;Operation=$Operation;Process=$child;Started=[datetime]::UtcNow
        }
        return 'Started'
    } catch [System.ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -eq 1223) { return 'UacCancelled' }
        throw
    }
}
function Poll-MiServiceRequest {
    if ($null -eq $script:MiServiceRequest) { return $null }
    $entry=$script:MiServiceRequest
    try {
        $entry.Process.Refresh()
        if (-not $entry.Process.HasExited) {
            if (([datetime]::UtcNow-$entry.Started).TotalMinutes -gt 5) {
                return [pscustomobject]@{State='StillPending';Operation=$entry.Operation;Name=$entry.Name}
            }
            return $null
        }
        $code=[int]$entry.Process.ExitCode
        $entry.Process.Dispose()
        $script:MiServiceRequest=$null
        $state=switch ($code) {
            0 {'Confirmed'}
            3 {'TimedOut'}
            4 {'Cancelled'}
            default {'RejectedOrUnknown'}
        }
        return [pscustomobject]@{State=$state;Operation=$entry.Operation;Name=$entry.Name}
    } catch {
        # Unknown outcome: preserve handle until child exit when possible; never retry automatically.
        return [pscustomobject]@{State='StillPending';Operation=$entry.Operation;Name=$entry.Name}
    }
}
function Close-MiServiceBridge {
    if ($null -ne $script:MiServiceRequest) {
        try { $script:MiServiceRequest.Process.Dispose() } catch {}
        $script:MiServiceRequest=$null
    }
}
