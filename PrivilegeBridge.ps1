#requires -Version 5.1
<#
Milestone 6 unprivileged GUI bridge. Launches ONLY a protected executor Probe
via UAC and reports the exit code asynchronously; no service state mutations.
#>
$script:MiPrivilegeProbe = $null
function Test-MiPrivilegeBridgeInstalled {
    try {
        $paths=Get-MiSecurityPaths
        $source=[IO.Path]::GetFullPath($script:Root).TrimEnd('\')
        $expected=[IO.Path]::GetFullPath($paths.Install).TrimEnd('\')
        if (-not [string]::Equals($source,$expected,[StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        foreach ($p in @($paths.Install,$paths.Executor,(Join-Path $paths.Install 'PrivilegeSecurity.ps1'))) {
            if (-not (Test-Path -LiteralPath $p) -or -not (Test-MiNoReparse $p) -or
                -not (Test-MiAclRestricted $p)) { return $false }
        }
        return $true
    } catch { return $false }
}
function Start-MiPrivilegeProbe {
    if ($null -ne $script:MiPrivilegeProbe) { throw 'An earlier UAC probe is still pending.' }
    if (Test-MiElevated) { throw 'GUI must run without administrator privileges.' }
    if (-not (Test-MiPrivilegeBridgeInstalled)) { throw 'Please run the protected installed copy, after using Installer.ps1.' }
    $paths=Get-MiSecurityPaths
    $request=[guid]::NewGuid().ToString('N')
    $powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not [IO.File]::Exists($powershell)) { throw 'Windows PowerShell 5.1 not found.' }
    $argument='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+'" -Operation Probe -RequestId '+$request
    try {
        $proc=Start-Process -FilePath $powershell -ArgumentList $argument -Verb RunAs -PassThru -ErrorAction Stop
        if ($null -eq $proc) { throw 'UAC process did not start.' }
        $script:MiPrivilegeProbe=[pscustomobject]@{Id=$request;Process=$proc;Started=[datetime]::UtcNow}
        return 'ProbeStarted'
    } catch [System.ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -eq 1223) { return 'UacCancelled' }
        throw
    }
}
function Poll-MiPrivilegeProbe {
    if ($null -eq $script:MiPrivilegeProbe) { return $null }
    $entry=$script:MiPrivilegeProbe
    try {
        $p=$entry.Process
        $p.Refresh()
        if (-not $p.HasExited) {
            if (([datetime]::UtcNow-$entry.Started).TotalMinutes -ge 2) {
                # Never kill an elevated process on a GUI polling timeout.
                $p.Dispose()
                $script:MiPrivilegeProbe=$null
                return 'ProbeNotConfirmed'
            }
            return $null
        }
        $code=$p.ExitCode
        $p.Dispose()
        $script:MiPrivilegeProbe=$null
        if ($code -eq 0) { return 'ProbeVerified' }
        return 'ProbeRejected'
    } catch {
        try { $entry.Process.Dispose() } catch {}
        $script:MiPrivilegeProbe=$null
        return 'ProbeNotConfirmed'
    }
}
function Close-MiPrivilegeBridge {
    if ($null -ne $script:MiPrivilegeProbe) {
        try { $script:MiPrivilegeProbe.Process.Dispose() } catch {}
        $script:MiPrivilegeProbe=$null
    }
}
