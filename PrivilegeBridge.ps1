#requires -Version 5.1
<#
Milestone 6 unprivileged GUI bridge. Launches ONLY a protected executor Probe
via UAC and reports the exit code asynchronously; no service state mutations.
#>
$script:MiPrivilegeProbe = $null
$script:MiTraceRequest=$null
$script:MiTraceReportModulePath=$PSCommandPath
function Read-MiTraceRequestReport {
    param([string]$Path,[string]$Id,[string]$OwnerSid,[string]$Operation)
    Assert-MiTracePath $Path
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($file.Length -gt 1048576) {throw 'Oversized status report.'}
        $reader=[IO.StreamReader]::new($file,[Text.UTF8Encoding]::new($false,$true));try {$text=$reader.ReadToEnd()} finally {$reader.Dispose()}
        $report=$text|ConvertFrom-Json -ErrorAction Stop
        if ($report.SchemaVersion -ne 1 -or $report.RequestId -cne $Id -or $report.OwnerSid -cne $OwnerSid -or $report.Operation -cne $Operation -or
            $report.ResultTrust -cne 'ProtectedStatusOnlyNotActionAuthority') {throw 'Unbound diagnostic report.'}
        $report|Add-Member NoteProperty PreviewText $(if ($text.Length -gt 32768) {$text.Substring(0,32768)+[Environment]::NewLine+'报告显示前 32768 字符；状态表保留最多 200 条记录。'} else {$text})
        return $report
    } finally {$file.Dispose()}
}
function Get-MiGuiDiagnosticReleaseStatus {
    return [pscustomobject]@{Enabled=$false;TraceUiAccepted=$false;ExportUiAccepted=$false;RecoveryUiAccepted=$false;
        Reason='M2M5AndM7WindowsGuiAcceptancePending'}
}
function Start-MiTraceRequest {
    param([ValidateSet('TraceStatus','TraceStart','TraceStop','TraceExportPrepare','TraceRecovery')][string]$Operation,
        [ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType='VirtualAlloc',
        [ValidateSet('Memory','File')][string]$RecordingMode='Memory',[ValidateRange(300,1800)][int]$DurationSeconds=300,
        [string]$TraceSessionId='',[string]$ArtifactId='',[string]$HeapImagePath='')
    if ($null -ne $script:MiTraceRequest -or $null -ne $script:MiPrivilegeProbe -or $null -ne $script:MiServiceRequest) {throw 'Another administrator request is pending.'}
    if (Test-MiElevated) {throw 'GUI must remain unelevated.'}
    if ($Operation -cin @('TraceStart','TraceStop','TraceExportPrepare')) {
        $gate=Get-MiGuiDiagnosticReleaseStatus
        if (-not $gate.Enabled -or -not $gate.TraceUiAccepted) {throw $gate.Reason}
        Assert-MiWprReleaseAccepted
        if ($Operation -ceq 'TraceExportPrepare') {if (-not $gate.ExportUiAccepted) {throw $gate.Reason};Assert-MiExportReleaseAccepted}
        if ($Operation -ceq 'TraceStart' -and $TraceType -ceq 'Heap') {Assert-MiHeapReleaseAccepted}
    }
    if ($Operation -ceq 'TraceRecovery') {
        $gate=Get-MiGuiDiagnosticReleaseStatus
        if (-not $gate.Enabled -or -not $gate.RecoveryUiAccepted) {throw $gate.Reason}
    }
    if (-not (Test-MiPrivilegeBridgeInstalled)) {throw 'Protected installed copy required.'}
    if (($Operation -ceq 'TraceStop' -and -not (Test-MiGuidN $TraceSessionId)) -or
        ($Operation -ceq 'TraceExportPrepare' -and -not (Test-MiGuidN $ArtifactId))) {throw 'Invalid trace/artifact identity.'}
    if ($HeapImagePath -match '["\r\n\x00]' -or $HeapImagePath.EndsWith('\') -or
        ($HeapImagePath -and ($Operation -cne 'TraceStart' -or $TraceType -cne 'Heap' -or -not [IO.Path]::IsPathRooted($HeapImagePath)))) {throw 'Invalid Heap executable path.'}
    $paths=Get-MiSecurityPaths;$id=[guid]::NewGuid().ToString('N')
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $session=[int](Get-Process -Id $PID).SessionId
    if ($sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $session -le 0) {throw 'Interactive requester identity unavailable.'}
    $arguments='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$paths.Executor+'" -Operation '+$Operation+' -RequestId '+$id+' -RequesterSid '+$sid+' -RequesterSession '+$session
    if ($Operation -ceq 'TraceStart') {$arguments+=' -TraceType '+$TraceType+' -RecordingMode '+$RecordingMode+' -DurationSeconds '+$DurationSeconds;if ($HeapImagePath) {$arguments+=' -HeapImagePath "'+$HeapImagePath+'"'}}
    if ($Operation -ceq 'TraceStop') {$arguments+=' -TraceSessionId '+$TraceSessionId}
    if ($Operation -ceq 'TraceExportPrepare') {$arguments+=' -ArtifactId '+$ArtifactId}
    try {
        # 启动/恢复需在受保护控制台中独立确认；只读状态请求使用隐藏窗口。
        $style=if ($Operation -cin @('TraceStart','TraceRecovery')) {'Normal'} else {'Hidden'}
        $child=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle $style -PassThru -ErrorAction Stop
        $script:MiTraceRequest=[pscustomobject]@{Id=$id;Operation=$Operation;Process=$child;OwnerSid=$sid;Clock=[Diagnostics.Stopwatch]::StartNew()}
        return 'Started'
    } catch [ComponentModel.Win32Exception] {if ($_.Exception.NativeErrorCode -eq 1223) {return 'UacCancelled'};throw}
}
function Poll-MiTraceRequest {
    if ($null -eq $script:MiTraceRequest) {return $null}
    $request=$script:MiTraceRequest
    $terminalHandled=$false;$childExited=$false
    try {
        $request.Process.Refresh()
        if (-not $request.Process.HasExited) {return $null}
        $childExited=$true
        $code=$request.Process.ExitCode;$report=$null;$paths=Get-MiSecurityPaths
        $path=Join-Path (Join-Path (Join-Path $paths.TraceArtifacts $request.OwnerSid) 'requests') ($request.Id+'.json')
        if ($code -eq 0) {
            if ($null -eq $request.Reader) {
                # ACL、文件 I/O 和 JSON 均放到后台；GUI 定时器只轮询完成状态。
                $ps=[Management.Automation.PowerShell]::Create()
                [void]$ps.AddScript('param($Module,$Path,$Id,$Owner,$Operation);$ErrorActionPreference="Stop";. (Join-Path (Split-Path -Parent $Module) "PrivilegeSecurity.ps1");. $Module;Read-MiTraceRequestReport $Path $Id $Owner $Operation').AddArgument($script:MiTraceReportModulePath).AddArgument($path).AddArgument($request.Id).AddArgument($request.OwnerSid).AddArgument($request.Operation)
                try {$request|Add-Member NoteProperty Reader ([pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke()})} catch {$ps.Dispose();throw}
                return $null
            }
            if (-not $request.Reader.Handle.IsCompleted) {return $null}
            $data=@($request.Reader.PowerShell.EndInvoke($request.Reader.Handle))
            if ($request.Reader.PowerShell.HadErrors -or $data.Count -ne 1) {throw 'Status report read/validation failed.'}
            $report=$data[0]
        }
        $terminalHandled=$true
        return [pscustomobject]@{State=if ($null -ne $report) {'Reported'} else {'RejectedOrUnknown'};Operation=$request.Operation;Report=$report}
    } catch {$terminalHandled=$true;return [pscustomobject]@{State='UnknownOutcome';Error=$_.Exception.Message;Report=$null}}
    finally {
        # 未知/仍活动的高权限请求不会因 GUI 超时被终止或重新派发。
        # IsCompleted 可在 return 与 finally 之间变化；只有本次真正交付终态后才能释放请求。
        if ($terminalHandled -and $childExited) {
            if ($null -ne $request.Reader) {$request.Reader.PowerShell.Dispose()}
            $request.Process.Dispose();$script:MiTraceRequest=$null
        }
    }
}
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
    if ($null -ne $script:MiPrivilegeProbe -or $null -ne $script:MiTraceRequest -or $null -ne $script:MiServiceRequest) { throw 'An earlier administrator request is still pending.' }
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
    if ($null -ne $script:MiTraceRequest) {
        if ($null -ne $script:MiTraceRequest.Reader) {
            try {if (-not $script:MiTraceRequest.Reader.Handle.IsCompleted) {[void]$script:MiTraceRequest.Reader.PowerShell.BeginStop($null,$null)} else {$script:MiTraceRequest.Reader.PowerShell.Dispose()}} catch {}
        }
        try {$script:MiTraceRequest.Process.Dispose()} catch {}
        $script:MiTraceRequest=$null # 仅释放 GUI 句柄；独立 Controller/Watchdog 继续负责追踪。
    }
    if ($null -ne $script:MiPrivilegeProbe) {
        try { $script:MiPrivilegeProbe.Process.Dispose() } catch {}
        $script:MiPrivilegeProbe=$null
    }
}
