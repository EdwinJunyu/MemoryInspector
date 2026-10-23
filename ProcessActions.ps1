#requires -Version 5.1
<#
Milestone 5: deliberately conservative local USER process actions only.
Never touches Windows services or admin elevation. All exit requests are manual.
A writable per-user action log is an operational record, NOT tamper-proof security audit.
#>
$script:MiActions = $null
function Initialize-MiActions {
    $folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector'
    $script:MiActions = [pscustomobject]@{
        AuditPath = (Join-Path $folder 'process-actions.jsonl')
        CanAudit = $false
        Pending = $null
        Busy = $false
        CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        CurrentSession = [int](Get-Process -Id $PID).SessionId
    }
    try {
        if (-not [IO.Directory]::Exists($folder)) { [void][IO.Directory]::CreateDirectory($folder) }
        $script:MiActions.CanAudit = $true
    } catch { $script:MiActions.CanAudit = $false }
}
function Test-MiElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $true }
}
function Test-MiProtectedProcess {
    param([string]$Name,[string]$Path)
    $protected = @('idle','system','registry','secure system','memory compression',
        'smss','csrss','wininit','winlogon','services','lsass','lsaiso','svchost',
        'dwm','explorer','conhost','cmd','powershell','pwsh','taskmgr','fontdrvhost',
        'sihost','taskhostw','spoolsv','dllhost','runtimebroker','backgroundtaskhost',
        'searchhost','searchindexer','textinputhost','ctfmon','audiodg','wmiprvse',
        'msiexec','msmpeng','nissrv','securityhealthservice','trustedinstaller','tiworker')
    if ([string]::IsNullOrWhiteSpace($Name) -or $protected -contains $Name.ToLowerInvariant()) { return $true }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { return $true }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $roots = @($env:WINDIR)
        if ($env:ProgramFiles) { $roots += (Join-Path $env:ProgramFiles 'WindowsApps') }
        foreach ($root in $roots) {
            if ([string]::IsNullOrWhiteSpace($root)) { return $true }
            $normalized = [IO.Path]::GetFullPath($root).TrimEnd('\')
            if ($full.StartsWith($normalized+'\',[StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    } catch { return $true }
}
function Test-MiActionSnapshot {
    param($Item,$Snapshot,[datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Item -or $null -eq $Snapshot -or $null -eq $Snapshot.Processes) { return 'MissingSnapshot' }
    if ($Snapshot.Processes.Status -eq 'Failed' -or $Item.Status -ne 'Success') { return 'IncompleteProcessData' }
    if ([int]$Item.PID -le 4 -or $null -eq $Item.StartUtcTicks -or [long]$Item.StartUtcTicks -le 0) { return 'InvalidIdentity' }
    if (Test-MiProtectedProcess -Name ([string]$Item.Name) -Path 'C:\placeholder\app.exe') { return 'ProtectedName' }
    try {
        $sampleUtc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
        $age = ($NowUtc - $sampleUtc).TotalSeconds
        if ($age -lt 0 -or $age -gt 90) { return 'StaleSnapshot' }
        $found = @($Snapshot.Processes.Items | Where-Object {
            $_.PID -eq $Item.PID -and $_.StartUtcTicks -eq $Item.StartUtcTicks -and $_.Name -ceq $Item.Name
        })
        if ($found.Count -ne 1) { return 'IdentityNotInSnapshot' }
        return 'Pass'
    } catch { return 'InvalidSnapshot' }
}
function Write-MiProcessAudit {
    param([string]$OperationId,[string]$State,[string]$Mode,[int]$TargetPid,[string]$Name,$Details)
    if (-not $script:MiActions.CanAudit) { return $false }
    try {
        $line = [pscustomobject]@{
            SchemaVersion=1; Utc=[datetime]::UtcNow.ToString('o')
            OperationId=$OperationId; State=$State; Mode=$Mode; PID=$TargetPid
            Process=$Name; Details=$Details
        } | ConvertTo-Json -Compress -Depth 6
        [IO.File]::AppendAllText($script:MiActions.AuditPath,$line+[Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        return $true
    } catch {
        $script:MiActions.CanAudit = $false
        return $false
    }
}
function Assert-MiProcessTarget {
    param($Item,$Snapshot)
    $reason = Test-MiActionSnapshot -Item $Item -Snapshot $Snapshot
    if ($reason -ne 'Pass') { throw ('目标检查失败：'+$reason) }
    if (Test-MiElevated) { throw '当前 GUI 以管理员权限运行，禁止在本阶段执行进程操作。' }
    if ($null -eq $script:MiActions -or -not $script:MiActions.CanAudit) { throw '本地审计日志不可写。' }
    if ($script:MiActions.CurrentSession -le 0) { throw '当前会话无法验证。' }
    if ([int]$Item.PID -eq $PID) { throw '禁止关闭工具本身。' }
    $proc = Get-Process -Id ([int]$Item.PID) -ErrorAction Stop
    try {
        $proc.Refresh()
        $started = [long]$proc.StartTime.ToUniversalTime().Ticks
        $name = [string]$proc.ProcessName
        $path = [string]$proc.Path
        if ($started -ne [long]$Item.StartUtcTicks -or $name -cne [string]$Item.Name) { throw 'PID 已被复用或进程身份改变。' }
        if (Test-MiProtectedProcess -Name $name -Path $path) { throw '受保护进程名称、路径不可信或位于系统目录。' }
        if ([int]$proc.SessionId -ne $script:MiActions.CurrentSession -or
            [long]$proc.MainWindowHandle.ToInt64() -eq 0) { throw '必须是当前会话具有可用主窗口的普通应用。' }

        $cim = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = {0}' -f $Item.PID) -ErrorAction Stop
        if ($null -eq $cim -or $null -eq $cim.CreationDate -or
            [string]::IsNullOrWhiteSpace([string]$cim.ExecutablePath)) { throw 'CIM 身份信息缺失。' }
        $cimTime = ([datetime]$cim.CreationDate).ToUniversalTime().Ticks
        if ([Math]::Abs([double]($cimTime-$started)) -gt [timespan]::FromSeconds(2).Ticks -or
            [int]$cim.SessionId -ne $script:MiActions.CurrentSession -or
            -not [string]::Equals([string]$cim.ExecutablePath,$path,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'CIM 身份、会话或可执行路径不一致。'
        }
        $owner = Invoke-CimMethod -InputObject $cim -MethodName GetOwnerSid -ErrorAction Stop
        if ($null -eq $owner -or [int]$owner.ReturnValue -ne 0 -or
            [string]$owner.Sid -cne $script:MiActions.CurrentSid) { throw '无法确认进程属于当前用户。' }
        $services = @(Get-CimInstance -ClassName Win32_Service -Filter ('ProcessId = {0}' -f $Item.PID) -ErrorAction Stop)
        if ($services.Count -gt 0) { throw '该 PID 承载 Windows 服务，禁止进程级关闭和 Kill。' }
        return $proc
    } catch {
        $proc.Dispose()
        throw
    }
}
function Invoke-MiProcessAction {
    param([ValidateSet('Graceful','Force')][string]$Mode,$Item,$Snapshot,[bool]$DangerEnabled)
    $id = [guid]::NewGuid().ToString('N')
    $started = [datetime]::UtcNow
    $result = [pscustomobject]@{
        OperationId=$id; Mode=$Mode; PID=[int]$Item.PID; Name=[string]$Item.Name
        StartUtcTicks=$Item.StartUtcTicks; StartedUtc=$started
        Outcome='Rejected'; Error=$null
        BeforeCommitted=$null; BeforeAvailable=$null; BeforePrivate=$Item.PrivateBytes
        Observations=(New-Object 'System.Collections.Generic.List[object]')
    }
    if ($null -ne $Snapshot -and $null -ne $Snapshot.System -and $Snapshot.System.Status -eq 'Success') {
        $result.BeforeCommitted=$Snapshot.System.CommittedBytes
        $result.BeforeAvailable=$Snapshot.System.AvailablePhysicalBytes
    }
    if ($null -ne $script:MiActions.Pending) { $result.Error='上一项操作仍在观察中。'; return $result }
    if ($script:MiActions.Busy) { $result.Error='已有操作正在执行。'; return $result }
    if ($Mode -eq 'Force' -and -not $DangerEnabled) { $result.Error='危险模式尚未明确启用。'; return $result }
    if ($null -eq $script:MiActions -or -not $script:MiActions.CanAudit) { $result.Error='审计未就绪。'; return $result }
    $mutex = $null; $acquired=$false; $proc=$null
    $script:MiActions.Busy=$true
    try {
        $mutex=[Threading.Mutex]::new($false,'Local\MemoryInspector.M5.ProcessMutation')
        try { $acquired=$mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { throw '检测到异常退出的操作锁，请重新启动应用并检查进程状态。' }
        if (-not $acquired) { throw '另一个实例正在执行管理操作。' }
        $proc=Assert-MiProcessTarget -Item $Item -Snapshot $Snapshot
        if (-not (Write-MiProcessAudit -OperationId $id -State 'REQUESTED' -Mode $Mode -TargetPid $Item.PID -Name $Item.Name -Details @{
            StartUtcTicks=$Item.StartUtcTicks; BeforeCommitted=$result.BeforeCommitted
            BeforeAvailable=$result.BeforeAvailable; BeforePrivate=$Item.PrivateBytes
        })) { throw '审计预记录失败，禁止操作。' }
        # Keep the validated Process object, revalidate its instance immediately before dispatch.
        $proc.Refresh()
        if ($proc.HasExited -or $proc.ProcessName -cne $Item.Name -or
            [long]$proc.StartTime.ToUniversalTime().Ticks -ne [long]$Item.StartUtcTicks) {
            throw '执行前目标身份已改变。'
        }
        if ($Mode -eq 'Graceful') {
            if (-not $proc.CloseMainWindow()) { throw '主窗口无法响应正常退出请求，未尝试强制终止。' }
            $result.Outcome='Requested'
        } else {
            $proc.Kill()
            $result.Outcome='Requested'
        }
        [void](Write-MiProcessAudit -OperationId $id -State 'SENT_NOT_CONFIRMED_EXIT' -Mode $Mode -TargetPid $Item.PID -Name $Item.Name -Details @{Note='等待后续采样核验，不声称已退出'})
        $script:MiActions.Pending = $result
    } catch {
        $result.Error=[string]$_.Exception.Message
        if ($result.Error -like '*已改变*' -or $result.Error -like '*审计预记录*') { $result.Outcome='Rejected' }
        else { $result.Outcome='FailedOrUnknown' }
        if ($script:MiActions.CanAudit) {
            [void](Write-MiProcessAudit -OperationId $id -State $result.Outcome -Mode $Mode -TargetPid $Item.PID -Name $Item.Name -Details @{Reason=$result.Error})
        }
    } finally {
        if ($null -ne $proc) { $proc.Dispose() }
        if ($acquired) { try { $mutex.ReleaseMutex() } catch {} }
        if ($null -ne $mutex) { $mutex.Dispose() }
        $script:MiActions.Busy=$false
    }
    return $result
}
function Update-MiActionObservation {
    param($Snapshot,[datetime]$NowUtc=[datetime]::UtcNow)
    if ($null -eq $script:MiActions -or $null -eq $script:MiActions.Pending) { return $null }
    $p=$script:MiActions.Pending
    $elapsed=($NowUtc-$p.StartedUtc).TotalSeconds
    $due=@(5,15,30,60)
    if ($null -ne $Snapshot) {
        $sampleUtc=([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
        foreach ($second in $due) {
            if ($elapsed -lt $second -or @($p.Observations | Where-Object { $_.TargetSecond -eq $second }).Count -gt 0) { continue }
            $targetUtc=$p.StartedUtc.AddSeconds($second)
            if ($sampleUtc -lt $targetUtc) { continue }
            # Never represent a 60-second sample as if it had been captured at 5/15/30.
            if (($sampleUtc-$targetUtc).TotalSeconds -gt 12) {
                $p.Observations.Add([pscustomobject]@{
                    TargetSecond=$second;SampleUtc=$null;CommittedBytes=$null
                    AvailablePhysicalBytes=$null;TargetPrivateBytes=$null;TargetStatus='MissingSample'
                })
                continue
            }
            $sys=$Snapshot.System
            $committed=$null;$available=$null;$observed='Unknown'
            if ($null -ne $sys -and $sys.Status -eq 'Success') {
                $committed=$sys.CommittedBytes;$available=$sys.AvailablePhysicalBytes
            }
            $targetPrivate=$null
            if ($null -ne $Snapshot.Processes -and $Snapshot.Processes.Status -ne 'Failed') {
                $matching=@($Snapshot.Processes.Items | Where-Object { $_.PID -eq $p.PID -and $_.StartUtcTicks -eq $p.StartUtcTicks })
                if ($matching.Count -gt 0) {
                    $observed='Present'
                    $targetPrivate=$matching[0].PrivateBytes
                } else { $observed='NotObserved' }
            }
            $p.Observations.Add([pscustomobject]@{
                TargetSecond=$second; SampleUtc=$sampleUtc.ToString('o')
                CommittedBytes=$committed; AvailablePhysicalBytes=$available
                TargetPrivateBytes=$targetPrivate; TargetStatus=$observed
            })
        }
    }
    if ($elapsed -ge 60 -and @($p.Observations | Where-Object { $_.TargetSecond -eq 60 }).Count -gt 0) {
        $last=@($p.Observations | Where-Object { $_.TargetSecond -eq 60 })[0]
        $net=$null
        if ($null -ne $p.BeforeCommitted -and $null -ne $last.CommittedBytes) {
            $net=[long]($last.CommittedBytes-$p.BeforeCommitted)
        }
        $details=@{
            TargetStatus=$last.TargetStatus; NetSystemCommitBytes=$net
            Attribution='Net system change only; concurrent workloads may contribute'
            Observations=@($p.Observations.ToArray())
        }
        [void](Write-MiProcessAudit -OperationId $p.OperationId -State 'OBSERVATION_COMPLETE' -Mode $p.Mode -TargetPid $p.PID -Name $p.Name -Details $details)
        $script:MiActions.Pending=$null
        return [pscustomobject]@{State='Complete';Operation=$p;NetCommitBytes=$net;TargetStatus=$last.TargetStatus}
    }
    if ($elapsed -gt 120) {
        [void](Write-MiProcessAudit -OperationId $p.OperationId -State 'OBSERVATION_INCOMPLETE' -Mode $p.Mode -TargetPid $p.PID -Name $p.Name -Details @{
            Reason='Monitoring timeout or sampling gaps';Observations=@($p.Observations.ToArray())
        })
        $script:MiActions.Pending=$null
        return [pscustomobject]@{State='Incomplete';Operation=$p;NetCommitBytes=$null;TargetStatus='Unknown'}
    }
    return $null
}

function Stop-MiActionObservation {
    if ($null -eq $script:MiActions -or $null -eq $script:MiActions.Pending) { return }
    $p=$script:MiActions.Pending
    [void](Write-MiProcessAudit -OperationId $p.OperationId -State 'OBSERVATION_INTERRUPTED' -Mode $p.Mode -TargetPid $p.PID -Name $p.Name -Details @{
        Reason='GUI exited before follow-up measurements were complete'
        Observations=@($p.Observations.ToArray())
    })
    $script:MiActions.Pending=$null
}
