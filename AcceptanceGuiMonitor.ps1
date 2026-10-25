#requires -Version 5.1
<#
M8 read-only external observer for a running MemoryInspector GUI PID.
The observer NEVER starts/stops a process or performs elevated operations.
Manual desktop UI interaction, UAC flows and Windows 10/11 coverage require separate validation.
#>
[CmdletBinding(DefaultParameterSetName='Gui')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Gui')][ValidateRange(1,2147483647)][int]$TargetPid,
    [Parameter(Mandatory=$true,ParameterSetName='Jobs')][string]$JobsPath,
    [Parameter(Mandatory=$true,ParameterSetName='Library')][switch]$FunctionsOnly,
    [ValidateRange(1,2880)][int]$DurationMinutes=1440,
    [ValidateRange(5,300)][int]$IntervalSeconds=10,
    [string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) 'MemoryInspectorGuiAcceptance')
)
$ErrorActionPreference='Stop'

function Read-MiAcceptanceTargets {
    param([int]$TargetPid,[string]$JobsPath)
    if (-not [string]::IsNullOrWhiteSpace($JobsPath)) {
        # PS5.1 的 JSON 数组先赋值，再逐条枚举；不能用 @(ConvertFrom-Json) 产生嵌套数组。
        $decoded=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($JobsPath,[Text.Encoding]::UTF8)) -ErrorAction Stop
        $seen=@{};$targets=New-Object 'System.Collections.Generic.List[object]'
        foreach($job in @($decoded)) {
            $targetId=0;$ticks=0L
            if ($null -eq $job -or $job -is [array] -or
                -not [int]::TryParse([string]$job.Pid,[ref]$targetId) -or $targetId -le 0 -or
                -not [long]::TryParse([string]$job.StartUtcTicks,[ref]$ticks) -or $ticks -le 0 -or
                $seen.ContainsKey($targetId)) {throw 'Invalid, nested or duplicate acceptance target.'}
            $seen[$targetId]=$true
            $targets.Add([pscustomobject]@{Pid=$targetId;StartUtcTicks=$ticks;Name=$null;IntervalSeconds=$job.IntervalSeconds})
        }
        if ($targets.Count -eq 0) {throw 'Acceptance target list is empty.'}
        return $targets.ToArray()
    }
    $initial=Get-Process -Id $TargetPid -ErrorAction Stop
    try {return [pscustomobject]@{Pid=$initial.Id;StartUtcTicks=[long]$initial.StartTime.ToUniversalTime().Ticks;Name=[string]$initial.ProcessName;IntervalSeconds=$null}}
    finally {$initial.Dispose()}
}

function Get-MiAcceptanceObservation {
    param($Process,$Target,[double]$Elapsed,$Previous,[int]$ProcessorCount=[Environment]::ProcessorCount)
    if ([int]$Process.Id -ne $Target.Pid -or
        [long]$Process.StartTime.ToUniversalTime().Ticks -ne $Target.StartUtcTicks -or
        ($null -ne $Target.Name -and [string]$Process.ProcessName -cne $Target.Name)) {throw 'PidReusedOrIdentityChanged'}
    $cpuNow=[double]$Process.TotalProcessorTime.TotalSeconds
    $cpu=$null;$span=0.0;$delta=0.0
    if ($null -ne $Previous) {
        $span=$Elapsed-$Previous.Elapsed;$delta=$cpuNow-$Previous.Cpu
        if ($span -le 0 -or $delta -lt 0) {throw 'Invalid observer CPU/time continuity.'}
        $cpu=100.0*$delta/$span/[math]::Max(1,$ProcessorCount)
    }
    $hasWindow=([long]$Process.MainWindowHandle.ToInt64() -ne 0)
    $responding='Unknown'
    if ($hasWindow) {try {$responding=if($Process.Responding){'True'}else{'False'}}catch{}}
    return [pscustomobject]@{Utc=[datetime]::UtcNow.ToString('o');ElapsedSeconds=$Elapsed;Pid=$Target.Pid
        WorkingSetMiB=[double]$Process.WorkingSet64/1MB;PrivateMiB=[double]$Process.PrivateMemorySize64/1MB
        CpuPercent=$cpu;CpuCounter=$cpuNow;CpuDelta=$delta;CpuSpan=$span;Responding=$responding;MainWindow=$hasWindow}
}

function ConvertTo-MiAcceptanceCsvRow {
    param($Row)
    # 固定小数点，避免非英文区域设置把逗号小数写成额外 CSV 列；首样本 CPU 留空。
    $cpu=if($null -eq $Row.CpuPercent){''}else{$Row.CpuPercent.ToString('F4',[Globalization.CultureInfo]::InvariantCulture)}
    return [string]::Format([Globalization.CultureInfo]::InvariantCulture,
        '{0},{1:F2},{2},{3:F2},{4:F2},{5},{6},{7}',
        $Row.Utc,$Row.ElapsedSeconds,$Row.Pid,$Row.WorkingSetMiB,$Row.PrivateMiB,$cpu,$Row.Responding,$Row.MainWindow)
}

if ($FunctionsOnly) {return}
if ($PSVersionTable.PSVersion.Major -ne 5 -or
    -not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) { throw 'Windows PowerShell 5.1 required.' }
$targets=@(Read-MiAcceptanceTargets -TargetPid $TargetPid -JobsPath $JobsPath)
if (@($targets|Where-Object Pid -eq $PID).Count -gt 0) {throw 'Observer cannot monitor itself.'}
$states=@{}
foreach($target in $targets) {$states[$target.Pid]=[pscustomobject]@{Target=$target;Active=$true;Previous=$null;Count=0;Missing=0;IdentityChanged=$false;Unresponsive=0;PeakWorking=0.0;PeakPrivate=0.0;PeakCpu=$null;CpuDelta=0.0;CpuSpan=0.0;LastError=$null}}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$startUtc=[datetime]::UtcNow
$stamp=$startUtc.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')
$csv=Join-Path $OutputDirectory ('m8-gui-'+$stamp+'.csv')
$json=Join-Path $OutputDirectory ('m8-gui-'+$stamp+'.json')
$writer=[IO.StreamWriter]::new($csv,$false,[Text.UTF8Encoding]::new($false))
$writer.WriteLine('Utc,ElapsedSeconds,Pid,WorkingSetMiB,PrivateMiB,CpuPercent,Responding,MainWindow')
$watch=[Diagnostics.Stopwatch]::StartNew()
$count=0
$missing=0
$unresponsive=0
$peakWorkingSet=0.0
$maxCpu=0.0
$reason='Completed'
$minutes=[timespan]::FromMinutes($DurationMinutes)
try {
    while ($watch.Elapsed -lt $minutes) {
        $iteration=$watch.Elapsed.TotalSeconds
        foreach($target in $targets) {
            $state=$states[$target.Pid]
            if (-not $state.Active) {continue}
            $p=$null
            try {
                $p=Get-Process -Id $target.Pid -ErrorAction Stop;$p.Refresh()
                $row=Get-MiAcceptanceObservation -Process $p -Target $target -Elapsed $watch.Elapsed.TotalSeconds -Previous $state.Previous
                if ($null -eq $target.Name) {$target.Name=[string]$p.ProcessName}
                $state.Previous=@{Elapsed=$row.ElapsedSeconds;Cpu=$row.CpuCounter}
                $state.PeakWorking=[math]::Max($state.PeakWorking,$row.WorkingSetMiB)
                $state.PeakPrivate=[math]::Max($state.PeakPrivate,$row.PrivateMiB)
                if ($null -ne $row.CpuPercent) {
                    $state.PeakCpu=[math]::Max([double]$state.PeakCpu,$row.CpuPercent)
                    $state.CpuDelta+=$row.CpuDelta;$state.CpuSpan+=$row.CpuSpan
                }
                if ($row.Responding -eq 'False') {$state.Unresponsive++;$unresponsive++}
                $peakWorkingSet=[math]::Max($peakWorkingSet,$row.WorkingSetMiB)
                $maxCpu=[math]::Max($maxCpu,[double]$row.CpuPercent)
                $writer.WriteLine((ConvertTo-MiAcceptanceCsvRow $row))
                $state.Count++;$count++
            } catch {
                $state.Active=$false;$state.Missing++;$missing++;$state.LastError=$_.Exception.Message
                $state.IdentityChanged=($_.Exception.Message -eq 'PidReusedOrIdentityChanged')
            } finally {if ($null -ne $p) {$p.Dispose()}}
        }
        $writer.Flush()
        if (@($states.Values|Where-Object Active).Count -eq 0) {$reason='AllTargetsEndedOrUnavailable';break}
        $wait=[int][math]::Max(0,[math]::Min(
            $minutes.TotalMilliseconds-$watch.Elapsed.TotalMilliseconds,
            ($iteration+$IntervalSeconds)*1000.0-$watch.Elapsed.TotalMilliseconds))
        if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
    }
} finally {
    $watch.Stop()
    $writer.Dispose()
    $targetSummaries=@(foreach($target in $targets){
        $state=$states[$target.Pid]
        [pscustomobject]@{Pid=$target.Pid;Name=$target.Name;StartUtcTicks=$target.StartUtcTicks;IntervalSeconds=$target.IntervalSeconds
            Observations=$state.Count;MissingOrChangedIdentity=$state.Missing;IdentityChanged=$state.IdentityChanged;LastError=$state.LastError
            PeakWorkingSetMiB=[math]::Round($state.PeakWorking,2);PeakPrivateMiB=[math]::Round($state.PeakPrivate,2)
            PeakNormalizedCpuPercent=$state.PeakCpu
            AverageNormalizedCpuPercent=$(if($state.CpuSpan -gt 0){[math]::Round(100*$state.CpuDelta/$state.CpuSpan/[math]::Max(1,[Environment]::ProcessorCount),4)}else{$null})
            CpuObservedSeconds=$state.CpuSpan;UnresponsiveWithWindowSamples=$state.Unresponsive}
    })
    $summary=[ordered]@{
        SchemaVersion=1
        ToolVersion=([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'VERSION'))).Trim()
        StartedUtc=$startUtc.ToString('o')
        CompletedUtc=[datetime]::UtcNow.ToString('o')
        ObservedSeconds=[math]::Round($watch.Elapsed.TotalSeconds,1)
        RequestedMinutes=$DurationMinutes
        IntervalSeconds=$IntervalSeconds
        LogicalProcessorCount=[Environment]::ProcessorCount
        TargetPid=$TargetPid
        TargetName=$targets[0].Name
        TargetStartUtcTicks=$targets[0].StartUtcTicks
        SourceKind=$(if($JobsPath){'BackendJobs'}else{'Gui'})
        Targets=$targetSummaries
        Observations=$count
        MissingOrChangedIdentity=$missing
        UnresponsiveWithWindowSamples=$unresponsive
        PeakWorkingSetMiB=[math]::Round($peakWorkingSet,2)
        PeakNormalizedCpuPercent=[math]::Round($maxCpu,2)
        FinishReason=$reason
        SamplesCsv=$csv
        Note='External read-only GUI process observer. Does not prove UI latency, service safety, or memory-leak absence.'
    }
    [IO.File]::WriteAllText($json,($summary | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    Write-Host ('M8 GUI observer report: '+$json)
}
if ($reason -ne 'Completed' -or $missing -gt 0 -or $count -eq 0) {
    throw ('GUI monitoring ended before full duration: '+$reason)
}
