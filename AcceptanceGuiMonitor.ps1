#requires -Version 5.1
<#
M8 read-only external observer for a running MemoryInspector GUI PID.
The observer NEVER starts/stops a process or performs elevated operations.
Manual desktop UI interaction, UAC flows and Windows 10/11 coverage require separate validation.
#>
param(
    [Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int]$TargetPid,
    [ValidateRange(1,2880)][int]$DurationMinutes=1440,
    [ValidateRange(5,300)][int]$IntervalSeconds=10,
    [string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) 'MemoryInspectorGuiAcceptance')
)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or
    -not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) { throw 'Windows PowerShell 5.1 required.' }
if ($TargetPid -eq $PID) { throw 'Observer cannot monitor itself.' }
$initial=Get-Process -Id $TargetPid -ErrorAction Stop
try {
    $identity=[long]$initial.StartTime.ToUniversalTime().Ticks
    $processName=[string]$initial.ProcessName
} finally { $initial.Dispose() }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$startUtc=[datetime]::UtcNow
$stamp=$startUtc.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')
$csv=Join-Path $OutputDirectory ('m8-gui-'+$stamp+'.csv')
$json=Join-Path $OutputDirectory ('m8-gui-'+$stamp+'.json')
$writer=[IO.StreamWriter]::new($csv,$false,[Text.UTF8Encoding]::new($false))
$writer.WriteLine('Utc,ElapsedSeconds,Pid,WorkingSetMiB,PrivateMiB,CpuPercent,Responding,MainWindow')
$watch=[Diagnostics.Stopwatch]::StartNew()
$previousCpu=$null
$previousElapsed=$null
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
        $p=$null
        try {
            $p=Get-Process -Id $TargetPid -ErrorAction Stop
            $p.Refresh()
            if ([long]$p.StartTime.ToUniversalTime().Ticks -ne $identity -or
                [string]$p.ProcessName -cne $processName) {
                $reason='PidReusedOrIdentityChanged'
                $missing++
                break
            }
            $working=[double]$p.WorkingSet64 / 1MB
            $private=[double]$p.PrivateMemorySize64 / 1MB
            $cpuNow=[double]$p.TotalProcessorTime.TotalSeconds
            $cpuPct=0.0
            if ($null -ne $previousCpu -and $null -ne $previousElapsed) {
                $span=$iteration-$previousElapsed
                if ($span -gt 0) {
                    $cpuPct=100.0*($cpuNow-$previousCpu)/$span/[math]::Max(1,[Environment]::ProcessorCount)
                }
            }
            $previousCpu=$cpuNow
            $previousElapsed=$iteration
            $responding='Unknown'
            $hasWindow=([long]$p.MainWindowHandle.ToInt64() -ne 0)
            if ($hasWindow) {
                try {
                    $responding=if ($p.Responding) {'True'} else {'False'}
                    if ($responding -eq 'False') { $unresponsive++ }
                } catch {}
            }
            $peakWorkingSet=[math]::Max($peakWorkingSet,$working)
            $maxCpu=[math]::Max($maxCpu,$cpuPct)
            $writer.WriteLine(('{0},{1:F2},{2},{3:F2},{4:F2},{5:F2},{6},{7}' -f
                [datetime]::UtcNow.ToString('o'),$iteration,$TargetPid,$working,$private,$cpuPct,
                $responding,$hasWindow))
            $writer.Flush()
            $count++
        } catch {
            $reason='TargetExitedOrUnavailable'
            $missing++
            break
        } finally { if ($null -ne $p) { $p.Dispose() } }
        $wait=[int][math]::Max(0,[math]::Min(
            $minutes.TotalMilliseconds-$watch.Elapsed.TotalMilliseconds,
            $count*$IntervalSeconds*1000.0-$watch.Elapsed.TotalMilliseconds))
        if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
    }
} finally {
    $watch.Stop()
    $writer.Dispose()
    $summary=[ordered]@{
        SchemaVersion=1
        ToolVersion=([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'VERSION'))).Trim()
        StartedUtc=$startUtc.ToString('o')
        CompletedUtc=[datetime]::UtcNow.ToString('o')
        ObservedSeconds=[math]::Round($watch.Elapsed.TotalSeconds,1)
        RequestedMinutes=$DurationMinutes
        IntervalSeconds=$IntervalSeconds
        TargetPid=$TargetPid
        TargetName=$processName
        TargetStartUtcTicks=$identity
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
