#requires -Version 5.1
<#
Read-only collector stability probe. For desktop acceptance use:
    AcceptanceSoak.ps1 -DurationMinutes 1440 -IntervalSeconds 10
This does not exercise the GUI, elevated executor, installer, or service state.
#>
param(
    [ValidateRange(1,2880)][int]$DurationMinutes = 5,
    [ValidateRange(5,3600)][int]$IntervalSeconds = 10,
    [string]$OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'MemoryInspectorAcceptance')
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or
    -not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
    throw 'Windows PowerShell 5.1 required.'
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'Collector.ps1')
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$startedUtc = [datetime]::UtcNow
$watch = [Diagnostics.Stopwatch]::StartNew()
$durationMs = [timespan]::FromMinutes($DurationMinutes).TotalMilliseconds
$rows = New-Object 'System.Collections.Generic.List[object]'
$sourceFailures = 0
$gaps = 0
$index = 0
$lastTime = -1.0
$self = Get-Process -Id $PID -ErrorAction Stop
$cpuStart = [double]$self.TotalProcessorTime.TotalSeconds
$peak = 0L
$output = Join-Path $OutputDirectory ('m8-collector-'+$startedUtc.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    while ($watch.Elapsed.TotalMilliseconds -lt $durationMs) {
        $index++
        $sampleWatch = [Diagnostics.Stopwatch]::StartNew()
        $status = 'Failed'
        $systemState = 'Failed'
        $processState = 'Failed'
        $count = 0
        $errorText = ''
        try {
            $snapshot = Get-MiSnapshot -Sequence $index
            $status = [string]$snapshot.Status
            $systemState = [string]$snapshot.System.Status
            $processState = [string]$snapshot.Processes.Status
            $count = [int]$snapshot.Processes.Total
            if ($systemState -eq 'Failed' -or $processState -eq 'Failed') { $sourceFailures++ }
        } catch {
            $sourceFailures++
            $errorText = [string]$_.Exception.Message
        }
        $sampleWatch.Stop()
        $elapsed = $watch.Elapsed.TotalSeconds
        if ($lastTime -ge 0 -and $elapsed-$lastTime -gt 2.5*$IntervalSeconds) { $gaps++ }
        $lastTime = $elapsed
        $self.Refresh()
        $peak = [math]::Max($peak,[long]$self.WorkingSet64)
        $rows.Add([pscustomobject]@{
            TimeUtc=[datetime]::UtcNow.ToString('o')
            Sequence=$index
            ElapsedSeconds=[math]::Round($elapsed,2)
            DurationMs=[math]::Round($sampleWatch.Elapsed.TotalMilliseconds,1)
            Status=$status
            SystemStatus=$systemState
            ProcessStatus=$processState
            ProcessCount=$count
            Error=$errorText
        })
        if (($index % 30) -eq 0) {
            Write-Host ('Read-only collector: {0:N1} / {1} minutes; failures={2}' -f ($elapsed/60),$DurationMinutes,$sourceFailures)
        }
        $wait = [int][math]::Max(0,[math]::Min(
            $durationMs-$watch.Elapsed.TotalMilliseconds,
            $index*$IntervalSeconds*1000.0-$watch.Elapsed.TotalMilliseconds))
        if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
    }
} finally {
    $watch.Stop()
    $self.Refresh()
    $cpu = [math]::Max(0,([double]$self.TotalProcessorTime.TotalSeconds-$cpuStart))
    $seconds = [math]::Max(0.001,$watch.Elapsed.TotalSeconds)
    $cpuPercent = 100.0*$cpu/$seconds/[math]::Max(1,[Environment]::ProcessorCount)
    $durations = @($rows | ForEach-Object { [double]$_.DurationMs } | Sort-Object)
    $p95 = $null
    if ($durations.Count -gt 0) {
        $p95 = [double]$durations[([int][math]::Ceiling($durations.Count*0.95)-1)]
    }
    $summary = [pscustomobject]@{
        SchemaVersion=1
        ToolVersion=([IO.File]::ReadAllText((Join-Path $root 'VERSION'))).Trim()
        StartedUtc=$startedUtc.ToString('o')
        CompletedUtc=[datetime]::UtcNow.ToString('o')
        WindowsVersion=[Environment]::OSVersion.VersionString
        RequestedMinutes=$DurationMinutes
        ActualSeconds=[math]::Round($seconds,1)
        IntervalSeconds=$IntervalSeconds
        SampleCount=$rows.Count
        FailedSourceSamples=$sourceFailures
        GapCount=$gaps
        P95CollectorMs=$p95
        CliAverageCpuPercent=[math]::Round($cpuPercent,3)
        CliPeakWorkingSetMiB=[math]::Round(([double]$peak/1MB),2)
        Note='Headless collector only. This is NOT a GUI, elevated action, Windows 10/11 matrix or 24h application acceptance result.'
        Samples=@($rows.ToArray())
    }
    $temp = $output+'.tmp'
    [IO.File]::WriteAllText($temp,($summary | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temp,$output)
    $self.Dispose()
    Write-Host ('Read-only collector report: '+$output)
}
if ($sourceFailures -gt 0 -or $rows.Count -eq 0) {
    throw 'The collector returned failed data sources; review the JSON report.'
}
