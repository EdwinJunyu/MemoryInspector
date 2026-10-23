#requires -Version 5.1
# Milestone 3 deterministic read-only fixtures. Does not touch real processes or services.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Analyzer.ps1')
. (Join-Path $PSScriptRoot 'Persistence.ps1')

function Assert-Mi([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw ('Analyzer test: '+$Message) }
}
function New-Fixture {
    param([datetime]$Utc,[int]$ProcessId=321,[long]$StartTicks=987654321L,
          [long]$PrivateBytes=209715200L,[bool]$IncludeProcess=$true)
    $rows = @()
    if ($IncludeProcess) {
        $rows = @([pscustomobject]@{
            PID=$ProcessId;Name='fixture';StartUtcTicks=$StartTicks
            PrivateBytes=$PrivateBytes;WorkingBytes=104857600L;Status='Success'
        })
    }
    return [pscustomobject]@{
        CaptureEndUtc=$Utc
        Processes=[pscustomobject]@{Status='Success';Items=$rows}
        System=[pscustomobject]@{
            Status='Success';CommittedBytes=4GB;CommitLimitBytes=16GB
            AvailablePhysicalBytes=6GB;TotalPhysicalBytes=8GB
            NonpagedPoolBytes=128MB
        }
    }
}
function New-Trend {
    param([scriptblock]$Calculate,[int]$ProcessId=321,[long]$StartTicks=987654321L,[int]$Step=1)
    $analyzer = New-MiAnalyzer -BootId 'TestBoot' -Root ''
    $end = [datetime]::UtcNow.AddMinutes(-1)
    $start=$end.AddMinutes(-30)
    $last=$null
    for ($i=0; $i -le 180; $i+=$Step) {
        $time = $start.AddSeconds($i*10)
        $bytes = [long](& $Calculate $i)
        $last=New-Fixture -Utc $time -ProcessId $ProcessId -StartTicks $StartTicks -PrivateBytes $bytes
        Add-MiTrackSample -Analyzer $analyzer -Snapshot $last
    }
    return [pscustomobject]@{Analyzer=$analyzer;Last=$last;End=$end}
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('mi-analyzer-test-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    # A steady, large process is not automatically a leak.
    $steady=New-Trend -Calculate { param($i) 3GB }
    $steadyReport=Get-MiProcessAnomaly -Analyzer $steady.Analyzer -Process $steady.Last.Processes.Items[0] -NowUtc $steady.End
    Assert-Mi ($steadyReport.AnomalyState -eq 'NoSignificantGrowth') 'Stable 3GiB was flagged as suspicious.'
    Assert-Mi ($steadyReport.CoverageRatio -ge 0.85) 'Valid coverage was not counted.'

    $rising=New-Trend -Calculate { param($i) (400MB + [long]($i*5MB)) }
    $report=Get-MiProcessAnomaly -Analyzer $rising.Analyzer -Process $rising.Last.Processes.Items[0] -NowUtc $rising.End
    Assert-Mi ($report.AnomalyState -eq 'SuspectedSustainedGrowth') 'Sustained growth not detected.'
    Assert-Mi ($report.GrowthBytes -ge 512MB -and $report.UpwardSegments -ge 4) 'Trend evidence missing.'
    Assert-Mi ($report.Explanation -match '不代表确认泄漏') 'Must not claim a confirmed memory leak.'

    # A temporary peak followed by release is not sustained growth.
    $released=New-Trend -Calculate {
        param($i)
        if ($i -lt 130) { return (400MB + [long]($i*8MB)) }
        return 450MB
    }
    $releasedReport=Get-MiProcessAnomaly -Analyzer $released.Analyzer -Process $released.Last.Processes.Items[0] -NowUtc $released.End
    Assert-Mi ($releasedReport.AnomalyState -eq 'NoSignificantGrowth') 'Temporary peak misclassified.'

    $sparse=New-Trend -Step 3 -Calculate { param($i) (400MB+[long]($i*5MB)) }
    $sparseReport=Get-MiProcessAnomaly -Analyzer $sparse.Analyzer -Process $sparse.Last.Processes.Items[0] -NowUtc $sparse.End
    Assert-Mi ($sparseReport.AnomalyState -eq 'InsufficientEvidence') 'Sparse samples incorrectly diagnosed.'

    # Reuse the same PID with a different start time: must not inherit the old track.
    $reuse = New-Fixture -Utc $rising.End.AddSeconds(10) -PID 321 -StartTicks 987654322L -PrivateBytes 1500MB
    Add-MiTrackSample -Analyzer $rising.Analyzer -Snapshot $reuse
    $reusedReport=Get-MiProcessAnomaly -Analyzer $rising.Analyzer -Process $reuse.Processes.Items[0] -NowUtc $reuse.CaptureEndUtc
    Assert-Mi ($reusedReport.AnomalyState -eq 'InsufficientEvidence' -and $reusedReport.ValidSampleCount -eq 1) 'PID reuse contaminated process history.'

    $unidentified=New-Fixture -Utc $rising.End.AddSeconds(15) -StartTicks 0 -PrivateBytes 1800MB
    $unidentifiedReport=Get-MiProcessAnomaly -Analyzer $rising.Analyzer -Process $unidentified.Processes.Items[0] -NowUtc $unidentified.CaptureEndUtc
    Assert-Mi ($unidentifiedReport.AnomalyState -eq 'InsufficientEvidence') 'Unknown identity was considered valid.'

    # Memory pressure is orthogonal to anomaly.
    $pressure=Get-MiMemoryPressure -Analyzer (New-MiAnalyzer -BootId TestBoot -Root '') -NowUtc $rising.End -System ([pscustomobject]@{
        Status='Success';CommittedBytes=15GB;CommitLimitBytes=16GB
        AvailablePhysicalBytes=200MB;TotalPhysicalBytes=8GB;NonpagedPoolBytes=100MB
    })
    Assert-Mi ($pressure.State -eq 'High') 'High memory pressure not detected.'
    $unknown=Get-MiMemoryPressure -Analyzer (New-MiAnalyzer -BootId TestBoot -Root '') -NowUtc $rising.End -System ([pscustomobject]@{
        Status='Failed';CommittedBytes=$null;CommitLimitBytes=$null
    })
    Assert-Mi ($unknown.State -eq 'Unknown') 'Missing system counters treated as normal.'

    # Restore must respect persisted BootId and reject a mismatched prior boot.
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'process'))
    $now=[datetime]::UtcNow
    $day=$now.ToString('yyyy-MM-dd')
    $log=Join-Path (Join-Path $root 'process') ('process-'+$day+'.jsonl')
    $lines=New-Object 'System.Collections.Generic.List[string]'
    for ($i=0;$i -lt 5;$i++) {
        $time=$now.AddMinutes(-5).AddSeconds($i*10)
        $row=[ordered]@{
            SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$time.ToString('o')
            ProcessStatus='Success';Items=@(
                [ordered]@{
                    PID=321;Name='fixture';StartUtcTicks=987654321L;PrivateBytes=(300MB+$i*1MB)
                    ProcessInstanceId='TestBoot:321:987654321'
                },
                [ordered]@{
                    PID=322;Name='wrongboot';StartUtcTicks=333L;PrivateBytes=3GB
                    ProcessInstanceId='OldBoot:322:333'
                }
            )
        }
        $lines.Add(($row|ConvertTo-Json -Compress -Depth 8))
    }
    [IO.File]::WriteAllLines($log,$lines.ToArray(),[Text.UTF8Encoding]::new($false))
    $restored=New-MiAnalyzer -BootId TestBoot -Root $root
    $readCount=Restore-MiAnalyzer -Analyzer $restored -NowUtc $now
    Assert-Mi ($readCount -eq 5) 'Recent saved samples not restored.'
    Assert-Mi ($restored.Tracks.Count -eq 1) 'Prior-boot records contaminated restored tracks.'
    Assert-Mi ($restored.Tracks['TestBoot:321:987654321'].Samples.Count -eq 5) 'Restore lost valid process samples.'
    $unknownBoot=New-MiAnalyzer -BootId BootUnavailable -Root $root
    Assert-Mi (-not $unknownBoot.CanRestore) 'Unknown boot id must disable cross-run restore.'

    # Historical baseline must compare a name-level aggregate, not a PID lifetime.
    $aggFolder=Join-Path $root 'aggregates'
    [void][IO.Directory]::CreateDirectory($aggFolder)
    foreach ($offset in @(2,3)) {
        $date=$now.Date.AddDays(-$offset)
        $file=Join-Path $aggFolder ('summary-'+$date.ToString('yyyy-MM-dd')+'.jsonl')
        $aggregateLines=New-Object 'System.Collections.Generic.List[string]'
        for ($i=0;$i -lt 73;$i++) {
            $aggregateLines.Add((([ordered]@{
                SchemaVersion=1;RecordType='FiveMinuteAggregate'
                ProgramStatistics=@([ordered]@{Name='fixture';AveragePrivateBytes=400MB;Samples=20})
            })|ConvertTo-Json -Compress -Depth 8))
        }
        [IO.File]::WriteAllLines($file,$aggregateLines.ToArray(),[Text.UTF8Encoding]::new($false))
    }
    Update-MiHistoricalBaselines -Analyzer $restored -NowUtc $now
    Assert-Mi ($restored.Historical.ContainsKey('fixture')) 'Cross-day historical program baseline missing.'
    Assert-Mi ($restored.Historical['fixture'].MedianProgramPrivateBytes -eq 400MB) 'Historical median incorrect.'
    Assert-Mi ($restored.Historical['fixture'].Scope -eq 'ProgramNameAggregate') 'History scope not clear.'

    # Read-only diagnosis must not remove/stop any Windows processes.
    $diagnosis=Invoke-MiDiagnosis -Analyzer $restored -Snapshot (New-Fixture -Utc $now -PrivateBytes 600MB)
    Assert-Mi ($diagnosis.Status -eq 'Success' -and $diagnosis.Reports.Count -eq 1) 'Diagnosis integration result absent.'
    Assert-Mi ($diagnosis.Reports[0].HistoricalScope -eq 'ProgramNameAggregate') 'Historical baseline not included in report.'
    $stale=Invoke-MiDiagnosis -Analyzer $restored -Snapshot (New-Fixture -Utc $now.AddSeconds(-1))
    Assert-Mi ($stale.Status -eq 'Stale') 'Clock regression was not rejected.'
    Write-Host 'PASS: M3 stable/growth/release/sparse/PID reuse/boot restore/history/pressure/stale.' -ForegroundColor Green
} finally {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root,$true) }
}
