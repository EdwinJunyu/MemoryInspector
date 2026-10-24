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
          [long]$PrivateBytes=209715200L,[bool]$IncludeProcess=$true,[int]$IntervalSeconds=0)
    $rows = @()
    if ($IncludeProcess) {
        $rows = @([pscustomobject]@{
            PID=$ProcessId;Name='fixture';StartUtcTicks=$StartTicks
            PrivateBytes=$PrivateBytes;WorkingBytes=104857600L;Status='Success'
        })
    }
    return [pscustomobject]@{
        CaptureEndUtc=$Utc
        IntervalSeconds=$(if ($IntervalSeconds -gt 0) { $IntervalSeconds } else { $null })
        Processes=[pscustomobject]@{Status='Success';Items=$rows}
        System=[pscustomobject]@{
            Status='Success';CommittedBytes=4GB;CommitLimitBytes=16GB
            AvailablePhysicalBytes=6GB;TotalPhysicalBytes=8GB
            NonpagedPoolBytes=128MB
        }
    }
}
function New-Trend {
    param([scriptblock]$Calculate,[int]$ProcessId=321,[long]$StartTicks=987654321L,[int]$Step=1,
        [int]$IntervalSeconds=10)
    $analyzer = New-MiAnalyzer -BootId 'TestBoot' -Root '' -IntervalSeconds $IntervalSeconds
    $end = [datetime]::UtcNow.AddMinutes(-1)
    $start=$end.AddMinutes(-30)
    $last=$null
    for ($seconds=0; $seconds -le 1800; $seconds+=($IntervalSeconds*$Step)) {
        $time = $start.AddSeconds($seconds)
        $bytes = [long](& $Calculate ($seconds/10.0))
        $last=New-Fixture -Utc $time -ProcessId $ProcessId -StartTicks $StartTicks -PrivateBytes $bytes
        Add-MiTrackSample -Analyzer $analyzer -Snapshot $last
    }
    return [pscustomobject]@{Analyzer=$analyzer;Last=$last;End=$last.CaptureEndUtc}
}
$artifactRoot=Join-Path $PSScriptRoot 'test-artifacts'
$root=Join-Path $artifactRoot ('mi-analyzer-test-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    # 每个受支持的代表周期及不整除 1800/300 的周期，独立检验增长、稳定、容量与分段覆盖。
    Assert-Mi ((New-MiAnalyzer -BootId TestBoot -Root '').IntervalSeconds -eq 5) 'Default cadence is not five seconds.'
    foreach ($interval in @(5,7,10,20,30,60)) {
        $dynamic=New-Trend -IntervalSeconds $interval -Calculate {param($i) (400MB+[long]($i*5MB))}
        $dynamicReport=Get-MiProcessAnomaly -Analyzer $dynamic.Analyzer -Process $dynamic.Last.Processes.Items[0] -NowUtc $dynamic.End
        $expected=[int][math]::Floor(1800.0/$interval)+1
        Assert-Mi ($dynamicReport.AnomalyState -eq 'SuspectedSustainedGrowth') ('Growth failed at cadence '+$interval)
        Assert-Mi ($dynamicReport.ExpectedSampleCount -eq $expected -and $dynamicReport.ValidSampleCount -eq $expected) ('Endpoint count incorrect at cadence '+$interval)
        Assert-Mi ($dynamic.Analyzer.Parameters.HistoryCapacity -gt $expected) ('Buffer cannot hold full window at cadence '+$interval)
        Assert-Mi (($dynamicReport.SegmentExpectedSampleCounts | Measure-Object -Sum).Sum -eq $expected) 'Segment boundary duplicated or omitted a scheduled sample.'
        Assert-Mi ($dynamicReport.SegmentValidSampleCounts.Count -eq 6) 'Missing segment coverage diagnostics.'
        $stable=New-Trend -IntervalSeconds $interval -Calculate {param($i) 3GB}
        $stableReport=Get-MiProcessAnomaly -Analyzer $stable.Analyzer -Process $stable.Last.Processes.Items[0] -NowUtc $stable.End
        Assert-Mi ($stableReport.AnomalyState -eq 'NoSignificantGrowth') ('Stable memory failed at cadence '+$interval)
    }
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

    $jitter=New-Trend -IntervalSeconds 5 -Calculate {param($i) (400MB+[long]($i*5MB))}
    $jitterSamples=$jitter.Analyzer.Tracks['TestBoot:321:987654321'].Samples
    for ($i=0;$i -lt $jitterSamples.Count;$i++) { $jitterSamples[$i].Utc=$jitterSamples[$i].Utc.AddMilliseconds(($i%2)*200) }
    $jitterReport=Get-MiProcessAnomaly -Analyzer $jitter.Analyzer -Process $jitter.Last.Processes.Items[0] -NowUtc $jitter.End
    Assert-Mi ($jitterReport.AnomalyState -eq 'SuspectedSustainedGrowth' -and $jitterReport.CoverageRatio -eq 1) 'Small completion-time jitter lost valid cadence slots.'
    $slowJitter=New-MiAnalyzer -BootId TestBoot -Root '' -IntervalSeconds 60
    $slowEnd=[datetime]::UtcNow
    for ($i=0;$i -le 30;$i++) {
        $slowUtc=$slowEnd.AddSeconds(-1800+$i*60)
        if ($i -eq 0) { $slowUtc=$slowUtc.AddMilliseconds(-200) }
        $slowLast=New-Fixture -Utc $slowUtc -PrivateBytes (400MB+$i*40MB)
        Add-MiTrackSample -Analyzer $slowJitter -Snapshot $slowLast
    }
    $slowReport=Get-MiProcessAnomaly -Analyzer $slowJitter -Process $slowLast.Processes.Items[0] -NowUtc $slowEnd
    Assert-Mi ($slowReport.ValidSampleCount -eq 31 -and $slowReport.AnomalyState -eq 'SuspectedSustainedGrowth') 'Sixty-second endpoint jitter discarded an otherwise complete schedule slot.'

    # 跨分段的 80 秒休眠仍可能满足全局和各段 85%，必须另外拒绝时间缺口。
    $gap=New-Trend -IntervalSeconds 5 -Calculate {param($i) (400MB+[long]($i*5MB))}
    $gapSamples=$gap.Analyzer.Tracks['TestBoot:321:987654321'].Samples
    $gapStart=$gap.End.AddSeconds(-1800)
    for ($i=$gapSamples.Count-1;$i -ge 0;$i--) {
        $offset=($gapSamples[$i].Utc-$gapStart).TotalSeconds
        if ($offset -ge 865 -and $offset -le 935) { $gapSamples.RemoveAt($i) }
    }
    $gapReport=Get-MiProcessAnomaly -Analyzer $gap.Analyzer -Process $gap.Last.Processes.Items[0] -NowUtc $gap.End
    Assert-Mi ($gapReport.CoverageRatio -gt 0.95 -and $gapReport.AnomalyState -eq 'InsufficientEvidence' -and $gapReport.Explanation -match '时间缺口') 'A long pause was hidden by otherwise high coverage.'

    # 全局数量充足也不能掩盖一个五分钟分段中持续跳过的采样。
    $segment=New-Trend -IntervalSeconds 5 -Calculate {param($i) (400MB+[long]($i*5MB))}
    $segmentSamples=$segment.Analyzer.Tracks['TestBoot:321:987654321'].Samples
    for ($i=178;$i -ge 120;$i-=2) { $segmentSamples.RemoveAt($i) }
    $segmentReport=Get-MiProcessAnomaly -Analyzer $segment.Analyzer -Process $segment.Last.Processes.Items[0] -NowUtc $segment.End
    Assert-Mi ($segmentReport.CoverageRatio -gt 0.85 -and $segmentReport.MaximumGapSeconds -le 10 -and $segmentReport.AnomalyState -eq 'InsufficientEvidence' -and $segmentReport.Explanation -match '五分钟分段') 'Sparse segment was hidden by global sample count.'

    $tolerated=New-Trend -IntervalSeconds 5 -Calculate {param($i) (400MB+[long]($i*5MB))}
    $toleratedSamples=$tolerated.Analyzer.Tracks['TestBoot:321:987654321'].Samples
    for ($i=350;$i -ge 10;$i-=10) { $toleratedSamples.RemoveAt($i) }
    $toleratedReport=Get-MiProcessAnomaly -Analyzer $tolerated.Analyzer -Process $tolerated.Last.Processes.Items[0] -NowUtc $tolerated.End
    Assert-Mi ($toleratedReport.AnomalyState -eq 'SuspectedSustainedGrowth') 'Coverage above threshold with occasional skipped samples was rejected.'

    # 大量集中补采既不能伪造 30 分钟跨度，也不能超过独立调度槽的数量。
    $burst=New-MiAnalyzer -BootId TestBoot -Root ''
    $burstEnd=[datetime]::UtcNow
    for ($i=0;$i -lt 500;$i++) {
        $burstLast=New-Fixture -Utc $burstEnd.AddMilliseconds(($i-499)*100) -PrivateBytes (400MB+$i*3MB)
        Add-MiTrackSample -Analyzer $burst -Snapshot $burstLast
    }
    $burstReport=Get-MiProcessAnomaly -Analyzer $burst -Process $burstLast.Processes.Items[0] -NowUtc $burstEnd
    Assert-Mi ($burstReport.ValidSampleCount -lt 20 -and $burstReport.AnomalyState -eq 'InsufficientEvidence') 'Burst samples forged window coverage.'
    Assert-Mi ($burst.Tracks['TestBoot:321:987654321'].Samples.Count -le $burst.Parameters.HistoryCapacity) 'Burst buffering is unbounded.'

    # 旧无周期字段的高密度记录恢复到慢周期时，容量不能截掉窗口前半段。
    $legacyDense=New-MiAnalyzer -BootId TestBoot -Root '' -IntervalSeconds 60
    $denseEnd=[datetime]::UtcNow
    for ($i=0;$i -le 360;$i++) {
        $denseLast=New-Fixture -Utc $denseEnd.AddSeconds(-1800+$i*5) -PrivateBytes (400MB+$i*3MB)
        Add-MiTrackSample -Analyzer $legacyDense -Snapshot $denseLast -Historical $true
    }
    $denseReport=Get-MiProcessAnomaly -Analyzer $legacyDense -Process $denseLast.Processes.Items[0] -NowUtc $denseEnd
    Assert-Mi ($denseReport.AnomalyState -eq 'SuspectedSustainedGrowth' -and $denseReport.ValidSampleCount -eq 31 -and $denseReport.RawSampleCount -eq 361) 'Unknown legacy cadence lost a valid observation window.'
    $futureReport=Get-MiProcessAnomaly -Analyzer $legacyDense -Process $denseLast.Processes.Items[0] -NowUtc $denseEnd.AddHours(-1)
    Assert-Mi ($futureReport.AnomalyState -eq 'InsufficientEvidence' -and $futureReport.ValidSampleCount -eq 0) 'Future timestamps supplied false evidence.'
    $oldReport=Get-MiProcessAnomaly -Analyzer $legacyDense -Process $denseLast.Processes.Items[0] -NowUtc $denseEnd.AddSeconds(120)
    Assert-Mi ($oldReport.AnomalyState -eq 'InsufficientEvidence') 'Old last sample was accepted as current.'

    $switched=New-Trend -IntervalSeconds 5 -Calculate {param($i) (400MB+[long]($i*5MB))}
    $switchTime=$switched.End.AddSeconds(60)
    $switchResult=Invoke-MiDiagnosis -Analyzer $switched.Analyzer -Snapshot (New-Fixture -Utc $switchTime -IntervalSeconds 60 -PrivateBytes 1500MB)
    Assert-Mi ($switched.Analyzer.IntervalSeconds -eq 60 -and $switched.Analyzer.WindowResetCount -eq 1 -and $switchResult.Reports[0].ValidSampleCount -eq 1 -and $switchResult.Reports[0].AnomalyState -eq 'InsufficientEvidence') 'Cadence switch reused the old analysis window.'
    for ($i=1;$i -le 30;$i++) {
        $switchLast=New-Fixture -Utc $switchTime.AddSeconds($i*60) -IntervalSeconds 60 -PrivateBytes (1500MB+$i*40MB)
        Add-MiTrackSample -Analyzer $switched.Analyzer -Snapshot $switchLast
    }
    $switchReport=Get-MiProcessAnomaly -Analyzer $switched.Analyzer -Process $switchLast.Processes.Items[0] -NowUtc $switchLast.CaptureEndUtc
    Assert-Mi ($switchReport.AnomalyState -eq 'SuspectedSustainedGrowth') 'New cadence did not establish a valid replacement window.'
    $invalidResult=Invoke-MiDiagnosis -Analyzer $switched.Analyzer -Snapshot (New-Fixture -Utc $switchLast.CaptureEndUtc.AddSeconds(60) -IntervalSeconds 1)
    Assert-Mi ($invalidResult.Status -eq 'InvalidCadence' -and $switched.Analyzer.IntervalSeconds -eq 60) 'Invalid cadence silently changed the algorithm.'

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

    # 恢复读取上限必须足够容纳完整 5 秒窗口；旧 schema=1 无周期字段仍然可读。
    $fullHistory=New-Object 'System.Collections.Generic.List[string]'
    for ($i=0;$i -le 360;$i++) {
        $fullHistory.Add((([ordered]@{
            SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$now.AddSeconds(-1800+$i*5).ToString('o')
            ProcessStatus='Success';Items=@([ordered]@{
                PID=321;Name='fixture';StartUtcTicks=987654321L;PrivateBytes=(400MB+$i*3MB)
                ProcessInstanceId='TestBoot:321:987654321'
            })
        })|ConvertTo-Json -Compress -Depth 8))
    }
    $fullHistory.Add((([ordered]@{
        SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$now.ToString('o');IntervalSeconds='invalid'
        ProcessStatus='Success';Items=@([ordered]@{
            PID=999;Name='wrongcadence';StartUtcTicks=999L;PrivateBytes=400MB
            ProcessInstanceId='TestBoot:999:999'
        })
    })|ConvertTo-Json -Compress -Depth 8))
    [IO.File]::WriteAllLines($log,$fullHistory.ToArray(),[Text.UTF8Encoding]::new($false))
    $fullRestored=New-MiAnalyzer -BootId TestBoot -Root $root
    $fullCount=Restore-MiAnalyzer -Analyzer $fullRestored -NowUtc $now
    Assert-Mi ($fullCount -eq 361 -and $fullRestored.Tracks.Count -eq 1) 'Complete five-second history or cadence filtering failed during raw restore.'
    $fullReport=Get-MiProcessAnomaly -Analyzer $fullRestored -Process $denseLast.Processes.Items[0] -NowUtc $now
    Assert-Mi ($fullReport.AnomalyState -eq 'SuspectedSustainedGrowth') 'Restored five-second history was truncated below a complete analysis window.'
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archives=Join-Path $root 'archives'
    [void][IO.Directory]::CreateDirectory($archives)
    $archive=Join-Path $archives ('raw-'+$day+'.zip')
    $zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
    try { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$log,[IO.Path]::GetFileName($log)) }
    finally { $zip.Dispose() }
    $backup=Join-Path $root 'fixture-raw-backup'
    [void][IO.Directory]::CreateDirectory($backup)
    [IO.File]::Move($log,(Join-Path $backup ([IO.Path]::GetFileName($log))))
    $zipRestored=New-MiAnalyzer -BootId TestBoot -Root $root
    Assert-Mi ((Restore-MiAnalyzer -Analyzer $zipRestored -NowUtc $now) -eq 361) 'Archived five-second history tail was truncated.'

    # 同周期历史被一次明确的其他周期隔开时，只能使用断点后的记录。
    $cadenceRoot=Join-Path $root 'cadence-history'
    $cadenceFolder=Join-Path $cadenceRoot 'process'
    [void][IO.Directory]::CreateDirectory($cadenceFolder)
    $cadenceRows=New-Object 'System.Collections.Generic.List[string]'
    foreach ($offset in @(1800,10,0)) {
        $cadenceRows.Add((([ordered]@{
            SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$now.AddSeconds(-$offset).ToString('o')
            IntervalSeconds=$(if ($offset -eq 10) {60} else {5})
            ProcessStatus='Success';Items=@([ordered]@{
                PID=321;Name='fixture';StartUtcTicks=987654321L;PrivateBytes=400MB
                ProcessInstanceId='TestBoot:321:987654321'
            })
        })|ConvertTo-Json -Compress -Depth 8))
    }
    [IO.File]::WriteAllLines((Join-Path $cadenceFolder ('process-'+$day+'.jsonl')),$cadenceRows.ToArray(),[Text.UTF8Encoding]::new($false))
    $cadenceRestored=New-MiAnalyzer -BootId TestBoot -Root $cadenceRoot
    [void](Restore-MiAnalyzer -Analyzer $cadenceRestored -NowUtc $now)
    Assert-Mi ($cadenceRestored.Tracks['TestBoot:321:987654321'].Samples.Count -eq 1 -and $null -ne $cadenceRestored.ContinuityReason) 'Restored history joined across a cadence change.'

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
    Assert-Mi ($restored.Tracks.Count -eq 0 -and $restored.WindowResetCount -eq 1) 'Clock discontinuity retained old trend data.'
    $afterRollback=Invoke-MiDiagnosis -Analyzer $restored -Snapshot (New-Fixture -Utc $now.AddSeconds(-0.5))
    Assert-Mi ($afterRollback.Status -eq 'Success' -and $afterRollback.Reports[0].ValidSampleCount -eq 1) 'Analyzer remained stuck after a clock discontinuity.'
    $afterSleep=Invoke-MiDiagnosis -Analyzer $restored -Snapshot (New-Fixture -Utc $now.AddHours(3))
    Assert-Mi ($afterSleep.Status -eq 'Success' -and $afterSleep.Reports[0].ValidSampleCount -eq 1 -and $afterSleep.Reports[0].AnomalyState -eq 'InsufficientEvidence') 'Resume after sleep reused expired history.'
    Write-Host 'PASS: M3 cadence 5/7/10/20/30/60, dynamic slots/capacity/bins, jitter/gaps/bursts/switch, raw/ZIP restore, growth/stability/history/pressure/clock continuity.' -ForegroundColor Green
} finally {
    if ([IO.Directory]::Exists($root)) {
        # 保留本次测试产物，便于失败后检查；遵守项目不实际删除文件的约定。
        Write-Host ('Analyzer test artifacts retained: '+$root)
    }
}
