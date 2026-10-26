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
# 证据点的整数精度不能因节省内存而退化为 double；窗口淘汰不能截断30分钟。
$packed=New-MiAnalyzer -BootId 'memory-fixture' -Root '' -IntervalSeconds 5
$packedUtc=[datetime]::SpecifyKind([datetime]'2026-10-24T10:00:00',[DateTimeKind]::Utc)
$exactBytes=[long]9007199254740993
for($packedIndex=0;$packedIndex -le 360;$packedIndex++) {
    Add-MiTrackSample -Analyzer $packed -Snapshot (New-Fixture -Utc $packedUtc.AddSeconds(5*$packedIndex) -PrivateBytes $exactBytes)
}
$packedList=$packed.Tracks['memory-fixture:321:987654321'].Samples
Assert-Mi ($packedList.Count -eq 361 -and $packedList[0].Bytes -eq $exactBytes -and
    ($packedList[360].Utc-$packedList[0].Utc).TotalSeconds -eq 1800) 'compact evidence lost exact bytes or full window'
Add-MiTrackSample -Analyzer $packed -Snapshot (New-Fixture -Utc $packedUtc.AddHours(2) -PrivateBytes $exactBytes)
Assert-Mi ($packedList.Count -eq 1 -and $packedList[0].Bytes -eq $exactBytes) 'compact evidence retained expired samples'
# 独立的存活对象预算：100实例各361点必须全部保留，不能靠缩短窗口通过。
# GC 仅在测试测量前后使用，不在生产循环内强迫回收或修剪工作集。
$budgetAnalyzer=New-MiAnalyzer -BootId 'budget' -Root '' -IntervalSeconds 5
$budgetRows=@(for($budgetPid=1;$budgetPid -le 100;$budgetPid++){
    [pscustomobject]@{PID=$budgetPid;StartUtcTicks=[long]$budgetPid;Name='budget';PrivateBytes=1GB}
})
$budgetBefore=[GC]::GetTotalMemory($true)
for($budgetStep=0;$budgetStep -le 360;$budgetStep++) {
    Add-MiTrackSample -Analyzer $budgetAnalyzer -Snapshot ([pscustomobject]@{CaptureEndUtc=$packedUtc.AddSeconds($budgetStep*5);Processes=[pscustomobject]@{Status='Success';Items=$budgetRows}})
}
$budgetAfter=[GC]::GetTotalMemory($true)
Assert-Mi (($budgetAfter-$budgetBefore) -lt 16MB) '100 complete instance windows exceeded 16 MiB retained-managed budget'
Assert-Mi ($budgetAnalyzer.Tracks.Count -eq 100 -and @($budgetAnalyzer.Tracks.Values|Where-Object {$_.Samples.Count -ne 361}).Count -eq 0) 'memory optimization dropped evidence to meet budget'
$budgetAnalyzer=$null

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
    # 值类型点以完整点写回列表，仍给每隔一个真实证据点注入原有200ms抖动。
    for ($i=0;$i -lt $jitterSamples.Count;$i++) {
        $point=$jitterSamples[$i]
        $jitterSamples[$i]=[MemoryInspector.AnalysisPoint]::new($point.Utc.AddMilliseconds(($i%2)*200),$point.Bytes)
    }
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
    $plainRecords=@(Get-MiRecentProcessRecords -Root $root -NowUtc $now -IntervalSeconds 10)
    $compactRecords=@(Get-MiRecentProcessRecords -Root $root -NowUtc $now -IntervalSeconds 10 -Compact)
    Assert-Mi ($plainRecords.Count -eq $compactRecords.Count) 'compact restore lost records'
    for($recordIndex=0;$recordIndex -lt $plainRecords.Count;$recordIndex++) {
        $plainRecord=$plainRecords[$recordIndex];$compactRecord=$compactRecords[$recordIndex]
        Assert-Mi ($plainRecord.CaptureEndUtc -eq $compactRecord.CaptureEndUtc -and $plainRecord.RecordType -eq $compactRecord.RecordType -and
            $plainRecord.ProcessStatus -eq $compactRecord.ProcessStatus -and $plainRecord.IntervalSeconds -eq $compactRecord.IntervalSeconds -and
            $plainRecord.MonotonicSeconds -eq $compactRecord.MonotonicSeconds -and $plainRecord.ContinuityId -eq $compactRecord.ContinuityId) 'compact restore changed ordering/continuity metadata'
    }
    $compactProbe=ConvertTo-MiCompactAnalysisRecord ([pscustomobject]@{SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$now.ToString('o');IntervalSeconds=5;MonotonicSeconds=12.5;ContinuityId='exact';ProcessStatus='Partial';Items=@(
        [pscustomobject]@{PID=1;Name='exact';StartUtcTicks=[long]9007199254740993;PrivateBytes=[long]9007199254740993;ProcessInstanceId='boot:1:9007199254740993'},
        [pscustomobject]@{PID=2;Name='unknown';StartUtcTicks=$null;PrivateBytes=1GB},
        [pscustomobject]@{PID=3;Name='negative';StartUtcTicks=3;PrivateBytes=-1},
        [pscustomobject]@{PID=4;Name='missing';StartUtcTicks=4;PrivateBytes=$null}
    )})
    Assert-Mi ($compactProbe.Items.Count -eq 3 -and $compactProbe.Items[0].PrivateBytes -eq [long]9007199254740993 -and
        $compactProbe.Items[0].StartUtcTicks -eq [long]9007199254740993 -and $compactProbe.Items[0].ProcessInstanceId -ceq 'boot:1:9007199254740993' -and
        $compactProbe.Items[1].PrivateBytes -eq -1 -and $null -eq $compactProbe.Items[2].PrivateBytes -and
        $compactProbe.MonotonicSeconds -eq 12.5 -and $compactProbe.ContinuityId -ceq 'exact') 'compact saved rows fabricated identities, rounded Int64 or lost metadata'
    # null/负数行本身不贡献证据，但A→B→A连续段断点不能被紧凑读取器吞掉。
    $counterIndex=0
    foreach($badCounter in @($null,-1)) {
        $counterRoot=Join-Path $root ('counter-continuity-'+$counterIndex++)
        $counterDir=Join-Path $counterRoot 'process';[void][IO.Directory]::CreateDirectory($counterDir)
        $counterLines=@(for($j=0;$j -lt 3;$j++){
            [pscustomobject]@{SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$now.AddMinutes(-10+$j*5).ToString('o');IntervalSeconds=5
                MonotonicSeconds=(100+$j*100);ContinuityId=$(if($j -eq 1){'B'}else{'A'});ProcessStatus='Partial'
                Items=@([pscustomobject]@{PID=321;Name='fixture';StartUtcTicks=987654321L;PrivateBytes=$(if($j -eq 1){$badCounter}else{400MB});ProcessInstanceId='TestBoot:321:987654321'})}|ConvertTo-Json -Depth 5 -Compress
        })
        [IO.File]::WriteAllLines((Join-Path $counterDir ('process-'+$now.ToString('yyyy-MM-dd')+'.jsonl')),$counterLines,[Text.UTF8Encoding]::new($false))
        $counterAnalyzer=New-MiAnalyzer -BootId TestBoot -Root $counterRoot -IntervalSeconds 5
        [void](Restore-MiAnalyzer $counterAnalyzer $now)
        Assert-Mi ($counterAnalyzer.Tracks['TestBoot:321:987654321'].Samples.Count -eq 1) 'compact restore spliced evidence across a null/invalid-counter continuity barrier'
    }
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


# P2-02：两小时回拨后仍能在新的 UTC 段完成完整分析；序号重复不能触发错误清窗。
$clockAnalyzer=New-MiAnalyzer -BootId TestBoot -Root ''
$origin=[datetime]::SpecifyKind([datetime]'2026-10-24T12:00:00',[DateTimeKind]::Utc)
function New-ClockFixture($Utc,$Sequence,$Monotonic,$Bytes=400MB) {
    $fixture=New-Fixture -Utc $Utc -PrivateBytes $Bytes
    $fixture | Add-Member -NotePropertyName Sequence -NotePropertyValue $Sequence
    $fixture | Add-Member -NotePropertyName MonotonicSeconds -NotePropertyValue $Monotonic
    return $fixture
}
[void](Invoke-MiDiagnosis $clockAnalyzer (New-ClockFixture $origin 1 100))
$segmentId=$clockAnalyzer.ContinuityId
$rollbackSample=New-ClockFixture ($origin.AddHours(-2)) 2 105
$rollbackResult=Invoke-MiDiagnosis $clockAnalyzer $rollbackSample
Assert-Mi ($rollbackResult.Status -eq 'Stale' -and $rollbackSample.TimeDiscontinuity -and $clockAnalyzer.ContinuityId -ne $segmentId) 'Rollback did not mark a new historical continuity segment.'
$newOrigin=$origin.AddHours(-2).AddSeconds(5)
for ($i=0;$i -le 360;$i++) {
    $lastClock=Invoke-MiDiagnosis $clockAnalyzer (New-ClockFixture ($newOrigin.AddSeconds($i*5)) ($i+3) (110+$i*5) (400MB+$i*3MB))
}
Assert-Mi ($lastClock.Reports[0].AnomalyState -eq 'SuspectedSustainedGrowth' -and $lastClock.Reports[0].ValidSampleCount -eq 361) 'Rollback recovery could not build a complete new window.'
$resetCount=$clockAnalyzer.WindowResetCount
$late=Invoke-MiDiagnosis $clockAnalyzer (New-ClockFixture $origin.AddHours(-3) 2 105)
Assert-Mi ($late.Status -eq 'Stale' -and $clockAnalyzer.WindowResetCount -eq $resetCount -and $clockAnalyzer.Tracks.Count -eq 1) 'Late sequence destroyed a valid current window.'
$hidden=New-MiAnalyzer -BootId TestBoot -Root ''
[void](Invoke-MiDiagnosis $hidden (New-ClockFixture $origin 1 100))
$hiddenRollback=New-ClockFixture ($origin.AddSeconds(1)) 2 105
[void](Invoke-MiDiagnosis $hidden $hiddenRollback)
Assert-Mi ($hiddenRollback.TimeDiscontinuity -and $hidden.WindowResetCount -eq 1) 'Monotonic time failed to detect a backward correction while UTC still increased.'
[void](Invoke-MiDiagnosis $hidden (New-ClockFixture ($origin.AddSeconds(6)) 3 110))
Assert-Mi ($hidden.Tracks['TestBoot:321:987654321'].Samples.Count -eq 1) 'Hidden rollback did not restart collection.'
# JSONL/ZIP 恢复仍使用 UTC，按追加顺序读取最后连续段，不排序后拼接回拨前后的增长。
$historyRoot=Join-Path $PSScriptRoot ('test-artifacts\p2-clock-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $historyRoot 'process'))
$historyPath=Join-Path $historyRoot 'process\process-2026-10-24.jsonl'
$historyLines=@()
foreach ($entry in @(
    @{Utc=$origin.AddMinutes(-10);Segment='before'},
    @{Utc=$origin;Segment='before'},
    @{Utc=$origin.AddMinutes(-5);Segment='after'},
    @{Utc=$origin.AddMinutes(-4);Segment='after'})) {
    $historyLines+=([pscustomobject]@{SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$entry.Utc.ToString('o');ContinuityId=$entry.Segment
        ProcessStatus='Success';Items=@([pscustomobject]@{PID=321;Name='fixture';StartUtcTicks=987654321L;PrivateBytes=400MB;ProcessInstanceId='TestBoot:321:987654321'})} | ConvertTo-Json -Compress -Depth 6)
}
[IO.File]::WriteAllLines($historyPath,[string[]]$historyLines,[Text.UTF8Encoding]::new($false))
$historyAnalyzer=New-MiAnalyzer -BootId TestBoot -Root $historyRoot
Assert-Mi ((Restore-MiAnalyzer $historyAnalyzer $origin) -eq 2 -and $historyAnalyzer.Tracks['TestBoot:321:987654321'].Samples.Count -eq 2) 'Historical rollback spliced continuity segments.'
Write-Host 'PASS: P2-02 UTC/monotonic rollback, sequence replay, full-window recovery and historical discontinuity.' -ForegroundColor Green


# 跨午夜回拨：按日期文件遍历会把新段排到旧段之前，必须由单调时间纠正。
$midRoot=Join-Path $historyRoot 'midnight'
[void][IO.Directory]::CreateDirectory((Join-Path $midRoot 'process'))
$midEnd=[datetime]::SpecifyKind([datetime]'2026-10-24T00:15:00',[DateTimeKind]::Utc)
foreach ($entry in @(
    @{Utc=$midEnd.AddMinutes(-15);Mono=100;Id='before'},
    @{Utc=$midEnd.AddMinutes(-5);Mono=200;Id='before'},
    @{Utc=$midEnd.AddMinutes(-20);Mono=205;Id='after'},
    @{Utc=$midEnd.AddMinutes(-10);Mono=805;Id='after'})) {
    $row=[pscustomobject]@{SchemaVersion=1;RecordType='ProcessSnapshot';CaptureEndUtc=$entry.Utc.ToString('o')
        MonotonicSeconds=$entry.Mono;ContinuityId=$entry.Id;ProcessStatus='Success'
        Items=@([pscustomobject]@{PID=321;Name='fixture';StartUtcTicks=987654321L;PrivateBytes=400MB;ProcessInstanceId='TestBoot:321:987654321'})}
    $file=Join-Path $midRoot ('process\process-'+$entry.Utc.ToString('yyyy-MM-dd')+'.jsonl')
    [IO.File]::AppendAllText($file,($row|ConvertTo-Json -Compress -Depth 6)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
$midAnalyzer=New-MiAnalyzer -BootId TestBoot -Root $midRoot
Assert-Mi ((Restore-MiAnalyzer $midAnalyzer $midEnd) -eq 2 -and $midAnalyzer.ContinuityId -eq 'after') 'Cross-midnight rollback restored the wrong continuity segment.'
$resumed=Invoke-MiDiagnosis $midAnalyzer (New-ClockFixture ($midEnd.AddMinutes(-10).AddSeconds(5)) 1 810)
Assert-Mi ($resumed.Status -eq 'Success' -and $resumed.Reports[0].ValidSampleCount -eq 3 -and $midAnalyzer.ContinuityId -eq 'after') 'Normal restart failed to preserve the recovered segment.'
Write-Host 'PASS: P2 cross-midnight historical ordering and restart continuity.' -ForegroundColor Green

# V3-M1：实际时间与独立统计口径。夹具只创建标量，不终止或修改真实进程。
foreach ($cadence in @(5,7,30,60)) {
    $a=New-MiAnalyzer -BootId V3 -Root '' -IntervalSeconds $cadence
    $end=[datetime]::SpecifyKind([datetime]'2026-10-25T12:30:00',[DateTimeKind]::Utc)
    $count=[int][math]::Floor(1800/$cadence)
    for ($i=$count;$i -ge 0;$i--) {
        $s=New-Fixture -Utc $end.AddSeconds(-$i*$cadence) -PrivateBytes (100MB+($count-$i)*10MB) -IntervalSeconds $cadence
        $s.System | Add-Member PagedPoolBytes (100MB+($count-$i)*10MB)
        $s.System.NonpagedPoolBytes=128MB+($count-$i)*10MB
        $d=Invoke-MiDiagnosis $a $s
    }
    $v3=$d.Attribution
    $pool=@($v3.Findings | Where-Object MetricName -eq PagedPoolBytes)[0]
    Assert-Mi ($pool.MeasurementQuality -eq 'Complete' -and $pool.Trend -eq 'SustainedGrowth') ('V3 pool trend/cadence '+$cadence)
    Assert-Mi ($pool.SamplingQuality.ExpectedSampleCount -eq ($count+1) -and $pool.SamplingQuality.ValidSampleCount -eq ($count+1)) 'V3 dynamic window counts incorrect.'
    Assert-Mi ($pool.SamplingQuality.ActualSpanSeconds -eq $count*$cadence) 'V3 manufactured time span.'
    Assert-Mi ($v3.Ram.AvailablePhysicalBytes -eq 6GB -and $null -eq $v3.Ram.CompressionBytes) 'V3 RAM mixed with commit or unknown compressed memory became zero.'
    $commit=@($v3.Findings | Where-Object MetricName -eq CommittedBytes)[0]
    $residual=@($v3.Findings | Where-Object Category -eq UnresolvedCommit)[0]
    Assert-Mi ($commit.ObservedBytes -eq 4GB -and $commit.GrowthBytes -eq 0 -and $residual.AttributionConfidence -eq 'Unresolved') 'V3 double counted Working Set or resolved a residual.'
    foreach ($finding in @($v3.Findings)+@($v3.ProcessFindings)) {
        foreach ($field in @('FindingId','SchemaVersion','Category','TimeRangeUtc','MetricName','ObservedBytes','GrowthBytes','SourceType',
            'ProcessInstanceId','TraceSessionId','MeasurementQuality','AttributionConfidence','EventLossStatus','Limitations','SuggestedNextStep')) {
            Assert-Mi ($null -ne $finding.PSObject.Properties[$field]) ('Missing Finding field '+$field)
        }
        Assert-Mi ($finding.EventLossStatus -eq 'NotApplicable' -and $null -eq $finding.TraceSessionId) 'Counter finding invented ETW completeness.'
    }
    # 一个缺失字段只降低自己的证据质量，不能抹掉其他可读指标或填零。
    $s=New-Fixture -Utc $end.AddSeconds($cadence) -IntervalSeconds $cadence
    $s.System.CommittedBytes=$null
    $partial=(Invoke-MiDiagnosis $a $s).Attribution
    $missing=@($partial.Findings | Where-Object MetricName -eq CommittedBytes)[0]
    Assert-Mi ($missing.MeasurementQuality -eq 'Unavailable' -and $null -eq $missing.ObservedBytes -and $null -eq $missing.GrowthBytes) 'Missing commit reused stale value.'
    Assert-Mi ($partial.ProcessFindings[0].ObservedBytes -eq 200MB) 'Missing commit removed valid process evidence.'
    # PID 相同但创建时间变化，不能继承前实例的趋势。
    $replacement=New-Fixture -Utc $end.AddSeconds(2*$cadence) -StartTicks 888888888 -IntervalSeconds $cadence
    $new=(Invoke-MiDiagnosis $a $replacement).Attribution.ProcessFindings[0]
    Assert-Mi ($new.SamplingQuality.ValidSampleCount -eq 1 -and $null -eq $new.GrowthBytes -and $new.MeasurementQuality -eq 'Partial') 'PID reuse inherited old attribution.'
}

$a=New-MiAnalyzer -BootId V3 -Root '' -IntervalSeconds 5
for ($i=0;$i -le 360;$i++) {
    if ($i -ge 150 -and $i -le 180) {continue}
    $s=New-Fixture -Utc $end.AddSeconds(($i-360)*5) -IntervalSeconds 5
    $s.System.NonpagedPoolBytes=128MB+$i*4MB
    $d=Invoke-MiDiagnosis $a $s
}
$gapFinding=@($d.Attribution.Findings | Where-Object MetricName -eq NonpagedPoolBytes)[0]
Assert-Mi ($gapFinding.MeasurementQuality -eq 'Partial' -and $gapFinding.Trend -eq 'InsufficientEvidence' -and
    $gapFinding.SamplingQuality.MissingSampleCount -eq 31 -and $gapFinding.SamplingQuality.MaximumGapSeconds -eq 160) 'Sleep gap hidden by high coverage.'
$dup=Invoke-MiDiagnosis $a $s
Assert-Mi ($dup.Status -eq 'Stale' -and $a.AttributionHistory.CommittedBytes.Count -eq 330) 'Duplicate samples inflated attribution.'
$s=New-Fixture -Utc $end.AddSeconds(30) -IntervalSeconds 30
$changed=(Invoke-MiDiagnosis $a $s).Attribution
Assert-Mi ($changed.Findings[0].SamplingQuality.ValidSampleCount -eq 1 -and $changed.Findings[0].SamplingQuality.ExpectedSampleCount -eq 61) 'Cadence change retained old system window.'
$s=New-Fixture -Utc $end.AddMinutes(-60) -IntervalSeconds 30
Assert-Mi ((Invoke-MiDiagnosis $a $s).Status -eq 'Stale' -and $a.AttributionHistory.Count -eq 0) 'Clock rollback retained attribution window.'

# 精确计数、合法零、非法计数器与高密度补采。
foreach ($bad in @($null,'',-1,'NaN','Infinity','1.5',$true,'9223372036854775808')) {
    Assert-Mi ($null -eq (Get-MiAttributionBytes $bad)) 'Invalid attribution counter accepted.'
}
Assert-Mi ((Get-MiAttributionBytes 0) -ceq 0L -and (Get-MiAttributionBytes 9007199254740993L) -eq 9007199254740993L) 'Exact Int64/zero lost.'
$points=New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]'
for ($i=0;$i -lt 400;$i++) {$points.Add([MemoryInspector.AnalysisPoint]::new($end.AddMilliseconds(-$i*10),100))}
$burst=[MemoryInspector.AttributionWindow]::Measure($points,$end,5)
Assert-Mi ($burst.ValidSampleCount -le 2 -and -not $burst.SufficientTrend) 'Burst fabricated full coverage.'

# 同名不同路径分开，同路径多个实例合并；父创建时间晚于子时不建立关系。
$members=@(
    [pscustomobject]@{PID=10;Name='same';StartUtcTicks=100;ExecutablePath='C:\fixture\a.exe';PrivateBytes=10MB},
    [pscustomobject]@{PID=11;Name='same';StartUtcTicks=110;ExecutablePath='C:\fixture\a.exe';PrivateBytes=20MB;ParentPid=10;ParentStartUtcTicks=100},
    [pscustomobject]@{PID=12;Name='same';StartUtcTicks=120;ExecutablePath='C:\fixture\b.exe';PrivateBytes=$null;ParentPid=10;ParentStartUtcTicks=999}
)
$exe=@(Get-MiProcessGroups $members V3 -Mode Executable)
Assert-Mi ($exe.Count -eq 2 -and @($exe | Where-Object ObservedPrivateBytes -eq 30MB).Count -eq 1) 'Executable grouping merged names or lost instances.'
$parents=@(Get-MiProcessGroups $members V3 -Mode Parent)
Assert-Mi ($parents.Count -eq 2 -and @($parents | Where-Object MemberCount -eq 2).Count -eq 1) 'Parent PID reuse linked wrong group.'
$logic=@(Get-MiProcessGroups $members V3 -Mode Logical -SelectedInstanceIds @('V3:10:100','V3:12:120','V3:99:999'))
Assert-Mi ($logic.Count -eq 1 -and $logic[0].MemberCount -eq 2 -and $logic[0].ObservedPrivateBytes -eq 10MB -and $logic[0].MeasurementQuality -eq 'Partial') 'Logical group hid missing members.'
$instances=@(Get-MiProcessGroups @($members[0],$members[0]) V3 -Mode Instance)
Assert-Mi ($instances.Count -eq 1 -and $instances[0].ObservedPrivateBytes -eq 10MB) 'Duplicate instance counted twice.'
Write-Host 'PASS: V3-M1 contracts, Commit/RAM separation, pool trends, cadence/gaps/reset, PID reuse and process grouping.' -ForegroundColor Green

# M5：实际 CSV/UTF-8/句柄，工具、已验收版本与 ETL 消费边界用显式替身；不录制/联网。
& {
    . (Join-Path $PSScriptRoot 'PrivilegeSecurity.ps1')
    function Assert-M5Rejected {param([scriptblock]$Action,[string]$Label)
        $denied=$false;try {& $Action|Out-Null} catch {$denied=$true};Assert-Mi $denied ('M5 accepted '+$Label)
    }
    $fixture=Join-Path $PSScriptRoot ('test-artifacts\WpaExport-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($fixture)
    $availability=Get-MiAttributionExportAvailability
    Assert-Mi (-not $availability.ReleaseReady -and $availability.State -ceq 'AnalysisUnavailable') 'M5 actual release gate opened'
    Assert-M5Rejected {Invoke-MiAttributionExport ([guid]::NewGuid().ToString('N'))} 'actual export gate'
    foreach ($type in @('VirtualAlloc','Pool','Heap')) {
        $candidate=Get-MiWpaExportContract $type;[xml]$xml=$candidate.Xml
        Assert-Mi ($candidate.AcceptedVersions.Count -eq 0 -and $candidate.Headers.Count -eq 0) 'invented accepted table/version'
    }
    Initialize-MiExporterNative # PS5.1 编译检查；不是 WPAExporter/Job 实机验收。
    $contract=[pscustomobject]@{TraceType='VirtualAlloc';Headers=@('Process','Type','Size (B)');SizeColumn='Size (B)';LabelColumn='Process';ByteMultiplier=1;MetricName='VirtualAlloc.ExportedAllocatedBytes'}
    $metadata=[pscustomobject]@{SchemaVersion=1;ArtifactId=[guid]::NewGuid().ToString('N');TraceSessionId=[guid]::NewGuid().ToString('N');
        TraceType='VirtualAlloc';StartUtc='2026-10-25T00:00:00.0000000Z';EndUtc='2026-10-25T00:05:00.0000000Z';EventLossStatus='NoLossReported'}
    $csv=Join-Path $fixture 'normal.csv'
    [IO.File]::WriteAllText($csv,"Process,Type,Size (B)`r`n`"程序,甲 (7)`",Commit,9007199254740993`r`nfixture (8),Reserve,0`r`n",[Text.UTF8Encoding]::new($false))
    $result=ConvertFrom-MiWpaCsv $csv $metadata $contract
    Assert-Mi ($result.Findings.Count -eq 2 -and $result.Findings[0].ObservedBytes -eq 9007199254740993L -and $result.Findings[1].ObservedBytes -eq 0) 'CSV integer/quoted Unicode precision'
    Assert-Mi ($null -eq $result.Findings[0].GrowthBytes -and $null -eq $result.Findings[0].ProcessInstanceId -and $result.Findings[0].SourceType -ceq 'WPAExporter') 'export invented growth/identity'
    Assert-M5Rejected {ConvertFrom-MiWpaCsv $csv $metadata $contract -MaxFindingBytes 100} 'normalized result amplification budget'
    $metadata.EventLossStatus='LossReported';$result=ConvertFrom-MiWpaCsv $csv $metadata $contract
    Assert-Mi ($result.Findings[0].MeasurementQuality -ceq 'Partial') 'event loss hidden'
    foreach ($bad in @("Process,Type,Size (MB)`nfixture,Commit,1", "Process,Type,Size (B)`nfixture,Commit,1.1", "Process,Type,Size (B)`nfixture,Commit,-1",
        "Process,Type,Size (B)`nfixture,Commit,NaN", "Process,Type,Size (B)`nfixture,Commit,9223372036854775808", "Process,Type,Size (B)`nfixture,Commit,1`nfixture,Commit,2",
        "Process,Type,Size (B)`nTotal,Commit,10", "Process,Type,Size (B)`n=BAD,Commit,1", "Process,Type,Size (B)`nfixture,Commit", "Process,Process,Size (B)`nfixture,Commit,1",
        "Process,Type,Size (B)`n`"unterminated,Commit,1")) {
        [IO.File]::WriteAllText($csv,$bad,[Text.UTF8Encoding]::new($false));Assert-M5Rejected {ConvertFrom-MiWpaCsv $csv $metadata $contract} 'malformed CSV'
    }
    [IO.File]::WriteAllText($csv,"Process,Type,Size (B)`n",[Text.UTF8Encoding]::new($false))
    Assert-Mi ((ConvertFrom-MiWpaCsv $csv $metadata $contract).State -ceq 'AnalysisPartial') 'empty table treated as no anomaly'
    [IO.File]::WriteAllBytes($csv,[byte[]]@(255,255,255));Assert-M5Rejected {ConvertFrom-MiWpaCsv $csv $metadata $contract} 'invalid UTF-8'
    $test=@{Fixture=$fixture;Calls=@();Admin=$false;ToolMissing=$false;ToolUnsupported=$false}
    function Get-MiExportReleaseStatus {return [pscustomobject]@{Enabled=$true;OfflineAccepted=$true;OnlineAccepted=$true;NormalizationAccepted=$true}}
    function Get-MiWprReleaseStatus {return [pscustomobject]@{Enabled=$true;M2Accepted=$true;MemoryAccepted=$true}}
    function Get-MiHeapReleaseStatus {return [pscustomobject]@{Enabled=$true;ConfigurationAccepted=$true;RecoveryAccepted=$true}}
    function Test-MiAdminToken {return $test.Admin}
    function Get-MiSecurityPaths {return $test.Paths}
    function Assert-MiTracePath {param($Path)
        if ($test.PathFault -or -not (Test-Path -LiteralPath $Path) -or
            (-not [IO.Path]::GetFullPath($Path).StartsWith($test.Fixture,[StringComparison]::OrdinalIgnoreCase) -and $Path -ine (Join-Path $test.Paths.Install 'Analyzer.ps1'))) {throw 'Fixture trust rejection'}
    }
    function Get-MiWpaExporterIdentity {if ($test.ToolMissing) {return $null};return [pscustomobject]@{SchemaVersion=1;Path='C:\Windows\fixture.exe';Version='FixtureOnly';Sha256=('A'*64)}}
    function Get-MiWpaExportContract {param($TraceType)
        return [pscustomobject]@{TraceType=$TraceType;AcceptedVersions=if ($test.ToolUnsupported) {@()} else {@('FixtureOnly')};Headers=@('Process','Type','Size (B)');
            SizeColumn='Size (B)';LabelColumn='Process';ByteMultiplier=1;MetricName='VirtualAlloc.ExportedAllocatedBytes';ProfileId='FixtureOnly';Xml='<fixture/>';CsvPattern='Mi_*.csv'}
    }
    function Test-MiEtlArtifact {param($Path)
        return [pscustomobject]@{SizeBytes=(Get-Item -LiteralPath $Path).Length;Sha256=if ($test.CorruptEtl) {('0'*64)} else {(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash};
            StartUtc=$test.Descriptor.StartUtc;EndUtc=$test.Descriptor.EndUtc;EventsLost=0;BuffersLost=0}
    }
    function Measure-MiProtectedTree {param($Root) if ($test.BudgetFault -or ($test.ResultBudgetFault -and $test.Calls.Count -gt 0)) {return 8589934592};return 0L}
    function Read-Host {param($Prompt) if ($test.Consent -and $Prompt -match 'SYMBOLS ([a-f0-9]{32})') {return 'SYMBOLS '+$matches[1]};return ''}
    function Invoke-MiWpaExportProcess {param($Tool,$Etl,$Profile,$Output,$Cache,[switch]$Online)
        $test.Calls+=,[pscustomobject]@{Online=[bool]$Online;Output=$Output}
        # 实际持有租约和 ETL 读句柄；即使替身也须证明并发归档/部署不能取得独占访问。
        Assert-M5Rejected {[IO.File]::Open($test.Paths.DeploymentLease,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)} 'active deployment lease'
        Assert-M5Rejected {[IO.File]::Open($Etl,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)} 'active ETL reference'
        if ($test.ThrowProcess) {throw 'Unknown exporter outcome'}
        if ($Online -and $test.SymbolFailure) {return 1}
        if (-not $test.MissingTable) {[IO.File]::WriteAllText((Join-Path $Output 'Mi_fixture.csv'),"Process,Type,Size (B)`nfixture,Commit,100`n",[Text.UTF8Encoding]::new($false))}
        return 0
    }
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $test.Paths=[pscustomobject]@{Install=$PSScriptRoot;TraceArtifacts=(Join-Path $fixture 'diagnostics');DeploymentLease=(Join-Path $fixture 'deployment.lock')}
    [IO.File]::WriteAllText($test.Paths.DeploymentLease,'lease')
    $directory=Join-Path $test.Paths.TraceArtifacts $owner;[void][IO.Directory]::CreateDirectory($directory)
    $etl=Join-Path $directory ($metadata.ArtifactId+'.etl');[IO.File]::WriteAllText($etl,'fixture ETL')
    $test.Descriptor=[pscustomobject][ordered]@{SchemaVersion=1;ArtifactId=$metadata.ArtifactId;TraceSessionId=$metadata.TraceSessionId;OwnerSid=$owner;
        TraceType='VirtualAlloc';SizeBytes=(Get-Item $etl).Length;Sha256=(Get-FileHash $etl -Algorithm SHA256).Hash;EventLossStatus='NoLossReported';
        StartUtc=$metadata.StartUtc;EndUtc=$metadata.EndUtc;AnalyzerSha256=(Get-FileHash (Join-Path $PSScriptRoot 'Analyzer.ps1') -Algorithm SHA256).Hash}
    [IO.File]::WriteAllText((Join-Path $directory ($metadata.ArtifactId+'.export.json')),($test.Descriptor|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    [void][IO.Directory]::CreateDirectory((Join-Path $directory ($metadata.ArtifactId+'.export')))
    foreach ($case in @('Offline','OnlineCancelled','Online','SymbolFailure','MissingTable','UnknownOutcome','MissingTool','UnsupportedTool','CorruptEtl','Budget','ResultBudget','Admin')) {
        $test.Calls=@();$test.Consent=$case -cin @('Online','SymbolFailure');$test.SymbolFailure=$case -ceq 'SymbolFailure';$test.MissingTable=$case -ceq 'MissingTable'
        $test.ThrowProcess=$case -ceq 'UnknownOutcome';$test.ToolMissing=$case -ceq 'MissingTool';$test.ToolUnsupported=$case -ceq 'UnsupportedTool'
        $test.CorruptEtl=$case -ceq 'CorruptEtl';$test.BudgetFault=$case -ceq 'Budget';$test.ResultBudgetFault=$case -ceq 'ResultBudget';$test.Admin=$case -ceq 'Admin'
        if ($case -cin @('CorruptEtl','Budget','Admin')) {Assert-M5Rejected {Invoke-MiAttributionExport $metadata.ArtifactId} $case;Assert-Mi ($test.Calls.Count -eq 0) 'rejected analysis dispatched';continue}
        $result=Invoke-MiAttributionExport $metadata.ArtifactId -OnlineSymbols:($case -cin @('OnlineCancelled','Online','SymbolFailure'))
        if ($case -cin @('MissingTool','UnsupportedTool')) {Assert-Mi ($result.State -ceq 'AnalysisUnavailable' -and $test.Calls.Count -eq 0) 'missing/unsupported tool not degraded';continue}
        if ($case -cin @('MissingTable','UnknownOutcome')) {Assert-Mi ($result.State -ceq 'AnalysisPartial' -and $result.Findings.Count -eq 0 -and $test.Calls.Count -eq 1) 'missing/unknown result accepted or retried';continue}
        if ($case -ceq 'ResultBudget') {Assert-Mi ($result.State -ceq 'AnalysisPartial' -and -not $result.ResultPersisted -and $result.Findings.Count -eq 0) 'result write exceeded refreshed budget';continue}
        Assert-Mi ($result.State -ceq 'Complete' -and $result.Findings.Count -eq 1 -and $result.ResultTrust -ceq 'UserOwnedDiagnosticOnly') 'ordinary export pipeline failed'
        if ($case -ceq 'SymbolFailure') {Assert-Mi ($test.Calls.Count -eq 2 -and $test.Calls[0].Online -and -not $test.Calls[1].Online) 'known symbol failure fallback'}
        else {Assert-Mi ($test.Calls.Count -eq 1 -and $test.Calls[0].Online -eq ($case -ceq 'Online')) 'network consent reused/ignored'}
    }
    foreach ($case in @('GuiOnline','GuiCancelled','GuiClosed')) {
        foreach ($flag in @('Admin','ToolMissing','ToolUnsupported','CorruptEtl','BudgetFault','ResultBudgetFault','SymbolFailure','MissingTable','ThrowProcess')) {$test[$flag]=$false}
        $test.Calls=@();$channel=[hashtable]::Synchronized(@{Question=$null;Answer=$null;Cancelled=($case -ceq 'GuiClosed')})
        if ($case -ceq 'GuiClosed') {
            Assert-M5Rejected {Invoke-MiAttributionExport $metadata.ArtifactId -OnlineSymbols -ConsentChannel $channel} 'GUI closed consent'
            Assert-Mi ($test.Calls.Count -eq 0) 'closed GUI dispatched analysis';continue
        }
        $responder=[Management.Automation.PowerShell]::Create()
        try {
            [void]$responder.AddScript('param($Channel,$Online) while ($null -eq $Channel.Question) {[Threading.Thread]::Sleep(10)}; $Channel.Answer=if ($Online) {"SYMBOLS "+$Channel.Question.AnalysisId} else {""}').AddArgument($channel).AddArgument($case -ceq 'GuiOnline')
            $response=$responder.BeginInvoke()
            $result=Invoke-MiAttributionExport $metadata.ArtifactId -OnlineSymbols -ConsentChannel $channel
            [void]$responder.EndInvoke($response)
            Assert-Mi ($test.Calls.Count -eq 1 -and $test.Calls[0].Online -eq ($case -ceq 'GuiOnline') -and $channel.Question.Prompt -match 'https://msdl.microsoft.com/download/symbols' -and $channel.Question.Prompt -match 'Cache:') 'GUI single analysis consent/fallback broken'
        } finally {$responder.Dispose()}
    }
    Write-Host 'PASS: M5 strict CSV/precision/quality, fixed version refusal, ordinary-worker gates, consent/fallback, unknown outcome, and real deployment/ETL read leases (exporter mocked); M7 GUI consent channel/cancel/close.'
}
