#requires -Version 5.1
<#
Milestone 3 / v0.0.3: READ-ONLY anomaly detection.
No process/service actions. Private Bytes trends are heuristics, NOT leak proof.
Analyzes immutable scalar snapshots from Collector and historical JSONL from M2.
#>
function Get-MiMedian {
    param([object[]]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $middle = [int][math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle-1] + [double]$sorted[$middle]) / 2.0
}

function Get-MiInstanceKey {
    param([string]$BootId,$Process)
    if ($null -eq $Process -or $null -eq $Process.PID -or $null -eq $Process.StartUtcTicks -or
        [long]$Process.StartUtcTicks -le 0 -or [string]::IsNullOrWhiteSpace([string]$Process.Name)) { return $null }
    return ('{0}:{1}:{2}' -f $BootId,[int]$Process.PID,[long]$Process.StartUtcTicks)
}

function Get-MiAnalysisParameters {
    param([ValidateRange(5,60)][int]$IntervalSeconds=5)
    # 窗口包含首尾采样点；不能把 1800 / 周期的近似值当成精确样本数。
    $expected = [int][math]::Floor(1800.0 / $IntervalSeconds) + 1
    return [pscustomobject]@{
        IntervalSeconds=$IntervalSeconds;WindowSeconds=1800;BinSeconds=300
        ExpectedSampleCount=$expected
        MinimumSampleCount=[int][math]::Ceiling($expected*0.85)
        HistoryCapacity=($expected+[int][math]::Ceiling($expected*0.20)+2)
        MinimumCoverageRatio=0.85
        BoundaryToleranceSeconds=($IntervalSeconds/2.0)
        MaximumGapSeconds=[math]::Max(60,3*$IntervalSeconds)
    }
}

function New-MiAnalyzer {
    param([string]$BootId,[string]$Root,[int]$WindowMinutes=30,
        [ValidateRange(5,60)][int]$IntervalSeconds=5)
    if ($WindowMinutes -ne 30) { throw 'Milestone 3 uses a fixed 30-minute diagnostic window.' }
    $usableBoot = -not [string]::IsNullOrWhiteSpace($BootId) -and $BootId -ne 'BootUnavailable'
    return [pscustomobject]@{
        BootId = $(if ($usableBoot) { $BootId } else { 'Session-'+[guid]::NewGuid().ToString('N') })
        CanRestore = $usableBoot
        Root = $Root
        Tracks = @{}
        PoolHistory = (New-Object 'System.Collections.Generic.List[object]')
        Historical = @{}
        HistoricalLoadedUtc = [datetime]::MinValue
        LastCaptureUtc = [datetime]::MinValue
        LastSequence = $null
        LastMonotonicSeconds = $null
        ContinuityId = [guid]::NewGuid().ToString('N')
        WindowMinutes = $WindowMinutes
        Parameters = (Get-MiAnalysisParameters -IntervalSeconds $IntervalSeconds)
        IntervalSeconds = $IntervalSeconds
        ContinuityReason = $null
        WindowResetCount = 0
        GrowthThresholdBytes = [long]512MB
        GrowthThresholdRatio = [double]0.20
    }
}

function Set-MiAnalyzerInterval {
    param($Analyzer,[ValidateRange(5,60)][int]$IntervalSeconds)
    if ($Analyzer.IntervalSeconds -eq $IntervalSeconds) { return }
    # 改变周期后重新积累完整窗口，防止旧高密度样本伪装成新周期的充分证据。
    $Analyzer.ContinuityReason = ('采样周期由 {0} 秒变为 {1} 秒，已重新建立分析窗口。' -f $Analyzer.IntervalSeconds,$IntervalSeconds)
    $Analyzer.IntervalSeconds=$IntervalSeconds
    $Analyzer.Parameters=Get-MiAnalysisParameters -IntervalSeconds $IntervalSeconds
    $Analyzer.Tracks.Clear()
    $Analyzer.PoolHistory.Clear()
    $Analyzer.LastCaptureUtc=[datetime]::MinValue
    $Analyzer.LastSequence=$null
    $Analyzer.LastMonotonicSeconds=$null
    $Analyzer.ContinuityId=[guid]::NewGuid().ToString('N')
    $Analyzer.WindowResetCount++
}

function Limit-MiAnalysisHistory {
    param($Analyzer,$Samples,[datetime]$NowUtc)
    $cutoff=$NowUtc.AddSeconds(-$Analyzer.Parameters.WindowSeconds-$Analyzer.Parameters.BoundaryToleranceSeconds)
    while ($Samples.Count -gt 0 -and $Samples[0].Utc -lt $cutoff) { $Samples.RemoveAt(0) }
    if ($Samples.Count -le $Analyzer.Parameters.HistoryCapacity) { return }
    # 旧文件没有周期字段时，按实际时间戳中最密的受支持周期增加容量，不能只留下当前周期的尾部数量。
    $retentionInterval=$Analyzer.IntervalSeconds
    for ($i=1;$i -lt $Samples.Count;$i++) {
        $delta=($Samples[$i].Utc-$Samples[$i-1].Utc).TotalSeconds
        if ($delta -gt 0 -and $delta -lt $retentionInterval) {
            $retentionInterval=[math]::Max(5,[int][math]::Floor($delta))
        }
    }
    $Analyzer.Parameters.HistoryCapacity=[math]::Max($Analyzer.Parameters.HistoryCapacity,
        (Get-MiAnalysisParameters -IntervalSeconds $retentionInterval).HistoryCapacity)
    if ($Samples.Count -le $Analyzer.Parameters.HistoryCapacity) { return }
    # 超过 5 秒上限密度的突发样本按固定 UTC 时间槽合并，避免随窗口锚点移动反复合并造成历史缺口。
    $slots=@{}
    foreach ($point in $Samples) {
        $slot=[long][math]::Floor($point.Utc.Ticks/([double][timespan]::TicksPerSecond*5))
        $slots[$slot]=$point
    }
    $Samples.Clear()
    foreach ($slot in @($slots.Keys | Sort-Object)) { $Samples.Add($slots[$slot]) }
}

function Add-MiTrackSample {
    param($Analyzer,$Snapshot,[bool]$Historical=$false)
    if ($null -eq $Snapshot -or $null -eq $Snapshot.Processes -or $Snapshot.Processes.Status -eq 'Failed') { return }
    try { $utc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime() } catch { return }
    if ($utc.Year -lt 2020) { return }
    foreach ($p in @($Snapshot.Processes.Items)) {
        if ($null -eq $p -or $null -eq $p.PrivateBytes) { continue }
        $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
        if ($null -eq $key) { continue }
        $bytes = [long]$p.PrivateBytes
        if ($bytes -lt 0) { continue }
        if (-not $Analyzer.Tracks.ContainsKey($key)) {
            $Analyzer.Tracks[$key] = [pscustomobject]@{
                Name = [string]$p.Name
                PID = [int]$p.PID
                StartUtcTicks = [long]$p.StartUtcTicks
                Samples = (New-Object 'System.Collections.Generic.List[object]')
            }
        }
        $list = $Analyzer.Tracks[$key].Samples
        if ($list.Count -gt 0 -and $utc -le $list[$list.Count-1].Utc) { continue }
        $list.Add([pscustomobject]@{Utc=$utc;Bytes=$bytes})
        Limit-MiAnalysisHistory -Analyzer $Analyzer -Samples $list -NowUtc $utc
    }
    # A process can exit, but stale traces must not accumulate indefinitely.
    if (-not $Historical) {
        $cutoff = $utc.AddMinutes(-30)
        foreach ($key in @($Analyzer.Tracks.Keys)) {
            $trace = $Analyzer.Tracks[$key]
            if ($trace.Samples.Count -eq 0 -or $trace.Samples[$trace.Samples.Count-1].Utc -lt $cutoff) {
                $Analyzer.Tracks.Remove($key)
            }
        }
    }
}

function Get-MiRecentProcessRecords {
    param([string]$Root,[datetime]$NowUtc,[ValidateRange(5,60)][int]$IntervalSeconds=5)
    if ([string]::IsNullOrWhiteSpace($Root)) { return @() }
    # 旧 schema=1 没有周期字段，恢复读取量按所有受支持周期中最密的 5 秒计算。
    $tailCapacity=(Get-MiAnalysisParameters -IntervalSeconds 5).HistoryCapacity
    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($day in @($NowUtc.Date.AddDays(-1),$NowUtc.Date)) {
        $date = $day.ToString('yyyy-MM-dd')
        $filename = 'process-'+$date+'.jsonl'
        $raw = Join-Path (Join-Path $Root 'process') $filename
        $recent = @()
        if ([IO.File]::Exists($raw)) {
            $recent = @(Read-MiJsonTail -Path $raw -Count $tailCapacity)
        } else {
            # M2 may compress yesterday's JSONL after midnight.
            $archive = Join-Path (Join-Path $Root 'archives') ('raw-'+$date+'.zip')
            if ([IO.File]::Exists($archive)) {
                Add-Type -AssemblyName System.IO.Compression
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [IO.Compression.ZipFile]::OpenRead($archive)
                try {
                    $entry = $zip.GetEntry($filename)
                    if ($entry) {
                        $stream = $entry.Open()
                        $reader = [IO.StreamReader]::new($stream,[Text.Encoding]::UTF8)
                        try {
                            $tail = New-Object 'System.Collections.Generic.Queue[string]'
                            while (-not $reader.EndOfStream) {
                                $line = $reader.ReadLine()
                                $tail.Enqueue($line)
                                if ($tail.Count -gt $tailCapacity) { [void]$tail.Dequeue() }
                            }
                            foreach ($line in $tail) {
                                try {
                                    $obj = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                                    if ([int]$obj.SchemaVersion -eq 1) { $recent += $obj }
                                } catch {}
                            }
                        } finally { $reader.Dispose() }
                    }
                } finally { $zip.Dispose() }
            }
        }
        foreach ($r in $recent) {
            try {
                $utc = ([datetime]$r.CaptureEndUtc).ToUniversalTime()
                if ($utc -ge $NowUtc.AddSeconds(-1800-$IntervalSeconds/2.0) -and $utc -le $NowUtc -and $r.RecordType -eq 'ProcessSnapshot') {
                    $records.Add($r)
                }
            } catch {}
        }
    }
    # 保留 JSONL 的追加顺序；按 UTC 排序会掩盖回拨断点。
    return @($records.ToArray())
}

function Restore-MiAnalyzer {
    param($Analyzer,[datetime]$NowUtc=[datetime]::UtcNow)
    if (-not $Analyzer.CanRestore -or [string]::IsNullOrWhiteSpace($Analyzer.Root)) { return 0 }
    $count = 0
    $previousUtc=[datetime]::MinValue;$previousContinuity=$null;$previousMonotonic=$null
    $recent=@(Get-MiRecentProcessRecords -Root $Analyzer.Root -NowUtc $NowUtc -IntervalSeconds $Analyzer.IntervalSeconds)
    # UTC 跨日回拨会把新行写入前一天的文件；同一启动内的单调时间恢复真实采样顺序。
    # 旧记录没有此可选字段，仍保持原追加顺序，不猜测单调时间。
    $ordered=New-Object 'System.Collections.Generic.List[object]'
    $index=0
    foreach ($record in $recent) {
        $mono=-1.0
        if ($null -ne $record.MonotonicSeconds) {
            $parsed=0.0
            if (-not [double]::TryParse([string]$record.MonotonicSeconds,[Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,[ref]$parsed) -or
                [double]::IsNaN($parsed) -or [double]::IsInfinity($parsed) -or $parsed -lt 0) { continue }
            $mono=$parsed
        }
        $ordered.Add([pscustomobject]@{Record=$record;Monotonic=$mono;Index=$index})
        $index++
    }
    foreach ($orderedRecord in @($ordered | Sort-Object Monotonic,Index)) {
        $r=$orderedRecord.Record
        if ($r.ProcessStatus -eq 'Failed') { continue }
        if ($null -ne $r.IntervalSeconds) {
            $savedInterval=0
            if (-not [int]::TryParse([string]$r.IntervalSeconds,[ref]$savedInterval) -or $savedInterval -lt 5 -or $savedInterval -gt 60) { continue }
            if ($savedInterval -ne $Analyzer.IntervalSeconds) {
                # 持久化记录中的明确周期切换也是连续性边界，不能把切换前后同周期的两段历史拼接起来。
                $Analyzer.Tracks.Clear()
                $Analyzer.PoolHistory.Clear()
                $Analyzer.ContinuityReason='历史中检测到其他采样周期，已从该断点后重新建立分析窗口。'
                continue
            }
        }
        # Existing M2 ProcessInstanceId contains the boot id, PID and start time.
        $matching = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in @($r.Items)) {
            $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
            if ($null -ne $key -and $key -ceq [string]$p.ProcessInstanceId) { $matching.Add($p) }
        }
        if ($matching.Count -eq 0) { continue }
        # 新记录使用连续段 ID；旧 schema=1 仍可读，但必须按追加时间检测回拨，不能拼接两段趋势。
        $recordUtc=([datetime]$r.CaptureEndUtc).ToUniversalTime()
        if (($previousUtc -ne [datetime]::MinValue -and $recordUtc -le $previousUtc) -or
            ($null -ne $previousContinuity -and $r.ContinuityId -ne $previousContinuity)) {
            $Analyzer.Tracks.Clear();$Analyzer.PoolHistory.Clear();$count=0
            $Analyzer.ContinuityReason='历史记录存在时间断点，仅恢复最后连续段。'
        }
        $previousUtc=$recordUtc;$previousContinuity=$r.ContinuityId;$previousMonotonic=$r.MonotonicSeconds

        Add-MiTrackSample -Analyzer $Analyzer -Historical $true -Snapshot ([pscustomobject]@{
            CaptureEndUtc=$r.CaptureEndUtc
            Processes=[pscustomobject]@{Status=$r.ProcessStatus;Items=$matching.ToArray()}
        })
        $count++
    }
    if ($count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$previousContinuity)) {
        $Analyzer.ContinuityId=[string]$previousContinuity
        $Analyzer.LastCaptureUtc=$previousUtc
        $Analyzer.LastMonotonicSeconds=$previousMonotonic
    }
    return $count
}

function Update-MiHistoricalBaselines {
    param($Analyzer,[datetime]$NowUtc=[datetime]::UtcNow)
    if (($NowUtc-$Analyzer.HistoricalLoadedUtc).TotalMinutes -lt 30) { return }
    $Analyzer.HistoricalLoadedUtc = $NowUtc
    $Analyzer.Historical = @{}
    if ([string]::IsNullOrWhiteSpace($Analyzer.Root)) { return }
    $folder = Join-Path $Analyzer.Root 'aggregates'
    if (-not [IO.Directory]::Exists($folder)) { return }
    $earliest = $NowUtc.Date.AddDays(-90)
    $byProgram = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter 'summary-*.jsonl' -File -ErrorAction Stop | Sort-Object Name)) {
        if ($file.Name -notmatch '^summary-(\d{4}-\d{2}-\d{2})\.jsonl$') { continue }
        $day = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($Matches[1],'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$day)) { continue }
        if ($day -lt $earliest -or $day -ge $NowUtc.Date) { continue }
        # Deterministic 2-hour sampling: at most 12 aggregate rows per day.
        $index = 0
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            if ((($index++) % 24) -ne 0) { continue }
            try {
                $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ([int]$record.SchemaVersion -ne 1 -or $record.RecordType -ne 'FiveMinuteAggregate') { continue }
                foreach ($p in @($record.ProgramStatistics)) {
                    if ([string]::IsNullOrWhiteSpace([string]$p.Name) -or $null -eq $p.AveragePrivateBytes) { continue }
                    $name = [string]$p.Name
                    $bytes = [long]$p.AveragePrivateBytes
                    if ($bytes -lt 0) { continue }
                    if (-not $byProgram.ContainsKey($name)) {
                        $byProgram[$name] = [pscustomobject]@{
                            Values = (New-Object 'System.Collections.Generic.List[object]')
                            Days = @{}
                        }
                    }
                    $byProgram[$name].Values.Add([double]$bytes)
                    $byProgram[$name].Days[$day.ToString('yyyy-MM-dd')] = $true
                }
            } catch {} # A damaged aggregate line is never a valid baseline.
        }
    }
    foreach ($name in @($byProgram.Keys)) {
        $record = $byProgram[$name]
        if ($record.Values.Count -lt 6 -or $record.Days.Count -lt 2) { continue }
        $Analyzer.Historical[$name] = [pscustomobject]@{
            MedianProgramPrivateBytes=[long](Get-MiMedian -Values $record.Values.ToArray())
            BucketCount=$record.Values.Count
            DayCount=$record.Days.Count
            Scope='ProgramNameAggregate'
        }
    }
}

function Get-MiProcessAnomaly {
    param($Analyzer,$Process,[datetime]$NowUtc)
    $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $Process
    $report = [ordered]@{
        PID = $Process.PID
        StartUtcTicks = $Process.StartUtcTicks
        ProcessInstanceId = $key
        AnomalyState = 'InsufficientEvidence'
        EvidenceQuality = 'Insufficient'
        ValidSampleCount = 0
        RawSampleCount = 0
        ExpectedSampleCount = $Analyzer.Parameters.ExpectedSampleCount
        MinimumSampleCount = $Analyzer.Parameters.MinimumSampleCount
        IntervalSeconds = $Analyzer.IntervalSeconds
        MaximumGapSeconds = $null
        SegmentExpectedSampleCounts = @()
        SegmentValidSampleCounts = @()
        ContinuityReason = $Analyzer.ContinuityReason
        CoverageRatio = 0.0
        AnalysisWindowMinutes = 30
        BaselinePrivateBytes = $null
        CurrentPrivateBytes = $Process.PrivateBytes
        GrowthBytes = $null
        GrowthPercentage = $null
        UpwardSegments = 0
        Explanation = '缺少足够的有效同实例采样，继续观察。'
        HistoricalProgramMedianBytes = $null
        HistoricalDeviationPercent = $null
        HistoricalScope = 'Unavailable'
    }
    if ($null -eq $key -or -not $Analyzer.Tracks.ContainsKey($key)) { return [pscustomobject]$report }
    $samples = @($Analyzer.Tracks[$key].Samples.ToArray() | Where-Object {
        $_.Utc -ge $NowUtc.AddSeconds(-$Analyzer.Parameters.WindowSeconds-$Analyzer.Parameters.BoundaryToleranceSeconds) -and $_.Utc -le $NowUtc
    } | Sort-Object Utc)
    $report.RawSampleCount=$samples.Count
    # 按当前调度周期的时间槽计算覆盖，一个时间槽至多贡献一份证据。
    # 最新时刻是调度锚点，四舍五入允许小幅采集完成时间抖动，不能靠密集补采填平休眠缺口。
    $slots=@{}
    $lastSlot=$Analyzer.Parameters.ExpectedSampleCount-1
    foreach ($point in $samples) {
        $slot=[int][math]::Round(($NowUtc-$point.Utc).TotalSeconds/$Analyzer.IntervalSeconds,
            [MidpointRounding]::AwayFromZero)
        if ($slot -ge 0 -and $slot -le $lastSlot) { $slots[$slot]=$point }
    }
    # 半周期只用于端点的槽归属，所有跨度和缺口验证都使用真正归入预期槽的代表点。
    $evidence=@($slots.Values | Sort-Object Utc)
    $report.ValidSampleCount=$slots.Count
    $coverage=[double]$slots.Count/$Analyzer.Parameters.ExpectedSampleCount
    $report.CoverageRatio=[math]::Round($coverage,3)
    $bins = @()
    for ($i=0;$i -lt 6;$i++) { $bins += ,(New-Object 'System.Collections.Generic.List[object]') }
    $expectedBins=@(0,0,0,0,0,0)
    $windowStart=$NowUtc.AddSeconds(-$Analyzer.Parameters.WindowSeconds)
    for ($slot=0;$slot -le $lastSlot;$slot++) {
        # 分段边界用预期调度点归属；最后分段包含 NowUtc，避免任意周期的边界重复计数。
        $nominalUtc=$NowUtc.AddSeconds(-$slot*$Analyzer.IntervalSeconds)
        $bin=[int][math]::Floor(($nominalUtc-$windowStart).TotalSeconds/$Analyzer.Parameters.BinSeconds)
        $bin=[math]::Max(0,[math]::Min(5,$bin))
        $expectedBins[$bin]++
        if ($slots.ContainsKey($slot)) { $bins[$bin].Add([double]$slots[$slot].Bytes) }
    }
    $report.SegmentExpectedSampleCounts=$expectedBins
    $report.SegmentValidSampleCounts=@($bins | ForEach-Object { $_.Count })
    if ($evidence.Count -eq 0) { return [pscustomobject]$report }
    $span=($evidence[$evidence.Count-1].Utc-$evidence[0].Utc).TotalSeconds
    $latestAge=($NowUtc-$evidence[$evidence.Count-1].Utc).TotalSeconds
    $largestGap=0.0
    for ($i=1;$i -lt $evidence.Count;$i++) {
        $largestGap=[math]::Max($largestGap,($evidence[$i].Utc-$evidence[$i-1].Utc).TotalSeconds)
    }
    $report.MaximumGapSeconds=$largestGap
    if ($coverage -lt $Analyzer.Parameters.MinimumCoverageRatio -or
        $span -lt ($Analyzer.Parameters.WindowSeconds-$Analyzer.IntervalSeconds) -or
        $latestAge -gt $Analyzer.IntervalSeconds) {
        $report.Explanation=('30 分钟窗口需 {0}/{1} 个独立时间槽且覆盖完整跨度；当前 {2}/{1}，跨度 {3:N0} 秒。' -f
            $Analyzer.Parameters.MinimumSampleCount,$Analyzer.Parameters.ExpectedSampleCount,$slots.Count,$span)
        return [pscustomobject]$report
    }
    if ($largestGap -gt $Analyzer.Parameters.MaximumGapSeconds) {
        $report.Explanation=('采样存在 {0:N0} 秒时间缺口，超过当前周期允许的 {1:N0} 秒，继续收集连续证据。' -f
            $largestGap,$Analyzer.Parameters.MaximumGapSeconds)
        return [pscustomobject]$report
    }
    $medians = @()
    for ($i=0;$i -lt 6;$i++) {
        $minimum=[int][math]::Ceiling($expectedBins[$i]*$Analyzer.Parameters.MinimumCoverageRatio)
        if ($bins[$i].Count -lt $minimum) {
            $report.Explanation = '至少一个五分钟分段的有效样本不足，暂不判断增长趋势。'
            return [pscustomobject]$report
        }
        $medians += [double](Get-MiMedian -Values $bins[$i].ToArray())
    }
    $baseline = [double]$medians[0]
    $growth = [double]($medians[5]-$baseline)
    $report.BaselinePrivateBytes = [long]$baseline
    $report.GrowthBytes = [long]$growth
    if ($baseline -gt 0) { $report.GrowthPercentage = [math]::Round(($growth/$baseline)*100.0,1) }
    $upward = 0
    for($i=1;$i -lt 6;$i++) { if ($medians[$i] -gt $medians[$i-1]) { $upward++ } }
    $report.UpwardSegments = $upward
    $report.EvidenceQuality = $(if ($report.CoverageRatio -ge 0.95) {'High'} else {'Moderate'})
    if ($baseline -gt 0 -and $growth -ge [long]$Analyzer.GrowthThresholdBytes -and ($growth/$baseline) -ge [double]$Analyzer.GrowthThresholdRatio -and $upward -ge 4) {
        $report.AnomalyState = 'SuspectedSustainedGrowth'
        $report.Explanation = ('六段中 {0}/5 段上升，窗口中位数增长 {1:N0} MiB（{2:N1}%）；仅为疑似增长，不代表确认泄漏。' -f
            $upward,($growth/1MB),$report.GrowthPercentage)
    } else {
        $report.AnomalyState = 'NoSignificantGrowth'
        $report.Explanation = ('30 分钟证据有效；增长 {0:N0} MiB、上升段数 {1}/5，未同时满足全部疑似增长条件。' -f
            ($growth/1MB),$upward)
    }
    return [pscustomobject]$report
}

function Get-MiMemoryPressure {
    param($Analyzer,$System,[datetime]$NowUtc)
    $result = [ordered]@{
        State='Unknown';CommitRatio=$null;AvailableRamRatio=$null
        CommitHeadroomBytes=$null;NonpagedPoolTrend='InsufficientEvidence'
        Explanation='内存系统计数器缺失，无法判断系统压力。'
    }
    if ($null -eq $System -or $System.Status -eq 'Failed' -or
        $null -eq $System.CommittedBytes -or $null -eq $System.CommitLimitBytes -or
        $null -eq $System.AvailablePhysicalBytes -or $null -eq $System.TotalPhysicalBytes -or
        [double]$System.CommitLimitBytes -le 0 -or [double]$System.TotalPhysicalBytes -le 0) {
        return [pscustomobject]$result
    }
    $committed = [double]$System.CommittedBytes
    $limit = [double]$System.CommitLimitBytes
    $available = [double]$System.AvailablePhysicalBytes
    $total = [double]$System.TotalPhysicalBytes
    if ($committed -lt 0 -or $available -lt 0 -or $available -gt $total) { return [pscustomobject]$result }
    $commitRatio = $committed / $limit
    $ramRatio = $available / $total
    $result.CommitRatio = [math]::Round($commitRatio,3)
    $result.AvailableRamRatio = [math]::Round($ramRatio,3)
    $result.CommitHeadroomBytes = [long][math]::Max([double]0.0,([double]$limit-[double]$committed))
    if ($commitRatio -ge 0.90 -or $ramRatio -le 0.05) { $result.State='High' }
    elseif ($commitRatio -ge 0.80 -or $ramRatio -le 0.10) { $result.State='Elevated' }
    else { $result.State='Normal' }
    $result.Explanation = ('Commit {0:P1}，可用 RAM {1:P1}；仅表示系统压力，不代表存在可清理的垃圾内存。' -f $commitRatio,$ramRatio)

    if ($null -ne $System.NonpagedPoolBytes -and [double]$System.NonpagedPoolBytes -ge 0) {
        $list = $Analyzer.PoolHistory
        if ($list.Count -eq 0 -or $NowUtc -gt $list[$list.Count-1].Utc) {
            $list.Add([pscustomobject]@{Utc=$NowUtc;Bytes=[long]$System.NonpagedPoolBytes})
        }
        Limit-MiAnalysisHistory -Analyzer $Analyzer -Samples $list -NowUtc $NowUtc
        if ($list.Count -gt 1 -and ($NowUtc-$list[0].Utc).TotalMinutes -ge 20) {
            $poolDelta = [long]$System.NonpagedPoolBytes - [long]$list[0].Bytes
            $result.NonpagedPoolTrend = $(if ($poolDelta -ge 128MB) {'Rising'} else {'NotRising'})
        }
    }
    return [pscustomobject]$result
}

function Invoke-MiDiagnosis {
    param($Analyzer,$Snapshot)
    if ($null -ne $Snapshot.IntervalSeconds) {
        $interval=0
        if (-not [int]::TryParse([string]$Snapshot.IntervalSeconds,[ref]$interval) -or $interval -lt 5 -or $interval -gt 60) {
            return [pscustomobject]@{
                Status='InvalidCadence';Reports=@();Pressure=[pscustomobject]@{State='Unknown'}
                Error='采样周期无效，未使用该样本进行诊断。'
            }
        }
        Set-MiAnalyzerInterval -Analyzer $Analyzer -IntervalSeconds $interval
    }
    $utc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
    $sequence=$Snapshot.Sequence
    $monotonic=$Snapshot.MonotonicSeconds
    # 序号倒序属于迟到/重复消息，不应把旧消息误认为新时钟、清空有效窗口。
    if ($null -ne $sequence -and $null -ne $Analyzer.LastSequence -and $sequence -le $Analyzer.LastSequence) {
        return [pscustomobject]@{Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'};Error='忽略重复或倒序的采样序号。'}
    }
    $rollback=$false
    if ($Analyzer.LastCaptureUtc -ne [datetime]::MinValue) {
        $wallDelta=($utc-$Analyzer.LastCaptureUtc).TotalSeconds
        $rollback=($wallDelta -lt 0)
        if ($null -ne $monotonic -and $null -ne $Analyzer.LastMonotonicSeconds) {
            $elapsed=[double]$monotonic-[double]$Analyzer.LastMonotonicSeconds
            # 即使 UTC 仍在增加，也能发现采样期间被向后校正的明显时间差。
            $rollback=$rollback -or $elapsed -lt 0 -or
                ($wallDelta-$elapsed) -lt -[math]::Max(1,$Analyzer.IntervalSeconds/2.0)
        }
        if ($rollback) {
            $Analyzer.Tracks.Clear();$Analyzer.PoolHistory.Clear()
            $Analyzer.LastCaptureUtc=[datetime]::MinValue
            $Analyzer.ContinuityId=[guid]::NewGuid().ToString('N')
            $Analyzer.ContinuityReason='检测到采样时间回拨，已重新建立分析窗口。'
            $Analyzer.WindowResetCount++
            # 历史基线的刷新节流也不能被旧的未来 UTC 时间永久阻塞。
            $Analyzer.HistoricalLoadedUtc=[datetime]::MinValue
        } elseif ($wallDelta -eq 0) {
            return [pscustomobject]@{Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'};Error='忽略重复采样时间。'}
        }
    }
    $Analyzer.LastSequence=$sequence
    $Analyzer.LastMonotonicSeconds=$monotonic
    $Snapshot | Add-Member -NotePropertyName ContinuityId -NotePropertyValue $Analyzer.ContinuityId -Force
    $Snapshot | Add-Member -NotePropertyName TimeDiscontinuity -NotePropertyValue $rollback -Force
    if ($rollback) {
        # 本轮只标记断点，下一轮从新的 UTC/单调时间锚点重新收集。
        return [pscustomobject]@{Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'};Error=$Analyzer.ContinuityReason}
    }
    $Analyzer.LastCaptureUtc=$utc
    Add-MiTrackSample -Analyzer $Analyzer -Snapshot $Snapshot
    $pressure = Get-MiMemoryPressure -Analyzer $Analyzer -System $Snapshot.System -NowUtc $utc
    $reports = New-Object 'System.Collections.Generic.List[object]'
    $top = @()
    if ($Snapshot.Processes.Status -ne 'Failed') {
        $top = @($Snapshot.Processes.Items | Where-Object {$null -ne $_.PrivateBytes} |
            Sort-Object -Property PrivateBytes -Descending | Select-Object -First 60)
    }
    $totals = @{}
    foreach ($p in @($Snapshot.Processes.Items)) {
        if ($null -eq $p.PrivateBytes -or [string]::IsNullOrWhiteSpace([string]$p.Name)) { continue }
        if (-not $totals.ContainsKey([string]$p.Name)) { $totals[[string]$p.Name]=[double]0 }
        $totals[[string]$p.Name] += [double]$p.PrivateBytes
    }
    foreach($p in $top) {
        $report = Get-MiProcessAnomaly -Analyzer $Analyzer -Process $p -NowUtc $utc
        if ($Analyzer.Historical.ContainsKey([string]$p.Name)) {
            $historical=$Analyzer.Historical[[string]$p.Name]
            $report.HistoricalProgramMedianBytes = $historical.MedianProgramPrivateBytes
            $report.HistoricalScope = 'ProgramNameAggregate'
            if ($historical.MedianProgramPrivateBytes -gt 0 -and $totals.ContainsKey([string]$p.Name)) {
                $report.HistoricalDeviationPercent = [math]::Round(
                    (($totals[[string]$p.Name] / $historical.MedianProgramPrivateBytes)-1.0)*100.0,1)
            }
        }
        $reports.Add($report)
    }
    return [pscustomobject]@{
        Status='Success'
        Reports=$reports.ToArray()
        Pressure=$pressure
        Error=$null
    }
}
