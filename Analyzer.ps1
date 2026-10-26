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
    $processId=0;$ticks=0L
    if ($null -eq $Process -or -not [int]::TryParse([string]$Process.PID,[ref]$processId) -or $processId -le 0 -or
        -not [long]::TryParse([string]$Process.StartUtcTicks,[ref]$ticks) -or $ticks -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$Process.Name)) { return $null }
    return ('{0}:{1}:{2}' -f $BootId,$processId,$ticks)
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

function Initialize-MiAnalysisStorage {
    if ($null -ne ('MemoryInspector.AnalysisPoint' -as [type])) { return }
    # 每个实例保留完整30分钟证据；紧凑值类型只消除 PSObject 开销，不降采样、不改归槽规则。
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace MemoryInspector {
    public struct AnalysisPoint {
        public readonly DateTime Utc;
        public readonly long Bytes;
        public AnalysisPoint(DateTime utc, long bytes) { Utc=utc; Bytes=bytes; }
    }
    public struct SavedAnalysisProcess {
        public int PID;
        public string Name;
        public long StartUtcTicks;
        public string ProcessInstanceId;
        public long? PrivateBytes;
    }
    // 在紧凑标量列表上计算质量，避免每轮为每个进程复制数百个 PowerShell 对象。
    public sealed class AttributionWindow {
        public int ExpectedSampleCount, ValidSampleCount, RawSampleCount, MissingSampleCount;
        public double CoverageRatio, ActualSpanSeconds, MaximumGapSeconds;
        public double LatestAgeSeconds;
        public int[] SegmentExpectedSampleCounts, SegmentValidSampleCounts;
        public double[] SegmentMedians;
        public DateTime? StartUtc, EndUtc;
        public long? GrowthBytes;
        public bool SufficientTrend;
        public int UpwardSegments;
        public static AttributionWindow Measure(IList<AnalysisPoint> points, DateTime now, int interval) {
            return Measure(points, now, interval, 0);
        }
        // 旧诊断保留半周期边界容差和 double 中位数；新 Finding 使用严格观察窗口。
        // 两者共享遍历，绝不以性能优化改变原 85%/分段/缺口阈值。
        public static AttributionWindow Measure(IList<AnalysisPoint> points, DateTime now, int interval, double boundaryTolerance) {
            var result = new AttributionWindow();
            result.ExpectedSampleCount = 1800 / interval + 1;
            var slots = new Dictionary<int,AnalysisPoint>();
            if (points != null) foreach (var p in points) {
                double age = (now-p.Utc).TotalSeconds;
                if (age < 0 || age > 1800+boundaryTolerance) continue;
                result.RawSampleCount++;
                int slot = (int)Math.Round(age/interval, MidpointRounding.AwayFromZero);
                if (slot >= result.ExpectedSampleCount) continue;
                AnalysisPoint prior;
                if (!slots.TryGetValue(slot, out prior) || p.Utc > prior.Utc) slots[slot]=p;
            }
            var evidence = new List<AnalysisPoint>(slots.Values);
            evidence.Sort((a,b) => a.Utc.CompareTo(b.Utc));
            result.ValidSampleCount=evidence.Count;
            result.MissingSampleCount=result.ExpectedSampleCount-evidence.Count;
            result.CoverageRatio=(double)evidence.Count/result.ExpectedSampleCount;
            if (evidence.Count > 0) {
                result.StartUtc=evidence[0].Utc; result.EndUtc=evidence[evidence.Count-1].Utc;
                result.ActualSpanSeconds=(result.EndUtc.Value-result.StartUtc.Value).TotalSeconds;
                result.LatestAgeSeconds=(now-result.EndUtc.Value).TotalSeconds;
            }
            if (evidence.Count >= 2) result.GrowthBytes=evidence[evidence.Count-1].Bytes-evidence[0].Bytes;
            for (int i=1;i<evidence.Count;i++) result.MaximumGapSeconds=Math.Max(result.MaximumGapSeconds,
                (evidence[i].Utc-evidence[i-1].Utc).TotalSeconds);
            var bins=new List<long>[6]; var expected=new int[6];
            for (int i=0;i<6;i++) bins[i]=new List<long>();
            for (int slot=0;slot<result.ExpectedSampleCount;slot++) {
                int bin=Math.Min(5,(1800-slot*interval)/300); expected[bin]++;
                AnalysisPoint p; if (slots.TryGetValue(slot,out p)) bins[bin].Add(p.Bytes);
            }
            result.SegmentExpectedSampleCounts=expected;
            result.SegmentValidSampleCounts=new int[6]; result.SegmentMedians=new double[6];
            bool adequate=result.CoverageRatio>=0.85 && result.ActualSpanSeconds>=1800-interval &&
                result.LatestAgeSeconds<=interval && result.MaximumGapSeconds<=Math.Max(60,3*interval);
            decimal? previous=null;
            for (int i=0;i<6;i++) {
                result.SegmentValidSampleCounts[i]=bins[i].Count;
                if (bins[i].Count<Math.Ceiling(expected[i]*0.85)) adequate=false;
                if (bins[i].Count==0) { previous=null; continue; }
                bins[i].Sort(); int mid=bins[i].Count/2;
                result.SegmentMedians[i]=(bins[i].Count%2==1) ? (double)bins[i][mid] : ((double)bins[i][mid-1]+(double)bins[i][mid])/2;
                decimal median=(bins[i].Count%2==1) ? bins[i][mid] : ((decimal)bins[i][mid-1]+bins[i][mid])/2;
                if (previous.HasValue && median>previous.Value) result.UpwardSegments++;
                previous=median;
            }
            result.SufficientTrend=adequate;
            return result;
        }
    }
}
'@ -ErrorAction Stop
}
function New-MiAnalyzer {
    param([string]$BootId,[string]$Root,[int]$WindowMinutes=30,
        [ValidateRange(5,60)][int]$IntervalSeconds=5)
    if ($WindowMinutes -ne 30) { throw 'Milestone 3 uses a fixed 30-minute diagnostic window.' }
    Initialize-MiAnalysisStorage
    $usableBoot = -not [string]::IsNullOrWhiteSpace($BootId) -and $BootId -ne 'BootUnavailable'
    return [pscustomobject]@{
        BootId = $(if ($usableBoot) { $BootId } else { 'Session-'+[guid]::NewGuid().ToString('N') })
        CanRestore = $usableBoot
        Root = $Root
        Tracks = @{}
        PoolHistory = (New-Object 'System.Collections.Generic.List[object]')
        AttributionHistory = @{}
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
    $Analyzer.AttributionHistory.Clear()
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
        $bytes = Get-MiAttributionBytes $p.PrivateBytes
        if ($null -eq $bytes) { continue }
        if (-not $Analyzer.Tracks.ContainsKey($key)) {
            $Analyzer.Tracks[$key] = [pscustomobject]@{
                Name = [string]$p.Name
                PID = [int]$p.PID
                StartUtcTicks = [long]$p.StartUtcTicks
                Samples = (New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]')
            }
        }
        $list = $Analyzer.Tracks[$key].Samples
        if ($list.Count -gt 0 -and $utc -le $list[$list.Count-1].Utc) { continue }
        $list.Add([MemoryInspector.AnalysisPoint]::new($utc,$bytes))
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

function ConvertTo-MiCompactAnalysisRecord {
    param($Record)
    # 仅用于内部恢复；缺失身份不能成为证据。有效身份的null/负计数器仍须保留，
    # 让原恢复逻辑观察其连续段断点，再由Add-MiTrackSample拒绝无效数值，不能省掉断点。
    $rows=New-Object 'System.Collections.Generic.List[MemoryInspector.SavedAnalysisProcess]'
    foreach($p in @($Record.Items)) {
        if ($null -eq $p -or $null -eq $p.PID -or $null -eq $p.StartUtcTicks -or
            [long]$p.StartUtcTicks -le 0 -or [string]::IsNullOrWhiteSpace([string]$p.Name)) {continue}
        $row=[MemoryInspector.SavedAnalysisProcess]::new()
        $row.PID=[int]$p.PID;$row.Name=[string]$p.Name;$row.StartUtcTicks=[long]$p.StartUtcTicks
        $row.ProcessInstanceId=[string]$p.ProcessInstanceId;$row.PrivateBytes=$p.PrivateBytes
        $rows.Add($row)
    }
    return [pscustomobject]@{SchemaVersion=$Record.SchemaVersion;RecordType=$Record.RecordType
        CaptureEndUtc=$Record.CaptureEndUtc;IntervalSeconds=$Record.IntervalSeconds
        ProcessStatus=$Record.ProcessStatus;MonotonicSeconds=$Record.MonotonicSeconds
        ContinuityId=$Record.ContinuityId;Items=$rows.ToArray()}
}
function Get-MiRecentProcessRecords {
    param([string]$Root,[datetime]$NowUtc,[ValidateRange(5,60)][int]$IntervalSeconds=5,[switch]$Compact)
    if ([string]::IsNullOrWhiteSpace($Root)) { return @() }
    # 旧 schema=1 没有周期字段，恢复读取量按所有受支持周期中最密的 5 秒计算。
    $tailCapacity=(Get-MiAnalysisParameters -IntervalSeconds 5).HistoryCapacity
    $records = New-Object 'System.Collections.Generic.List[object]'
    $projection=$null
    if($Compact){Initialize-MiAnalysisStorage;$projection={param($r) ConvertTo-MiCompactAnalysisRecord $r}}
    foreach ($day in @($NowUtc.Date.AddDays(-1),$NowUtc.Date)) {
        $date = $day.ToString('yyyy-MM-dd')
        $filename = 'process-'+$date+'.jsonl'
        $raw = Join-Path (Join-Path $Root 'process') $filename
        $recent = @()
        if ([IO.File]::Exists($raw)) {
            $recent = @(Read-MiJsonTail -Path $raw -Count $tailCapacity -Projection $projection)
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
                                    if ([int]$obj.SchemaVersion -eq 1) {
                                        if($Compact){$recent += ConvertTo-MiCompactAnalysisRecord $obj}else{$recent += $obj}
                                    }
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
    $recent=@(Get-MiRecentProcessRecords -Root $Analyzer.Root -NowUtc $NowUtc -IntervalSeconds $Analyzer.IntervalSeconds -Compact)
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
    # 已实测的热点是对每个进程历史反复创建管道/排序对象；复用原模块的紧凑计算。
    # 原诊断继续使用半周期端点容差、首末跨度、分段 double 中位数及原报告格式。
    $window=[MemoryInspector.AttributionWindow]::Measure($Analyzer.Tracks[$key].Samples,$NowUtc,
        $Analyzer.IntervalSeconds,$Analyzer.Parameters.BoundaryToleranceSeconds)
    $report.RawSampleCount=$window.RawSampleCount
    $report.ValidSampleCount=$window.ValidSampleCount
    $coverage=$window.CoverageRatio
    $report.CoverageRatio=[math]::Round($coverage,3)
    $expectedBins=$window.SegmentExpectedSampleCounts
    $report.SegmentExpectedSampleCounts=$expectedBins
    $report.SegmentValidSampleCounts=$window.SegmentValidSampleCounts
    if ($window.ValidSampleCount -eq 0) { return [pscustomobject]$report }
    $span=$window.ActualSpanSeconds
    $latestAge=$window.LatestAgeSeconds
    $largestGap=$window.MaximumGapSeconds
    $report.MaximumGapSeconds=$largestGap
    if ($coverage -lt $Analyzer.Parameters.MinimumCoverageRatio -or
        $span -lt ($Analyzer.Parameters.WindowSeconds-$Analyzer.IntervalSeconds) -or
        $latestAge -gt $Analyzer.IntervalSeconds) {
        $report.Explanation=('30 分钟窗口需 {0}/{1} 个独立时间槽且覆盖完整跨度；当前 {2}/{1}，跨度 {3:N0} 秒。' -f
            $Analyzer.Parameters.MinimumSampleCount,$Analyzer.Parameters.ExpectedSampleCount,$window.ValidSampleCount,$span)
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
        if ($window.SegmentValidSampleCounts[$i] -lt $minimum) {
            $report.Explanation = '至少一个五分钟分段的有效样本不足，暂不判断增长趋势。'
            return [pscustomobject]$report
        }
        $medians += $window.SegmentMedians[$i]
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
            $Analyzer.AttributionHistory.Clear()
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
        Attribution=(Get-MiSystemAttribution -Analyzer $Analyzer -Snapshot $Snapshot -NowUtc $utc)
        Error=$null
    }
}

function Get-MiAttributionBytes {
    param($Value)
    # 保留 null 与 0 的区别；拒绝负数、NaN、字符串小数及溢出，旧历史缺字段不能变成零。
    $number=0L
    if ($null -eq $Value -or $Value -is [bool] -or
        -not [long]::TryParse($Value.ToString(),[ref]$number) -or $number -lt 0) { return $null }
    return $number
}

function New-MiAttributionFinding {
    param($Analyzer,[string]$Category,[string]$MetricName,$Current,$Samples,[datetime]$NowUtc,
        [string]$ProcessInstanceId,[string]$SourceType='Counter',[string[]]$Limitations=@())
    $window=[MemoryInspector.AttributionWindow]::Measure($Samples,$NowUtc,$Analyzer.IntervalSeconds)
    $quality='Partial'
    if ($null -eq $Current) { $quality='Unavailable' }
    elseif ($window.MissingSampleCount -eq 0 -and $window.SufficientTrend) { $quality='Complete' }
    $limits=New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $Limitations) { $limits.Add($item) }
    if ($quality -ne 'Complete') { $limits.Add('观察窗口不完整；不插值、不补零，不将缺失样本视为有效证据。') }
    if ($Analyzer.ContinuityReason) { $limits.Add($Analyzer.ContinuityReason) }
    return [pscustomobject]@{
        SchemaVersion=1;FindingId=[guid]::NewGuid().ToString('N');Category=$Category
        TimeRangeUtc=[pscustomobject]@{StartUtc=$window.StartUtc;EndUtc=$window.EndUtc}
        MetricName=$MetricName;ObservedBytes=$Current
        GrowthBytes=$(if ($null -ne $Current) {$window.GrowthBytes} else {$null})
        SourceType=$SourceType;ProcessInstanceId=$ProcessInstanceId;TraceSessionId=$null
        MeasurementQuality=$quality
        AttributionConfidence=$(if ($null -ne $Current) {'DirectlyObserved'} else {'Unresolved'})
        EventLossStatus='NotApplicable';Limitations=$limits.ToArray()
        SuggestedNextStep='继续观察完整窗口；增长本身不能证明泄漏。'
        SamplingQuality=$window;TargetIntervalSeconds=$Analyzer.IntervalSeconds
        RequestedTimeRangeUtc=[pscustomobject]@{StartUtc=$NowUtc.AddMinutes(-30);EndUtc=$NowUtc}
        Trend='InsufficientEvidence'
    }
}

function Get-MiProcessGroups {
    param([object[]]$Processes,[string]$BootId,
        [ValidateSet('Instance','Executable','Parent','Logical')][string]$Mode='Executable',
        [string[]]$SelectedInstanceIds=@(),[string]$CollectionStatus='Success')
    # 诊断分组没有动作能力。路径只是本轮可执行文件路径口径，不是签名或文件哈希授权。
    $groups=@{};$seen=@{};$byKey=@{}
    foreach ($p in $Processes) {
        $key=Get-MiInstanceKey -BootId $BootId -Process $p
        if ($key) { $byKey[$key]=$p }
    }
    foreach ($p in $Processes) {
        $instance=Get-MiInstanceKey -BootId $BootId -Process $p
        if (-not $instance -or $seen.ContainsKey($instance)) { continue }
        $seen[$instance]=$true;$id=$instance;$label=('{0} · PID {1}' -f $p.Name,$p.PID)
        if ($Mode -eq 'Logical') {
            if ($instance -notin $SelectedInstanceIds) {continue}
            $id='UserSelection';$label='用户选定的精确进程实例'
        } elseif ($Mode -eq 'Executable') {
            if (-not [string]::IsNullOrWhiteSpace([string]$p.ExecutablePath)) {
                $id=([string]$p.ExecutablePath).ToUpperInvariant();$label=[string]$p.ExecutablePath
            } else { $label+='（路径未知，单独保留）' }
        } elseif ($Mode -eq 'Parent') {
            # 只合并当前可核验的根及后代；父进程已退出或 PID 被复用时不猜测旧关系。
            $ancestor=$p;$visited=@{$instance=$true}
            while ($null -ne $ancestor.ParentPid -and $null -ne $ancestor.ParentStartUtcTicks) {
                $parentKey='{0}:{1}:{2}' -f $BootId,$ancestor.ParentPid,$ancestor.ParentStartUtcTicks
                if (-not $byKey.ContainsKey($parentKey) -or $visited.ContainsKey($parentKey) -or
                    $ancestor.ParentStartUtcTicks -gt $ancestor.StartUtcTicks) {break}
                $visited[$parentKey]=$true;$ancestor=$byKey[$parentKey];$id=$parentKey
                $label=('{0} · 根 PID {1}' -f $ancestor.Name,$ancestor.PID)
            }
        }
        if (-not $groups.ContainsKey($id)) {
            $groups[$id]=[pscustomobject]@{SchemaVersion=1;GroupId=$id;GroupingKind=$Mode;Label=$label
                ProcessInstanceIds=(New-Object 'System.Collections.Generic.List[string]')
                ObservedPrivateBytes=[decimal]0;ValidMemberCount=0;MemberCount=0
                MeasurementQuality='Complete';AttributionConfidence='Correlated'
                Scope='当前采样中可验证实例的 Private Bytes 之和；不含共享内存，不等于 RAM 或可释放量。'
                Limitations='进程枚举非原子；路径/父子关系仅用于诊断，缺失身份不参与分组。'}
        }
        $g=$groups[$id];$g.MemberCount++;$g.ProcessInstanceIds.Add($instance)
        if (($Mode -eq 'Executable' -and [string]::IsNullOrWhiteSpace([string]$p.ExecutablePath)) -or
            ($Mode -eq 'Parent' -and $null -eq $p.ParentStartUtcTicks -and $p.ParentPid -ne 0)) {
            $g.MeasurementQuality='Partial'
        }
        $bytes=Get-MiAttributionBytes $p.PrivateBytes
        if ($null -ne $bytes) { $g.ObservedPrivateBytes+=[decimal]$bytes;$g.ValidMemberCount++ }
    }
    foreach ($g in $groups.Values) {
        if ($g.ValidMemberCount -eq 0 -or $g.ObservedPrivateBytes -gt [long]::MaxValue) {
            $g.ObservedPrivateBytes=$null;$g.MeasurementQuality='Unavailable'
        } else {
            $g.ObservedPrivateBytes=[long]$g.ObservedPrivateBytes
            if ($g.ValidMemberCount -ne $g.MemberCount -or $CollectionStatus -ne 'Success' -or
                ($Mode -eq 'Logical' -and $g.MemberCount -ne @($SelectedInstanceIds | Select-Object -Unique).Count)) {
                $g.MeasurementQuality='Partial'
            }
        }
        $g.ProcessInstanceIds=$g.ProcessInstanceIds.ToArray()
        $g
    }
}

function Get-MiSystemAttribution {
    param($Analyzer,$Snapshot,[datetime]$NowUtc)
    $findings=New-Object 'System.Collections.Generic.List[object]'
    $system=$Snapshot.System
    $values=[ordered]@{}
    foreach ($metric in @('CommittedBytes','CommitLimitBytes','PagedPoolBytes','NonpagedPoolBytes')) {
        $values[$metric]=$(if ($system.Status -ne 'Failed') {Get-MiAttributionBytes $system.$metric} else {$null})
    }
    $values['CommitHeadroomBytes']=$null
    if ($null -ne $values.CommittedBytes -and $null -ne $values.CommitLimitBytes -and
        $values.CommitLimitBytes -gt 0 -and $values.CommitLimitBytes -ge $values.CommittedBytes) {
        $values.CommitHeadroomBytes=$values.CommitLimitBytes-$values.CommittedBytes
    }
    $sum=[decimal]0;$valid=0;$unknown=0
    $processRows=@();$processFindings=New-Object 'System.Collections.Generic.List[object]';$identities=@{}
    if ($Snapshot.Processes.Status -ne 'Failed') {$processRows=@($Snapshot.Processes.Items)}
    foreach ($p in $processRows) {
        $bytes=Get-MiAttributionBytes $p.PrivateBytes
        $key=Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
        if ($key -and $identities.ContainsKey($key)) {$unknown++;continue}
        if ($key) {$identities[$key]=$true}
        if ($null -ne $bytes) {$sum+=[decimal]$bytes;$valid++}
        if (-not $key) {$unknown++;continue}
        $samples=$null
        if ($Analyzer.Tracks.ContainsKey($key)) {$samples=$Analyzer.Tracks[$key].Samples}
        $f=New-MiAttributionFinding $Analyzer ProcessPrivate PrivateBytes $bytes $samples $NowUtc -ProcessInstanceId $key -SourceType Snapshot
        $f | Add-Member -NotePropertyName Label -NotePropertyValue ('{0} · PID {1}' -f $p.Name,$p.PID)
        $processFindings.Add($f)
    }
    $values['ProcessPrivateBytes']=$null
    if ($valid -gt 0 -and $sum -le [long]::MaxValue) {$values.ProcessPrivateBytes=[long]$sum}
    $collectionComplete=$Snapshot.Processes.Status -eq 'Success' -and $valid -eq $processRows.Count -and $unknown -eq 0 -and $valid -gt 0
    foreach ($metric in $values.Keys) {
        if (-not $Analyzer.AttributionHistory.ContainsKey($metric)) {
            $Analyzer.AttributionHistory[$metric]=New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]'
        }
        $history=$Analyzer.AttributionHistory[$metric];$current=$values[$metric]
        # 全进程汇总缺成员时不写入完整趋势，避免退出/权限缺失造成假增长或假释放。
        if ($null -ne $current -and ($metric -ne 'ProcessPrivateBytes' -or $collectionComplete) -and
            ($history.Count -eq 0 -or $NowUtc -gt $history[$history.Count-1].Utc)) {
            $history.Add([MemoryInspector.AnalysisPoint]::new($NowUtc,$current))
        }
        Limit-MiAnalysisHistory $Analyzer $history $NowUtc
        $category='SystemCommit'
        if ($metric -like '*PoolBytes') {$category='KernelPool'}
        if ($metric -eq 'ProcessPrivateBytes') {$category='ProcessAggregate'}
        $source='Counter';if ($metric -eq 'ProcessPrivateBytes') {$source='Snapshot'}
        $f=New-MiAttributionFinding $Analyzer $category $metric $current $history $NowUtc -SourceType $source
        if ($metric -eq 'ProcessPrivateBytes' -and -not $collectionComplete) {
            $f.MeasurementQuality=$(if ($null -eq $current) {'Unavailable'} else {'Partial'})
            $f.GrowthBytes=$null;$f.Limitations+=('仅 {0}/{1} 个可读 Private Bytes；身份未知 {2} 个，枚举状态 {3}。' -f $valid,$processRows.Count,$unknown,$Snapshot.Processes.Status)
        }
        if ($category -eq 'KernelPool') {
            $f.Limitations+='Pool 计数器不能归属到具体驱动或 Pool Tag，也不能证明泄漏。'
            if ($null -ne $current -and $f.SamplingQuality.SufficientTrend) {
                $f.Trend=$(if ($f.GrowthBytes -ge 128MB -and $f.SamplingQuality.UpwardSegments -ge 4) {'SustainedGrowth'} else {'NoSustainedGrowth'})
            }
        }
        $findings.Add($f)
    }
    # 差额仅是两个不同统计口径的残差，绝不把 Pool/Working Set 再加进去凑成 Commit。
    $residualValue=$null
    if ($null -ne $values.CommittedBytes -and $null -ne $values.ProcessPrivateBytes) {
        $residualValue=$values.CommittedBytes-$values.ProcessPrivateBytes
    }
    if (-not $Analyzer.AttributionHistory.ContainsKey('Residual')) {
        $Analyzer.AttributionHistory['Residual']=New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]'
    }
    $residualHistory=$Analyzer.AttributionHistory['Residual']
    if ($null -ne $residualValue -and $collectionComplete -and
        ($residualHistory.Count -eq 0 -or $NowUtc -gt $residualHistory[$residualHistory.Count-1].Utc)) {
        $residualHistory.Add([MemoryInspector.AnalysisPoint]::new($NowUtc,$residualValue))
    }
    Limit-MiAnalysisHistory $Analyzer $residualHistory $NowUtc
    $residual=New-MiAttributionFinding $Analyzer UnresolvedCommit CommitMinusObservedPrivateBytes $residualValue $residualHistory $NowUtc -SourceType Snapshot
    $residual.AttributionConfidence='Unresolved'
    if ($null -ne $values.CommittedBytes -and $null -ne $values.ProcessPrivateBytes) {
        $residual.ObservedBytes=$values.CommittedBytes-$values.ProcessPrivateBytes
        $residual.MeasurementQuality='Partial';$residual.TimeRangeUtc=[pscustomobject]@{StartUtc=$NowUtc;EndUtc=$NowUtc}
    }
    if (-not $collectionComplete) {$residual.GrowthBytes=$null}
    elseif ($null -ne $residual.SamplingQuality.StartUtc) {
        $residual.TimeRangeUtc=[pscustomobject]@{StartUtc=$residual.SamplingQuality.StartUtc;EndUtc=$residual.SamplingQuality.EndUtc}
    }
    $residual.Limitations=@('系统 Commit 减去可读进程 Private Bytes；采集不同步且可能缺进程，差额可为负。','包含尚未归属的系统提交及统计差异，不代表泄漏；Pool 与进程指标不能保证完整分解 Commit。')
    $residual.SuggestedNextStep='结合进程及 Pool 趋势继续调查；高级 ETW 诊断尚未开放。'
    $findings.Add($residual)
    $ram=[ordered]@{SchemaVersion=1}
    foreach ($metric in @('TotalPhysicalBytes','AvailablePhysicalBytes','CacheBytes','StandbyBytes','CompressionBytes')) {
        $ram[$metric]=$(if ($system.Status -ne 'Failed') {Get-MiAttributionBytes $system.$metric} else {$null})
    }
    $ram['Limitations']='RAM 与 Commit 独立；Working Set 仅显示单进程，禁止求和作为物理占用。Cache/Standby 可能重叠；压缩量不可用时保持 null。'
    return [pscustomobject]@{
        SchemaVersion=1;CapturedUtc=$NowUtc;BootId=$Analyzer.BootId;Status='Success'
        Findings=$findings.ToArray();ProcessFindings=$processFindings.ToArray();Ram=[pscustomobject]$ram
        ProcessGroups=@(Get-MiProcessGroups $processRows $Analyzer.BootId -Mode Executable -CollectionStatus $Snapshot.Processes.Status)
        ParentGroups=@(Get-MiProcessGroups $processRows $Analyzer.BootId -Mode Parent -CollectionStatus $Snapshot.Processes.Status)
        UnassociatedProcessCount=$unknown;CollectionStatus=$Snapshot.Processes.Status
    }
}
