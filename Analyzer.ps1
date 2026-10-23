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

function New-MiAnalyzer {
    param([string]$BootId,[string]$Root,[int]$WindowMinutes=30)
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
        WindowMinutes = $WindowMinutes
    }
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
        $cutoff = $utc.AddMinutes(-30)
        while ($list.Count -gt 0 -and $list[0].Utc -lt $cutoff) { $list.RemoveAt(0) }
        while ($list.Count -gt 185) { $list.RemoveAt(0) }
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
    param([string]$Root,[datetime]$NowUtc)
    if ([string]::IsNullOrWhiteSpace($Root)) { return @() }
    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($day in @($NowUtc.Date.AddDays(-1),$NowUtc.Date)) {
        $date = $day.ToString('yyyy-MM-dd')
        $filename = 'process-'+$date+'.jsonl'
        $raw = Join-Path (Join-Path $Root 'process') $filename
        $recent = @()
        if ([IO.File]::Exists($raw)) {
            # 240 records covers a 30-minute window at 10-second cadence.
            $recent = @(Read-MiJsonTail -Path $raw -Count 240)
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
                                if ($tail.Count -gt 240) { [void]$tail.Dequeue() }
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
                if ($utc -ge $NowUtc.AddMinutes(-30) -and $utc -le $NowUtc -and $r.RecordType -eq 'ProcessSnapshot') {
                    $records.Add($r)
                }
            } catch {}
        }
    }
    return @($records.ToArray() | Sort-Object CaptureEndUtc)
}

function Restore-MiAnalyzer {
    param($Analyzer,[datetime]$NowUtc=[datetime]::UtcNow)
    if (-not $Analyzer.CanRestore -or [string]::IsNullOrWhiteSpace($Analyzer.Root)) { return 0 }
    $count = 0
    foreach ($r in @(Get-MiRecentProcessRecords -Root $Analyzer.Root -NowUtc $NowUtc)) {
        if ($r.ProcessStatus -eq 'Failed') { continue }
        # Existing M2 ProcessInstanceId contains the boot id, PID and start time.
        $matching = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in @($r.Items)) {
            $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
            if ($null -ne $key -and $key -ceq [string]$p.ProcessInstanceId) { $matching.Add($p) }
        }
        if ($matching.Count -eq 0) { continue }
        Add-MiTrackSample -Analyzer $Analyzer -Historical $true -Snapshot ([pscustomobject]@{
            CaptureEndUtc=$r.CaptureEndUtc
            Processes=[pscustomobject]@{Status=$r.ProcessStatus;Items=$matching.ToArray()}
        })
        $count++
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
        $_.Utc -ge $NowUtc.AddMinutes(-30) -and $_.Utc -le $NowUtc
    } | Sort-Object Utc)
    $report.ValidSampleCount = $samples.Count
    $report.CoverageRatio = [math]::Round(([double]$samples.Count / 180.0),3)
    if ($samples.Count -lt 153 -or ($samples[$samples.Count-1].Utc-$samples[0].Utc).TotalMinutes -lt 29.0) {
        $report.Explanation = ('30 分钟窗口需要至少 153/180 个有效样本并覆盖约 29 分钟；当前 {0}/180。' -f $samples.Count)
        return [pscustomobject]$report
    }
    $bins = @()
    for ($i=0;$i -lt 6;$i++) { $bins += ,(New-Object 'System.Collections.Generic.List[object]') }
    $windowStart = $NowUtc.AddMinutes(-30)
    foreach ($point in $samples) {
        $slot = [int][math]::Floor(($point.Utc-$windowStart).TotalSeconds / 300.0)
        $slot = [math]::Max(0,[math]::Min(5,$slot))
        $bins[$slot].Add([double]$point.Bytes)
    }
    $medians = @()
    foreach ($bin in $bins) {
        if ($bin.Count -lt 15) {
            $report.Explanation = '至少一个五分钟分段的有效样本不足，暂不判断增长趋势。'
            return [pscustomobject]$report
        }
        $medians += [double](Get-MiMedian -Values $bin.ToArray())
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
    if ($baseline -gt 0 -and $growth -ge 512MB -and ($growth/$baseline) -ge 0.20 -and $upward -ge 4) {
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
    $result.CommitHeadroomBytes = [long][math]::Max(0,$limit-$committed)
    if ($commitRatio -ge 0.90 -or $ramRatio -le 0.05) { $result.State='High' }
    elseif ($commitRatio -ge 0.80 -or $ramRatio -le 0.10) { $result.State='Elevated' }
    else { $result.State='Normal' }
    $result.Explanation = ('Commit {0:P1}，可用 RAM {1:P1}；仅表示系统压力，不代表存在可清理的垃圾内存。' -f $commitRatio,$ramRatio)

    if ($null -ne $System.NonpagedPoolBytes -and [double]$System.NonpagedPoolBytes -ge 0) {
        $list = $Analyzer.PoolHistory
        if ($list.Count -eq 0 -or $NowUtc -gt $list[$list.Count-1].Utc) {
            $list.Add([pscustomobject]@{Utc=$NowUtc;Bytes=[long]$System.NonpagedPoolBytes})
        }
        while($list.Count -gt 0 -and $list[0].Utc -lt $NowUtc.AddMinutes(-30)) { $list.RemoveAt(0) }
        while($list.Count -gt 185) { $list.RemoveAt(0) }
        if ($list.Count -gt 1 -and ($NowUtc-$list[0].Utc).TotalMinutes -ge 20) {
            $poolDelta = [long]$System.NonpagedPoolBytes - [long]$list[0].Bytes
            $result.NonpagedPoolTrend = $(if ($poolDelta -ge 128MB) {'Rising'} else {'NotRising'})
        }
    }
    return [pscustomobject]$result
}

function Invoke-MiDiagnosis {
    param($Analyzer,$Snapshot)
    $utc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
    if ($Analyzer.LastCaptureUtc -ne [datetime]::MinValue -and $utc -le $Analyzer.LastCaptureUtc) {
        return [pscustomobject]@{
            Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'}
            Error='检测到倒退或重复的采样时间，已忽略本轮诊断。'
        }
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
