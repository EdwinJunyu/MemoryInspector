#requires -Version 5.1
<# Independent background runspace; never touches Windows Forms controls. #>
param(
    [string]$CollectorPath,
    [string]$PersistencePath,
    [string]$AnalyzerPath,
    [System.Collections.Concurrent.ConcurrentQueue[object]]$Mailbox,
    [System.Threading.CancellationTokenSource]$Cancellation,
    [ValidateRange(5000,60000)][ValidateScript({($_ % 1000) -eq 0})][int]$IntervalMs=5000,
    [ValidateRange(1,100)][int]$QueueLimit=3,
    [string]$UiSettingsPath
)
$ErrorActionPreference = 'Stop'
. $CollectorPath
. $PersistencePath
. $AnalyzerPath
$storage = New-MiPersistence
$analyzer = New-MiAnalyzer -BootId $storage.BootId -Root $storage.Root -IntervalSeconds ($IntervalMs/1000.0)
if (-not [string]::IsNullOrWhiteSpace($UiSettingsPath) -and [IO.File]::Exists($UiSettingsPath)) {
    try {
        $preferences=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($UiSettingsPath,[Text.Encoding]::UTF8)) -ErrorAction Stop
        if ([int]$preferences.SchemaVersion -eq 1) {
            if ($null -ne $preferences.GrowthMiB -and [int]$preferences.GrowthMiB -ge 64 -and [int]$preferences.GrowthMiB -le 8192) {
                $analyzer.GrowthThresholdBytes=[long]$preferences.GrowthMiB * 1MB
            }
            if ($null -ne $preferences.GrowthPercent -and [int]$preferences.GrowthPercent -ge 5 -and [int]$preferences.GrowthPercent -le 200) {
                $analyzer.GrowthThresholdRatio=[double]$preferences.GrowthPercent / 100.0
            }
        }
    } catch { } # Invalid preferences must not stop collection; use safe defaults.
}
try {
    [void](Restore-MiAnalyzer -Analyzer $analyzer)
    Update-MiHistoricalBaselines -Analyzer $analyzer
} catch {
    # Historical analysis is best-effort; never take down live monitoring.
    $analyzer.Historical = @{}
}
$sequence = 0
# 单一后台循环只执行一个采样。Stopwatch 不受系统时钟校正影响，超时轮次不补排任务。
$schedule = [Diagnostics.Stopwatch]::StartNew()
try {
while (-not $Cancellation.IsCancellationRequested) {
    $sequence++
    $started = [datetime]::UtcNow
    $startedMs = $schedule.Elapsed.TotalMilliseconds
    try {
        $snapshot = Get-MiSnapshot -Sequence $sequence
    } catch {
        # Catastrophic sample failure still produces an explicit gap marker.
        $snapshot = [pscustomobject]@{
            SchemaVersion = 1; Sequence = $sequence
            CaptureStartUtc = $started; CaptureEndUtc = [datetime]::UtcNow
            DurationMs = 0; Status = 'Failed'
            System = [pscustomobject]@{Status='Failed'; Error=[string]$_.Exception.Message}
            Processes = [pscustomobject]@{Status='Failed';Items=@();Total=0;Incomplete=0;Error='采样中断'}
        }
    }
    # 可选元数据不改变 schema=1 的原有字段；分析和历史恢复以真实配置周期审核覆盖率。
    $snapshot | Add-Member -NotePropertyName IntervalSeconds -NotePropertyValue ($IntervalMs/1000.0) -Force
    # 与 UTC 并存的单调时间只作连续性校验，不替代历史时间戳。
    $snapshot | Add-Member -NotePropertyName MonotonicSeconds -NotePropertyValue ([Diagnostics.Stopwatch]::GetTimestamp()/[double][Diagnostics.Stopwatch]::Frequency) -Force
    # Diagnosis only reads scalar measurements. It must never modify processes.
    try {
        $diagnosis = Invoke-MiDiagnosis -Analyzer $analyzer -Snapshot $snapshot
        $snapshot | Add-Member -NotePropertyName Diagnosis -NotePropertyValue $diagnosis -Force
    } catch {
        $snapshot | Add-Member -NotePropertyName Diagnosis -NotePropertyValue ([pscustomobject]@{
            Status='Failed'; Reports=@()
            Pressure=[pscustomobject]@{State='Unknown';Explanation='诊断不可用'}
            Error=[string]$_.Exception.Message
        }) -Force
    }
    $written = $false
    # Save 内部对暂时故障进行低频、有界恢复；失败期间仍发布实时数据，不重放旧采样。
    try { $written = Save-MiSnapshot -State $storage -Snapshot $snapshot }
    catch {
        Set-MiPersistenceFailure -State $storage -Failure $_ -Prefix '历史保存异常，实时监控继续：'
    }
    # Refresh long-term baseline infrequently; disk parsing stays off the UI thread.
    if (($snapshot.CaptureEndUtc - $analyzer.HistoricalLoadedUtc).TotalMinutes -ge 30) {
        try { Update-MiHistoricalBaselines -Analyzer $analyzer -NowUtc $snapshot.CaptureEndUtc }
        catch { $analyzer.HistoricalLoadedUtc = $snapshot.CaptureEndUtc }
    }
    $snapshot | Add-Member -NotePropertyName PersistenceStatus -NotePropertyValue $(if ($written) { 'Saved' } else { 'Unavailable' }) -Force
    $snapshot | Add-Member -NotePropertyName PersistenceError -NotePropertyValue $storage.Warning -Force
    $snapshot | Add-Member -NotePropertyName PersistenceFailureKind -NotePropertyValue $storage.FailureKind -Force
    $snapshot | Add-Member -NotePropertyName PersistenceRecoveredUtc -NotePropertyValue $storage.RecoveredUtc -Force
    $Mailbox.Enqueue($snapshot)
    # Bounded mailbox: discard old UI updates rather than accumulating snapshots.
    while ($Mailbox.Count -gt $QueueLimit) {
        $discard = $null
        if (-not $Mailbox.TryDequeue([ref]$discard)) { break }
    }
    $spent = $schedule.Elapsed.TotalMilliseconds - $startedMs
    $remaining = [int][math]::Max(0,$IntervalMs-$spent)
    if ($remaining -gt 0) {
        [void]$Cancellation.Token.WaitHandle.WaitOne([int]$remaining)
    }
}
} finally {
    # 即使采样异常或取消，也在拥有锁的同一线程释放持久化资源。
    $schedule.Stop()
    Close-MiPersistence -State $storage
}
