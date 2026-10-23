#requires -Version 5.1
<# Independent background runspace; never touches Windows Forms controls. #>
param(
    [string]$CollectorPath,
    [string]$PersistencePath,
    [string]$AnalyzerPath,
    [System.Collections.Concurrent.ConcurrentQueue[object]]$Mailbox,
    [System.Threading.CancellationTokenSource]$Cancellation,
    [int]$IntervalMs,
    [int]$QueueLimit,
    [string]$UiSettingsPath
)
$ErrorActionPreference = 'Stop'
. $CollectorPath
. $PersistencePath
. $AnalyzerPath
$storage = New-MiPersistence
$analyzer = New-MiAnalyzer -BootId $storage.BootId -Root $storage.Root
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
while (-not $Cancellation.IsCancellationRequested) {
    $sequence++
    $started = [datetime]::UtcNow
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
    if ($storage.Healthy) { $written = Save-MiSnapshot -State $storage -Snapshot $snapshot }
    # Refresh long-term baseline infrequently; disk parsing stays off the UI thread.
    if (($snapshot.CaptureEndUtc - $analyzer.HistoricalLoadedUtc).TotalMinutes -ge 30) {
        try { Update-MiHistoricalBaselines -Analyzer $analyzer -NowUtc $snapshot.CaptureEndUtc }
        catch { $analyzer.HistoricalLoadedUtc = $snapshot.CaptureEndUtc }
    }
    $snapshot | Add-Member -NotePropertyName PersistenceStatus -NotePropertyValue $(if ($written) { 'Saved' } else { 'Unavailable' }) -Force
    $snapshot | Add-Member -NotePropertyName PersistenceError -NotePropertyValue $storage.Warning -Force
    $Mailbox.Enqueue($snapshot)
    # Bounded mailbox: discard old UI updates rather than accumulating snapshots.
    while ($Mailbox.Count -gt $QueueLimit) {
        $discard = $null
        if (-not $Mailbox.TryDequeue([ref]$discard)) { break }
    }
    $spent = [int]([datetime]::UtcNow - $started).TotalMilliseconds
    $remaining = [math]::Max(0,$IntervalMs-$spent)
    if ($remaining -gt 0) {
        [void]$Cancellation.Token.WaitHandle.WaitOne([int]$remaining)
    }
}

Close-MiPersistence -State $storage
