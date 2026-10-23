#requires -Version 5.1
<# Independent background runspace; never touches Windows Forms controls. #>
param(
    [string]$CollectorPath,
    [string]$PersistencePath,
    [System.Collections.Concurrent.ConcurrentQueue[object]]$Mailbox,
    [System.Threading.CancellationTokenSource]$Cancellation,
    [int]$IntervalMs,
    [int]$QueueLimit
)
$ErrorActionPreference = 'Stop'
. $CollectorPath
. $PersistencePath
$storage = New-MiPersistence
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
    $written = $false
    if ($storage.Healthy) { $written = Save-MiSnapshot -State $storage -Snapshot $snapshot }
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
