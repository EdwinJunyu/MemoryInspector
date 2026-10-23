#requires -Version 5.1
<# Read-only smoke test, run on Windows PowerShell 5.1. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Collector.ps1')
$sample = Get-MiSnapshot -Sequence 1
if ($sample.SchemaVersion -ne 1 -or $sample.Sequence -ne 1) {
    throw 'Snapshot schema / sequence mismatch.'
}
if ($sample.CaptureEndUtc -lt $sample.CaptureStartUtc) {
    throw 'Snapshot clock order mismatch.'
}
if ($sample.System.Status -eq 'Success') {
    if ($sample.System.TotalPhysicalBytes -le 0 -or $sample.System.CommitLimitBytes -le 0) {
        throw 'System metrics must be positive.'
    }
}
if ($sample.Processes.Status -ne 'Failed') {
    if ($sample.Processes.Total -ne @($sample.Processes.Items).Count) {
        throw 'Process count mismatch.'
    }
}
Write-Host ('Snapshot: {0}; System: {1}; Processes: {2}; Rows: {3}' -f
    $sample.Status,$sample.System.Status,$sample.Processes.Status,$sample.Processes.Total)
if ($sample.Status -eq 'Failed') {
    throw ('All collection sources failed. System={0}; Process={1}' -f
        $sample.System.Error,$sample.Processes.Error)
}
Write-Host 'PASS: snapshot schema and available collection sources.' -ForegroundColor Green
