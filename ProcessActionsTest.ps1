#requires -Version 5.1
<# Milestone 5 - pure validation and forbidden-command regression. Never terminates a process. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('ProcessActions.ps1','MemoryInspector.ps1','GuiV4.ps1','ProcessActionsTest.ps1')
foreach($file in $files) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $file),[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { throw ('PowerShell parse error: '+$file+' '+($errors|Out-String)) }
}
. (Join-Path $root 'ProcessActions.ps1')
$start=[datetime]::UtcNow.AddMinutes(-5)
$record=[pscustomobject]@{
    PID=42424;Name='M5-TestApp';StartUtcTicks=[long]$start.Ticks
    Status='Success';PrivateBytes=100MB
}
$sample=[pscustomobject]@{
    CaptureEndUtc=[datetime]::UtcNow
    Processes=[pscustomobject]@{Status='Success';Items=@($record)}
}
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'Pass') {throw 'Valid snapshot rejected.'}
$sample.CaptureEndUtc=[datetime]::UtcNow.AddSeconds(-91)
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'StaleSnapshot') {throw 'Stale snapshot accepted.'}
$sample.CaptureEndUtc=[datetime]::UtcNow
$record.Status='Partial'
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'IncompleteProcessData') {throw 'Incomplete data accepted.'}
$record.Status='Success'
$sample.Processes.Items=@()
if ((Test-MiActionSnapshot -Item $record -Snapshot $sample) -ne 'IdentityNotInSnapshot') {throw 'Identity mismatch not rejected.'}
if (-not (Test-MiProtectedProcess -Name 'svchost' -Path 'C:\App\svchost.exe')) {throw 'Protected name not rejected.'}
if (-not (Test-MiProtectedProcess -Name 'normal' -Path '')) {throw 'Missing path not rejected.'}
$actionCode=Get-Content -LiteralPath (Join-Path $root 'ProcessActions.ps1') -Raw -Encoding UTF8
if ($actionCode -match '(?i)\b(Stop-Service|Start-Service|Invoke-Expression|Clear-StandbyList|EmptyWorkingSet)\b') { throw 'Forbidden action in M5 process module.' }
$guiCode=Get-Content -LiteralPath (Join-Path $root 'GuiV4.ps1') -Raw -Encoding UTF8
if ($guiCode -match '(?i)\.Kill\s*\(' -or $guiCode -match '(?i)\b(Stop-Process|Stop-Service)\b') { throw 'GUI directly performs destructive operations.' }
if ($actionCode -notmatch 'GetOwnerSid' -or $actionCode -notmatch 'Win32_Service' -or
    $actionCode -notmatch 'CloseMainWindow' -or $actionCode -notmatch 'Write-MiProcessAudit') {
    throw 'Missing process safety checks or audit.'
}
Write-Host 'PASS: M5 syntax, fail-closed snapshot, protected target, audit and separation.' -ForegroundColor Green
