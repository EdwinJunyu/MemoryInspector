#requires -Version 5.1
<# Milestone 4 - GUI pure-function + source safety regression. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('MemoryInspector.ps1','GuiV4.ps1','Worker.ps1','Analyzer.ps1')
foreach ($name in $files) {
    $file=Join-Path $root $name
    $tokens=$null; $errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
    if ($null -ne $errors -and $errors.Count -gt 0) { throw ("PowerShell parse failed: "+$name+" :: "+($errors|Out-String)) }
}
. (Join-Path $root 'GuiV4.ps1')
if ((Protect-MiV4Csv '=HYPERLINK("x")') -ne "'=HYPERLINK(`"x`")") {
    throw 'CSV formula neutralization failed.'
}
if ((Protect-MiV4Csv 'normal') -ne 'normal') { throw 'Safe CSV content unexpectedly changed.' }
$script:ServicePids=@{42=$true}
$process=[pscustomobject]@{PID=42;Name='service-host';StartUtcTicks=100;Status='Success';PrivateBytes=1000;WorkingBytes=800;DeltaBytes=10}
if ((Get-MiV4Risk -Item $process) -ne '受限（服务宿主）') { throw 'Service-host read-only risk guard failed.' }
$unverified=[pscustomobject]@{PID=43;Name='unknown';StartUtcTicks=$null;Status='Partial';PrivateBytes=500;WorkingBytes=200;DeltaBytes=0}
if ((Get-MiV4Risk -Item $unverified) -ne '未知（禁止操作）') { throw 'Unverified process classification failed.' }
$rows=@(
    [pscustomobject]@{PID=17;Name='alpha';StartUtcTicks=10;Status='Success';PrivateBytes=300;WorkingBytes=100;DeltaBytes=20},
    [pscustomobject]@{PID=22;Name='beta';StartUtcTicks=20;Status='Success';PrivateBytes=500;WorkingBytes=200;DeltaBytes=1}
)
if (@(Select-MiV4Rows -Rows $rows -Filter 'alpha' -Order 'Private' -Limit 60).Count -ne 1) {
    throw 'Process filtering failed.'
}
if ((@(Select-MiV4Rows -Rows $rows -Filter '' -Order 'Private' -Limit 60)[0].Name) -ne 'beta') {
    throw 'Process sorting failed.'
}
$gui=Get-Content -LiteralPath (Join-Path $root 'GuiV4.ps1') -Raw -Encoding UTF8
if ($gui -match '(?i)\b(Stop-Process|Stop-Service|taskkill|Clear-StandbyList)\b' -or $gui -match '(?i)\.Kill\s*\(') {
    throw 'Unsafe mutation command found in M4 GUI.'
}
$main=Get-Content -LiteralPath (Join-Path $root 'MemoryInspector.ps1') -Raw -Encoding UTF8
if ($main -notmatch 'Initialize-MiV4Gui' -or $main -notmatch 'Poll-MiV4Jobs' -or $main -notmatch 'Close-MiV4Gui') {
    throw 'GUI integration missing lifecycle calls.'
}
Write-Host 'PASS: M4 syntax, safe classification, search, sorting, CSV guards and integration.' -ForegroundColor Green
