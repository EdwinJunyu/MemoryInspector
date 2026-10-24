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
# P1：真正调用现有 GUI 缓存函数，最密周期必须保留 30 分钟，旧数据按时间淘汰。
$script:ProcessTrend=@{}
$base=[datetime]::SpecifyKind([datetime]'2026-10-23T10:00:00',[DateTimeKind]::Utc)
for ($i=0;$i -le 360;$i++) {
    Add-MiV4ProcessHistory -Snapshot ([pscustomobject]@{
        CaptureEndUtc=$base.AddSeconds($i*5)
        Processes=[pscustomobject]@{Status='Success';Items=@($process)}
    })
}
$trace=$script:ProcessTrend['42:100']
if ($trace.Count -ne 361 -or ($trace[$trace.Count-1].Utc-$trace[0].Utc).TotalMinutes -ne 30) {
    throw '5-second process chart history cannot retain the full 30-minute window.'
}
Add-MiV4ProcessHistory -Snapshot ([pscustomobject]@{
    CaptureEndUtc=$base.AddHours(2)
    Processes=[pscustomobject]@{Status='Success';Items=@($process)}
})
if ($script:ProcessTrend['42:100'].Count -ne 1) { throw 'Expired process chart data was not removed.' }

# 仅提取纯缓存函数，不启动 WinForms，验证总览图表保持相同的时间窗口。
$tokens=$null;$errors=$null
$mainAst=[Management.Automation.Language.Parser]::ParseInput($main,[ref]$tokens,[ref]$errors)
$historyFunction=$mainAst.Find({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Add-MiHistory'
},$true)
. ([scriptblock]::Create($historyFunction.Extent.Text))
$script:History=New-Object 'System.Collections.Generic.List[object]'
$script:HistoryLimit=362
for ($i=0;$i -le 360;$i++) { Add-MiHistory ([pscustomobject]@{CaptureEndUtc=$base.AddSeconds($i*5)}) }
if ($script:History.Count -ne 361) { throw 'Overview chart truncated 5-second history.' }
Add-MiHistory ([pscustomobject]@{CaptureEndUtc=$base.AddHours(2)})
if ($script:History.Count -ne 1) { throw 'Overview chart kept expired data.' }
if ($main -notmatch '\$script:PeriodMs = 5000' -or $gui -notmatch '默认 5 秒') {
    throw 'Default sampling period is inconsistent between controller and settings.'
}

# 保存已有设置也必须在 PS5.1 成功；测试资料留在项目专用文件夹，不触及真实用户偏好。
$settingsFixture=Join-Path (Join-Path $root '_test-artifacts') ('GuiSettings-'+[guid]::NewGuid().ToString('N'))
$script:UiSettingsPath=Join-Path $settingsFixture 'ui-settings.json'
$script:SampleSetting=[pscustomobject]@{Value=10}
$script:TraySetting=[pscustomobject]@{Checked=$true}
$script:GrowthSetting=[pscustomobject]@{Value=512}
$script:GrowthPercentSetting=[pscustomobject]@{Value=20}
$script:SettingsNote=[pscustomobject]@{Text=''}
Save-MiV4Settings
$script:SampleSetting.Value=5
Save-MiV4Settings
$savedSettings=[IO.File]::ReadAllText($script:UiSettingsPath,[Text.Encoding]::UTF8)|ConvertFrom-Json
if ($savedSettings.SamplingSeconds -ne 5 -or $script:PeriodMs -ne 5000 -or $savedSettings.GrowthMiB -ne 512) {
    throw 'Existing GUI settings could not be updated without losing preferences.'
}

# 独立后台 runspace 执行原 Worker 循环，仅替换磁盘/采集依赖为测试对象。
# 第一轮故意超过5秒，第二轮取消：验证不并行补排、继续尝试保存、队列有界且finally释放资源。
$worker=[IO.File]::ReadAllText((Join-Path $root 'Worker.ps1'),[Text.Encoding]::UTF8)
$mockDependencies=@'
function New-MiPersistence {
    return [pscustomobject]@{Healthy=$true;BootId='test';Root='';Warning=$null;FailureKind='None';RecoveredUtc=$null}
}
function New-MiAnalyzer {
    param($BootId,$Root,$IntervalSeconds)
    $MiWorkerTest.Cadence=$IntervalSeconds
    return [pscustomobject]@{Historical=@{};HistoricalLoadedUtc=[datetime]::UtcNow}
}
function Restore-MiAnalyzer { return 0 }
function Update-MiHistoricalBaselines {}
function Invoke-MiDiagnosis {
    param($Analyzer,$Snapshot)
    if ($Snapshot.IntervalSeconds -ne 5) { throw 'Missing cadence metadata.' }
    return [pscustomobject]@{Status='Success';Reports=@();Pressure=[pscustomobject]@{State='Normal'}}
}
function Get-MiSnapshot {
    param($Sequence)
    $MiWorkerTest.Collects++
    $MiWorkerTest.Active++
    $MiWorkerTest.Peak=[math]::Max($MiWorkerTest.Peak,$MiWorkerTest.Active)
    try {
        if ($Sequence -eq 1) { Start-Sleep -Milliseconds 5100 }
        return [pscustomobject]@{
            Sequence=$Sequence;CaptureEndUtc=[datetime]::UtcNow;Status='Success'
            System=[pscustomobject]@{Status='Success'}
            Processes=[pscustomobject]@{Status='Success';Items=@();Total=0}
        }
    } finally { $MiWorkerTest.Active-- }
}
function Save-MiSnapshot {
    param($State,$Snapshot)
    $MiWorkerTest.Saves++
    if ($MiWorkerTest.Saves -eq 1) {
        $State.Healthy=$false;$State.Warning='Injected transient failure';$State.FailureKind='Transient'
        return $false
    }
    $State.Healthy=$true;$State.Warning=$null;$State.FailureKind='None';$State.RecoveredUtc=[datetime]::UtcNow
    $Cancellation.Cancel()
    return $true
}
function Close-MiPersistence { $MiWorkerTest.Closed=$true }
'@
$worker=$worker.Replace('. $CollectorPath',$mockDependencies).Replace('. $PersistencePath','').Replace('. $AnalyzerPath','')
$stats=[hashtable]::Synchronized(@{Collects=0;Active=0;Peak=0;Saves=0;Closed=$false;Cadence=0})
$queue=[Collections.Concurrent.ConcurrentQueue[object]]::new()
$cancel=[Threading.CancellationTokenSource]::new()
$testRunspace=[runspacefactory]::CreateRunspace()
$testRunspace.Open()
$runner=[Management.Automation.PowerShell]::Create()
$runner.Runspace=$testRunspace
try {
    $testRunspace.SessionStateProxy.SetVariable('MiWorkerTest',$stats)
    [void]$runner.AddScript($worker).AddArgument('').AddArgument('').AddArgument('').AddArgument($queue).AddArgument($cancel).AddArgument(5000).AddArgument(1).AddArgument('')
    $pending=$runner.BeginInvoke()
    if (-not $pending.AsyncWaitHandle.WaitOne(20000)) {
        $cancel.Cancel();$runner.Stop();throw 'Worker fixture failed to stop within its bounded deadline.'
    }
    [void]$runner.EndInvoke($pending)
    if ($runner.HadErrors) { throw ('Worker regression failed: '+($runner.Streams.Error|Out-String)) }
    if ($stats.Collects -ne 2 -or $stats.Saves -ne 2 -or $stats.Peak -ne 1 -or -not $stats.Closed -or $stats.Cadence -ne 5) {
        throw ('Worker scheduling/recovery/cleanup failed: '+($stats|ConvertTo-Json -Compress))
    }
    $latest=$null
    if ($queue.Count -ne 1 -or -not $queue.TryDequeue([ref]$latest) -or $latest.Sequence -ne 2 -or
        $latest.PersistenceStatus -ne 'Saved' -or $null -eq $latest.PersistenceRecoveredUtc) {
        throw 'Bounded mailbox did not publish the latest recovered persistence status.'
    }
} finally {
    $cancel.Cancel();$runner.Dispose();$testRunspace.Dispose();$cancel.Dispose()
}
Write-Host 'PASS: M4 syntax, classification, CSV, 5-second full-window charts, bounded sequential Worker and persistence retry/status.' -ForegroundColor Green
