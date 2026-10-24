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


# P2-01/P2-03/P2-04：调用真实 GUI 控制函数，使用内存标签和图表，不执行危险操作。
. (Join-Path $root 'ProcessActions.ps1')
foreach ($name in @('Set-MiStatus','Set-MiOperationStatus','Show-MiProcessObservation','Update-MiGuiProcessJob',
    'Update-MiActionButtons','Format-MiGiB','Update-MiKpi','Update-MiCharts','Process-MiMailbox')) {
    $node=$mainAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if ($null -eq $node) { throw ('Missing GUI function: '+$name) }
    . ([scriptblock]::Create($node.Extent.Text))
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms.DataVisualization
$script:Closing=$false
$script:Amber=[Drawing.Color]::DarkOrange;$script:Muted=[Drawing.Color]::Gray;$script:Ink=[Drawing.Color]::Black
$script:StatusLabel=[pscustomobject]@{Text='';ForeColor=$null}
$script:OperationLabel=[pscustomobject]@{Text='';ForeColor=$null}
$script:KpiValues=@(0..3 | ForEach-Object {[pscustomobject]@{Text=''}})
$script:KpiNotes=@(0..3 | ForEach-Object {[pscustomobject]@{Text=''}})
$script:LineChart=[Windows.Forms.DataVisualization.Charting.Chart]::new()
[void]$script:LineChart.Series.Add('Committed');[void]$script:LineChart.Series.Add('RAM')
$script:BarChart=[Windows.Forms.DataVisualization.Charting.Chart]::new()
[void]$script:BarChart.Series.Add('Private')
$script:History=New-Object 'System.Collections.Generic.List[object]'
$script:HistoryLimit=362;$script:CurrentProcesses=@()
$script:MiActions=[pscustomobject]@{Pending=$null;Busy=$false;CanAudit=$true}
$script:Mailbox=[Collections.Concurrent.ConcurrentQueue[object]]::new()
$script:LastSequence=0
function Update-MiGrid { param($ProcessCollection) }
$partial=[pscustomobject]@{
    Status='Partial';CommittedBytes=$null;CommitLimitBytes=16GB;UsedPhysicalBytes=5GB;TotalPhysicalBytes=8GB
    AvailablePhysicalBytes=3GB;NonpagedPoolBytes=32MB;PagedPoolBytes=64MB;Error='Unavailable: CommittedBytes'
}
try {
    foreach ($state in @('Confirmed','Failed','TimedOut','UnknownOutcome')) {
        Set-MiOperationStatus $state ('fixture operation '+$state) ($state -ne 'Confirmed')
        $savedText=$script:OperationLabel.Text
        foreach ($n in 1..3) {
            $script:Mailbox.Enqueue([pscustomobject]@{
                Sequence=($script:LastSequence+1);CaptureEndUtc=[datetime]::UtcNow;DurationMs=1;Status='Partial';System=$partial
                Processes=[pscustomobject]@{Status='Success';Items=@();Total=0;Error=$null}
                PersistenceStatus='Saved';PersistenceError=$null
                Diagnosis=[pscustomobject]@{Status='Success';Reports=@();Pressure=[pscustomobject]@{State='Unknown'}}
            })
            Process-MiMailbox
            if ($script:OperationLabel.Text -cne $savedText -or $script:LastOperationStatus.State -cne $state) {
                throw 'Periodic sampling overwrote the latest operation result.'
            }
        }
        if ($script:StatusLabel.Text -notmatch '采样') { throw 'Monitoring status stopped updating.' }
    }
    if ($script:KpiValues[0].Text -notmatch '不可用' -or $script:KpiValues[3].Text -match '0.00') { throw 'Null commit became a zero KPI or zero delta.' }
    if (@($script:LineChart.Series['Committed'].Points | Where-Object {-not $_.IsEmpty}).Count -ne 0 -or
        @($script:LineChart.Series['RAM'].Points | Where-Object {-not $_.IsEmpty}).Count -eq 0) { throw 'Partial counter chart fabricated zero or discarded valid RAM.' }
    $operation=[pscustomobject]@{Name='fixture';PID=42}
    Show-MiProcessObservation ([pscustomobject]@{State='Complete';Operation=$operation;NetCommitBytes=$null;TargetStatus='Present'})
    if ($script:LastOperationStatus.State -ne 'NotExited') { throw 'Present process was falsely reported as exited.' }
    Show-MiProcessObservation ([pscustomobject]@{State='Incomplete';Operation=$operation;NetCommitBytes=$null;TargetStatus='Unknown'})
    if ($script:LastOperationStatus.State -ne 'TimedOut') { throw 'Observation timeout was not distinct.' }
} finally { $script:LineChart.Dispose();$script:BarChart.Dispose() }

# 已完成的预验证必须与当前完整实例身份匹配；慢检查、旧选择和 PID 复用不能启用按钮。
$script:Chosen=[pscustomobject]@{PID=42424;Name='fixture';StartUtcTicks=100;Status='Success';PrivateBytes=100MB}
function Get-MiSelectedProcess { return $script:Chosen }
function Test-MiElevated { return $false }
$script:MiGracefulButton=[pscustomobject]@{Enabled=$false}
$script:MiForceButton=[pscustomobject]@{Enabled=$false}
$script:MiDangerCheck=[pscustomobject]@{Checked=$true}
$script:ProcessCheckLabel=[pscustomobject]@{Text=''}
$script:ServicePids=@{}
$script:LatestSnapshot=[pscustomobject]@{CaptureEndUtc=[datetime]::UtcNow;Processes=[pscustomobject]@{Status='Success';Items=@($script:Chosen)}}
$script:StartedPreflights=0
function Start-MiProcessJob {
    param($Kind,$Item,$Snapshot)
    $script:StartedPreflights++;$script:MiProcessJob=[pscustomobject]@{Kind=$Kind;Key=(Get-MiProcessCheckKey $Item)}
}
function Poll-MiProcessJob { $script:MiProcessJob=$null;return $script:TestReply }
Update-MiActionButtons
if ($script:MiGracefulButton.Enabled -or $script:MiForceButton.Enabled -or $script:StartedPreflights -ne 1) { throw 'Unverified target enabled destructive actions.' }
$oldKey=Get-MiProcessCheckKey $script:Chosen
$script:Chosen=$script:Chosen.PSObject.Copy();$script:Chosen.StartUtcTicks=200
$script:LatestSnapshot.Processes.Items=@($script:Chosen)
$script:TestReply=[pscustomobject]@{Kind='Check';Key=$oldKey;State='Verified'}
Update-MiGuiProcessJob
if ($script:MiGracefulButton.Enabled -or $script:StartedPreflights -ne 2) { throw 'Late validation for a reused PID enabled the new instance.' }
$script:TestReply=[pscustomobject]@{Kind='Check';Key=(Get-MiProcessCheckKey $script:Chosen);State='Verified'}
Update-MiGuiProcessJob
if (-not $script:MiGracefulButton.Enabled -or -not $script:MiForceButton.Enabled) { throw 'Matching successful prevalidation did not enable actions.' }
$script:LatestSnapshot.CaptureEndUtc=[datetime]::UtcNow.AddSeconds(-91)
Update-MiActionButtons
if ($script:MiGracefulButton.Enabled -or $script:MiForceButton.Enabled) { throw 'Stale snapshot reused prior verification.' }
if ($main -match 'Get-Content[^\r\n]*-Tail 100' -or $main -notmatch 'Get-MiSecurityPaths' -or $gui -notmatch '完整操作审计') { throw 'Complete process/admin audit entry is missing.' }
Write-Host 'PASS: P2 null KPI/chart gaps, persistent operation results during mailbox refresh, distinct outcomes and exact-instance async button gating.' -ForegroundColor Green


# 完整审计对话框必须包含第 1 行和第 140 行，不能仅展示最后 100 条。
$auditFixture=Join-Path $settingsFixture 'complete-audit.jsonl'
$adminAuditFixture=Join-Path $settingsFixture 'admin-audit.jsonl'
[IO.File]::WriteAllLines($auditFixture,[string[]]@(1..140 | ForEach-Object { 'audit-line-'+$_ }),[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($adminAuditFixture,'protected-audit-fixture',[Text.Encoding]::UTF8)
$script:MiActions | Add-Member -NotePropertyName AuditPath -NotePropertyValue $auditFixture -Force
function Get-MiSecurityPaths { return [pscustomobject]@{Audit=$adminAuditFixture} }
function Test-MiAuditDialog($Dialog) {
    $tabs=$Dialog.Controls[0]
    $processText=$tabs.TabPages[0].Controls[0].Text
    $adminText=$tabs.TabPages[1].Controls[0].Text
    if ($processText -notmatch 'audit-line-1\r?\n' -or $processText -notmatch 'audit-line-140' -or
        $adminText -cne 'protected-audit-fixture') { throw 'Full process/admin audit record is inaccessible.' }
}
$logNode=$mainAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-MiActionLog'},$true)
$logCode=$logNode.Extent.Text.Replace('[void]$form.ShowDialog($script:Form)','Test-MiAuditDialog $form')
. ([scriptblock]::Create($logCode))
Show-MiActionLog
Write-Host 'PASS: complete process/admin audit dialog retains records beyond 100 lines.' -ForegroundColor Green


# P3：改变夹具 VERSION 验证实际控件绑定，不修改项目 VERSION。
$versionRoot=Join-Path $settingsFixture 'version-fixture'
[void][IO.Directory]::CreateDirectory($versionRoot)
$versionFile=Join-Path $versionRoot 'VERSION'
$guiTokens=$null;$guiErrors=$null
$guiAst=[Management.Automation.Language.Parser]::ParseInput($gui,[ref]$guiTokens,[ref]$guiErrors)
function New-MiLabel { param([string]$Text,[int]$Size) return [pscustomobject]@{Text=$Text} }
$script:Form=[pscustomobject]@{Text=''}
$script:TrayIcon=[pscustomobject]@{Text=''}
foreach ($expected in @('0.0.8','1.2.3')) {
    [IO.File]::WriteAllText($versionFile,(' '+$expected+[Environment]::NewLine),[Text.UTF8Encoding]::new($true))
    $script:VersionInfo=Get-MiVersionPresentation -Root $versionRoot
    foreach ($binding in @(
        @{Ast=$mainAst;Left='$script:Form.Text'},
        @{Ast=$guiAst;Left='$script:TrayIcon.Text'},
        @{Ast=$guiAst;Left='$script:ServiceNote'},
        @{Ast=$guiAst;Left='$script:MiPrivilegeNote'}
    )) {
        $assignment=$binding.Ast.Find({param($n)
            $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq $binding.Left
        },$true)
        if ($null -eq $assignment) { throw ('Version UI binding missing: '+$binding.Left) }
        . ([scriptblock]::Create($assignment.Extent.Text))
    }
    foreach ($text in @($script:Form.Text,$script:TrayIcon.Text,$script:ServiceNote.Text,$script:MiPrivilegeNote.Text)) {
        if (-not $text.Contains($expected)) { throw ('UI did not use VERSION: '+$text) }
    }
    if ($script:VersionInfo.Version -cne $expected -or $script:TrayIcon.Text.Length -gt 63) { throw 'Version parsing or WinForms tray length failed.' }
}
foreach ($invalid in @('', 'garbage', '0.0', '0.0.8.1', '0.0.8<script>', ('0.0.8'+[Environment]::NewLine+'1.2.3'), '999999999999999999999999.1.1')) {
    [IO.File]::WriteAllText($versionFile,$invalid,[Text.UTF8Encoding]::new($false))
    $rejected=$false
    try { [void](Get-MiVersionPresentation -Root $versionRoot) } catch { $rejected=$true }
    if (-not $rejected) { throw ('Invalid VERSION silently displayed: '+$invalid) }
}
# 缺失和不可读的 VERSION 不得回退旧版本；移动保留测试资料，不删除。
[IO.File]::Move($versionFile,(Join-Path $versionRoot 'invalid-version.retained'))
$rejected=$false
try { [void](Get-MiVersionPresentation -Root $versionRoot) } catch { $rejected=$true }
if (-not $rejected) { throw 'Missing VERSION fell back to a fabricated version.' }
[void][IO.Directory]::CreateDirectory($versionFile)
$rejected=$false
try { [void](Get-MiVersionPresentation -Root $versionRoot) } catch { $rejected=$true }
if (-not $rejected) { throw 'Unreadable VERSION fell back to a fabricated version.' }
$actual=Get-MiVersionPresentation -Root $root
if ($actual.Version -cne ([IO.File]::ReadAllText((Join-Path $root 'VERSION'))).Trim()) { throw 'Project GUI version differs from VERSION.' }
if ($main -match 'Windows 服务仍|不操作服务|0\.0\.[0-9]+' -or $gui -match '0\.0\.[0-9]+') { throw 'Hardcoded release version remains in the GUI modules.' }
$serviceBridge=[IO.File]::ReadAllText((Join-Path $root 'ServiceBridge.ps1'),[Text.Encoding]::UTF8)
if ($serviceBridge -match '0\.0\.7') { throw 'Old service installation prompt remains.' }
$installerCode=[IO.File]::ReadAllText((Join-Path $root 'Installer.ps1'),[Text.Encoding]::UTF8)
$it=$null;$ie=$null
$installerAst=[Management.Automation.Language.Parser]::ParseInput($installerCode,[ref]$it,[ref]$ie)
$manifestAssignment=$installerAst.Find({param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$manifest'
},$true)
$sourceVersion=$actual.Version
$entries=New-Object 'System.Collections.Generic.List[object]'
. ([scriptblock]::Create($manifestAssignment.Extent.Text))
if ($manifest.Version -cne $actual.Version -or $installerCode -notmatch '\$sourceVersion -cne ''0\.0\.8''' -or
    $installerCode -notmatch '''Installed MemoryInspector ''\+\$sourceVersion') {
    throw 'Installation metadata/display differs from validated VERSION or release pin was weakened.'
}
Write-Host 'PASS: P3 VERSION-driven window/tray/service/install text, future-version fixture, invalid/missing/unreadable VERSION rejection and installer version pin.' -ForegroundColor Green
