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
# 大对象图不能因系统曲线缓存而存活；拷贝后原计数器变化也不能篡改已保存的图点。
$full=[pscustomobject]@{Sequence=99;CaptureEndUtc=$base.AddHours(3)
    System=[pscustomobject]@{Status='Partial';CommittedBytes=$null;UsedPhysicalBytes=4GB}
    Processes=[pscustomobject]@{Items=@([pscustomobject]@{PID=42;PrivateBytes=1GB})}
    Diagnosis=[pscustomobject]@{Reports=@('large-object-graph')}}
Add-MiHistory $full
$full.System.UsedPhysicalBytes=8GB
$retained=$script:History[0]
if ($null -ne $retained.Processes -or $null -ne $retained.Diagnosis -or
    $retained.System.UsedPhysicalBytes -ne 4GB -or $null -ne $retained.System.CommittedBytes -or
    $retained.Sequence -ne 99 -or $retained.System.Status -ne 'Partial') {throw 'Overview retained the snapshot graph, aliased counters or fabricated missing values.'}

# 紧凑存储必须保持精确字节数、未知RAM、实例隔离与完整窗口，而非以少存样本换内存。
$script:ProcessTrend=@{}
$largeBytes=[long]9007199254740993
$trendItem=[pscustomobject]@{PID=7;StartUtcTicks=123;PrivateBytes=$largeBytes;WorkingBytes=$null}
for($i=0;$i -le 360;$i++) {
    Add-MiV4ProcessHistory ([pscustomobject]@{CaptureEndUtc=$base.AddSeconds(5*$i);Processes=[pscustomobject]@{Status='Success';Items=@($trendItem)}})
}
$points=$script:ProcessTrend['7:123']
if ($points.Count -ne 361 -or $points[0].PrivateBytes -ne $largeBytes -or $null -ne $points[0].WorkingBytes -or
    ($points[360].Utc-$points[0].Utc).TotalSeconds -ne 1800) {throw 'Compact process history lost exact counters, null RAM or full-window samples.'}
$trendItem.StartUtcTicks=124
Add-MiV4ProcessHistory ([pscustomobject]@{CaptureEndUtc=$base.AddSeconds(1805);Processes=[pscustomobject]@{Status='Success';Items=@($trendItem)}})
if ($script:ProcessTrend['7:123'].Count -ne 361 -or $script:ProcessTrend['7:124'].Count -ne 1) {throw 'Compact display cache spliced reused PID identities.'}
Add-MiV4ProcessHistory ([pscustomobject]@{CaptureEndUtc=$base.AddHours(2);Processes=[pscustomobject]@{Status='Success';Items=@($trendItem)}})
if ($script:ProcessTrend.ContainsKey('7:123') -or $script:ProcessTrend['7:124'].Count -ne 1) {throw 'Compact display cache kept expired instances.'}
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
foreach ($expected in @('0.0.8','0.0.9','1.2.3')) {
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
if ($manifest.Version -cne $actual.Version -or $installerCode -notmatch '\$sourceVersion -cne ''0\.0\.9''' -or
    $installerCode -notmatch '''Installed MemoryInspector ''\+\$sourceVersion') {
    throw 'Installation metadata/display differs from validated VERSION or release pin was weakened.'
}
Write-Host 'PASS: P3 VERSION-driven window/tray/service/install text, future-version fixture, invalid/missing/unreadable VERSION rejection and installer version pin.' -ForegroundColor Green

# 从真实主控制器创建完整控件，再喂入第一条邮箱；不手动预置趋势缓存或替换真实 Grid 刷新。
# 只禁用实际动作、辅助后台查询和模态主循环，防止原来的分函数夹具掩盖冷启动缺陷。
$runtimeRepo=$root
$prefix=$main.Substring(0,$main.IndexOf('$script:UiTimer ='))
$prefix=$prefix.Replace('$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path','$script:Root = $runtimeRepo')
$prefix=[regex]::Replace($prefix,'(?m)^Initialize-MiActions\r?$', '$script:MiActions=[pscustomobject]@{AuditPath="";CanAudit=$false;Busy=$false;Pending=$null}')
$prefix=$prefix.Replace('Initialize-MiV4Gui -Root $root',"function Start-MiV4ServicesLoad {}`r`nfunction Start-MiV4HistoryLoad {}`r`nInitialize-MiV4Gui -Root `$root")
$script:ProcessTrend=$null
try {
    . ([scriptblock]::Create($prefix))
    if ($null -eq $script:ProcessTrend -or $script:ProcessTrend.Count -ne 0) {throw 'Fresh GUI did not initialize its empty process trend cache.'}
    $script:Mailbox=[Collections.Concurrent.ConcurrentQueue[object]]::new()
    $now=[datetime]::UtcNow
    $item=[pscustomobject]@{PID=9001;Name='gui-cold-start-fixture';StartUtcTicks=100;PrivateBytes=128MB;WorkingBytes=64MB;Status='Success'}
    $snapshot=[pscustomobject]@{Sequence=1;CaptureEndUtc=$now;DurationMs=1;Status='Success';TimeDiscontinuity=$false
        System=[pscustomobject]@{Status='Success';CommittedBytes=4GB;CommitLimitBytes=16GB;UsedPhysicalBytes=5GB;TotalPhysicalBytes=8GB;AvailablePhysicalBytes=3GB;NonpagedPoolBytes=32MB;PagedPoolBytes=64MB;Error=$null}
        Processes=[pscustomobject]@{Status='Success';Items=@($item);Total=1;Error=$null}
        Diagnosis=[pscustomobject]@{Status='Success';Reports=@();Pressure=[pscustomobject]@{State='Normal'}}
        PersistenceStatus='Saved';PersistenceError=$null}
    $script:Mailbox.Enqueue($snapshot)
    Process-MiMailbox
    if ($script:Grid.Rows.Count -ne 1 -or $script:Grid.Columns.Count -ne 9 -or
        $script:KpiValues[0].Text -notmatch '4.00 / 16.00' -or
        $script:LineChart.Series['Committed'].Points.Count -ne 1 -or $script:BarChart.Series[0].Points.Count -ne 1 -or
        $script:ProcessTrend.Count -ne 1 -or $script:StatusLabel.Text -notmatch '第 1 次采样' -or
        $script:MiGracefulButton.Enabled -or $script:MiForceButton.Enabled) {throw 'Fresh full GUI failed to render its first snapshot or enabled actions.'}
    # 复用行控件不能复用旧快照/旧身份。排序移动后跟随实例，PID复用和筛空后取消选择。
    $firstRow=$script:Grid.Rows[0];$firstRow.Selected=$true
    $fresh=[pscustomobject]@{PID=9001;Name='gui-cold-start-fixture';StartUtcTicks=100;PrivateBytes=256MB;WorkingBytes=$null;Status='Success'}
    Update-MiGrid ([pscustomobject]@{Status='Success';Items=@($fresh);Total=1})
    if(-not [object]::ReferenceEquals($firstRow,$script:Grid.Rows[0]) -or
        -not [object]::ReferenceEquals($script:Grid.Rows[0].Tag,$fresh) -or
        $script:Grid.Rows[0].Cells['Private'].Value -ne (Format-MiGiB 256MB) -or
        $script:Grid.Rows[0].Cells['Working'].Value -ne '不可用'){throw 'Reused row kept stale identity/counters or recreated the row.'}
    $larger=[pscustomobject]@{PID=9002;Name='larger';StartUtcTicks=200;PrivateBytes=512MB;WorkingBytes=128MB;Status='Success'}
    Update-MiGrid ([pscustomobject]@{Status='Success';Items=@($fresh,$larger);Total=2})
    if($script:Grid.Rows[0].Tag.PID -ne 9002 -or (Get-MiSelectedProcess).PID -ne 9001){throw 'Sorting reused rows lost exact-instance selection.'}
    $replacement=[pscustomobject]@{PID=9001;Name='replacement';StartUtcTicks=101;PrivateBytes=256MB;WorkingBytes=64MB;Status='Success'}
    Update-MiGrid ([pscustomobject]@{Status='Success';Items=@($replacement);Total=1})
    if($null -ne (Get-MiSelectedProcess) -or $script:MiGracefulButton.Enabled -or $script:MiForceButton.Enabled){throw 'Row reuse transferred selection/permission to a reused PID.'}
    $script:SearchInput.Text='no-matching-fixture'
    if($script:Grid.Rows.Count -ne 0 -or $null -ne (Get-MiSelectedProcess)){throw 'Filtering did not remove stale reused rows.'}
    $script:SearchInput.Text=''
    if($script:Grid.Rows.Count -ne 1 -or $script:Grid.Rows[0].Tag.Name -ne 'replacement'){throw 'Clearing filter failed to rebuild current rows.'}
    # 此窗口属于测试自身；创建真实布局句柄，透明且不占任务栏，不触碰用户的运行窗口。
    . (Join-Path $runtimeRepo 'Analyzer.ps1')
    $v3Analyzer=New-MiAnalyzer -BootId GuiV3 -Root ''
    $snapshot.Processes.Items=@($fresh,$larger)
    $script:CurrentDiagnosis=Invoke-MiDiagnosis $v3Analyzer $snapshot
    $script:Tabs.SelectedIndex=5
    Update-MiAttributionView
    if ($script:AttributionGrid.Rows.Count -ne 7 -or $script:AttributionNote.Text -notmatch 'RAM') {throw 'Attribution page missing independent system/RAM views.'}
    $script:AttributionGrid.Rows[0].Selected=$true
    Show-MiAttributionDetails
    if ($script:AttributionDetails.Text -notmatch '实际观察 UTC' -or $script:AttributionDetails.Text -notmatch '局限：') {throw 'Finding evidence details missing.'}
    $script:AttributionMode.SelectedIndex=1
    $script:AttributionGrid.Rows[0].Selected=$true;$script:AttributionGrid.Rows[1].Selected=$true
    Show-MiAttributionDetails
    if ($script:AttributionDetails.Text -notmatch '用户逻辑组：2' -or $script:AttributionDetails.Text -notmatch '0.750 GiB') {throw 'User-selected group sum incorrect.'}
    $snapshot.CaptureEndUtc=$now.AddSeconds(5);$snapshot.Processes.Items=@($replacement)
    $script:CurrentDiagnosis=Invoke-MiDiagnosis $v3Analyzer $snapshot
    Update-MiAttributionView
    if ($script:AttributionGrid.SelectedRows.Count -ne 0) {throw 'Attribution logical selection survived PID reuse.'}
    $script:CurrentDiagnosis=$null;Update-MiAttributionView
    if ($script:AttributionGrid.Rows.Count -ne 0 -or $script:AttributionNote.Text -notmatch '不可用') {throw 'Unavailable attribution retained old findings.'}
    $script:CurrentDiagnosis=[pscustomobject]@{Attribution=(Get-MiSystemAttribution $v3Analyzer $snapshot $snapshot.CaptureEndUtc)}
    $script:AttributionMode.SelectedIndex=0;Update-MiAttributionView
    $script:Form.ShowInTaskbar=$false;$script:Form.Opacity=0;$script:Form.Show()
    # 主机字体缩放会放大 MinimumSize；本夹具固定物理像素，确保真的覆盖1020窄窗。
    $script:Form.AutoScaleMode='None';$script:Form.MinimumSize=[Drawing.Size]::new(1020,690)
    # 对真实父子控件做布局，检查标题与内容的矩形不重叠，而不是只断言 Dock 属性。
    foreach($size in @([Drawing.Size]::new(1300,850),[Drawing.Size]::new(1020,690))) {
        $script:Form.Size=$size
        if($script:Form.Width -ne $size.Width -or $script:Form.Height -ne $size.Height){throw 'Layout fixture did not reach its requested physical size.'}
        [void]$script:Form.Handle
        foreach($tabIndex in @(0,1,2,3,4,5,6)) {
            $script:Tabs.SelectedIndex=$tabIndex
            $script:Form.PerformLayout();$script:Tabs.TabPages[$tabIndex].PerformLayout()
            [Windows.Forms.Application]::DoEvents()
            foreach($content in @($script:Grid,$script:LineChart,$script:BarChart,$script:Details.Parent)) {
                $parent=$content.Parent
                foreach($header in @($parent.Controls|Where-Object {$_ -is [Windows.Forms.Label] -and $_.Dock -eq 'Top'})) {
                    if ($content.Bounds.IntersectsWith($header.Bounds)) {throw ('Header overlaps content at '+$size+' / '+$header.Text)}
                }
            }
            if ($tabIndex -eq 0 -and ($script:Grid.ColumnHeadersHeight -lt $script:Grid.Font.Height+6 -or
                $script:Grid.GetCellDisplayRectangle(0,-1,$false).Height -le 0)) {throw 'Visible process column headers are clipped or missing.'}
            if ($tabIndex -eq 5) {
                if ($script:AttributionGrid.Height -lt 100 -or $script:AttributionDetails.Height -lt 80 -or
                    $script:AttributionGrid.Bounds.IntersectsWith($script:AttributionNote.Bounds)) {throw 'Attribution layout clipped/overlapped.'}
                $script:AttributionGrid.Rows[0].Selected=$true;Show-MiAttributionDetails
                $image=[Drawing.Bitmap]::new($script:Form.Width,$script:Form.Height)
                try {
                    $script:Form.DrawToBitmap($image,[Drawing.Rectangle]::new(0,0,$image.Width,$image.Height))
                    $renderRoot=Join-Path $runtimeRepo 'test-artifacts\v3-m1'
                    [void][IO.Directory]::CreateDirectory($renderRoot)
                    $image.Save((Join-Path $renderRoot ('attribution-'+$size.Width+'.png')))
                } finally {$image.Dispose()}
            }
            if ($tabIndex -eq 6) {
                Update-MiDiagnosticsView
                foreach ($name in @('Start','Stop','Prepare','Analyze','Recovery')) {if ($script:DiagnosticButtons[$name].Enabled) {throw ('Unaccepted GUI operation enabled: '+$name)}}
                if ($script:DiagnosticOnline.Enabled -or $script:DiagnosticDetails.Height -lt 60 -or $script:DiagnosticSessions.Height -lt 60) {throw 'Diagnostic gate/layout failed'}
                $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $report=[pscustomobject]@{ResultTrust='ProtectedStatusOnlyNotActionAuthority';OwnerSid=$sid;Utc=[datetime]::UtcNow.ToString('o');
                    Sessions=@([pscustomobject]@{TraceSessionId=('1'*32);RequestedTraceType='Heap';State='CleanupPending';StopState='Confirmed';SaveState='Saved';CleanupState='CleanupPending';AnalysisState='Unavailable'});
                    Artifacts=@([pscustomobject]@{ArtifactId=('2'*32);State='Ready';SizeBytes=100;EventLossStatus='LossReported';RetainUntilUtc='2026-11-01T00:00:00Z'})}
                Show-MiDiagnosticReport $report
                if ($script:DiagnosticSessions.Rows[0].Cells['Save'].Value -cne 'Saved' -or $script:DiagnosticSessions.Rows[0].Cells['Cleanup'].Value -cne 'CleanupPending' -or $script:DiagnosticSessions.SelectedRows.Count -gt 0) {throw 'Diagnostic outcomes merged or stale selection retained'}
                $image=[Drawing.Bitmap]::new($script:Form.Width,$script:Form.Height)
                try {$script:Form.DrawToBitmap($image,[Drawing.Rectangle]::new(0,0,$image.Width,$image.Height));[void][IO.Directory]::CreateDirectory((Join-Path $runtimeRepo 'test-artifacts\v3-m67'));$image.Save((Join-Path $runtimeRepo ('test-artifacts\v3-m67\diagnostics-'+$size.Width+'.png')))} finally {$image.Dispose()}
            }
        }
    }
    & {
        function Get-MiDiagnosticUiCapabilities {return [pscustomobject]@{CanRead=$true;CanTrace=$true;CanRecovery=$true;CanHeap=$true;CanFile=$true;CanExport=$true;CanOnline=$true}}
        function Show-MiActionTypedDialog {return $true}
        function Start-MiTraceRequest {param($Operation,$TraceType,$RecordingMode,$DurationSeconds,$HeapImagePath)
            $script:CapturedHeapPath=$HeapImagePath;return 'UacCancelled'
        }
        $script:DiagnosticImage.Text='C:\fixture.exe';$script:DiagnosticType.SelectedIndex=2
        Request-MiGuiDiagnosticAction 'TraceStart'
        if ($script:CapturedHeapPath -cne 'C:\fixture.exe') {throw 'Heap target path not bound to Heap request'}
        $script:DiagnosticType.SelectedIndex=0;Request-MiGuiDiagnosticAction 'TraceStart'
        if ($script:CapturedHeapPath) {throw 'Switching trace type leaked a stale Heap path'}
    }
} finally {
    Close-MiV4Gui
    if ($script:Form) {$script:Form.Dispose()}
}
Write-Host 'PASS: full fresh GUI initialization, first real mailbox/grid/KPI/chart refresh and safe disabled actions.' -ForegroundColor Green

# M7 固定桥：真实文件读写，UAC/ACL 是替身；取消、独立验收门和未知报告不得触发重试。
& {
    . (Join-Path $runtimeRepo 'PrivilegeSecurity.ps1');. (Join-Path $runtimeRepo 'PrivilegeBridge.ps1')
    $context=@{Launches=0;Cancelled=$false;Alive=$false;GuiEnabled=$false;TraceAccepted=$false;ExportAccepted=$false;RecoveryAccepted=$false}
    $folder=Join-Path $runtimeRepo ('test-artifacts\M7-Bridge-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($folder)
    function Get-MiSecurityPaths {return [pscustomobject]@{Install=$folder;Executor=(Join-Path $folder 'ElevatedExecutor.ps1');TraceArtifacts=$folder}}
    function Test-MiPrivilegeBridgeInstalled {return $true}
    function Test-MiElevated {return $false}
    function Assert-MiWprReleaseAccepted {}
    function Assert-MiExportReleaseAccepted {}
    function Get-MiGuiDiagnosticReleaseStatus {return [pscustomobject]@{Enabled=$context.GuiEnabled;TraceUiAccepted=$context.TraceAccepted;ExportUiAccepted=$context.ExportAccepted;RecoveryUiAccepted=$context.RecoveryAccepted;Reason='FixtureGate'}}
    function Assert-MiTracePath {param($Path) if (-not [IO.File]::Exists($Path) -or -not $Path.StartsWith($folder,[StringComparison]::OrdinalIgnoreCase)) {throw 'Fixture trust refused'}}
    function Start-Process {param($FilePath,$ArgumentList,$Verb,$WindowStyle,[switch]$PassThru,$ErrorAction)
        $context.Launches++;$context.Arguments=$ArgumentList
        if ($context.Cancelled) {throw [ComponentModel.Win32Exception]::new(1223)}
        $process=[pscustomobject]@{HasExited=(-not $context.Alive);ExitCode=0}
        $process|Add-Member ScriptMethod Refresh {};$process|Add-Member ScriptMethod Dispose {}
        return $process
    }
    # 后台运行原桥读取函数，仅替换夹具 ACL；300 ms 慢磁盘读不得阻塞首次 GUI 轮询。
    [IO.File]::WriteAllBytes((Join-Path $folder 'PrivilegeSecurity.ps1'),[IO.File]::ReadAllBytes((Join-Path $runtimeRepo 'PrivilegeSecurity.ps1')))
    $bridgeFixture=[IO.File]::ReadAllText((Join-Path $runtimeRepo 'PrivilegeBridge.ps1'))
    $bridgeFixture+=[Environment]::NewLine+'function Assert-MiTracePath {param($Path);Start-Sleep -Milliseconds 300;if (-not [IO.File]::Exists($Path)) {throw "Fixture report missing"}}'
    $script:MiTraceReportModulePath=Join-Path $folder 'PrivilegeBridge.fixture.ps1'
    [IO.File]::WriteAllText($script:MiTraceReportModulePath,$bridgeFixture,[Text.UTF8Encoding]::new($true))
    foreach ($operation in @('TraceStart','TraceStop','TraceExportPrepare','TraceRecovery')) {
        $denied=$false;try {Start-MiTraceRequest -Operation $operation -TraceSessionId ('1'*32) -ArtifactId ('2'*32)|Out-Null} catch {$denied=$true}
        if (-not $denied -or $context.Launches -ne 0) {throw 'Disabled bridge launched UAC'}
    }
    $context.GuiEnabled=$true;$context.TraceAccepted=$true
    foreach ($operation in @('TraceExportPrepare','TraceRecovery')) {
        $denied=$false;try {Start-MiTraceRequest -Operation $operation -ArtifactId ('2'*32)|Out-Null} catch {$denied=$true}
        if (-not $denied -or $context.Launches -ne 0) {throw 'Per-operation UI gate bypassed'}
    }
    foreach ($corrupt in @($false,$true)) {
        [void](Start-MiTraceRequest 'TraceStatus');$request=$script:MiTraceRequest
        if ($context.Arguments -notmatch '-RequesterSid S-1-5-21-' -or $context.Arguments -notmatch '-RequesterSession \d+') {throw 'Requester identity missing'}
        $directory=Join-Path (Join-Path $folder $request.OwnerSid) 'requests';[void][IO.Directory]::CreateDirectory($directory)
        [pscustomobject]@{SchemaVersion=1;RequestId=if ($corrupt) {('0'*32)} else {$request.Id};OwnerSid=$request.OwnerSid;Operation='TraceStatus';ResultTrust='ProtectedStatusOnlyNotActionAuthority'}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $directory ($request.Id+'.json')) -Encoding UTF8
        $pollClock=[Diagnostics.Stopwatch]::StartNew();$reply=Poll-MiTraceRequest
        if ($null -ne $reply -or $pollClock.Elapsed.TotalMilliseconds -gt 200) {throw 'Report I/O blocked the GUI poll'}
        $pollClock.Restart()
        while ($null -eq $reply -and $pollClock.Elapsed.TotalSeconds -lt 10) {Start-Sleep -Milliseconds 20;$reply=Poll-MiTraceRequest}
        if ($reply.State -cne $(if ($corrupt) {'UnknownOutcome'} else {'Reported'}) -or $null -ne $script:MiTraceRequest) {throw 'Report/request binding or completed handle release failed'}
    }
    # 确定性制造“检查未完成后马上完成”的窗口；完成不等于本次 Poll 已交付结果。
    [void](Start-MiTraceRequest 'TraceStatus');$context.ReadChecks=0;$context.EndInvokes=0
    $handle=[pscustomobject]@{};$handle|Add-Member ScriptProperty IsCompleted {$context.ReadChecks++;return $context.ReadChecks -gt 1}
    $reader=[pscustomobject]@{HadErrors=$false}
    $reader|Add-Member ScriptMethod EndInvoke {param($Handle);$context.EndInvokes++;return [pscustomobject]@{ResultTrust='ProtectedStatusOnlyNotActionAuthority'}}
    $reader|Add-Member ScriptMethod Dispose {}
    $script:MiTraceRequest|Add-Member NoteProperty Reader ([pscustomobject]@{PowerShell=$reader;Handle=$handle})
    if ($null -ne (Poll-MiTraceRequest) -or $null -eq $script:MiTraceRequest -or $context.EndInvokes -ne 0) {throw 'Fast reader completion lost the undelivered report'}
    $reply=Poll-MiTraceRequest
    if ($reply.State -cne 'Reported' -or $context.EndInvokes -ne 1 -or $null -ne $script:MiTraceRequest) {throw 'Fast reader terminal result not delivered once'}
    $context.Cancelled=$true
    if ((Start-MiTraceRequest 'TraceStatus') -cne 'UacCancelled' -or $null -ne $script:MiTraceRequest) {throw 'UAC cancellation reused pending request'}
    $context.Cancelled=$false;$context.Alive=$true;[void](Start-MiTraceRequest 'TraceStatus')
    if ($null -ne (Poll-MiTraceRequest) -or $null -eq $script:MiTraceRequest) {throw 'Active unknown child released/retried'}
    Close-MiPrivilegeBridge
    Write-Host 'PASS: V3-M7 fixed UAC bridge, independent UI gates, SID/session/report binding, slow/fast-completion report delivery, cancellation and active unknown request retention (UAC/ACL mocked).'
}
