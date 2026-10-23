#requires -Version 5.1
<#
MemoryInspector v2 / Milestones 1 + 2 + 3 + 4 + 5 (v0.0.5)
Windows PowerShell 5.1 + built-in WinForms and Charting.
Read-only diagnostics plus explicitly confirmed, safety-checked USER GUI process actions. No service changes, elevation, cache purge or registry writes.
Architecture: asynchronous collector runspace -> bounded ConcurrentQueue -> UI timer.
Milestone 3 read-only anomaly analysis is enabled; privileged operations are NOT implemented.
#>
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw '需要 Windows PowerShell 5.1（powershell.exe），不是 PowerShell 7（pwsh.exe）。'
}
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    throw '需要 STA。请使用随附的 Run_MemoryInspector.cmd 启动。'
}
if (-not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
    throw '本工具仅支持 Windows。'
}

$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:CollectorPath = Join-Path $script:Root 'Collector.ps1'
$script:WorkerPath = Join-Path $script:Root 'Worker.ps1'
$script:PersistencePath = Join-Path $script:Root 'Persistence.ps1'
$script:AnalyzerPath = Join-Path $script:Root 'Analyzer.ps1'
$script:GuiPath = Join-Path $script:Root 'GuiV4.ps1'
$script:ActionPath = Join-Path $script:Root 'ProcessActions.ps1'
foreach ($path in @($script:CollectorPath,$script:WorkerPath,$script:PersistencePath,$script:AnalyzerPath,$script:GuiPath,$script:ActionPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('缺少项目文件：' + $path) }
}

. $script:PersistencePath
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms.DataVisualization
[System.Windows.Forms.Application]::EnableVisualStyles()
. $script:GuiPath
. $script:ActionPath
Initialize-MiActions

$script:PeriodMs = 10000
$script:QueueLimit = 3
$script:HistoryLimit = 180
$script:History = New-Object 'System.Collections.Generic.List[object]'
$script:PreviousInstances = @{}
$script:CurrentProcesses = @()
$script:LatestSnapshot = $null
$script:CurrentDiagnosis = $null
$script:LastSequence = 0
$script:LastReceiveUtc = $null
$script:UiUpdating = $false
$script:RestartPending = $false
$script:Closing = $false
$script:WorkerPs = $null
$script:WorkerRunspace = $null
$script:WorkerAsync = $null
$script:Cancellation = $null
$script:Mailbox = $null

$script:Background = [System.Drawing.ColorTranslator]::FromHtml('#F3F6FB')
$script:Ink = [System.Drawing.ColorTranslator]::FromHtml('#17283E')
$script:Muted = [System.Drawing.ColorTranslator]::FromHtml('#63748A')
$script:Blue = [System.Drawing.ColorTranslator]::FromHtml('#3269DA')
$script:Teal = [System.Drawing.ColorTranslator]::FromHtml('#159A92')
$script:Amber = [System.Drawing.ColorTranslator]::FromHtml('#A86615')
$script:Outline = [System.Drawing.ColorTranslator]::FromHtml('#DDE5EE')
$script:Font = [System.Drawing.Font]::new('Microsoft YaHei UI',[single]9)

function New-MiLabel {
    param([string]$Text,[int]$Size=9,[bool]$Bold=$false)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.ForeColor = $script:Ink
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold) { $style = [System.Drawing.FontStyle]::Bold }
    $label.Font = [System.Drawing.Font]::new('Microsoft YaHei UI',[single]$Size,$style)
    $label.AutoSize = $false
    return $label
}
function New-MiPanel {
    $panel = New-Object System.Windows.Forms.Panel
    $panel.BackColor = [System.Drawing.Color]::White
    $panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $panel.Margin = [System.Windows.Forms.Padding]::new(5)
    return $panel
}
function New-MiButton {
    param([string]$Text,[int]$Width)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Size = [System.Drawing.Size]::new($Width,33)
    $button.FlatStyle = 'Flat'
    $button.BackColor = [System.Drawing.Color]::White
    $button.ForeColor = $script:Ink
    $button.FlatAppearance.BorderColor = $script:Outline
    $button.Font = $script:Font
    return $button
}
function Format-MiGiB {
    param($Bytes)
    if ($null -eq $Bytes) { return '—' }
    return ('{0:N2}' -f ([double]$Bytes / 1GB))
}
function Set-MiStatus {
    param([string]$Text,[bool]$Warning=$false)
    if ($script:Closing) { return }
    $script:StatusLabel.Text = $Text
    $script:StatusLabel.ForeColor = if ($Warning) { $script:Amber } else { $script:Muted }
}
function Stop-MiWorker {
    if ($null -ne $script:Cancellation) {
        try { $script:Cancellation.Cancel() } catch {}
    }
}
function Dispose-MiCompletedWorker {
    if ($null -eq $script:WorkerAsync -or -not $script:WorkerAsync.IsCompleted) { return $false }
    try {
        [void]$script:WorkerPs.EndInvoke($script:WorkerAsync)
    } catch { }
    try { $script:WorkerPs.Dispose() } catch {}
    try { $script:WorkerRunspace.Close(); $script:WorkerRunspace.Dispose() } catch {}
    try { $script:Cancellation.Dispose() } catch {}
    $script:WorkerPs = $null
    $script:WorkerRunspace = $null
    $script:WorkerAsync = $null
    $script:Cancellation = $null
    $script:Mailbox = $null
    return $true
}
function Start-MiWorker {
    if ($null -ne $script:WorkerAsync) { throw '上一个采样器尚未退出。' }
    $runspace = $null; $powershell = $null; $cancellation = $null
    try {
        $queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        $cancellation = New-Object System.Threading.CancellationTokenSource
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $runspace.ApartmentState = [System.Threading.ApartmentState]::MTA
        $runspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
        $runspace.Open()
        $powershell = [System.Management.Automation.PowerShell]::Create()
        $powershell.Runspace = $runspace
        $workerCode = [System.IO.File]::ReadAllText($script:WorkerPath,[System.Text.Encoding]::UTF8)
        [void]$powershell.AddScript($workerCode)
        [void]$powershell.AddArgument($script:CollectorPath)
        [void]$powershell.AddArgument($script:PersistencePath)
        [void]$powershell.AddArgument($script:AnalyzerPath)
        [void]$powershell.AddArgument($queue)
        [void]$powershell.AddArgument($cancellation)
        [void]$powershell.AddArgument($script:PeriodMs)
        [void]$powershell.AddArgument($script:QueueLimit)
        [void]$powershell.AddArgument($script:UiSettingsPath)
        $handle = $powershell.BeginInvoke()

        $script:Mailbox = $queue
        $script:Cancellation = $cancellation
        $script:WorkerRunspace = $runspace
        $script:WorkerPs = $powershell
        $script:WorkerAsync = $handle
        $script:LastReceiveUtc = [datetime]::UtcNow
        $script:LastSequence = 0
        $script:PreviousInstances = @{}
        Set-MiStatus '后台采样器已启动；首次数据采集中…'
    } catch {
        if ($null -ne $cancellation) { $cancellation.Dispose() }
        if ($null -ne $powershell) { $powershell.Dispose() }
        if ($null -ne $runspace) { try { $runspace.Dispose() } catch {} }
        throw
    }
}
function Restore-MiGuiHistory {
    try {
        $root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector'
        $readState = [pscustomobject]@{Root=$root}
        $restored = @(Get-MiRecentSystemHistory -State $readState -Limit $script:HistoryLimit)
        $script:History.Clear()
        foreach ($row in $restored) { $script:History.Add($row) }
        if ($restored.Count -gt 0) { Update-MiCharts }
    } catch { Set-MiStatus ('历史读取失败；实时监控仍可使用：' + $_.Exception.Message) $true }
}
function Add-MiHistory {
    param($Snapshot)
    $script:History.Add($Snapshot)
    if ($script:History.Count -gt $script:HistoryLimit) { $script:History.RemoveAt(0) }
}
function Get-MiSelectedProcess {
    if ($script:Grid.SelectedRows.Count -eq 0) { return $null }
    return $script:Grid.SelectedRows[0].Tag
}
function Get-MiDiagnosisReport {
    param($Item)
    if ($null -eq $Item -or $null -eq $script:CurrentDiagnosis) { return $null }
    foreach ($r in @($script:CurrentDiagnosis.Reports)) {
        if ($r.PID -eq $Item.PID -and $null -ne $Item.StartUtcTicks -and
            $r.StartUtcTicks -eq $Item.StartUtcTicks) { return $r }
    }
    return $null
}
function Format-MiDiagnosisState {
    param($Report)
    if ($null -eq $Report) { return '未分析' }
    switch ([string]$Report.AnomalyState) {
        'SuspectedSustainedGrowth' { return '疑似持续增长' }
        'NoSignificantGrowth' { return '暂无明显增长' }
        'InsufficientEvidence' { return '证据不足' }
        default { return '诊断不可用' }
    }
}
function Update-MiSelectedProcess {
    if ($script:UiUpdating) { return }
    $item = Get-MiSelectedProcess
    if ($null -eq $item) {
        $script:Details.Text = '选择一条进程记录查看其内存信息。' + [Environment]::NewLine +
            '普通进程提供受限手动管理；Windows 服务仍为只读。'
        Update-MiV4ProcessChart
        Update-MiActionButtons
        return
    }
    $startString = '不可读取'
    if ($null -ne $item.StartUtcTicks) {
        try { $startString = ([datetime]::new([long]$item.StartUtcTicks,[System.DateTimeKind]::Utc)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch {}
    }
    $growth = '—（首次采样或身份无法验证）'
    if ($null -ne $item.DeltaBytes) { $growth = ('{0:+0.0;-0.0;0.0} MiB' -f ([double]$item.DeltaBytes / 1MB)) }
    $diagnosis = Get-MiDiagnosisReport -Item $item
    $diagText = Format-MiDiagnosisState -Report $diagnosis
    $diagExplain = '暂无可信诊断数据；继续观察。'
    $historyExplain = '暂无有效跨日程序基线。'
    if ($null -ne $diagnosis) {
        $diagExplain = [string]$diagnosis.Explanation
        if ($null -ne $diagnosis.HistoricalProgramMedianBytes) {
            $historyExplain = ('历史同名程序合计 Private Bytes 中位数：{0} GiB（当前同名进程合计偏离 {1:+0.0;-0.0;0.0}%）。' -f
                (Format-MiGiB $diagnosis.HistoricalProgramMedianBytes),$diagnosis.HistoricalDeviationPercent)
        }
    }
    $script:Details.Text = @(
        ('进程：{0}' -f $item.Name),
        ('PID：{0}' -f $item.PID),
        ('状态：{0}' -f $item.Status),
        ('启动时间：{0}' -f $startString),
        '',
        ('Private Bytes：{0} GiB' -f (Format-MiGiB $item.PrivateBytes)),
        ('Working Set：{0} GiB' -f (Format-MiGiB $item.WorkingBytes)),
        ('本轮增长：{0}' -f $growth),
        '',
        ('30 分钟诊断：{0}' -f $diagText),
        ('操作风险：{0}' -f (Get-MiV4Risk -Item $item)),
        $diagExplain,
        ('跨日程序基线：{0}' -f $historyExplain),
        '历史比较按同名程序合计，不代表本进程实例泄漏。',
        '',
        'Private Bytes 是进程的私有提交量，不等于目前实际驻留 RAM。',
        '高占用不等于无用，也不能凭一次增长认定 Memory Leak。',
        '',
        'Milestone 5：普通进程可手动申请关闭；Windows 服务仍然只读。'
    ) -join [Environment]::NewLine
    Update-MiV4ProcessChart
    Update-MiActionButtons
}
function Update-MiKpi {
    param($Snapshot)
    $sys = $Snapshot.System
    if ($sys.Status -eq 'Failed') {
        foreach ($label in $script:KpiValues) { $label.Text = '不可用' }
        foreach ($note in $script:KpiNotes) { $note.Text = '本轮系统采样失败' }
        return
    }
    $script:KpiValues[0].Text = ('{0} / {1} GiB' -f (Format-MiGiB $sys.CommittedBytes),(Format-MiGiB $sys.CommitLimitBytes))
    $script:KpiValues[1].Text = ('{0} / {1} GiB' -f (Format-MiGiB $sys.UsedPhysicalBytes),(Format-MiGiB $sys.TotalPhysicalBytes))
    $script:KpiValues[2].Text = (Format-MiGiB $sys.NonpagedPoolBytes) + ' GiB'
    $script:KpiNotes[0].Text = '系统 Committed / Commit Limit'
    $script:KpiNotes[1].Text = ('Available RAM：{0} GiB' -f (Format-MiGiB $sys.AvailablePhysicalBytes))
    $script:KpiNotes[2].Text = ('Paged pool：{0} GiB' -f (Format-MiGiB $sys.PagedPoolBytes))
    $first = $null
    foreach ($record in $script:History) {
        if ($record.System.Status -ne 'Failed' -and $null -ne $record.System.CommittedBytes) {
            $first = $record; break
        }
    }
    if ($null -eq $first) {
        $script:KpiValues[3].Text = '—'
        $script:KpiNotes[3].Text = '暂无有效基线'
    } else {
        $delta = [double]($sys.CommittedBytes - $first.System.CommittedBytes) / 1GB
        $script:KpiValues[3].Text = ('{0:+0.00;-0.00;0.00} GiB' -f $delta)
        $script:KpiNotes[3].Text = ('窗口起点 {0:HH:mm:ss}' -f $first.CaptureEndUtc.ToLocalTime())
    }
}
function Update-MiGrid {
    param($ProcessCollection)
    Update-MiV4Grid -ProcessCollection $ProcessCollection
}
function Update-MiCharts {
    $seriesCommit = $script:LineChart.Series['Committed']
    $seriesRam = $script:LineChart.Series['RAM']
    $seriesCommit.Points.Clear(); $seriesRam.Points.Clear()
    $prevSequence = 0
    foreach ($sample in $script:History) {
        $x = $sample.CaptureEndUtc.ToLocalTime().ToOADate()
        if ($prevSequence -gt 0 -and $sample.Sequence -gt ($prevSequence + 1)) {
            $gap = New-Object System.Windows.Forms.DataVisualization.Charting.DataPoint
            $gap.XValue = $x - (1.0 / 86400.0)
            $gap.IsEmpty = $true
            [void]$seriesCommit.Points.Add($gap)
            $gapRam = New-Object System.Windows.Forms.DataVisualization.Charting.DataPoint
            $gapRam.XValue = $gap.XValue; $gapRam.IsEmpty = $true
            [void]$seriesRam.Points.Add($gapRam)
        }
        if ($sample.System.Status -eq 'Failed') {
            $miss1 = New-Object System.Windows.Forms.DataVisualization.Charting.DataPoint
            $miss1.XValue = $x; $miss1.IsEmpty = $true
            [void]$seriesCommit.Points.Add($miss1)
            $miss2 = New-Object System.Windows.Forms.DataVisualization.Charting.DataPoint
            $miss2.XValue = $x; $miss2.IsEmpty = $true
            [void]$seriesRam.Points.Add($miss2)
        } else {
            [void]$seriesCommit.Points.AddXY($x,[double]$sample.System.CommittedBytes / 1GB)
            [void]$seriesRam.Points.AddXY($x,[double]$sample.System.UsedPhysicalBytes / 1GB)
        }
        $prevSequence = $sample.Sequence
    }
    $bars = $script:BarChart.Series[0]
    $bars.Points.Clear()
    foreach ($p in @($script:CurrentProcesses | Select-Object -First 8)) {
        if ($null -eq $p.PrivateBytes) { continue }
        $name = $p.Name
        if ($name.Length -gt 12) { $name = $name.Substring(0,11) + '…' }
        [void]$bars.Points.AddXY(('{0} #{1}' -f $name,$p.PID),[double]$p.PrivateBytes / 1GB)
    }
}
function Process-MiMailbox {
    if ($null -eq $script:Mailbox) { return }
    $latest = $null; $candidate = $null
    while ($script:Mailbox.TryDequeue([ref]$candidate)) { $latest = $candidate; $candidate = $null }
    if ($null -eq $latest) { return }
    if ($script:LastSequence -gt 0 -and $latest.Sequence -gt $script:LastSequence + 1) {
        Set-MiStatus ('UI 丢弃了 {0} 个旧采样；图表已标记时间缺口。' -f ($latest.Sequence-$script:LastSequence-1)) $true
    }
    $script:LatestSnapshot = $latest
    $script:CurrentDiagnosis = $latest.Diagnosis
    $script:LastSequence = $latest.Sequence
    $script:LastReceiveUtc = [datetime]::UtcNow
    Add-MiHistory -Snapshot $latest
    Add-MiV4ProcessHistory -Snapshot $latest
    Update-MiKpi -Snapshot $latest
    $actionObservation=Update-MiActionObservation -Snapshot $latest
    if ($null -ne $actionObservation) {
        $change='unavailable'
        if ($null -ne $actionObservation.NetCommitBytes) { $change=('{0:+0.00;-0.00;0.00} GiB' -f ([double]$actionObservation.NetCommitBytes/1GB)) }
        Set-MiStatus ('进程操作观察：'+$actionObservation.State+'；系统提交净变化 '+$change)
    }
    Update-MiGrid -ProcessCollection $latest.Processes
    Update-MiCharts
    $timeString = $latest.CaptureEndUtc.ToLocalTime().ToString('HH:mm:ss')
    $text = ('{0} | 第 {1} 次采样 | 耗时 {2} ms | 系统：{3} | 进程：{4} ({5} 条)' -f
        $timeString,$latest.Sequence,$latest.DurationMs,$latest.System.Status,$latest.Processes.Status,$latest.Processes.Total)
    if ($latest.Status -ne 'Success') {
        $text += (' | {0} {1}' -f $latest.System.Error,$latest.Processes.Error)
    }
    if ($null -ne $latest.Diagnosis -and $latest.Diagnosis.Status -eq 'Success') {
        $pressure = [string]$latest.Diagnosis.Pressure.State
        $suspected = @($latest.Diagnosis.Reports | Where-Object { $_.AnomalyState -eq 'SuspectedSustainedGrowth' }).Count
        $text += (' | 压力：{0} | 疑似增长：{1}' -f $pressure,$suspected)
    } elseif ($null -ne $latest.Diagnosis) {
        $text += (' | 诊断不可用：{0}' -f $latest.Diagnosis.Error)
    }
    if ($latest.PersistenceStatus -ne 'Saved') {
        $text += (' | 历史未保存：{0}' -f $latest.PersistenceError)
    }
    Set-MiStatus $text ($latest.Status -ne 'Success' -or $latest.PersistenceStatus -ne 'Saved' -or
        $null -eq $latest.Diagnosis -or $latest.Diagnosis.Status -ne 'Success')
}

# ---- WinForms layout, all created and updated on GUI thread ----
$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text = 'MemoryInspector v0.0.5 · 安全进程管理'
$script:Form.StartPosition = 'CenterScreen'
$script:Form.Size = [System.Drawing.Size]::new(1300,850)
$script:Form.MinimumSize = [System.Drawing.Size]::new(1020,690)
$script:Form.BackColor = $script:Background
$script:Form.Font = $script:Font

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = 'Fill'; $root.ColumnCount = 1; $root.RowCount = 5
$root.Padding = [System.Windows.Forms.Padding]::new(12,9,12,9)
[void]$root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,[single]53)))
[void]$root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,[single]109)))
[void]$root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,[single]285)))
[void]$root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Percent,[single]100)))
[void]$root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,[single]31)))
$script:Form.Controls.Add($root)

$toolbar = New-Object System.Windows.Forms.Panel
$toolbar.Dock='Fill'; $root.Controls.Add($toolbar,0,0)
$title = New-MiLabel 'MemoryInspector  /  内存观察仪' 14 $true
$title.Location = [System.Drawing.Point]::new(6,8)
$title.Size = [System.Drawing.Size]::new(520,36)
$toolbar.Controls.Add($title)
$btnRestart = New-MiButton '重启采样器' 114
$btnRestart.Anchor = 'Top,Right'; $btnRestart.Location = [System.Drawing.Point]::new(0,0)
$toolbar.Controls.Add($btnRestart)
$readOnly = New-MiLabel 'MANUAL ACTIONS · 不操作服务' 9 $true
$readOnly.ForeColor = $script:Teal
$readOnly.Size = [System.Drawing.Size]::new(200,33)
$readOnly.TextAlign = 'MiddleRight'
$readOnly.Dock = 'Right'
$toolbar.Controls.Add($readOnly)
$btnRestart.Dock = 'Right'
$btnRestart.Margin = [System.Windows.Forms.Padding]::new(6)
$btnRestart.BringToFront()

$cards = New-Object System.Windows.Forms.TableLayoutPanel
$cards.Dock='Fill'; $cards.RowCount=1; $cards.ColumnCount=4
for($i=0;$i -lt 4;$i++) { [void]$cards.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,[single]25))) }
$root.Controls.Add($cards,0,1)
$script:KpiValues=@();$script:KpiNotes=@()
$captions=@('系统提交 / Commit','物理内存 / RAM','非分页池 / Nonpaged','窗口提交变化 / Delta')
for($i=0;$i -lt 4;$i++) {
    $card=New-MiPanel; $card.Dock='Fill'; $cards.Controls.Add($card,$i,0)
    $caption=New-MiLabel $captions[$i] 9
    $caption.ForeColor=$script:Muted; $caption.SetBounds(12,7,300,24); $card.Controls.Add($caption)
    $value=New-MiLabel '采集中…' 15 $true
    $value.SetBounds(12,34,330,35); $card.Controls.Add($value); $script:KpiValues+= $value
    $note=New-MiLabel '等待首次有效样本' 8
    $note.ForeColor=$script:Muted; $note.SetBounds(12,77,330,19); $card.Controls.Add($note); $script:KpiNotes+= $note
}

$chartLayout = New-Object System.Windows.Forms.TableLayoutPanel
$chartLayout.Dock='Fill'; $chartLayout.RowCount=1; $chartLayout.ColumnCount=2
[void]$chartLayout.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,[single]57)))
[void]$chartLayout.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,[single]43)))
$root.Controls.Add($chartLayout,0,2)
$linePanel = New-MiPanel; $linePanel.Dock='Fill'; $chartLayout.Controls.Add($linePanel,0,0)
$lineHeader=New-MiLabel '系统内存趋势 · 最近 30 分钟（GiB）' 10 $true
$lineHeader.Dock='Top';$lineHeader.Height=30;$lineHeader.Padding=[System.Windows.Forms.Padding]::new(10,6,0,0)
$linePanel.Controls.Add($lineHeader)
$script:LineChart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
$script:LineChart.Dock='Fill';$script:LineChart.BackColor=[System.Drawing.Color]::White
$area = [System.Windows.Forms.DataVisualization.Charting.ChartArea]::new('Memory')
$area.AxisX.LabelStyle.Format='HH:mm';$area.AxisX.MajorGrid.Enabled=$false
$area.AxisX.IsMarginVisible=$false;$area.AxisY.MajorGrid.LineColor=$script:Outline
[void]$script:LineChart.ChartAreas.Add($area)
$legend=[System.Windows.Forms.DataVisualization.Charting.Legend]::new('Legend')
$legend.Docking='Top';$legend.Alignment='Far';[void]$script:LineChart.Legends.Add($legend)
foreach($def in @(@('Committed',$script:Blue),@('RAM',$script:Teal))) {
    $s=[System.Windows.Forms.DataVisualization.Charting.Series]::new([string]$def[0])
    $s.ChartType='Line';$s.XValueType='DateTime';$s.BorderWidth=3
    $s.Color=[System.Drawing.Color]$def[1]
    $s.ChartArea='Memory'
    [void]$script:LineChart.Series.Add($s)
}
$linePanel.Controls.Add($script:LineChart)
$script:LineChart.BringToFront();$lineHeader.BringToFront()

$barPanel=New-MiPanel;$barPanel.Dock='Fill';$chartLayout.Controls.Add($barPanel,1,0)
$barHeader=New-MiLabel '进程 Top 8 · Private Bytes（GiB）' 10 $true
$barHeader.Dock='Top';$barHeader.Height=30;$barHeader.Padding=[System.Windows.Forms.Padding]::new(10,6,0,0)
$barPanel.Controls.Add($barHeader)
$script:BarChart=New-Object System.Windows.Forms.DataVisualization.Charting.Chart
$script:BarChart.Dock='Fill';$script:BarChart.BackColor=[System.Drawing.Color]::White
$barArea=[System.Windows.Forms.DataVisualization.Charting.ChartArea]::new('Top')
$barArea.AxisX.Interval=1;$barArea.AxisX.IsReversed=$true
$barArea.AxisX.MajorGrid.Enabled=$false;$barArea.AxisY.MajorGrid.LineColor=$script:Outline
[void]$script:BarChart.ChartAreas.Add($barArea)
$barSeries=[System.Windows.Forms.DataVisualization.Charting.Series]::new('Private GiB')
$barSeries.ChartType='Bar';$barSeries.Color=$script:Blue;$barSeries.ChartArea='Top'
$barSeries.IsValueShownAsLabel=$true;$barSeries.LabelFormat='0.00'
[void]$script:BarChart.Series.Add($barSeries)
$barPanel.Controls.Add($script:BarChart)
$script:BarChart.BringToFront();$barHeader.BringToFront()

$bottom=New-Object System.Windows.Forms.TableLayoutPanel
$bottom.Dock='Fill';$bottom.RowCount=1;$bottom.ColumnCount=2
[void]$bottom.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,[single]71)))
[void]$bottom.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,[single]29)))
$root.Controls.Add($bottom,0,3)
$tablePanel=New-MiPanel;$tablePanel.Dock='Fill';$bottom.Controls.Add($tablePanel,0,0)
$tableHeader=New-MiLabel '进程明细 · Private Bytes 排序 / 30 分钟诊断（前 60 项）' 10 $true
$tableHeader.Dock='Top';$tableHeader.Height=33;$tableHeader.Padding=[System.Windows.Forms.Padding]::new(10,7,0,0)
$tablePanel.Controls.Add($tableHeader)
$script:Grid=New-Object System.Windows.Forms.DataGridView
$script:Grid.Dock='Fill';$script:Grid.ReadOnly=$true
$script:Grid.AllowUserToAddRows=$false;$script:Grid.AllowUserToDeleteRows=$false
$script:Grid.AllowUserToResizeRows=$false;$script:Grid.MultiSelect=$false
$script:Grid.RowHeadersVisible=$false;$script:Grid.SelectionMode='FullRowSelect'
$script:Grid.AutoSizeColumnsMode='Fill';$script:Grid.AutoGenerateColumns=$false
$script:Grid.BackgroundColor=[System.Drawing.Color]::White
$script:Grid.RowTemplate.Height=26
foreach($def in @(
    @('PID','PID',11),@('Name','进程',27),@('Private','Private GiB',17),
    @('Working','RAM GiB',16),@('Delta','增量 MiB',14),
    @('Anomaly','异常诊断',19),@('Status','采样',11)
)) {
    $column=New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column.Name=[string]$def[0];$column.HeaderText=[string]$def[1]
    $column.FillWeight=[single]$def[2];$column.SortMode='NotSortable'
    [void]$script:Grid.Columns.Add($column)
}
$tablePanel.Controls.Add($script:Grid);$script:Grid.BringToFront();$tableHeader.BringToFront()
$detailPanel=New-MiPanel;$detailPanel.Dock='Fill';$bottom.Controls.Add($detailPanel,1,0)
$detailHeader=New-MiLabel '进程详情 · 趋势诊断（只读）' 10 $true
$detailHeader.Dock='Top';$detailHeader.Height=33;$detailHeader.Padding=[System.Windows.Forms.Padding]::new(10,7,0,0)
$detailPanel.Controls.Add($detailHeader)
$script:Details=New-Object System.Windows.Forms.RichTextBox
$script:Details.Dock='Fill';$script:Details.ReadOnly=$true
$script:Details.BorderStyle='None';$script:Details.BackColor=[System.Drawing.Color]::White
$script:Details.Font=$script:Font;$script:Details.ForeColor=$script:Ink
$script:Details.Text='等待读取进程信息…'
$detailPanel.Controls.Add($script:Details);$script:Details.BringToFront();$detailHeader.BringToFront()

$statusBar=New-Object System.Windows.Forms.Panel
$statusBar.Dock='Fill';$root.Controls.Add($statusBar,0,4)
$script:StatusLabel=New-MiLabel '初始化中…' 8
$script:StatusLabel.Dock='Fill';$script:StatusLabel.ForeColor=$script:Muted
$script:StatusLabel.TextAlign='MiddleLeft';$statusBar.Controls.Add($script:StatusLabel)
Initialize-MiV4Gui -Root $root -Cards $cards -Charts $chartLayout -Bottom $bottom -StatusBar $statusBar

$script:UiTimer = New-Object System.Windows.Forms.Timer
$script:UiTimer.Interval=400
$script:UiTimer.Add_Tick({
    if ($script:Closing) { return }
    try {
        Process-MiMailbox
        Poll-MiV4Jobs
        $timed=Update-MiActionObservation -Snapshot $null
        if ($null -ne $timed) { Set-MiStatus '进程操作观察已超时；已保留已有样本，结果未确认。' $true; Update-MiActionButtons }
        if ($script:RestartPending) {
            if (Dispose-MiCompletedWorker) {
                Restore-MiGuiHistory
                $script:PreviousInstances=@{}
                $script:ProcessTrend=@{}
                $script:CurrentProcesses=@()
                $script:LatestSnapshot=$null
                $script:CurrentDiagnosis=$null
                $script:Grid.Rows.Clear()
                $script:Details.Text='等待新的进程快照…'
                foreach ($v in $script:KpiValues) { $v.Text='采集中…' }
                foreach ($n in $script:KpiNotes) { $n.Text='等待首次有效样本' }
                foreach ($series in @($script:LineChart.Series)) { $series.Points.Clear() }
                $script:BarChart.Series[0].Points.Clear()
                $script:RestartPending=$false
                Start-MiWorker
                $btnRestart.Enabled=$true
            }
        } elseif ($null -ne $script:WorkerAsync -and $script:WorkerAsync.IsCompleted) {
            $extra='';
            try { if ($script:WorkerPs.Streams.Error.Count -gt 0) { $extra=[string]$script:WorkerPs.Streams.Error[0] } }
            catch {}
            Set-MiStatus ('后台采样器意外退出。可点击“重启采样器”。' + $extra) $true
            [void](Dispose-MiCompletedWorker)
        } elseif ($null -ne $script:LastReceiveUtc -and
            ([datetime]::UtcNow-$script:LastReceiveUtc).TotalSeconds -gt 25) {
            Set-MiStatus '超过 25 秒未收到新样本：后台采样可能很慢或已卡住，当前画面可能过期。' $true
        }
    } catch {
        Set-MiStatus ('界面更新失败：' + $_.Exception.Message) $true
    }
})
$script:Grid.Add_SelectionChanged({Update-MiSelectedProcess})

function Show-MiActionTypedDialog {
    param([string]$Prompt,[string]$Expected)
    $dialog=[System.Windows.Forms.Form]::new()
    $dialog.Text='MemoryInspector · 操作确认';$dialog.StartPosition='CenterParent'
    $dialog.FormBorderStyle='FixedDialog';$dialog.MaximizeBox=$false;$dialog.MinimizeBox=$false
    $dialog.ClientSize=[Drawing.Size]::new(520,165)
    $label=New-MiLabel $Prompt 9; $label.SetBounds(15,14,490,46);$dialog.Controls.Add($label)
    $input=[Windows.Forms.TextBox]::new();$input.SetBounds(15,69,480,28);$dialog.Controls.Add($input)
    $ok=New-MiButton '确认' 110;$ok.SetBounds(270,115,110,33);$ok.Enabled=$false;$ok.DialogResult='OK';$dialog.Controls.Add($ok)
    $cancel=New-MiButton '取消' 110;$cancel.SetBounds(389,115,110,33);$cancel.DialogResult='Cancel';$dialog.Controls.Add($cancel)
    $dialog.CancelButton=$cancel
    $input.Add_TextChanged({$ok.Enabled=($input.Text -ceq $Expected)})
    try { return ($dialog.ShowDialog($script:Form) -eq [Windows.Forms.DialogResult]::OK) }
    finally { $dialog.Dispose() }
}
function Update-MiActionButtons {
    if (-not $script:MiGracefulButton -or -not $script:MiForceButton) { return }
    $item=Get-MiSelectedProcess
    $active=$false
    if ($null -ne $item -and $null -ne $script:LatestSnapshot -and -not $script:MiActions.Busy -and
        $null -eq $script:MiActions.Pending -and $script:MiActions.CanAudit -and -not (Test-MiElevated)) {
        $active=((Test-MiActionSnapshot -Item $item -Snapshot $script:LatestSnapshot) -eq 'Pass')
        if ($script:ServicePids.ContainsKey([int]$item.PID)) { $active=$false }
    }
    $script:MiGracefulButton.Enabled=$active
    $script:MiForceButton.Enabled=$active -and $script:MiDangerCheck.Checked
}
function Request-MiGuiProcessAction {
    param([ValidateSet('Graceful','Force')][string]$Mode)
    if ($script:MiActions.Busy -or $null -ne $script:MiActions.Pending) { return }
    $item=Get-MiSelectedProcess
    if ($null -eq $item -or $null -eq $script:LatestSnapshot) { return }
    if ((Test-MiActionSnapshot -Item $item -Snapshot $script:LatestSnapshot) -ne 'Pass') {
        Set-MiStatus '选中进程样本已经无效，请等待新扫描。' $true;return
    }
    if ($Mode -eq 'Force' -and -not $script:MiDangerCheck.Checked) { return }
    $modeText=if ($Mode -eq 'Force') {'强制结束（可能丢失未保存的数据）'} else {'向主窗口发送普通关闭请求'}
    $answer=[Windows.Forms.MessageBox]::Show($script:Form,
        ('目标：{0} (PID {1})'+[Environment]::NewLine+'操作：{2}'+[Environment]::NewLine+'此操作不可撤销，提交内存高也不代表没有用。继续？' -f $item.Name,$item.PID,$modeText),
        '独立确认目标与后果','YesNo','Warning')
    if ($answer -ne [Windows.Forms.DialogResult]::Yes) {return}
    $word=if ($Mode -eq 'Force') {'KILL'} else {'CLOSE'}
    if (-not (Show-MiActionTypedDialog -Prompt ('请输入 '+$word+' '+$item.PID+' 确认所选进程：'+$item.Name) -Expected ($word+' '+$item.PID))) {return}
    if ($Mode -eq 'Force') {
        if (-not (Show-MiActionTypedDialog -Prompt '最后确认：强制结束可能丢失未保存的数据。' -Expected 'I ACCEPT DATA LOSS')) {return}
    }
    $result=Invoke-MiProcessAction -Mode $Mode -Item $item -Snapshot $script:LatestSnapshot -DangerEnabled ([bool]$script:MiDangerCheck.Checked)
    Update-MiActionButtons
    if ($result.Outcome -eq 'Requested') {
        Set-MiStatus ('已发送 '+$modeText+'：'+$item.Name+'；观察窗口 60 秒，不保证立刻退出。')
    } else {
        Set-MiStatus ('操作拒绝或失败：'+$result.Error) $true
    }
}
function Show-MiActionLog {
    $form=[Windows.Forms.Form]::new();$form.Text='进程操作审计（当前用户可修改的本地记录）'
    $form.Size=[Drawing.Size]::new(850,530);$form.StartPosition='CenterParent'
    $box=[Windows.Forms.TextBox]::new();$box.Multiline=$true;$box.ReadOnly=$true
    $box.ScrollBars='Both';$box.WordWrap=$false;$box.Dock='Fill'
    $box.Font=[Drawing.Font]::new('Consolas',[single]9)
    try {
        if ([IO.File]::Exists($script:MiActions.AuditPath)) {
            $box.Lines=[string[]]@(Get-Content -LiteralPath $script:MiActions.AuditPath -Tail 100 -Encoding UTF8 -ErrorAction Stop)
        } else { $box.Text='暂无普通进程操作记录。' }
    } catch { $box.Text='读取日志失败：'+$_.Exception.Message }
    $form.Controls.Add($box)
    try {[void]$form.ShowDialog($script:Form)}finally{$form.Dispose()}
}

$btnRestart.Add_Click({
    if ($script:RestartPending) { return }
    if ($null -eq $script:WorkerAsync) {
        try { Start-MiWorker } catch { Set-MiStatus ('启动失败：'+$_.Exception.Message) $true }
        return
    }
    $script:RestartPending=$true
    $btnRestart.Enabled=$false
    Stop-MiWorker
    Set-MiStatus '正在取消当前采样；待后台采样器退出后自动重新启动。'
})
$script:Form.Add_Shown({
    try { Restore-MiGuiHistory; Start-MiWorker; $script:UiTimer.Start() }
    catch {
        Set-MiStatus ('采样器启动失败：' + $_.Exception.Message) $true
        $script:UiTimer.Start()
    }
})
$script:Form.Add_FormClosing({
    param($sender,$e)
    if ($script:CloseToTray -and -not $script:ExitRequested -and
        $e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
        $e.Cancel=$true
        $script:Form.Hide()
        return
    }
    $script:Closing=$true
    $script:UiTimer.Stop()
    Stop-MiWorker
})
try {
    [void]$script:Form.ShowDialog()
} finally {
    $script:Closing=$true
    $script:UiTimer.Stop()
    Stop-MiWorker
    if ($null -ne $script:WorkerAsync) {
        # Bounded exit: CIM may be stuck. Do not block the UI indefinitely on shutdown.
        try { [void]$script:WorkerAsync.AsyncWaitHandle.WaitOne(1500) } catch {}
        if ($script:WorkerAsync.IsCompleted) {
            [void](Dispose-MiCompletedWorker)
        } else {
            # Best-effort asynchronous stop; no blocking Stop()/EndInvoke() call.
            try { [void]$script:WorkerPs.BeginStop($null,$null) } catch {}
        }
    }
    Stop-MiActionObservation
    Close-MiV4Gui
    $script:UiTimer.Dispose()
    $script:Form.Dispose()
}
