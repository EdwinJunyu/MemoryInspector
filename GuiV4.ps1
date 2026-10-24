#requires -Version 5.1
<#
Milestone 4 - read-only GUI integration.
No process termination, service control, elevation, cache purge or settings that modify Windows.
All WinForms access stays on the GUI thread; auxiliary CIM/history reads run asynchronously.
#>
function Get-MiV4Risk {
    param($Item)
    if ($null -eq $Item) { return '未知（禁止操作）' }
    if ($null -eq $Item.StartUtcTicks -or $Item.Status -ne 'Success') { return '未知（禁止操作）' }
    if ($null -ne $script:ServicePids -and $script:ServicePids.ContainsKey([int]$Item.PID)) {
        return '受限（服务宿主）'
    }
    return '待核验（不可自动操作）'
}
function Get-MiVersionPresentation {
    param([string]$Root=$PSScriptRoot)
    # VERSION 只作为显示来源，不替代管理员执行器的版本白名单、ACL 或哈希校验。
    # 缺失或损坏时明确中止初始化，不能回退到旧的硬编码版本冒充当前版本。
    $versionPath=Join-Path $Root 'VERSION'
    try { $version=[IO.File]::ReadAllText($versionPath,[Text.Encoding]::UTF8).Trim() }
    catch { throw ('无法读取 VERSION，不能确认应用版本：'+$_.Exception.Message) }
    $parsed=$null
    if ($version.Length -gt 24 -or $version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        -not [version]::TryParse($version,[ref]$parsed)) { throw 'VERSION 格式无效；需要 major.minor.patch。' }
    return [pscustomobject]@{
        Version=$version
        WindowTitle=('MemoryInspector v{0} · 安全进程管理' -f $version)
        TrayText=('MemoryInspector v{0} · 受控操作' -f $version)
        ServiceNote=('M7：受保护服务管理 · 需先安装当前版本 {0}，并经管理员逐项批准。' -f $version)
        PrivilegeNote=('M7：使用 Installer.ps1 安装当前版本 {0}。受保护服务操作须 UAC + 管理员再次确认。' -f $version)
    }
}

function Protect-MiV4Csv {
    param($Value)
    if ($null -eq $Value) { return '' }
    $v=[string]$Value
    if ($v -match '^[\s]*[=+\-@]') { return ("'" + $v) }
    return $v
}
function Select-MiV4Rows {
    param([object[]]$Rows,[string]$Filter,[string]$Order,[int]$Limit=60)
    $match=@($Rows | Where-Object {
        [string]::IsNullOrWhiteSpace($Filter) -or
        ([string]$_.Name).IndexOf($Filter,[System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        ([string]$_.PID).Contains($Filter)
    })
    switch ($Order) {
        '增长量' { $match=@($match | Sort-Object -Property @{Expression={if($null -eq $_.DeltaBytes){[long]::MinValue}else{[long]$_.DeltaBytes}}} -Descending) }
        'RAM' { $match=@($match | Sort-Object -Property @{Expression={if($null -eq $_.WorkingBytes){-1L}else{[long]$_.WorkingBytes}}} -Descending) }
        '名称' { $match=@($match | Sort-Object -Property Name,PID) }
        'PID' { $match=@($match | Sort-Object -Property PID) }
        '异常优先' {
            $match=@($match | Sort-Object -Property @{Expression={
                $report=Get-MiDiagnosisReport -Item $_
                if ($null -ne $report -and $report.AnomalyState -eq 'SuspectedSustainedGrowth') { 2 }
                elseif ($null -ne $report -and $report.AnomalyState -eq 'InsufficientEvidence') { 1 }
                else { 0 }
            }},@{Expression={if($null -eq $_.PrivateBytes){-1L}else{[long]$_.PrivateBytes}}} -Descending)
        }
        default { $match=@($match | Sort-Object -Property @{Expression={if($null -eq $_.PrivateBytes){-1L}else{[long]$_.PrivateBytes}}} -Descending) }
    }
    return @($match | Select-Object -First $Limit)
}
function Update-MiV4Grid {
    param($ProcessCollection)
    if ($ProcessCollection.Status -eq 'Failed') {
        $script:Grid.Rows.Clear()
        $script:CurrentProcesses=@()
        $script:AllProcesses=@()
    $script:ProcessTrend=@{}
        $script:Details.Text='本轮进程采样失败；不显示过期进程数据。'
        return
    }
    $next=@{}
    $all=@($ProcessCollection.Items)
    foreach ($p in $all) {
        $p | Add-Member -NotePropertyName DeltaBytes -NotePropertyValue $null -Force
        if ($null -eq $p.StartUtcTicks) { continue }
        $key='{0}:{1}' -f $p.PID,$p.StartUtcTicks
        if ($script:PreviousInstances.ContainsKey($key) -and
            $null -ne $p.PrivateBytes -and $null -ne $script:PreviousInstances[$key].PrivateBytes) {
            $p.DeltaBytes=[long]($p.PrivateBytes-$script:PreviousInstances[$key].PrivateBytes)
        }
        $next[$key]=$p
    }
    $script:AllProcesses=$all
    $script:PreviousInstances=$next
    Render-MiV4Grid
}
function Render-MiV4Grid {
    if ($null -eq $script:Grid) { return }
    $selected=Get-MiSelectedProcess
    $oldPid=-1; $oldTicks=$null
    if ($null -ne $selected) { $oldPid=$selected.PID; $oldTicks=$selected.StartUtcTicks }
    $filter=''
    $order='Private'
    if ($null -ne $script:SearchInput) { $filter=$script:SearchInput.Text.Trim() }
    if ($null -ne $script:OrderInput -and $null -ne $script:OrderInput.SelectedItem) { $order=[string]$script:OrderInput.SelectedItem }
    $rows=@(Select-MiV4Rows -Rows $script:AllProcesses -Filter $filter -Order $order -Limit 60)
    $script:UiUpdating=$true
    $script:Grid.SuspendLayout()
    try {
        $script:Grid.Rows.Clear()
        foreach ($p in $rows) {
            $delta='—'
            if ($null -ne $p.DeltaBytes) { $delta=('{0:+0.0;-0.0;0.0}' -f ([double]$p.DeltaBytes/1MB)) }
            $report=Get-MiDiagnosisReport -Item $p
            $serviceFlag='—'
            if ($null -ne $script:ServicePids -and $script:ServicePids.ContainsKey([int]$p.PID)) { $serviceFlag='服务' }
            $idx=$script:Grid.Rows.Add([object[]]@(
                $p.PID,$p.Name,(Format-MiGiB $p.PrivateBytes),(Format-MiGiB $p.WorkingBytes),
                $delta,(Format-MiDiagnosisState -Report $report),(Get-MiV4Risk -Item $p),$serviceFlag,$p.Status
            ))
            $script:Grid.Rows[$idx].Tag=$p
            if ($p.PID -eq $oldPid -and $null -ne $oldTicks -and $p.StartUtcTicks -eq $oldTicks) {
                $script:Grid.Rows[$idx].Selected=$true
            }
        }
        $script:Grid.ClearSelection()
        foreach ($row in $script:Grid.Rows) {
            if ($row.Tag -and $row.Tag.PID -eq $oldPid -and $null -ne $oldTicks -and $row.Tag.StartUtcTicks -eq $oldTicks) {
                $row.Selected=$true
                break
            }
        }
    } finally {
        $script:Grid.ResumeLayout()
        $script:UiUpdating=$false
    }
    $script:CurrentProcesses=$rows
    if ($script:ListSummary) { $script:ListSummary.Text=('显示 {0} / {1} 个进程（最多 60）' -f $rows.Count,$script:AllProcesses.Count) }
    Update-MiSelectedProcess
}

function Add-MiV4ProcessHistory {
    param($Snapshot)
    if ($null -eq $Snapshot -or $null -eq $Snapshot.Processes -or $Snapshot.Processes.Status -eq 'Failed') { return }
    $time=([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
    if ($Snapshot.TimeDiscontinuity) { $script:ProcessTrend.Clear() }
    $cutoff=$time.AddMinutes(-30)
    foreach ($p in @($Snapshot.Processes.Items | Where-Object { $null -ne $_.PrivateBytes } |
        Sort-Object -Property PrivateBytes -Descending | Select-Object -First 60)) {
        if ($null -eq $p.StartUtcTicks -or [long]$p.StartUtcTicks -le 0) { continue }
        $key='{0}:{1}' -f $p.PID,$p.StartUtcTicks
        if (-not $script:ProcessTrend.ContainsKey($key)) {
            $script:ProcessTrend[$key]=New-Object 'System.Collections.Generic.List[object]'
        }
        $list=$script:ProcessTrend[$key]
        if ($list.Count -eq 0 -or $time -gt $list[$list.Count-1].Utc) {
            $list.Add([pscustomobject]@{Utc=$time;PrivateBytes=$p.PrivateBytes;WorkingBytes=$p.WorkingBytes})
        }
        while ($list.Count -gt 0 -and $list[0].Utc -lt $cutoff) { $list.RemoveAt(0) }
        # 显示缓存按支持的最密周期保留全窗口；诊断仍由后台分析器独立审核证据。
        $capacity=[int][math]::Ceiling(1800.0/5.0)+2
        while ($list.Count -gt $capacity) { $list.RemoveAt(0) }
    }
    foreach ($key in @($script:ProcessTrend.Keys)) {
        $list=$script:ProcessTrend[$key]
        if ($list.Count -eq 0 -or $list[$list.Count-1].Utc -lt $cutoff) {
            $script:ProcessTrend.Remove($key)
        }
    }
}
function Update-MiV4ProcessChart {
    if (-not $script:ProcessChart) { return }
    $a=$script:ProcessChart.Series['Private']
    $b=$script:ProcessChart.Series['RAM']
    $a.Points.Clear();$b.Points.Clear()
    $p=Get-MiSelectedProcess
    if ($null -eq $p -or $null -eq $p.StartUtcTicks) { return }
    $key='{0}:{1}' -f $p.PID,$p.StartUtcTicks
    if (-not $script:ProcessTrend.ContainsKey($key)) { return }
    foreach ($point in $script:ProcessTrend[$key]) {
        $x=$point.Utc.ToLocalTime().ToOADate()
        [void]$a.Points.AddXY($x,[double]$point.PrivateBytes / 1GB)
        if ($null -ne $point.WorkingBytes) { [void]$b.Points.AddXY($x,[double]$point.WorkingBytes / 1GB) }
    }
}

function Start-MiV4Job {
    param([string]$Kind,[string]$Code)
    if ($script:AuxJobs.ContainsKey($Kind)) { return }
    $ps=$null
    try {
        $ps=[System.Management.Automation.PowerShell]::Create()
        [void]$ps.AddScript($Code)
        $handle=$ps.BeginInvoke()
        $script:AuxJobs[$Kind]=[pscustomobject]@{PowerShell=$ps;Handle=$handle}
    } catch {
        if ($ps) { $ps.Dispose() }
        Set-MiStatus ('后台查询失败：'+$_.Exception.Message) $true
    }
}
function Start-MiV4ServicesLoad {
    $script:ServiceNote.Text='后台读取 Windows 服务（只读）…'
    Start-MiV4Job -Kind 'Services' -Code @'
Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
    Select-Object Name,DisplayName,State,StartMode,ProcessId,CanStop,ServiceType |
    Sort-Object Name
'@
}
function Start-MiV4HistoryLoad {
    $script:HistoryNote.Text='后台读取历史聚合文件…'
    $root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector'
    # Encode the path as Base64 so it is never interpolated as executable PowerShell.
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($root))
    $code=@'
$folder=Join-Path ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('REPLACE_ROOT'))) 'aggregates'
if (Test-Path -LiteralPath $folder -PathType Container) {
    $cutoff=[datetime]::UtcNow.AddDays(-90)
    foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter 'summary-*.jsonl' -File -ErrorAction Stop | Sort-Object Name)) {
        if ($file.Name -notmatch '^summary-\d{4}-\d{2}-\d{2}\.jsonl$') { continue }
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $r=ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($r.RecordType -ne 'FiveMinuteAggregate' -or [int]$r.SchemaVersion -ne 1) { continue }
                $when=([datetime]::Parse([string]$r.BucketStartUtc)).ToUniversalTime()
                if ($when -lt $cutoff -or $when -gt [datetime]::UtcNow) { continue }
                [pscustomobject]@{
                    TimestampUtc=$when
                    Committed=$r.AverageCommittedBytes
                    UsedRam=$r.AverageUsedPhysicalBytes
                    Samples=$r.SystemSampleCount
                }
            } catch {} # A corrupt JSONL line is not valid history.
        }
    }
}
'@.Replace('REPLACE_ROOT',$encoded)
    Start-MiV4Job -Kind 'History' -Code $code
}
function Poll-MiV4Jobs {
    foreach ($kind in @($script:AuxJobs.Keys)) {
        $job=$script:AuxJobs[$kind]
        if (-not $job.Handle.IsCompleted) { continue }
        try {
            $data=@($job.PowerShell.EndInvoke($job.Handle))
            if ($job.PowerShell.Streams.Error.Count -gt 0) {
                throw [string]$job.PowerShell.Streams.Error[0]
            }
            if ($kind -eq 'Services') { Show-MiV4Services -Rows $data }
            elseif ($kind -eq 'History') { Show-MiV4History -Rows $data }
        } catch {
            if ($kind -eq 'Services') { $script:ServiceNote.Text='无法读取服务：'+$_.Exception.Message }
            else { $script:HistoryNote.Text='无法读取历史：'+$_.Exception.Message }
        } finally {
            $job.PowerShell.Dispose()
            $script:AuxJobs.Remove($kind)
        }
    }
}
function Show-MiV4Services {
    param([object[]]$Rows)
    $script:ServiceRows=@($Rows)
    $script:ServiceApprovals=Get-MiServiceApprovalMap
    $script:ServicePids=@{}
    foreach ($s in $Rows) {
        if ([int]$s.ProcessId -gt 0) { $script:ServicePids[[int]$s.ProcessId]=$true }
    }
    $script:ServiceNote.Text=('{0} 个服务 · M7 服务操作需审核名单、UAC 和独立高权限检查；此列表仅供参考' -f $Rows.Count)
    Render-MiV4Services
    if ($script:AllProcesses.Count -gt 0) { Render-MiV4Grid }
}
function Render-MiV4Services {
    $query=$script:ServiceSearch.Text.Trim()
    $previous=Get-MiSelectedService
    $previousName=if ($null -ne $previous) {[string]$previous.Name} else {''}
    $script:MiServiceRendering=$true
    try {
        $script:ServiceGrid.Rows.Clear()
        foreach ($service in $script:ServiceRows) {
            if ($query -and ([string]$service.Name).IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                ([string]$service.DisplayName).IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            $approved=$script:ServiceApprovals.ContainsKey([string]$service.Name)
            $status=if ($approved) {'已批准（仍需逐项安全检查）'} else {'未批准 / 受限'}
            $index=$script:ServiceGrid.Rows.Add([object[]]@(
                $service.Name,$service.DisplayName,$service.State,$service.StartMode,$service.ProcessId,$status))
            $script:ServiceGrid.Rows[$index].Tag=$service
            if ($previousName -and [string]::Equals($previousName,[string]$service.Name,[StringComparison]::OrdinalIgnoreCase)) {
                $script:ServiceGrid.Rows[$index].Selected=$true
            }
        }
    } finally { $script:MiServiceRendering=$false }
    Update-MiV4ServiceButtons
}
function Get-MiSelectedService {
    if ($null -eq $script:ServiceGrid -or $script:ServiceGrid.SelectedRows.Count -lt 1) { return $null }
    return $script:ServiceGrid.SelectedRows[0].Tag
}
function Update-MiV4ServiceButtons {
    if ($script:MiServiceRendering -or $null -eq $script:MiServiceButtons) { return }
    $service=Get-MiSelectedService
    $installed=(Test-MiPrivilegeBridgeInstalled)
    $busy=($null -ne $script:MiServiceRequest -or $null -ne $script:MiPrivilegeProbe)
    $enabled=($installed -and -not $busy -and -not (Test-MiElevated) -and $null -ne $service)
    $approved=$false
    if ($null -ne $service) { $approved=$script:ServiceApprovals.ContainsKey([string]$service.Name) }
    $script:MiServiceButtons.Approve.Enabled=$enabled -and -not $approved
    $script:MiServiceButtons.Revoke.Enabled=$enabled -and $approved
    $script:MiServiceButtons.Stop.Enabled=$enabled -and $approved -and $service.State -eq 'Running' -and [bool]$service.CanStop
    $script:MiServiceButtons.Restore.Enabled=$enabled -and $approved -and $service.State -eq 'Stopped'
}
function Request-MiV4ServiceAction {
    param([ValidateSet('ApproveService','RevokeServiceApproval','StopApprovedService','StartPreviouslyStoppedService')][string]$Operation)
    $service=Get-MiSelectedService
    if ($null -eq $service -or $null -ne $script:MiServiceRequest -or $null -ne $script:MiPrivilegeProbe) { return }
    $label=switch ($Operation) {
        'ApproveService' {'APPROVE'} 'RevokeServiceApproval' {'REVOKE'}
        'StopApprovedService' {'STOP'} 'StartPreviouslyStoppedService' {'START'}
    }
    $message=('目标服务：{0} ({1})' -f $service.Name,$service.DisplayName)+[Environment]::NewLine+
        ('当前状态：{0} · 宿主 PID：{1}' -f $service.State,$service.ProcessId)+[Environment]::NewLine+
        '系统服务操作可能影响其他软件；即使服务重新启动也不能恢复所有会话状态。'+
        [Environment]::NewLine+'只有执行器完成独立安全核验后才会执行，继续？'
    if ([Windows.Forms.MessageBox]::Show($script:Form,$message,'M7 服务操作风险确认',
        'YesNo','Warning') -ne [Windows.Forms.DialogResult]::Yes) { return }
    if (-not (Show-MiActionTypedDialog -Prompt ('输入 '+$label+' '+$service.Name+' 确认目标') -Expected ($label+' '+$service.Name))) {
        return
    }
    try {
        $status=Start-MiServiceRequest -Operation $Operation -ServiceName ([string]$service.Name)
        if ($status -eq 'UacCancelled') {
            $script:ServiceNote.Text='用户拒绝 UAC；没有执行服务操作。'
        } else {
            $script:ServiceNote.Text=('UAC 已启动：'+$label+' '+$service.Name+'；请在提升权限的窗口中再次输入确认。')
        }
        Set-MiOperationStatus $status $script:ServiceNote.Text
    } catch {
        $script:ServiceNote.Text='服务操作未启动：'+$_.Exception.Message
        Set-MiOperationStatus 'Rejected' $script:ServiceNote.Text $true
    }
    Update-MiV4ServiceButtons
}
function Show-MiV4History {
    param([object[]]$Rows)
    $script:AggregateHistory=@($Rows | Where-Object {
        $null -ne $_.Committed -and $null -ne $_.UsedRam -and [int]$_.Samples -gt 0
    } | Sort-Object TimestampUtc)
    Render-MiV4History
}
function Render-MiV4History {
    $days=7
    if ($script:HistoryRange.SelectedItem) { $days=[int]$script:HistoryRange.SelectedItem }
    $cutoff=[datetime]::UtcNow.AddDays(-$days)
    $rows=@($script:AggregateHistory | Where-Object {$_.TimestampUtc -ge $cutoff})
    $series1=$script:HistoryChart.Series['Committed']
    $series2=$script:HistoryChart.Series['RAM']
    $series1.Points.Clear();$series2.Points.Clear()
    $skip=[math]::Max(1,[int][math]::Ceiling($rows.Count/900.0))
    for ($i=0;$i -lt $rows.Count;$i+=$skip) {
        $r=$rows[$i]
        $x=$r.TimestampUtc.ToLocalTime().ToOADate()
        [void]$series1.Points.AddXY($x,[double]$r.Committed/1GB)
        [void]$series2.Points.AddXY($x,[double]$r.UsedRam/1GB)
    }
    $script:HistoryNote.Text=('{0} 天内 {1} 个有效五分钟聚合桶，绘制 {2} 个点（抽样展示，不插值）' -f
        $days,$rows.Count,$series1.Points.Count)
}
function Save-MiV4Settings {
    $new=[ordered]@{
        SchemaVersion=1
        SamplingSeconds=[int]$script:SampleSetting.Value
        CloseToTray=[bool]$script:TraySetting.Checked
        GrowthMiB=[int]$script:GrowthSetting.Value
        GrowthPercent=[int]$script:GrowthPercentSetting.Value
    }
    $dir=Split-Path -Parent $script:UiSettingsPath
    [void][IO.Directory]::CreateDirectory($dir)
    $tmp=$script:UiSettingsPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($tmp,($new|ConvertTo-Json -Depth 3),[Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($script:UiSettingsPath)) {
            # PS5.1 的重载绑定会把普通 $null 转成空路径，必须传入真正的空字符串引用。
            [IO.File]::Replace($tmp,$script:UiSettingsPath,[NullString]::Value)
        } else { [IO.File]::Move($tmp,$script:UiSettingsPath) }
    } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
    $script:PeriodMs=[int]$new.SamplingSeconds*1000
    $script:CloseToTray=$new.CloseToTray
    $script:SettingsNote.Text='GUI 设置已保存；监测阈值与采样周期将在重启采样器后生效。'
}
function Export-MiV4Processes {
    if (-not $script:LatestSnapshot -or $script:LatestSnapshot.Processes.Status -eq 'Failed') {
        Set-MiStatus '没有可导出的有效进程快照。' $true
        return
    }
    $dialog=New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title='导出当前进程列表（只读）'
    $dialog.Filter='CSV (*.csv)|*.csv'
    $dialog.FileName='MemoryInspector-processes-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.csv'
    try {
        if ($dialog.ShowDialog($script:Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $rows=@(foreach ($p in $script:CurrentProcesses) {
            [pscustomobject]@{
                TimeUtc=$script:LatestSnapshot.CaptureEndUtc.ToString('o')
                PID=$p.PID;ProcessName=(Protect-MiV4Csv $p.Name)
                StartUtcTicks=$p.StartUtcTicks
                PrivateBytes=$p.PrivateBytes;WorkingSetBytes=$p.WorkingBytes
                DeltaBytes=$p.DeltaBytes;Anomaly=(Format-MiDiagnosisState (Get-MiDiagnosisReport $p))
                ActionRisk=(Get-MiV4Risk $p)
            }
        })
        $rows | Export-Csv -LiteralPath $dialog.FileName -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Set-MiStatus ('已导出 '+$rows.Count+' 条显示记录：'+$dialog.FileName)
    } catch { Set-MiStatus ('导出失败：'+$_.Exception.Message) $true }
    finally { $dialog.Dispose() }
}
function New-MiV4Chart {
    $chart=New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    $chart.Dock='Fill';$chart.BackColor=[Drawing.Color]::White
    $area=[System.Windows.Forms.DataVisualization.Charting.ChartArea]::new('Trend')
    $area.AxisX.LabelStyle.Format='MM-dd'
    $area.AxisX.MajorGrid.Enabled=$false
    $area.AxisY.MajorGrid.LineColor=$script:Outline
    [void]$chart.ChartAreas.Add($area)
    $legend=[System.Windows.Forms.DataVisualization.Charting.Legend]::new('Legend')
    $legend.Docking='Top';[void]$chart.Legends.Add($legend)
    foreach ($def in @(@('Committed',$script:Blue),@('RAM',$script:Teal))) {
        $s=[System.Windows.Forms.DataVisualization.Charting.Series]::new([string]$def[0])
        $s.ChartType='Line';$s.XValueType='DateTime';$s.BorderWidth=2;$s.Color=[Drawing.Color]$def[1]
        $s.ChartArea='Trend'
        [void]$chart.Series.Add($s)
    }
    return $chart
}
function New-MiV4DataGrid {
    param([object[]]$Defs)
    $grid=New-Object System.Windows.Forms.DataGridView
    $grid.Dock='Fill';$grid.ReadOnly=$true;$grid.AllowUserToAddRows=$false;$grid.AllowUserToDeleteRows=$false
    $grid.SelectionMode='FullRowSelect';$grid.RowHeadersVisible=$false;$grid.MultiSelect=$false
    $grid.AutoGenerateColumns=$false;$grid.AutoSizeColumnsMode='Fill';$grid.BackgroundColor=[Drawing.Color]::White
    foreach ($d in $Defs) {
        $c=New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name=[string]$d[0];$c.HeaderText=[string]$d[1];$c.FillWeight=[single]$d[2]
        $c.SortMode='NotSortable'
        [void]$grid.Columns.Add($c)
    }
    return $grid
}
function Initialize-MiV4Gui {
    param($Root,$Cards,$Charts,$Bottom,$StatusBar)
    $script:AllProcesses=@()
    $script:ServicePids=@{}
    $script:ServiceRows=@()
    $script:ServiceApprovals=@{}
    $script:MiServiceRendering=$false
    $script:AggregateHistory=@()
    $script:AuxJobs=@{}
    $script:ExitRequested=$false
    $script:CloseToTray=$true
    $script:GrowthMiB=512
    $script:GrowthPercent=20
    $script:UiSettingsPath=Join-Path (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector') 'ui-settings.json'
    try {
        if ([IO.File]::Exists($script:UiSettingsPath)) {
            $cfg=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($script:UiSettingsPath,[Text.Encoding]::UTF8)) -ErrorAction Stop
            if ([int]$cfg.SchemaVersion -eq 1 -and [int]$cfg.SamplingSeconds -ge 5 -and [int]$cfg.SamplingSeconds -le 60) {
                $script:PeriodMs=[int]$cfg.SamplingSeconds*1000
                $script:CloseToTray=[bool]$cfg.CloseToTray
                if ($null -ne $cfg.GrowthMiB -and [int]$cfg.GrowthMiB -ge 64 -and [int]$cfg.GrowthMiB -le 8192) { $script:GrowthMiB=[int]$cfg.GrowthMiB }
                if ($null -ne $cfg.GrowthPercent -and [int]$cfg.GrowthPercent -ge 5 -and [int]$cfg.GrowthPercent -le 200) { $script:GrowthPercent=[int]$cfg.GrowthPercent }
            }
        }
    } catch { } # Invalid GUI preferences never affect the history writer.

    $Root.SuspendLayout()
    foreach ($control in @($Cards,$Charts,$Bottom,$StatusBar)) { $Root.Controls.Remove($control) }
    $Root.RowStyles.Clear();$Root.RowCount=3
    [void]$Root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Absolute',[single]53)))
    [void]$Root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Percent',[single]100)))
    [void]$Root.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Absolute',[single]82)))
    $script:Tabs=New-Object System.Windows.Forms.TabControl
    $script:Tabs.Dock='Fill'
    $script:Tabs.Font=[Drawing.Font]::new('Microsoft YaHei UI',[single]10)
    foreach ($title in @('Processes · 进程','Overview · 总览','Services · 服务','History · 历史','Settings · 设置')) {
        $page=New-Object System.Windows.Forms.TabPage
        $page.Text=$title;$page.BackColor=$script:Background
        [void]$script:Tabs.TabPages.Add($page)
    }
    $Root.Controls.Add($script:Tabs,0,1)
    $Root.Controls.Add($StatusBar,0,2)
    $Root.ResumeLayout()

    # 监控和操作反馈分别占固定行；长结果保留文本，完整审计始终可通过按钮访问。
    $StatusBar.SuspendLayout()
    $StatusBar.Controls.Clear()
    $statusLayout=[Windows.Forms.TableLayoutPanel]::new()
    $statusLayout.Dock='Fill';$statusLayout.RowCount=2;$statusLayout.ColumnCount=2
    [void]$statusLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute',[single]27))
    [void]$statusLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent',[single]100))
    [void]$statusLayout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent',[single]100))
    [void]$statusLayout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute',[single]126))
    $statusLayout.Controls.Add($script:StatusLabel,0,0);$statusLayout.SetColumnSpan($script:StatusLabel,2)
    $script:OperationLabel=New-MiLabel '操作结果：暂无操作。' 9
    $script:OperationLabel.Dock='Fill';$script:OperationLabel.TextAlign='MiddleLeft'
    $script:OperationLabel.AutoEllipsis=$true;$script:OperationLabel.AccessibleName='最近操作结果'
    $statusLayout.Controls.Add($script:OperationLabel,0,1)
    $auditButton=New-MiButton '完整操作审计' 120;$auditButton.Dock='Fill'
    $auditButton.Add_Click({Show-MiActionLog})
    $statusLayout.Controls.Add($auditButton,1,1)
    $StatusBar.Controls.Add($statusLayout);$StatusBar.ResumeLayout()


    $procPage=$script:Tabs.TabPages[0]
    $procLayout=New-Object System.Windows.Forms.TableLayoutPanel
    $procLayout.Dock='Fill';$procLayout.RowCount=2;$procLayout.ColumnCount=1
    [void]$procLayout.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Absolute',[single]48)))
    [void]$procLayout.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Percent',[single]100)))
    $procPage.Controls.Add($procLayout)
    $filters=New-Object System.Windows.Forms.FlowLayoutPanel
    $filters.Dock='Fill';$filters.WrapContents=$false;$filters.Padding=[Windows.Forms.Padding]::new(6,6,0,0)
    $procLayout.Controls.Add($filters,0,0)
    $script:SearchInput=New-Object System.Windows.Forms.TextBox
    $script:SearchInput.Width=220;$script:SearchInput.Font=$script:Font
    $script:OrderInput=New-Object System.Windows.Forms.ComboBox
    $script:OrderInput.DropDownStyle='DropDownList';$script:OrderInput.Width=118
    [void]$script:OrderInput.Items.AddRange([object[]]@('Private','增长量','RAM','名称','PID','异常优先'))
    $script:OrderInput.SelectedIndex=0
    $export=New-MiButton '导出显示项 CSV' 136
    $script:ListSummary=New-MiLabel '等待进程数据' 9
    $script:ListSummary.Width=250;$script:ListSummary.Height=32;$script:ListSummary.TextAlign='MiddleLeft'
    $filters.Controls.Add((New-MiLabel '搜索 PID / 进程名' 9))
    $filters.Controls[$filters.Controls.Count-1].Width=128
    $filters.Controls[$filters.Controls.Count-1].Height=30
    $filters.Controls.Add($script:SearchInput)
    $filters.Controls.Add($script:OrderInput)
    $filters.Controls.Add($export)
    $filters.Controls.Add($script:ListSummary)
    $procLayout.Controls.Add($Bottom,0,1)
    $script:Grid.Columns.Clear()
    foreach ($d in @(
        @('PID','PID',10),@('Name','进程',22),@('Private','Private GiB',14),
        @('Working','RAM GiB',13),@('Delta','增量 MiB',12),
        @('Anomaly','内存异常',19),@('Risk','操作风险',17),
        @('Service','服务',8),@('Status','采样',8)
    )) {
        $c=New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name=[string]$d[0];$c.HeaderText=[string]$d[1];$c.FillWeight=[single]$d[2]
        $c.SortMode='NotSortable'
        [void]$script:Grid.Columns.Add($c)
    }
    # The instance chart is read-only; it plots the last 30 minutes of samples kept in memory.
    $hostPanel=$script:Details.Parent
    $hostPanel.Controls.Remove($script:Details)
    $split=New-Object System.Windows.Forms.TableLayoutPanel
    $split.Dock='Fill';$split.RowCount=3;$split.ColumnCount=1
    [void]$split.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Percent',[single]100)))
    [void]$split.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Absolute',[single]100)))
    [void]$split.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Absolute',[single]155)))
    $hostPanel.Controls.Add($split)
    $split.Controls.Add($script:Details,0,0)
    $script:ProcessChart=New-MiV4Chart
    $script:ProcessChart.Series['Committed'].Name='Private'
    $script:ProcessChart.ChartAreas[0].AxisX.LabelStyle.Format='HH:mm'
    $script:ProcessChart.Series['RAM'].Name='RAM'
    $split.Controls.Add($script:ProcessChart,0,2)
    $actionPanel=New-Object System.Windows.Forms.TableLayoutPanel
    $actionPanel.Dock='Fill';$actionPanel.RowCount=3;$actionPanel.ColumnCount=2
    [void]$actionPanel.ColumnStyles.Add(([Windows.Forms.ColumnStyle]::new('Percent',[single]50)))
    [void]$actionPanel.ColumnStyles.Add(([Windows.Forms.ColumnStyle]::new('Percent',[single]50)))
    [void]$actionPanel.RowStyles.Add(([Windows.Forms.RowStyle]::new('Absolute',[single]24)))
    [void]$actionPanel.RowStyles.Add(([Windows.Forms.RowStyle]::new('Percent',[single]48)))
    [void]$actionPanel.RowStyles.Add(([Windows.Forms.RowStyle]::new('Percent',[single]52)))
    $script:ProcessCheckLabel=New-MiLabel '等待目标身份预检查。' 8
    $script:ProcessCheckLabel.Dock='Fill';$script:ProcessCheckLabel.AutoEllipsis=$true
    $actionPanel.Controls.Add($script:ProcessCheckLabel,0,0);$actionPanel.SetColumnSpan($script:ProcessCheckLabel,2)
    $script:MiDangerCheck=[Windows.Forms.CheckBox]::new()
    $script:MiDangerCheck.Text='危险模式（仅对核验后的普通 GUI 应用）';$script:MiDangerCheck.Dock='Fill'
    $script:MiDangerCheck.Checked=$false;$script:MiDangerCheck.Font=$script:Font
    $actionPanel.Controls.Add($script:MiDangerCheck,0,1);$actionPanel.SetColumnSpan($script:MiDangerCheck,2)
    $script:MiGracefulButton=New-MiButton '正常关闭' 115;$script:MiGracefulButton.Dock='Fill';$script:MiGracefulButton.Enabled=$false
    $script:MiForceButton=New-MiButton '强制结束' 115;$script:MiForceButton.Dock='Fill';$script:MiForceButton.Enabled=$false
    $actionPanel.Controls.Add($script:MiGracefulButton,0,2);$actionPanel.Controls.Add($script:MiForceButton,1,2)
    $split.Controls.Add($actionPanel,0,1)
    $script:MiDangerCheck.Add_CheckedChanged({Update-MiActionButtons})
    $script:MiGracefulButton.Add_Click({Request-MiGuiProcessAction -Mode Graceful})
    $script:MiForceButton.Add_Click({Request-MiGuiProcessAction -Mode Force})
    $split.BringToFront()
    foreach ($control in @($hostPanel.Controls)) {
        if ($control -is [System.Windows.Forms.Label]) { $control.BringToFront() }
    }
    $script:SearchInput.Add_TextChanged({ Render-MiV4Grid; Update-MiCharts })
    $script:OrderInput.Add_SelectedIndexChanged({ Render-MiV4Grid; Update-MiCharts })
    $export.Add_Click({ Export-MiV4Processes })

    $overview=New-Object System.Windows.Forms.TableLayoutPanel
    $overview.Dock='Fill';$overview.RowCount=2;$overview.ColumnCount=1
    [void]$overview.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Absolute',[single]113)))
    [void]$overview.RowStyles.Add(([System.Windows.Forms.RowStyle]::new('Percent',[single]100)))
    $script:Tabs.TabPages[1].Controls.Add($overview)
    $overview.Controls.Add($Cards,0,0);$overview.Controls.Add($Charts,0,1)

    $servicePage=$script:Tabs.TabPages[2]
    $serviceHeader=New-Object System.Windows.Forms.Panel
    $serviceHeader.Dock='Top';$serviceHeader.Height=68
    $servicePage.Controls.Add($serviceHeader)
    $script:ServiceNote=New-MiLabel $script:VersionInfo.ServiceNote 9
    $script:ServiceNote.Dock='Bottom';$script:ServiceNote.Height=26
    $serviceHeader.Controls.Add($script:ServiceNote)
    $script:ServiceSearch=New-Object System.Windows.Forms.TextBox
    $script:ServiceSearch.SetBounds(10,7,245,27);$serviceHeader.Controls.Add($script:ServiceSearch)
    $serviceRefresh=New-MiButton '刷新服务（只读）' 160
    $serviceRefresh.SetBounds(270,5,160,30);$serviceHeader.Controls.Add($serviceRefresh)
    $script:ServiceActions=New-Object System.Windows.Forms.FlowLayoutPanel
    $script:ServiceActions.Dock='Bottom';$script:ServiceActions.Height=46
    $script:ServiceActions.Padding=[Windows.Forms.Padding]::new(10,5,0,0)
    $serviceApprove=New-MiButton '管理员批准' 120
    $serviceRevoke=New-MiButton '撤销批准' 120
    $serviceStop=New-MiButton '受控停止' 120
    $serviceRestore=New-MiButton '手动恢复' 120
    foreach ($control in @($serviceApprove,$serviceRevoke,$serviceStop,$serviceRestore)) { $script:ServiceActions.Controls.Add($control) }
    $script:MiServiceButtons=[pscustomobject]@{Approve=$serviceApprove;Revoke=$serviceRevoke;Stop=$serviceStop;Restore=$serviceRestore}
    $servicePage.Controls.Add($script:ServiceActions)
    $script:ServiceGrid=New-MiV4DataGrid -Defs @(
        @('Name','ServiceName',25),@('Display','显示名',28),@('State','状态',12),
        @('Start','启动类型',12),@('PID','宿主 PID',9),@('Risk','安全状态',14)
    )
    $servicePage.Controls.Add($script:ServiceGrid);$script:ServiceGrid.BringToFront()
    $script:ServiceSearch.Add_TextChanged({ Render-MiV4Services })
    $script:ServiceGrid.Add_SelectionChanged({Update-MiV4ServiceButtons})
    $serviceRefresh.Add_Click({Start-MiV4ServicesLoad})
    $serviceApprove.Add_Click({Request-MiV4ServiceAction -Operation ApproveService})
    $serviceRevoke.Add_Click({Request-MiV4ServiceAction -Operation RevokeServiceApproval})
    $serviceStop.Add_Click({Request-MiV4ServiceAction -Operation StopApprovedService})
    $serviceRestore.Add_Click({Request-MiV4ServiceAction -Operation StartPreviouslyStoppedService})
    Update-MiV4ServiceButtons

    $historyPage=$script:Tabs.TabPages[3]
    $hbar=New-Object System.Windows.Forms.Panel
    $hbar.Dock='Top';$hbar.Height=66
    $historyPage.Controls.Add($hbar)
    $script:HistoryRange=New-Object System.Windows.Forms.ComboBox
    $script:HistoryRange.DropDownStyle='DropDownList'
    $script:HistoryRange.SetBounds(10,5,100,28)
    [void]$script:HistoryRange.Items.AddRange([object[]]@(1,7,30,90))
    $script:HistoryRange.SelectedIndex=1
    $hbar.Controls.Add($script:HistoryRange)
    $logButton=New-MiButton '操作记录' 118
    $logButton.SetBounds(252,3,118,31);$hbar.Controls.Add($logButton)
    $logButton.Add_Click({Show-MiActionLog})
    $hReload=New-MiButton '读取历史' 122
    $hReload.SetBounds(120,3,122,31);$hbar.Controls.Add($hReload)
    $script:HistoryNote=New-MiLabel '后台加载 90 天五分钟聚合数据；进程操作记录可通过右上按钮查看。' 9
    $script:HistoryNote.Dock='Bottom';$script:HistoryNote.Height=26;$hbar.Controls.Add($script:HistoryNote)
    $script:HistoryChart=New-MiV4Chart
    $historyPage.Controls.Add($script:HistoryChart);$script:HistoryChart.BringToFront()
    $script:HistoryRange.Add_SelectedIndexChanged({ Render-MiV4History })
    $hReload.Add_Click({Start-MiV4HistoryLoad})

    $settingsPage=$script:Tabs.TabPages[4]
    $settingsPanel=New-Object System.Windows.Forms.FlowLayoutPanel
    $settingsPanel.Dock='Fill';$settingsPanel.AutoScroll=$true;$settingsPanel.FlowDirection='TopDown'
    $settingsPanel.WrapContents=$false;$settingsPanel.Padding=[Windows.Forms.Padding]::new(22,22,12,12)
    $settingsPage.Controls.Add($settingsPanel)
    $head=New-MiLabel '用户界面与监控偏好（仅影响当前用户）' 12 $true
    $head.Size=[Drawing.Size]::new(640,44);$settingsPanel.Controls.Add($head)
    $periodLabel=New-MiLabel '采样间隔（秒）：保存后重启采样器生效，默认 5 秒。' 9
    $periodLabel.Size=[Drawing.Size]::new(640,28);$settingsPanel.Controls.Add($periodLabel)
    $script:SampleSetting=New-Object System.Windows.Forms.NumericUpDown
    $script:SampleSetting.Minimum=5;$script:SampleSetting.Maximum=60
    $script:SampleSetting.Value=[decimal]($script:PeriodMs/1000)
    $script:SampleSetting.Width=120;$settingsPanel.Controls.Add($script:SampleSetting)
    $growthLabel=New-MiLabel '疑似增长阈值：同时满足绝对增长（MiB）与相对增长（%）；重启采样器后生效。' 9
    $growthLabel.Size=[Drawing.Size]::new(740,32);$settingsPanel.Controls.Add($growthLabel)
    $script:GrowthSetting=New-Object System.Windows.Forms.NumericUpDown
    $script:GrowthSetting.Minimum=64;$script:GrowthSetting.Maximum=8192
    $script:GrowthSetting.Increment=64;$script:GrowthSetting.Value=$script:GrowthMiB
    $script:GrowthSetting.Width=130;$settingsPanel.Controls.Add($script:GrowthSetting)
    $script:GrowthPercentSetting=New-Object System.Windows.Forms.NumericUpDown
    $script:GrowthPercentSetting.Minimum=5;$script:GrowthPercentSetting.Maximum=200
    $script:GrowthPercentSetting.Value=$script:GrowthPercent
    $script:GrowthPercentSetting.Width=130;$settingsPanel.Controls.Add($script:GrowthPercentSetting)
    $script:TraySetting=New-Object System.Windows.Forms.CheckBox
    $script:TraySetting.Text='点击 X 时最小化到系统托盘；使用托盘菜单“完全退出”结束程序。'
    $script:TraySetting.Checked=$script:CloseToTray
    $script:TraySetting.Size=[Drawing.Size]::new(650,43);$settingsPanel.Controls.Add($script:TraySetting)
    $script:MiPrivilegeNote=New-MiLabel $script:VersionInfo.PrivilegeNote 9
    $script:MiPrivilegeNote.Size=[Drawing.Size]::new(750,45)
    $settingsPanel.Controls.Add($script:MiPrivilegeNote)
    $verifyButton=New-MiButton '验证管理员执行器（UAC）' 260
    $verifyButton.Enabled=(Test-MiPrivilegeBridgeInstalled)
    $settingsPanel.Controls.Add($verifyButton)
    $verifyButton.Add_Click({
        try {
            $state=Start-MiPrivilegeProbe
            if ($state -eq 'UacCancelled') { $script:MiPrivilegeNote.Text='用户取消 UAC；未执行高权限操作。' }
            else { $script:MiPrivilegeNote.Text='已请求一次性 UAC Probe；等待受保护执行器核验。' }
            Set-MiStatus $script:MiPrivilegeNote.Text
        } catch {
            $script:MiPrivilegeNote.Text='UAC Probe 被阻止：'+$_.Exception.Message
            Set-MiStatus $script:MiPrivilegeNote.Text $true
        }
    })
    $save=New-MiButton '保存 GUI 设置' 170;$settingsPanel.Controls.Add($save)
    $script:SettingsNote=New-MiLabel '诊断窗口 30 分钟，至少 85% 有效样本；历史 7 天原始 / 90 天聚合。M7 服务操作仅能在受保护安装下授权执行；不会直接 Kill 服务宿主。' 9
    $script:SettingsNote.Size=[Drawing.Size]::new(740,60);$settingsPanel.Controls.Add($script:SettingsNote)
    $save.Add_Click({
        try { Save-MiV4Settings }
        catch { $script:SettingsNote.Text='保存失败：'+$_.Exception.Message }
    })

    $script:Tabs.Add_SelectedIndexChanged({
        if ($script:Tabs.SelectedIndex -eq 2 -and $script:ServiceRows.Count -eq 0) { Start-MiV4ServicesLoad }
        if ($script:Tabs.SelectedIndex -eq 3 -and $script:AggregateHistory.Count -eq 0) { Start-MiV4HistoryLoad }
    })

    $script:TrayMenu=New-Object System.Windows.Forms.ContextMenuStrip
    $showItem=$script:TrayMenu.Items.Add('打开 MemoryInspector')
    $exitItem=$script:TrayMenu.Items.Add('完全退出')
    $script:TrayIcon=New-Object System.Windows.Forms.NotifyIcon
    $script:TrayIcon.Icon=[Drawing.SystemIcons]::Information
    $script:TrayIcon.Text=$script:VersionInfo.TrayText
    $script:TrayIcon.ContextMenuStrip=$script:TrayMenu
    $script:TrayIcon.Visible=$true
    $showItem.Add_Click({$script:Form.Show();$script:Form.WindowState='Normal';$script:Form.Activate()})
    $script:TrayIcon.Add_DoubleClick({$script:Form.Show();$script:Form.WindowState='Normal';$script:Form.Activate()})
    $exitItem.Add_Click({$script:ExitRequested=$true;$script:Form.Close()})
}
function Close-MiV4Gui {
    foreach ($job in @($script:AuxJobs.Values)) {
        try { if (-not $job.Handle.IsCompleted) { [void]$job.PowerShell.BeginStop($null,$null) } }
        catch {}
        try { if ($job.Handle.IsCompleted) { [void]$job.PowerShell.EndInvoke($job.Handle);$job.PowerShell.Dispose() } }
        catch {}
    }
    if ($script:TrayIcon) {
        $script:TrayIcon.Visible=$false
        $script:TrayIcon.Dispose()
    }
    if ($script:TrayMenu) { $script:TrayMenu.Dispose() }
}
