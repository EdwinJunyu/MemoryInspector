#requires -Version 5.1
<#
Milestone 1 read-only collector.
All outputs are scalar snapshots. Never return live System.Diagnostics.Process objects.
No mutating operations, no process termination, no privilege elevation.
#>

function Get-MiMemoryCounter {
    param($Source,[string]$Property,[long]$Scale=1,[long]$Minimum=0)
    # 先检查空值和整数格式再转换，避免 PowerShell 将 $null、空串或无效计数器变成合法的 0。
    try {
        $value=$Source.$Property
        $number=0L
        if ($null -eq $value -or $value -is [bool] -or
            -not [long]::TryParse([string]$value,[Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,[ref]$number) -or $number -lt $Minimum) { return $null }
        $bytes=[decimal]$number*$Scale
        if ($bytes -gt [long]::MaxValue) { return $null }
        return [long]$bytes
    } catch { return $null }
}

function Get-MiSystemSnapshot {
    $result = [ordered]@{
        Status='Failed';TotalPhysicalBytes=$null;AvailablePhysicalBytes=$null;UsedPhysicalBytes=$null
        CommittedBytes=$null;CommitLimitBytes=$null;PagedPoolBytes=$null;NonpagedPoolBytes=$null;Error=$null
    }
    $errors=New-Object 'System.Collections.Generic.List[string]'
    $memory=$null;$os=$null
    # 两个只读来源独立失败；保留本轮仍可验证的字段，不回填上一轮数据。
    try { $memory=Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop }
    catch { $errors.Add('内存计数器读取失败：'+$_.Exception.Message) }
    try { $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    catch { $errors.Add('物理内存读取失败：'+$_.Exception.Message) }
    $result.TotalPhysicalBytes=Get-MiMemoryCounter $os TotalVisibleMemorySize -Scale 1024 -Minimum 1
    $result.AvailablePhysicalBytes=Get-MiMemoryCounter $memory AvailableBytes
    if ($null -eq $result.AvailablePhysicalBytes) {
        $result.AvailablePhysicalBytes=Get-MiMemoryCounter $os FreePhysicalMemory -Scale 1024
    }
    if ($null -ne $result.TotalPhysicalBytes -and $null -ne $result.AvailablePhysicalBytes) {
        if ($result.AvailablePhysicalBytes -gt $result.TotalPhysicalBytes) {
            $result.AvailablePhysicalBytes=$null
            $errors.Add('可用物理内存超过总量。')
        } else { $result.UsedPhysicalBytes=$result.TotalPhysicalBytes-$result.AvailablePhysicalBytes }
    }
    $result.CommittedBytes=Get-MiMemoryCounter $memory CommittedBytes
    $result.CommitLimitBytes=Get-MiMemoryCounter $memory CommitLimit -Minimum 1
    $result.PagedPoolBytes=Get-MiMemoryCounter $memory PoolPagedBytes
    $result.NonpagedPoolBytes=Get-MiMemoryCounter $memory PoolNonpagedBytes
    $missing=@('TotalPhysicalBytes','AvailablePhysicalBytes','UsedPhysicalBytes','CommittedBytes',
        'CommitLimitBytes','PagedPoolBytes','NonpagedPoolBytes' | Where-Object { $null -eq $result[$_] })
    if ($missing.Count -eq 0 -and $errors.Count -eq 0) { $result.Status='Success' }
    elseif ($missing.Count -lt 7) { $result.Status='Partial' }
    if ($missing.Count -gt 0) { $errors.Add('Unavailable：'+($missing -join ', ')) }
    if ($errors.Count -gt 0) { $result.Error=$errors -join '；' }
    return [pscustomobject]$result
}
function Get-MiProcessSnapshot {
    $items = New-Object 'System.Collections.Generic.List[object]'
    $incomplete = 0
    $errorText = $null
    try {
        $processes = @(Get-Process -ErrorAction Stop)
    } catch {
        return [pscustomobject]@{
            Status = 'Failed'; Items = @(); Total = 0; Incomplete = 0
            Error = [string]$_.Exception.Message
        }
    }

    foreach ($proc in $processes) {
        $row = [ordered]@{
            PID            = $null
            Name           = $null
            StartUtcTicks  = $null
            PrivateBytes   = $null
            WorkingBytes   = $null
            Status         = 'Success'
        }
        try {
            $row.PID = [int]$proc.Id
            $row.Name = [string]$proc.ProcessName
            try {
                $start = $proc.StartTime
                if ($null -ne $start) { $row.StartUtcTicks = [long]$start.ToUniversalTime().Ticks }
            } catch { $row.Status = 'Partial' }
            try { $row.PrivateBytes = [long]$proc.PrivateMemorySize64 }
            catch { $row.Status = 'Partial' }
            try { $row.WorkingBytes = [long]$proc.WorkingSet64 }
            catch { $row.Status = 'Partial' }
            if ($null -eq $row.PrivateBytes -or $null -eq $row.WorkingBytes) { $row.Status = 'Partial' }
            if ($row.Status -ne 'Success') { $incomplete++ }
            $items.Add([pscustomobject]$row)
        } catch {
            $incomplete++
        } finally {
            if ($null -ne $proc) { $proc.Dispose() }
        }
    }
    $status = if ($incomplete -eq 0) { 'Success' } else { 'Partial' }
    if ($items.Count -eq 0) { $status = 'Failed'; $errorText = '没有取得任何有效进程记录。' }
    elseif ($incomplete -gt 0) { $errorText = ('{0} 条进程信息不完整（可能是权限限制或进程退出）。' -f $incomplete) }
    return [pscustomobject]@{
        Status = $status
        Items = $items.ToArray()
        Total = $items.Count
        Incomplete = $incomplete
        Error = $errorText
    }
}

function Get-MiSnapshot {
    param([int]$Sequence)
    $started = [datetime]::UtcNow
    $sys = Get-MiSystemSnapshot
    $proc = Get-MiProcessSnapshot
    $ended = [datetime]::UtcNow
    $status = 'Success'
    if ($sys.Status -eq 'Failed' -and $proc.Status -eq 'Failed') { $status = 'Failed' }
    elseif ($sys.Status -ne 'Success' -or $proc.Status -ne 'Success') { $status = 'Partial' }
    return [pscustomobject]@{
        SchemaVersion    = 1
        Sequence         = $Sequence
        CaptureStartUtc  = $started
        CaptureEndUtc    = $ended
        DurationMs       = [int][math]::Max(0,($ended-$started).TotalMilliseconds)
        Status           = $status
        System           = $sys
        Processes        = $proc
    }
}
