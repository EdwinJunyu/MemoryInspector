#requires -Version 5.1
<#
Milestone 1 read-only collector.
All outputs are scalar snapshots. Never return live System.Diagnostics.Process objects.
No mutating operations, no process termination, no privilege elevation.
#>

function Get-MiSystemSnapshot {
    $result = [ordered]@{
        Status                 = 'Failed'
        TotalPhysicalBytes     = $null
        AvailablePhysicalBytes = $null
        UsedPhysicalBytes      = $null
        CommittedBytes         = $null
        CommitLimitBytes       = $null
        PagedPoolBytes         = $null
        NonpagedPoolBytes      = $null
        Error                  = $null
    }
    try {
        $memory = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($null -eq $memory -or $null -eq $os) { throw 'CIM 返回了空记录。' }

        $total = [long]$os.TotalVisibleMemorySize * 1024L
        # Prefer the performance counter for Available RAM; Win32_OperatingSystem is fallback.
        $available = $null
        if ($null -ne $memory.AvailableBytes) {
            $available = [long]$memory.AvailableBytes
        } elseif ($null -ne $os.FreePhysicalMemory) {
            $available = [long]$os.FreePhysicalMemory * 1024L
        }
        $committed = [long]$memory.CommittedBytes
        $limit = [long]$memory.CommitLimit
        if ($total -le 0 -or $null -eq $available -or $available -lt 0 -or
            $available -gt $total -or $limit -le 0 -or $committed -lt 0) {
            throw 'CIM 内存计数器缺失或数值无效。'
        }

        $result.TotalPhysicalBytes = $total
        $result.AvailablePhysicalBytes = $available
        $result.UsedPhysicalBytes = $total - $available
        $result.CommittedBytes = $committed
        $result.CommitLimitBytes = $limit
        if ($null -ne $memory.PoolPagedBytes) { $result.PagedPoolBytes = [long]$memory.PoolPagedBytes }
        if ($null -ne $memory.PoolNonpagedBytes) { $result.NonpagedPoolBytes = [long]$memory.PoolNonpagedBytes }
        $result.Status = if ($null -ne $result.PagedPoolBytes -and $null -ne $result.NonpagedPoolBytes) { 'Success' } else { 'Partial' }
        if ($result.Status -eq 'Partial') { $result.Error = '无法读取一个或多个内存池计数器。' }
    } catch {
        $result.Error = [string]$_.Exception.Message
    }
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
