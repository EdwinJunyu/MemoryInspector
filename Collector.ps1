#requires -Version 5.1
<#
Milestone 1 read-only collector.
All outputs are scalar snapshots. Never return live System.Diagnostics.Process objects.
No mutating operations, no process termination, no privilege elevation.
#>

function Initialize-MiCollectorProcessTimes {
    # .NET Framework 的 Process.StartTime 在部分受限进程上有昂贵的失败路径。
    # 只申请 QUERY_LIMITED_INFORMATION，每轮重新读同一 Windows 创建时间；不缓存 PID 身份。
    # 这里没有终止、写内存或调试权限，失败仍返回 null，动作模块继续独立完整复核身份。
    if ($null -ne ('MemoryInspector.CollectorProcessTimes' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace MemoryInspector {
    public static class CollectorProcessTimes {
        private const uint QueryLimitedInformation = 0x1000;
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(SafeProcessHandle process,
            out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(SafeProcessHandle process, int flags,
            StringBuilder name, ref int size);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry {
            public uint Size, Usage, Pid;
            public UIntPtr Heap;
            public uint Module, Threads, Parent;
            public int Priority;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32First(SafeFileHandle snapshot, ref ProcessEntry entry);
        [DllImport("kernel32.dll", EntryPoint = "Process32NextW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32Next(SafeFileHandle snapshot, ref ProcessEntry entry);
        // 只读枚举父 PID；调用方还需核对父子创建时间，不能直接把 PID 当作实例关系。
        public static Dictionary<int,int> ReadParents() {
            var result = new Dictionary<int,int>();
            using (var snapshot = CreateToolhelp32Snapshot(2, 0)) {
                if (snapshot == null || snapshot.IsInvalid) return result;
                var entry = new ProcessEntry(); entry.Size = (uint)Marshal.SizeOf(entry);
                if (!Process32First(snapshot, ref entry)) return result;
                do { result[(int)entry.Pid] = (int)entry.Parent; }
                while (Process32Next(snapshot, ref entry));
            }
            return result;
        }
        public static string ReadImagePath(int pid, long expectedTicks) {
            using (var handle = OpenProcess(QueryLimitedInformation, false, pid)) {
                if (handle == null || handle.IsInvalid) return null;
                long creation, exit, kernel, user;
                if (!GetProcessTimes(handle, out creation, out exit, out kernel, out user) ||
                    DateTime.FromFileTimeUtc(creation).Ticks != expectedTicks) return null;
                int size = 32768; var name = new StringBuilder(size);
                return QueryFullProcessImageName(handle, 0, name, ref size) ? name.ToString() : null;
            }
        }
        public static long? ReadStartUtcTicks(int processId) {
            if (processId <= 0) return null;
            try {
                // 每次调用都释放句柄，不保留跨采样状态或任何操作能力。
                using (SafeProcessHandle handle = OpenProcess(QueryLimitedInformation, false, processId)) {
                    if (handle == null || handle.IsInvalid) return null;
                    long creation, exit, kernel, user;
                    if (!GetProcessTimes(handle, out creation, out exit, out kernel, out user) || creation <= 0)
                        return null;
                    return DateTime.FromFileTimeUtc(creation).Ticks;
                }
            } catch { return null; }
        }
    }
}
'@ -ErrorAction Stop
}

function Get-MiProcessStartUtcTicks {
    param([int]$ProcessId)
    return [MemoryInspector.CollectorProcessTimes]::ReadStartUtcTicks($ProcessId)
}

function Get-MiMemoryCounter {
    param($Source,[string]$Property,[long]$Scale=1,[long]$Minimum=0)
    # 先检查空值和整数格式再转换，避免 PowerShell 将 $null、空串或无效计数器变成合法的 0。
    try {
        $value=$Source.$Property
        $number=0L
        if ($null -eq $value -or $value -is [bool] -or
            -not [long]::TryParse($value.ToString(),[Globalization.NumberStyles]::Integer,
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
        CacheBytes=$null;StandbyBytes=$null;CompressionBytes=$null
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
    # 可选 RAM 视角：缓存、Standby 可能重叠，不能加入 Commit 或当成可释放量。
    $result.CacheBytes=Get-MiMemoryCounter $memory CacheBytes
    $standby=@('StandbyCacheCoreBytes','StandbyCacheNormalPriorityBytes','StandbyCacheReserveBytes' |
        ForEach-Object { Get-MiMemoryCounter $memory $_ })
    if (@($standby | Where-Object {$null -eq $_}).Count -eq 0 -and $standby.Count -eq 3) {
        $sum=[decimal]$standby[0]+[decimal]$standby[1]+[decimal]$standby[2]
        if ($sum -le [long]::MaxValue) { $result.StandbyBytes=[long]$sum }
    }
    # 当前来源没有可靠的压缩内存字节定义，明确保持 Unavailable，不以进程名称猜测。
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
        Initialize-MiCollectorProcessTimes
        $parentCaptureUtc=[datetime]::UtcNow
        $parents=[MemoryInspector.CollectorProcessTimes]::ReadParents()
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
            ExecutablePath = $null
            ParentPid      = $null
            ParentStartUtcTicks = $null
            Status         = 'Success'
        }
        try {
            $row.PID = [int]$proc.Id
            $row.Name = [string]$proc.ProcessName
            try {
                $row.StartUtcTicks = Get-MiProcessStartUtcTicks -ProcessId $row.PID
                if ($null -eq $row.StartUtcTicks) { $row.Status = 'Partial' }
            } catch { $row.Status = 'Partial' }
            try { $row.PrivateBytes = [long]$proc.PrivateMemorySize64 }
            catch { $row.Status = 'Partial' }
            try { $row.WorkingBytes = [long]$proc.WorkingSet64 }
            catch { $row.Status = 'Partial' }
            if ($null -ne $row.StartUtcTicks) {
                try { $row.ExecutablePath=[MemoryInspector.CollectorProcessTimes]::ReadImagePath($row.PID,$row.StartUtcTicks) } catch {}
                # Get-Process 内含枚举时的缓存；若新实例晚于枚举前时间边界，即使两次
                # 查询都看到新实例，也不能把旧缓存内存归给它。保留数值但移除实例归属。
                if ($row.StartUtcTicks -gt $parentCaptureUtc.Ticks -or
                    (Get-MiProcessStartUtcTicks -ProcessId $row.PID) -ne $row.StartUtcTicks) {
                    $row.StartUtcTicks=$null;$row.ExecutablePath=$null;$row.Status='Partial'
                } elseif ($row.StartUtcTicks -le $parentCaptureUtc.Ticks -and $parents.ContainsKey($row.PID)) {
                    $row.ParentPid=$parents[$row.PID]
                }
            }
            if ($null -eq $row.PrivateBytes -or $null -eq $row.WorkingBytes) { $row.Status = 'Partial' }
            if ($row.Status -ne 'Success') { $incomplete++ }
            $items.Add([pscustomobject]$row)
        } catch {
            $incomplete++
        } finally {
            if ($null -ne $proc) { $proc.Dispose() }
        }
    }
    $byPid=@{}
    foreach ($item in $items) { $byPid[$item.PID]=$item }
    foreach ($item in $items) {
        if ($null -eq $item.ParentPid -or $item.ParentPid -eq $item.PID -or -not $byPid.ContainsKey($item.ParentPid)) { continue }
        $parent=$byPid[$item.ParentPid]
        if ($null -ne $item.StartUtcTicks -and $null -ne $parent.StartUtcTicks -and $parent.StartUtcTicks -le $item.StartUtcTicks) {
            $item.ParentStartUtcTicks=$parent.StartUtcTicks
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
