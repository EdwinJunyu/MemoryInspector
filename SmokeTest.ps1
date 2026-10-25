#requires -Version 5.1
<# Read-only smoke test, run on Windows PowerShell 5.1. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Collector.ps1')
$sample = Get-MiSnapshot -Sequence 1
if ($sample.SchemaVersion -ne 1 -or $sample.Sequence -ne 1) {
    throw 'Snapshot schema / sequence mismatch.'
}
if ($sample.CaptureEndUtc -lt $sample.CaptureStartUtc) {
    throw 'Snapshot clock order mismatch.'
}
if ($sample.System.Status -eq 'Success') {
    if ($sample.System.TotalPhysicalBytes -le 0 -or $sample.System.CommitLimitBytes -le 0) {
        throw 'System metrics must be positive.'
    }
}
if ($sample.Processes.Status -ne 'Failed') {
    if ($sample.Processes.Total -ne @($sample.Processes.Items).Count) {
        throw 'Process count mismatch.'
    }
}
Write-Host ('Snapshot: {0}; System: {1}; Processes: {2}; Rows: {3}' -f
    $sample.Status,$sample.System.Status,$sample.Processes.Status,$sample.Processes.Total)
if ($sample.Status -eq 'Failed') {
    throw ('All collection sources failed. System={0}; Process={1}' -f
        $sample.System.Error,$sample.Processes.Error)
}
Write-Host 'PASS: snapshot schema and available collection sources.' -ForegroundColor Green


# P2-01：独立模拟 CIM 来源，绝不修改真实计数器；每个无效值都必须保持 null。
& {
    $script:MemoryFixture=[pscustomobject]@{CommittedBytes=4GB;CommitLimit=16GB;AvailableBytes=3GB;PoolPagedBytes=64MB;PoolNonpagedBytes=32MB}
    $script:OsFixture=[pscustomobject]@{TotalVisibleMemorySize=8GB/1KB;FreePhysicalMemory=3GB/1KB}
    $script:FailSource=''
    function Get-CimInstance {
        param($ClassName,$ErrorAction)
        if ($script:FailSource -eq 'All' -or $script:FailSource -eq $ClassName) { throw 'Injected CIM failure' }
        if ($ClassName -eq 'Win32_OperatingSystem') { return $script:OsFixture }
        return $script:MemoryFixture
    }
    foreach ($field in @('CommittedBytes','CommitLimit','PoolPagedBytes','PoolNonpagedBytes')) {
        $saved=$script:MemoryFixture.$field
        $outputField=switch ($field) {'CommitLimit' {'CommitLimitBytes'} 'PoolPagedBytes' {'PagedPoolBytes'} 'PoolNonpagedBytes' {'NonpagedPoolBytes'} default {$field}}
        foreach ($invalid in @($null,'','bad',-1,'NaN','Infinity',1.5,$true,[decimal]::MaxValue)) {
            $script:MemoryFixture.$field=$invalid
            $result=Get-MiSystemSnapshot
            if ($result.Status -ne 'Partial' -or $null -ne $result.$outputField -or $result.Error -notmatch 'Unavailable') {
                throw ('Invalid memory counter became available: '+$field+' / '+[string]$invalid)
            }
        }
        $script:MemoryFixture.$field=$saved
    }
    $script:MemoryFixture.CommittedBytes=0L
    if ((Get-MiSystemSnapshot).CommittedBytes -cne 0L) { throw 'Legitimate zero commit was rejected.' }
    $script:MemoryFixture.CommitLimit=0L
    if ($null -ne (Get-MiSystemSnapshot).CommitLimitBytes) { throw 'Zero commit limit was accepted.' }
    $script:MemoryFixture.CommitLimit=16GB
    $script:MemoryFixture.AvailableBytes='invalid'
    if ((Get-MiSystemSnapshot).AvailablePhysicalBytes -ne 3GB) { throw 'Validated OS fallback failed.' }
    $script:MemoryFixture.AvailableBytes=9GB
    if ($null -ne (Get-MiSystemSnapshot).AvailablePhysicalBytes) { throw 'Available RAM exceeded physical total.' }
    $script:FailSource='Win32_PerfFormattedData_PerfOS_Memory'
    $result=Get-MiSystemSnapshot
    if ($result.Status -ne 'Partial' -or $null -ne $result.CommittedBytes -or $result.TotalPhysicalBytes -ne 8GB) { throw 'CIM failure fabricated commit or lost valid RAM.' }
    $script:FailSource='All'
    $result=Get-MiSystemSnapshot
    if ($result.Status -ne 'Failed' -or $null -ne $result.CommittedBytes -or $null -ne $result.TotalPhysicalBytes) { throw 'Complete CIM failure fabricated zero memory.' }
    $script:FailSource=''
    $script:MemoryFixture=$null;$script:OsFixture=$null
    if ((Get-MiSystemSnapshot).Status -ne 'Failed') { throw 'Empty CIM records were accepted.' }
}
Write-Host 'PASS: P2-01 null/invalid/overflow/zero counters, partial sources, fallback and CIM failures.' -ForegroundColor Green

# 本轮性能修复仍读取真实 Windows 创建时间，不能靠缓存身份或把失败改成零提速。
$self=Get-Process -Id $PID
try {
    $expectedTicks=$self.StartTime.ToUniversalTime().Ticks
    if ((Get-MiProcessStartUtcTicks -ProcessId $PID) -ne $expectedTicks -or
        (Get-MiProcessStartUtcTicks -ProcessId $PID) -ne $expectedTicks) {throw 'Limited-query creation time differs from the actual process identity.'}
    foreach($invalidPid in @(0,-1,2147483647)) {
        if ($null -ne (Get-MiProcessStartUtcTicks -ProcessId $invalidPid)) {throw 'Unavailable creation time became a valid identity.'}
    }
    $self.Refresh();$handlesBefore=$self.HandleCount
    for($i=0;$i -lt 200;$i++) {[void](Get-MiProcessStartUtcTicks -ProcessId $PID)}
    $self.Refresh()
    if ($self.HandleCount -gt $handlesBefore+8) {throw 'Creation-time sampling leaked process handles.'}
} finally {$self.Dispose()}
& {
    $script:KnownCreationTicks=$expectedTicks
    function Get-MiProcessStartUtcTicks {param($ProcessId) return $script:KnownCreationTicks}
    function Get-Process {
        param($ErrorAction)
        $p=[pscustomobject]@{Id=42;ProcessName='collector-fixture';PrivateMemorySize64=8MB;WorkingSet64=4MB}
        $p|Add-Member ScriptProperty StartTime {throw 'Slow legacy StartTime getter must not be called.'}
        $p|Add-Member ScriptMethod Dispose {}
        return $p
    }
    $known=Get-MiProcessSnapshot
    if ($known.Status -ne 'Success' -or $known.Items[0].StartUtcTicks -ne $expectedTicks) {throw 'Fresh collector identity was lost.'}
    $script:KnownCreationTicks=$null
    $unknown=Get-MiProcessSnapshot
    if ($unknown.Status -ne 'Partial' -or $unknown.Incomplete -ne 1 -or $null -ne $unknown.Items[0].StartUtcTicks -or
        $unknown.Items[0].PrivateBytes -ne 8MB) {throw 'Unavailable identity was fabricated or valid independent memory was lost.'}
}
Write-Host 'PASS: fresh limited-query creation times, failure/null identity, handle release and no legacy getter.' -ForegroundColor Green
