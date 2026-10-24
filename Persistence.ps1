#requires -Version 5.1
<#
MemoryInspector v0.0.2 - user-scoped JSONL persistence.
Writes only to %LOCALAPPDATA%\MemoryInspector. No process/service operations.
Single writer via named mutex; errors fail closed for disk writes, not monitoring.
#>
function Set-MiPersistenceFailure {
    param($State,$Failure,[string]$Prefix='历史写入失败：',[switch]$Permanent)
    $errorObject=$Failure
    if ($Failure -is [Management.Automation.ErrorRecord]) { $errorObject=$Failure.Exception }
    $integrityFailure=$false
    while ($errorObject -is [Exception]) {
        if ($errorObject -is [IO.InvalidDataException]) { $integrityFailure=$true }
        if (-not $errorObject.InnerException) { break }
        $errorObject=$errorObject.InnerException
    }
    $State.Healthy=$false
    $State.FailureKind=if ($Permanent -or $integrityFailure) {'Permanent'} else {'Transient'}
    $State.Warning=$Prefix+[string]$errorObject.Message
    $State.LastFailurePath=$State.WritePath
    $State.NextRecoveryUtc=[datetime]::UtcNow.AddSeconds($State.RecoveryIntervalSeconds)
}
function Read-MiPersistenceSettings {
    param([string]$Path)
    try {
        $c=([IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8)|ConvertFrom-Json -ErrorAction Stop)
        if ([int]$c.SchemaVersion -ne 1 -or [int]$c.RawDays -lt 1 -or [int]$c.RawDays -gt 30 -or
            [int]$c.AggregateDays -lt 1 -or [int]$c.AggregateDays -gt 365 -or
            [long]$c.DiskBudgetBytes -lt 4096 -or [int]$c.TopProcessCount -lt 1 -or
            [int]$c.TopProcessCount -gt 500 -or [int]$c.OtherProcessIntervalSeconds -lt 10 -or
            [int]$c.OtherProcessIntervalSeconds -gt 3600) {
            throw [IO.InvalidDataException]::new('settings.json 无效；保留原文件，不覆盖用户设置。')
        }
        return $c
    } catch {
        $e=$_.Exception
        while ($e.InnerException) { $e=$e.InnerException }
        if ($e -is [IO.IOException] -or $e -is [UnauthorizedAccessException]) { throw }
        throw [IO.InvalidDataException]::new(('settings.json 无效；保留原文件：'+$e.Message),$e)
    }
}
function Initialize-MiPersistenceStorage {
    param($State,[switch]$Recovering)
    foreach ($dir in @('system','process','aggregates','archives')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $State.Root $dir))
    }
    if (-not $State.Mutex) {
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $sha=[Security.Cryptography.SHA256]::Create()
        try {
            $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($State.Root.ToLowerInvariant()))).Replace('-','')
        } finally { $sha.Dispose() }
        # Global 同时保护同一用户在不同 Windows 会话中的历史写入。
        $State.Mutex=[Threading.Mutex]::new($false,('Global\MemoryInspectorHistory_'+$sid.Replace('-','_')+'_'+$hash))
    }
    if ($Recovering -and $State.Locked) {
        # ReleaseMutex 只有拥有线程才能调用；重新获取后才进行恢复验证，状态不明一律拒绝。
        try { $State.Mutex.ReleaseMutex();$State.Locked=$false }
        catch { throw [IO.InvalidDataException]::new('恢复写锁的线程所有权无法确认，拒绝写入。',$_.Exception) }
    }
    if (-not $State.Locked) {
        try { $State.Locked=$State.Mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $State.Locked=$true }
    }
    if (-not $State.Locked) { throw [IO.IOException]::new('另一个实例已经持有此目录的写入锁。') }
    $configFile=Join-Path $State.Root 'settings.json'
    if ([IO.File]::Exists($configFile)) { $State.SettingsEverExisted=$true }
    if (-not [IO.File]::Exists($configFile)) {
        if ($Recovering -and $State.SettingsEverExisted) { throw [IO.InvalidDataException]::new('恢复时 settings.json 缺失；拒绝重建或覆盖用户设置。') }
        $settings=[ordered]@{
            SchemaVersion=1; RawDays=7; AggregateDays=90; DiskBudgetBytes=2147483648L
            TopProcessCount=60; OtherProcessIntervalSeconds=60
        }
        $tmp=$configFile+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        try {
            [IO.File]::WriteAllText($tmp,($settings|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
            [IO.File]::Move($tmp,$configFile)
        } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
    }
    $State.SettingsEverExisted=$true
    $State.Settings=Read-MiPersistenceSettings -Path $configFile
    if ($Recovering) {
        # 恢复只验证原文件，绝不通过截断/删除损坏文件恢复健康状态。
        $usage=[long]0
        foreach ($kind in @('system','process','aggregates','archives')) {
            foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -File -ErrorAction Stop)) {
                $usage+=[long]$file.Length
                if ($file.Extension -eq '.jsonl') { Test-MiJsonlRecoveryFile -Path $file.FullName }
            }
            $probe=Join-Path (Join-Path $State.Root $kind) ('.mi-write-probe.'+[guid]::NewGuid().ToString('N')+'.tmp')
            $f=$null
            try {
                $f=[IO.File]::Open($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                $f.WriteByte(10);$f.Flush($true)
                [void]$f.Seek(0,[IO.SeekOrigin]::Begin)
                if ($f.ReadByte() -ne 10) { throw [IO.IOException]::new('持久化目录读写验证失败。') }
            } finally {
                if ($f) { $f.Dispose() }
                if ([IO.File]::Exists($probe)) { [IO.File]::Delete($probe) }
            }
        }
        if ($usage -gt [long]$State.Settings.DiskBudgetBytes) { throw [IO.IOException]::new('磁盘预算仍不足，继续暂停历史保存。') }
    }
    if ($State.BootId -eq 'BootUnavailable') {
        try {
            $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $State.BootId='{0}_{1}' -f $env:COMPUTERNAME,$os.LastBootUpTime.ToUniversalTime().Ticks
        } catch { }
    }
    $State.Bucket=$null;$State.SavedBuckets=@{};$State.Repaired=@{}
    Restore-MiPendingBucket -State $State
}
function New-MiPersistence {
    param([string]$Root = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector'))
    $canonicalRoot=[IO.Path]::GetFullPath($Root)
    if ($canonicalRoot.Length -gt [IO.Path]::GetPathRoot($canonicalRoot).Length) { $canonicalRoot=$canonicalRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) }
    $s = [pscustomobject]@{
        Root=$canonicalRoot; Healthy=$false; Warning=$null; Mutex=$null; Locked=$false
        Settings=$null; SettingsEverExisted=$false; Bucket=$null; Repaired=@{}; SavedBuckets=@{}; LastAppendIdentity=@{}
        LastFullUtc=[datetime]::MinValue; NextMaintenanceUtc=[datetime]::MinValue
        BootId='BootUnavailable'; LastSaveUtc=$null; Closed=$false
        FailureKind='None'; RecoveryAttempts=0; RecoveryIntervalSeconds=30
        NextRecoveryUtc=[datetime]::MinValue; RecoveredUtc=$null; WritePath=$null; LastFailurePath=$null
    }
    try { Initialize-MiPersistenceStorage -State $s; $s.Healthy=$true }
    catch {
        Set-MiPersistenceFailure -State $s -Failure $_ -Prefix '历史初始化失败：'
        if ($s.Locked -and $s.Mutex) {
            try { $s.Mutex.ReleaseMutex() } catch {}
            $s.Locked=$false
        }
    }
    return $s
}
function Resume-MiPersistence {
    param($State,[datetime]$NowUtc=[datetime]::UtcNow)
    if (-not $State -or $State.Closed) { return $false }
    if ($State.Healthy) { return $true }
    if ($State.FailureKind -eq 'Permanent' -or $NowUtc.ToUniversalTime() -lt $State.NextRecoveryUtc) { return $false }
    $State.RecoveryAttempts++
    try {
        Initialize-MiPersistenceStorage -State $State -Recovering
        $State.Healthy=$true;$State.FailureKind='None';$State.Warning=$null
        $State.RecoveryIntervalSeconds=30;$State.RecoveredUtc=$NowUtc.ToUniversalTime()
        return $true
    } catch {
        # 单次检查无等待锁；失败后最多每五分钟重试一次，不积累保存任务。
        $State.RecoveryIntervalSeconds=[math]::Min(300,30*[math]::Pow(2,[math]::Min(4,$State.RecoveryAttempts)))
        Set-MiPersistenceFailure -State $State -Failure $_ -Prefix '历史保存尚未恢复：'
        $State.NextRecoveryUtc=$NowUtc.ToUniversalTime().AddSeconds($State.RecoveryIntervalSeconds)
        return $false
    }
}
function Close-MiPersistence {
    param($State)
    if ($null -eq $State) { return }
    $State.Closed=$true;$State.Healthy=$false
    if ($State.Locked -and $State.Mutex) {
        try { $State.Mutex.ReleaseMutex() } catch {}
        $State.Locked=$false
    }
    if ($State.Mutex) { $State.Mutex.Dispose(); $State.Mutex=$null }
}
function Test-MiJsonlRecoveryFile {
    param([string]$Path)
    $f=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        if ($f.Length -eq 0) { return }
        [void]$f.Seek(-1,[IO.SeekOrigin]::End)
        if ($f.ReadByte() -ne 10) { throw [IO.InvalidDataException]::new(('历史文件尾部不完整，保留原文件并拒绝自动恢复：'+$Path)) }
        # 由 4 KiB 起向前扩展，最多 4 MiB；通常只读最后一条记录，避免扫描整段历史。
        $count=[int][math]::Min($f.Length,4096)
        while ($true) {
            [void]$f.Seek(-$count,[IO.SeekOrigin]::End)
            $buffer=New-Object byte[] $count
            $read=0
            while ($read -lt $count) {
                $n=$f.Read($buffer,$read,$count-$read)
                if ($n -le 0) { throw [IO.IOException]::new('历史文件读取未完成。') }
                $read+=$n
            }
            $tail=[Text.Encoding]::UTF8.GetString($buffer).TrimEnd([char[]]@([char]13,[char]10))
            $boundary=$tail.LastIndexOf([char]10)
            if ($boundary -ge 0 -or $count -eq $f.Length) { break }
            if ($count -ge 4MB) { throw [IO.InvalidDataException]::new('历史记录超过恢复校验上限；保留原文件。') }
            $count=[int][math]::Min($f.Length,[math]::Min(4MB,$count*2))
        }
        if ($boundary -ge 0) { $tail=$tail.Substring($boundary+1) }
        try {
            $record=ConvertFrom-Json -InputObject $tail -ErrorAction Stop
            if ($null -eq $record -or [int]$record.SchemaVersion -ne 1) { throw 'Invalid schema.' }
        } catch { throw [IO.InvalidDataException]::new(('历史文件记录损坏，保留原文件：'+$Path),$_.Exception) }
    } finally { $f.Dispose() }
}
function Repair-MiJsonlTail {
    param([string]$Path)
    if (-not [IO.File]::Exists($Path)) { return }
    $f=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        if ($f.Length -eq 0) { return }
        [void]$f.Seek(-1,[IO.SeekOrigin]::End)
        if ($f.ReadByte() -eq 10) { return }
        # 首次启动保留兼容尾修复，但必须先保存完整受损文件及其全部字节。
        $preserved=Join-Path (Split-Path -Parent $Path) 'recovery-preserved'
        [void][IO.Directory]::CreateDirectory($preserved)
        $backup=Join-Path $preserved ([IO.Path]::GetFileName($Path)+'.'+[guid]::NewGuid().ToString('N')+'.damaged')
        $copy=[IO.File]::Open($backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { [void]$f.Seek(0,[IO.SeekOrigin]::Begin);$f.CopyTo($copy);$copy.Flush($true) }
        finally { $copy.Dispose() }
        $i=$f.Length-1
        while ($i -ge 0) {
            [void]$f.Seek($i,[IO.SeekOrigin]::Begin)
            if ($f.ReadByte() -eq 10) { break }
            $i--
        }
        $f.SetLength($i+1); $f.Flush($true)
    } finally { $f.Dispose() }
}
function Get-MiRecordIdentity {
    param($Record)
    if ($Record.RecordType -eq 'FiveMinuteAggregate') { return ('Aggregate|'+$Record.BucketStartUtc) }
    return ('{0}|{1}|{2}' -f $Record.RecordType,$Record.CaptureEndUtc,$Record.Sequence)
}
function Write-MiJsonlBytes {
    param([IO.Stream]$Stream,[byte[]]$Bytes)
    $Stream.Write($Bytes,0,$Bytes.Length)
    $Stream.Flush($true)
}
function Add-MiJsonl {
    param($State,[string]$Path,$Record,[switch]$PassThru)
    $State.WritePath=$Path
    if (-not $State.Repaired.ContainsKey($Path)) {
        Repair-MiJsonlTail -Path $Path
        $State.Repaired[$Path]=$true
    }
    $identity=Get-MiRecordIdentity -Record $Record
    if (-not $State.LastAppendIdentity.ContainsKey($Path)) {
        $last=@(Read-MiJsonTail -Path $Path -Count 1)
        if ($last.Count -gt 0) { $State.LastAppendIdentity[$Path]=Get-MiRecordIdentity -Record $last[-1] }
    }
    if ($State.LastAppendIdentity[$Path] -ceq $identity) {
        $State.WritePath=$null
        if ($PassThru) { return $false }
        return
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Compress -Depth 10 -ErrorAction Stop)+[Environment]::NewLine)
    $f=[IO.File]::Open($Path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        $originalLength=$f.Length
        [void]$f.Seek(0,[IO.SeekOrigin]::End)
        try { Write-MiJsonlBytes -Stream $f -Bytes $bytes }
        catch {
            $writeFailure=$_
            # 只回滚本次追加；回滚未确认时永久拒绝自动恢复，防止重复/损坏。
            try { $f.SetLength($originalLength);$f.Flush($true) }
            catch { throw [IO.InvalidDataException]::new('追加失败且回滚未确认；保留文件，需要人工检查。',$_.Exception) }
            throw $writeFailure
        }
    } finally { $f.Dispose() }
    $State.LastAppendIdentity[$Path]=$identity
    $State.WritePath=$null
    if ($PassThru) { return $true }
}
function Read-MiJsonTail {
    param([string]$Path,[int]$Count=240)
    if (-not [IO.File]::Exists($Path)) { return @() }
    $items=New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $Count -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $o=ConvertFrom-Json -InputObject $line -ErrorAction Stop
            if ($null -ne $o -and [int]$o.SchemaVersion -eq 1) { $items.Add($o) }
        } catch { } # Corrupt lines are never interpreted as successful samples.
    }
    return $items.ToArray()
}
function Get-MiBucketKey {
    param([datetime]$Utc)
    $t=$Utc.ToUniversalTime()
    return ([datetime]::new($t.Year,$t.Month,$t.Day,$t.Hour,([int][math]::Floor($t.Minute/5)*5),0,[DateTimeKind]::Utc)).ToString('yyyy-MM-ddTHH:mm:ssZ')
}
function New-MiBucket {
    param([string]$Key)
    return [pscustomobject]@{
        Key=$Key; Samples=0; SystemSamples=0; CommitSum=[double]0; RamSum=[double]0
        CommitMin=[double]::PositiveInfinity; CommitMax=[double]0; Programs=@{}
    }
}
function Add-MiBucketRecord {
    param($Bucket,$SystemRecord,$ProcessRecord)
    if ($null -ne $SystemRecord) {
        $Bucket.Samples++
        if ($SystemRecord.SystemStatus -ne 'Failed' -and $null -ne $SystemRecord.CommittedBytes -and
            $null -ne $SystemRecord.UsedPhysicalBytes) {
            $v=[double]$SystemRecord.CommittedBytes
            $Bucket.SystemSamples++; $Bucket.CommitSum+=$v
            $Bucket.RamSum += [double]$SystemRecord.UsedPhysicalBytes
            $Bucket.CommitMin=[math]::Min($Bucket.CommitMin,$v)
            $Bucket.CommitMax=[math]::Max($Bucket.CommitMax,$v)
        }
    }
    if ($null -ne $ProcessRecord -and $ProcessRecord.ProcessStatus -ne 'Failed') {
        $totals=@{}
        foreach ($p in @($ProcessRecord.Items)) {
            if ($null -eq $p -or $null -eq $p.PrivateBytes -or [string]::IsNullOrWhiteSpace([string]$p.Name)) { continue }
            $name=[string]$p.Name
            if (-not $totals.ContainsKey($name)) { $totals[$name]=[double]0 }
            $totals[$name] += [double]$p.PrivateBytes
        }
        foreach ($name in $totals.Keys) {
            if (-not $Bucket.Programs.ContainsKey($name)) {
                $Bucket.Programs[$name]=[pscustomobject]@{Name=$name;Samples=0;Sum=[double]0;Peak=[double]0}
            }
            $stat=$Bucket.Programs[$name]
            $stat.Samples++; $stat.Sum+=$totals[$name]; $stat.Peak=[math]::Max($stat.Peak,$totals[$name])
        }
    }
}
function Get-MiAggregatePath {
    param($State,[string]$Key)
    return (Join-Path (Join-Path $State.Root 'aggregates') ('summary-'+$Key.Substring(0,10)+'.jsonl'))
}
function Test-MiBucketSaved {
    param($State,[string]$Key)
    if ($State.SavedBuckets.ContainsKey($Key)) { return $true }
    foreach ($record in @(Read-MiJsonTail -Path (Get-MiAggregatePath -State $State -Key $Key) -Count 400)) {
        if ($record.BucketStartUtc -eq $Key) {
            $State.SavedBuckets[$Key]=$true
            return $true
        }
    }
    return $false
}
function Complete-MiBucket {
    param($State,$Bucket)
    if ($null -eq $Bucket -or $Bucket.Samples -eq 0 -or (Test-MiBucketSaved -State $State -Key $Bucket.Key)) { return }
    $avg=$null;$ram=$null;$minimum=$null;$maximum=$null
    if ($Bucket.SystemSamples -gt 0) {
        $avg=[long]($Bucket.CommitSum/$Bucket.SystemSamples)
        $ram=[long]($Bucket.RamSum/$Bucket.SystemSamples)
        $minimum=[long]$Bucket.CommitMin; $maximum=[long]$Bucket.CommitMax
    }
    $programs=@($Bucket.Programs.Values |
        Sort-Object -Property @{Expression={$_.Sum/[math]::Max(1,$_.Samples)}} -Descending |
        Select-Object -First 60 | ForEach-Object {
            [ordered]@{Name=$_.Name;Samples=$_.Samples;AveragePrivateBytes=[long]($_.Sum/$_.Samples);PeakPrivateBytes=[long]$_.Peak}
        })
    $record=[ordered]@{
        SchemaVersion=1;RecordType='FiveMinuteAggregate';BucketStartUtc=$Bucket.Key
        BucketEndUtc=([datetime]::Parse($Bucket.Key).ToUniversalTime().AddMinutes(5)).ToString('yyyy-MM-ddTHH:mm:ssZ')
        SampleCount=$Bucket.Samples;SystemSampleCount=$Bucket.SystemSamples
        AverageCommittedBytes=$avg;MinimumCommittedBytes=$minimum
        MaximumCommittedBytes=$maximum;AverageUsedPhysicalBytes=$ram
        ProgramStatistics=$programs
    }
    Add-MiJsonl -State $State -Path (Get-MiAggregatePath -State $State -Key $Bucket.Key) -Record $record
    $State.SavedBuckets[$Bucket.Key]=$true
}

function Restore-MiPendingBucket {
    param($State)
    $now=[datetime]::UtcNow
    $systems=@();$processes=@{}
    foreach ($day in @($now.Date.AddDays(-1),$now.Date)) {
        $date=$day.ToString('yyyy-MM-dd')
        $systemPath=Join-Path (Join-Path $State.Root 'system') ('system-'+$date+'.jsonl')
        $processPath=Join-Path (Join-Path $State.Root 'process') ('process-'+$date+'.jsonl')
        $systems+=@(Read-MiJsonTail -Path $systemPath -Count 80)
        foreach ($p in @(Read-MiJsonTail -Path $processPath -Count 80)) {
            if ($p.CaptureEndUtc) { $processes[[string]$p.CaptureEndUtc]=$p }
        }
    }
    $bucket=$null
    foreach ($sys in @($systems|Sort-Object CaptureEndUtc)) {
        try { $when=[datetime]::Parse([string]$sys.CaptureEndUtc).ToUniversalTime() } catch { continue }
        $key=Get-MiBucketKey -Utc $when
        if ($null -eq $bucket -or $bucket.Key -ne $key) {
            if ($bucket) { Complete-MiBucket -State $State -Bucket $bucket }
            $bucket=New-MiBucket -Key $key
        }
        if (-not (Test-MiBucketSaved -State $State -Key $key)) {
            Add-MiBucketRecord -Bucket $bucket -SystemRecord $sys -ProcessRecord $processes[[string]$sys.CaptureEndUtc]
        }
    }
    if ($bucket) {
        if ($bucket.Key -eq (Get-MiBucketKey -Utc $now)) { $State.Bucket=$bucket }
        else { Complete-MiBucket -State $State -Bucket $bucket }
    }
}
function Get-MiRecentSystemHistory {
    param($State,[int]$Limit=365)
    $now=[datetime]::UtcNow
    $out=New-Object 'System.Collections.Generic.List[object]'
    foreach ($day in @($now.Date.AddDays(-1),$now.Date)) {
        $path=Join-Path (Join-Path $State.Root 'system') ('system-'+$day.ToString('yyyy-MM-dd')+'.jsonl')
        foreach ($r in @(Read-MiJsonTail -Path $path -Count ([math]::Max(365,$Limit+5)))) {
            try { $t=[datetime]::Parse([string]$r.CaptureEndUtc).ToUniversalTime() } catch { continue }
            if ($t -lt $now.AddMinutes(-30) -or $t -gt $now.AddMinutes(1)) { continue }
            $out.Add([pscustomobject]@{
                SchemaVersion=1; Sequence=0; CaptureEndUtc=$t; IntervalSeconds=$r.IntervalSeconds
                System=[pscustomobject]@{
                    Status=$r.SystemStatus;CommittedBytes=$r.CommittedBytes
                    UsedPhysicalBytes=$r.UsedPhysicalBytes;CommitLimitBytes=$r.CommitLimitBytes
                    AvailablePhysicalBytes=$r.AvailablePhysicalBytes
                    TotalPhysicalBytes=$r.TotalPhysicalBytes;PagedPoolBytes=$r.PagedPoolBytes
                    NonpagedPoolBytes=$r.NonpagedPoolBytes
                }
            })
        }
    }
    return @($out.ToArray()|Sort-Object CaptureEndUtc|Select-Object -Last $Limit)
}
function Save-MiSnapshot {
    param($State,$Snapshot)
    if (-not $State -or -not (Resume-MiPersistence -State $State) -or -not $State.Locked) { return $false }
    try {
        $t=([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
        $stamp=$t.ToString('o');$day=$t.ToString('yyyy-MM-dd')
        $sys=[ordered]@{
            SchemaVersion=1;RecordType='SystemSnapshot';Sequence=$Snapshot.Sequence;IntervalSeconds=$Snapshot.IntervalSeconds
            ContinuityId=$Snapshot.ContinuityId;TimeDiscontinuity=$Snapshot.TimeDiscontinuity;MonotonicSeconds=$Snapshot.MonotonicSeconds
            CaptureEndUtc=$stamp;Status=$Snapshot.Status;DurationMs=$Snapshot.DurationMs
            SystemStatus=$Snapshot.System.Status;Error=$Snapshot.System.Error
            TotalPhysicalBytes=$Snapshot.System.TotalPhysicalBytes
            AvailablePhysicalBytes=$Snapshot.System.AvailablePhysicalBytes
            UsedPhysicalBytes=$Snapshot.System.UsedPhysicalBytes
            CommittedBytes=$Snapshot.System.CommittedBytes
            CommitLimitBytes=$Snapshot.System.CommitLimitBytes
            PagedPoolBytes=$Snapshot.System.PagedPoolBytes
            NonpagedPoolBytes=$Snapshot.System.NonpagedPoolBytes
        }
        $all=@()
        if ($Snapshot.Processes.Status -ne 'Failed') {
            $all=@($Snapshot.Processes.Items|Sort-Object -Property @{Expression={if ($null -eq $_.PrivateBytes){-1L}else{[long]$_.PrivateBytes}}} -Descending)
        }
        $full=($State.LastFullUtc -eq [datetime]::MinValue -or ($t-$State.LastFullUtc).TotalSeconds -ge [int]$State.Settings.OtherProcessIntervalSeconds)
        $selected=$all
        if (-not $full) { $selected=@($all|Select-Object -First ([int]$State.Settings.TopProcessCount)) }
        $rows=New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in $selected) {
            $id=$null
            if ($null -ne $p.StartUtcTicks) { $id='{0}:{1}:{2}' -f $State.BootId,$p.PID,$p.StartUtcTicks }
            $rows.Add([ordered]@{
                PID=$p.PID;Name=$p.Name;StartUtcTicks=$p.StartUtcTicks
                ProcessInstanceId=$id;PrivateBytes=$p.PrivateBytes
                WorkingBytes=$p.WorkingBytes;Status=$p.Status
            })
        }
        $proc=[ordered]@{
            SchemaVersion=1;RecordType='ProcessSnapshot';Sequence=$Snapshot.Sequence;IntervalSeconds=$Snapshot.IntervalSeconds
            ContinuityId=$Snapshot.ContinuityId;TimeDiscontinuity=$Snapshot.TimeDiscontinuity;MonotonicSeconds=$Snapshot.MonotonicSeconds
            CaptureEndUtc=$stamp;ProcessStatus=$Snapshot.Processes.Status
            Total=$Snapshot.Processes.Total;Incomplete=$Snapshot.Processes.Incomplete
            Error=$Snapshot.Processes.Error;Full=$full;Items=@($rows.ToArray())
        }
        $systemAdded=Add-MiJsonl -State $State -Path (Join-Path (Join-Path $State.Root 'system') ('system-'+$day+'.jsonl')) -Record $sys -PassThru
        Add-MiJsonl -State $State -Path (Join-Path (Join-Path $State.Root 'process') ('process-'+$day+'.jsonl')) -Record $proc
        if ($full) { $State.LastFullUtc=$t }
        $key=Get-MiBucketKey -Utc $t
        if (-not $State.Bucket) { $State.Bucket=New-MiBucket -Key $key }
        if ($State.Bucket.Key -ne $key) {
            Complete-MiBucket -State $State -Bucket $State.Bucket
            $State.Bucket=New-MiBucket -Key $key
        }
        if ($systemAdded) { Add-MiBucketRecord -Bucket $State.Bucket -SystemRecord $sys -ProcessRecord $proc }
        $State.LastSaveUtc=$t;$State.Warning=$null
        if ($t -ge $State.NextMaintenanceUtc) {
            $State.NextMaintenanceUtc=$t.AddMinutes(5)
            try { Invoke-MiMaintenance -State $State } catch { $State.Warning='维护失败：'+$_.Exception.Message }
        }
        return [bool]$State.Healthy
    } catch {
        Set-MiPersistenceFailure -State $State -Failure $_
        return $false
    }
}
function Get-MiStreamSha256 {
    param([IO.Stream]$Stream)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-','') }
    finally { $sha.Dispose() }
}
function Test-MiArchiveIntegrity {
    param([string]$Path,[object[]]$Sources)
    $check=[IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($source in $Sources) {
            $entries=@($check.Entries|Where-Object {$_.FullName -ceq $source.Name})
            if ($entries.Count -ne 1 -or [long]$entries[0].Length -ne [long]$source.Length) {
                throw [IO.InvalidDataException]::new('ZIP 条目或长度不一致，原始文件予以保留。')
            }
            $stream=$entries[0].Open()
            try {
                # ComputeHash 完整读取解压流；长度相同的内容损坏也必须拒绝。
                $hash=Get-MiStreamSha256 -Stream $stream
                if ($hash -cne $source.Sha256) { throw [IO.InvalidDataException]::new('ZIP SHA-256 不一致，原始文件予以保留。') }
            } finally { $stream.Dispose() }
        }
    } finally { $check.Dispose() }
}
function Invoke-MiMaintenance {
    param($State,[datetime]$NowUtc=[datetime]::UtcNow)
    $today=$NowUtc.ToUniversalTime().Date
    $rawCutoff=$today.AddDays(-[int]$State.Settings.RawDays)
    $aggCutoff=$today.AddDays(-[int]$State.Settings.AggregateDays)
    $archiveDir=Join-Path $State.Root 'archives'

    # Delete only well-formed, expired snapshot/summary files in managed folders.
    foreach ($kind in @('system','process')) {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -Filter '*.jsonl' -File)) {
            if ($f.Name -notmatch ('^'+$kind+'-(\d{4}-\d{2}-\d{2})\.jsonl$')) { continue }
            $date=[datetime]::MinValue
            if ([datetime]::TryParseExact($Matches[1],'yyyy-MM-dd',
                [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date) -and
                $date -lt $rawCutoff) {
                [IO.File]::Delete($f.FullName)
            }
        }
    }
    foreach ($kind in @('archives','aggregates')) {
        $pattern=if($kind -eq 'archives'){'^raw-(\d{4}-\d{2}-\d{2})\.zip$'}else{'^summary-(\d{4}-\d{2}-\d{2})\.jsonl$'}
        $cutoff=if($kind -eq 'archives'){$rawCutoff}else{$aggCutoff}
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -File)) {
            if ($f.Name -notmatch $pattern) { continue }
            $date=[datetime]::MinValue
            if ([datetime]::TryParseExact($Matches[1],'yyyy-MM-dd',
                [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date) -and
                $date -lt $cutoff) {
                [IO.File]::Delete($f.FullName)
            }
        }
    }

    # Archive one completed day at a time (resume after interruption).
    $candidates=@()
    foreach ($kind in @('system','process')) {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -Filter '*.jsonl' -File)) {
            if ($f.Name -notmatch '^(system|process)-(\d{4}-\d{2}-\d{2})\.jsonl$') { continue }
            $date=[datetime]::MinValue
            if ([datetime]::TryParseExact($Matches[2],'yyyy-MM-dd',
                [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date) -and
                $date -lt $today -and $date -ge $rawCutoff) {
                $candidates+= $date.ToString('yyyy-MM-dd')
            }
        }
    }
    if ($candidates.Count -gt 0) {
        $date=@($candidates | Sort-Object -Unique)[0]
        $zipPath=Join-Path $archiveDir ('raw-'+$date+'.zip')
        $sources=@()
        foreach ($kind in @('system','process')) {
            $source=Join-Path (Join-Path $State.Root $kind) ($kind+'-'+$date+'.jsonl')
            if ([IO.File]::Exists($source)) { $sources+= $source }
        }
        if ($sources.Count -gt 0) {
            Add-Type -AssemblyName System.IO.Compression
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $originals=New-Object 'System.Collections.Generic.List[object]'
            $tmp=$null
            try {
                # 归档前锁定并计算原始字节哈希，验证期间禁止其他写入者改变源文件。
                foreach ($source in $sources) {
                    $stream=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                    $item=[pscustomobject]@{Path=$source;Name=[IO.Path]::GetFileName($source);Length=$stream.Length;Sha256=$null;Stream=$stream}
                    $originals.Add($item)
                    $item.Sha256=Get-MiStreamSha256 -Stream $stream
                }
                if (-not [IO.File]::Exists($zipPath)) {
                    # 中断文件有明确 pending 名称；失败时保留为 failed 供检查，不会误作正式归档。
                    $tmp=$zipPath+'.pending.'+[guid]::NewGuid().ToString('N')+'.tmp'
                    $zip=[IO.Compression.ZipFile]::Open($tmp,[IO.Compression.ZipArchiveMode]::Create)
                    try {
                        foreach ($source in $sources) {
                            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                                $zip,$source,[IO.Path]::GetFileName($source),[IO.Compression.CompressionLevel]::Optimal)
                        }
                    } finally { $zip.Dispose() }
                    Test-MiArchiveIntegrity -Path $tmp -Sources $originals.ToArray()
                    [IO.File]::Move($tmp,$zipPath)
                    $tmp=$null
                }
                # 必须重开正式归档、完整解压并逐一校验 SHA-256 后才允许移除任何源文件。
                Test-MiArchiveIntegrity -Path $zipPath -Sources $originals.ToArray()
            } catch {
                if ($tmp -and [IO.File]::Exists($tmp)) {
                    $failed=Join-Path $archiveDir 'failed'
                    [void][IO.Directory]::CreateDirectory($failed)
                    [IO.File]::Move($tmp,(Join-Path $failed ([IO.Path]::GetFileName($tmp)+'.failed.zip')))
                }
                throw
            } finally {
                foreach ($item in $originals) { $item.Stream.Dispose() }
            }
            foreach ($source in $sources) { [IO.File]::Delete($source) }
        }
    }

    # Quota is strictly confined to monitoring files; never delete audit files.
    $managed=New-Object 'System.Collections.Generic.List[object]'
    foreach ($kind in @('system','process','aggregates','archives')) {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -File)) {
            $managed.Add($f)
        }
    }
    $usage=[long]0
    foreach ($f in $managed) { $usage += [long]$f.Length }
    if ($usage -gt [long]$State.Settings.DiskBudgetBytes) {
        foreach ($f in @(Get-ChildItem -LiteralPath $archiveDir -Filter 'raw-*.zip' -File | Sort-Object Name)) {
            if ($usage -le [long]$State.Settings.DiskBudgetBytes) { break }
            $usage -= [long]$f.Length
            [IO.File]::Delete($f.FullName)
            $State.Warning='磁盘预算不足，部分历史归档提前过期。'
        }
        if ($usage -gt [long]$State.Settings.DiskBudgetBytes) {
            Set-MiPersistenceFailure -State $State -Failure ([IO.IOException]::new('磁盘预算不足，已暂停持久化以防止继续增长。')) -Prefix ''
        }
    }
}
