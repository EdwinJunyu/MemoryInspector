#requires -Version 5.1
<#
MemoryInspector v0.0.2 - user-scoped JSONL persistence.
Writes only to %LOCALAPPDATA%\MemoryInspector. No process/service operations.
Single writer via named mutex; errors fail closed for disk writes, not monitoring.
#>
function New-MiPersistence {
    param([string]$Root = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector'))
    $s = [pscustomobject]@{
        Root=$Root; Healthy=$false; Warning=$null; Mutex=$null; Locked=$false
        Settings=$null; Bucket=$null; Repaired=@{}; SavedBuckets=@{}
        LastFullUtc=[datetime]::MinValue; NextMaintenanceUtc=[datetime]::MinValue
        BootId='BootUnavailable'; LastSaveUtc=$null
    }
    try {
        foreach ($dir in @('system','process','aggregates','archives')) {
            [void][IO.Directory]::CreateDirectory((Join-Path $Root $dir))
        }
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $sha=[Security.Cryptography.SHA256]::Create()
        try {
            $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Root.ToLowerInvariant()))).Replace('-','').Substring(0,16)
        } finally { $sha.Dispose() }
        $mutexName='Local\MemoryInspectorHistory_'+$sid.Replace('-','_')+'_'+$hash
        $s.Mutex=[Threading.Mutex]::new($false,$mutexName)
        try { $s.Locked=$s.Mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $s.Locked=$true }
        if (-not $s.Locked) { throw '另一个实例已经持有此目录的写入锁。' }

        $configFile=Join-Path $Root 'settings.json'
        if (-not [IO.File]::Exists($configFile)) {
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
        $c=([IO.File]::ReadAllText($configFile,[Text.Encoding]::UTF8)|ConvertFrom-Json -ErrorAction Stop)
        if ([int]$c.SchemaVersion -ne 1 -or [int]$c.RawDays -lt 1 -or [int]$c.RawDays -gt 30 -or
            [int]$c.AggregateDays -lt 1 -or [int]$c.AggregateDays -gt 365 -or
            [long]$c.DiskBudgetBytes -lt 4096 -or [int]$c.TopProcessCount -lt 1 -or
            [int]$c.TopProcessCount -gt 500 -or [int]$c.OtherProcessIntervalSeconds -lt 10 -or
            [int]$c.OtherProcessIntervalSeconds -gt 3600) {
            throw 'settings.json 无效；保留原文件，不覆盖用户设置。'
        }
        $s.Settings=$c
        try {
            $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $s.BootId='{0}_{1}' -f $env:COMPUTERNAME,$os.LastBootUpTime.ToUniversalTime().Ticks
        } catch { }
        $s.Healthy=$true
        Restore-MiPendingBucket -State $s
    } catch {
        $s.Warning=$_.Exception.Message; $s.Healthy=$false
        if ($s.Locked -and $s.Mutex) {
            try { $s.Mutex.ReleaseMutex() } catch {}
            $s.Locked=$false
        }
    }
    return $s
}
function Close-MiPersistence {
    param($State)
    if ($null -eq $State) { return }
    if ($State.Locked -and $State.Mutex) {
        try { $State.Mutex.ReleaseMutex() } catch {}
        $State.Locked=$false
    }
    if ($State.Mutex) { $State.Mutex.Dispose(); $State.Mutex=$null }
}
function Repair-MiJsonlTail {
    param([string]$Path)
    if (-not [IO.File]::Exists($Path)) { return }
    $f=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        if ($f.Length -eq 0) { return }
        [void]$f.Seek(-1,[IO.SeekOrigin]::End)
        if ($f.ReadByte() -eq 10) { return }
        $i=$f.Length-1
        while ($i -ge 0) {
            [void]$f.Seek($i,[IO.SeekOrigin]::Begin)
            if ($f.ReadByte() -eq 10) { break }
            $i--
        }
        $f.SetLength($i+1); $f.Flush($true)
    } finally { $f.Dispose() }
}
function Add-MiJsonl {
    param($State,[string]$Path,$Record)
    if (-not $State.Repaired.ContainsKey($Path)) {
        Repair-MiJsonlTail -Path $Path
        $State.Repaired[$Path]=$true
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Compress -Depth 10 -ErrorAction Stop)+[Environment]::NewLine)
    $f=[IO.File]::Open($Path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $f.Write($bytes,0,$bytes.Length); $f.Flush($true) }
    finally { $f.Dispose() }
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
    param($State,[int]$Limit=180)
    $now=[datetime]::UtcNow
    $out=New-Object 'System.Collections.Generic.List[object]'
    foreach ($day in @($now.Date.AddDays(-1),$now.Date)) {
        $path=Join-Path (Join-Path $State.Root 'system') ('system-'+$day.ToString('yyyy-MM-dd')+'.jsonl')
        foreach ($r in @(Read-MiJsonTail -Path $path -Count 210)) {
            try { $t=[datetime]::Parse([string]$r.CaptureEndUtc).ToUniversalTime() } catch { continue }
            if ($t -lt $now.AddMinutes(-30) -or $t -gt $now.AddMinutes(1)) { continue }
            $out.Add([pscustomobject]@{
                SchemaVersion=1; Sequence=0; CaptureEndUtc=$t
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
    if (-not $State -or -not $State.Healthy -or -not $State.Locked) { return $false }
    try {
        $t=([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
        $stamp=$t.ToString('o');$day=$t.ToString('yyyy-MM-dd')
        $sys=[ordered]@{
            SchemaVersion=1;RecordType='SystemSnapshot';Sequence=$Snapshot.Sequence
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
            SchemaVersion=1;RecordType='ProcessSnapshot';Sequence=$Snapshot.Sequence
            CaptureEndUtc=$stamp;ProcessStatus=$Snapshot.Processes.Status
            Total=$Snapshot.Processes.Total;Incomplete=$Snapshot.Processes.Incomplete
            Error=$Snapshot.Processes.Error;Full=$full;Items=@($rows.ToArray())
        }
        Add-MiJsonl -State $State -Path (Join-Path (Join-Path $State.Root 'system') ('system-'+$day+'.jsonl')) -Record $sys
        Add-MiJsonl -State $State -Path (Join-Path (Join-Path $State.Root 'process') ('process-'+$day+'.jsonl')) -Record $proc
        if ($full) { $State.LastFullUtc=$t }
        $key=Get-MiBucketKey -Utc $t
        if (-not $State.Bucket) { $State.Bucket=New-MiBucket -Key $key }
        if ($State.Bucket.Key -ne $key) {
            Complete-MiBucket -State $State -Bucket $State.Bucket
            $State.Bucket=New-MiBucket -Key $key
        }
        Add-MiBucketRecord -Bucket $State.Bucket -SystemRecord $sys -ProcessRecord $proc
        $State.LastSaveUtc=$t;$State.Warning=$null
        if ($t -ge $State.NextMaintenanceUtc) {
            $State.NextMaintenanceUtc=$t.AddMinutes(5)
            try { Invoke-MiMaintenance -State $State } catch { $State.Warning='维护失败：'+$_.Exception.Message }
        }
        return $true
    } catch {
        $State.Warning='历史写入失败：'+$_.Exception.Message
        $State.Healthy=$false
        return $false
    }
}
function Invoke-MiMaintenance {
    param($State,[datetime]$NowUtc=[datetime]::UtcNow)
    $today=$NowUtc.Date
    $rawCutoff=$today.AddDays(-[int]$State.Settings.RawDays)
    $aggCutoff=$today.AddDays(-[int]$State.Settings.AggregateDays)
    $archiveDir=Join-Path $State.Root 'archives'
    foreach ($kind in @('system','process')) {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -Filter '*.jsonl' -File)) {
            if ($f.Name -match '^(system|process)-(\d{4}-\d{2}-\d{2})\.jsonl$') {
                $date=[datetime]::MinValue
                if ([datetime]::TryParseExact($Matches[2],'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)) {
                    if ($date -lt $rawCutoff) { [IO.File]::Delete($f.FullName) }
                }
            }
        }
    }
    foreach ($kind in @('archives','aggregates')) {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -File)) {
            $pattern=if ($kind -eq 'archives') {'^raw-(\d{4}-\d{2}-\d{2})\.zip$'}else{'^summary-(\d{4}-\d{2}-\d{2})\.jsonl$'}
            if ($f.Name -match $pattern) {
                $date=[datetime]::MinValue
                if ([datetime]::TryParseExact($Matches[1],'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)) {
                    $cutoff=if($kind -eq 'archives'){$rawCutoff}else{$aggCutoff}
                    if ($date -lt $cutoff) { [IO.File]::Delete($f.FullName) }
                }
            }
        }
    }
    # Compress the oldest unarchived completed day, catching up after downtime.
    $candidates = @()
    foreach ($kind in @('system','process')) {
        foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $State.Root $kind) -Filter '*.jsonl' -File)) {
            if ($file.Name -match '^(system|process)-(\d{4}-\d{2}-\d{2})\.jsonl
    $zipPath=Join-Path $archiveDir ('raw-'+$date+'.zip')
    $sources=@()
    foreach ($kind in @('system','process')) {
        $source=Join-Path (Join-Path $State.Root $kind) ($kind+'-'+$date+'.jsonl')
        if ([IO.File]::Exists($source)) { $sources+= $source }
    }
    if ($sources.Count -gt 0 -and -not [IO.File]::Exists($zipPath)) {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $tmp=$zipPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        try {
            $zip=[IO.Compression.ZipFile]::Open($tmp,[IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($source in $sources) {
                    [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$source,[IO.Path]::GetFileName($source),[IO.Compression.CompressionLevel]::Optimal)
                }
            } finally { $zip.Dispose() }
            $check=[IO.Compression.ZipFile]::OpenRead($tmp)
            try {
                foreach ($source in $sources) {
                    $found=$false
                    foreach ($e in $check.Entries) {
                        if ($e.Name -eq [IO.Path]::GetFileName($source) -and $e.Length -eq ([IO.FileInfo]$source).Length) { $found=$true }
                    }
                    if (-not $found) { throw 'ZIP 验证失败，原文件仍保留。' }
                }
            } finally { $check.Dispose() }
            [IO.File]::Move($tmp,$zipPath)
        } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
    }
    if ([IO.File]::Exists($zipPath)) {
        $check=[IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            foreach ($source in $sources) {
                $found=$false
                foreach ($e in $check.Entries) {
                    if ($e.Name -eq [IO.Path]::GetFileName($source) -and $e.Length -eq ([IO.FileInfo]$source).Length) { $found=$true }
                }
                if (-not $found) { throw '归档与源数据不一致，拒绝删除。' }
            }
        } finally { $check.Dispose() }
        foreach ($source in $sources) { [IO.File]::Delete($source) }
    }
    # Monitoring quota does not touch audits or arbitrary files.
    $files=@(@('system','process','aggregates','archives') | ForEach-Object { Get-ChildItem -LiteralPath (Join-Path $State.Root $_) -File })
    $usage=[long]0; foreach($f in $files) { $usage+=$f.Length }
    if ($usage -gt [long]$State.Settings.DiskBudgetBytes) {
        foreach ($f in @(Get-ChildItem -LiteralPath $archiveDir -Filter 'raw-*.zip' -File|Sort-Object Name)) {
            if ($usage -le [long]$State.Settings.DiskBudgetBytes) { break }
            $usage-=$f.Length;[IO.File]::Delete($f.FullName)
            $State.Warning='磁盘预算不足，部分历史归档提前过期。'
        }
        if ($usage -gt [long]$State.Settings.DiskBudgetBytes) {
            $State.Warning='磁盘预算不足，已暂停持久化以防止继续增长。'
            $State.Healthy=$false
        }
    }
}
) {
                $dateValue=[datetime]::MinValue
                if ([datetime]::TryParseExact($Matches[2],'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$dateValue) -and $dateValue -lt $today) {
                    $candidates += $Matches[2]
                }
            }
        }
    }
    if ($candidates.Count -eq 0) { return }
    $date = @($candidates | Sort-Object -Unique)[0]
    $zipPath=Join-Path $archiveDir ('raw-'+$date+'.zip')
    $sources=@()
    foreach ($kind in @('system','process')) {
        $source=Join-Path (Join-Path $State.Root $kind) ($kind+'-'+$date+'.jsonl')
        if ([IO.File]::Exists($source)) { $sources+= $source }
    }
    if ($sources.Count -gt 0 -and -not [IO.File]::Exists($zipPath)) {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $tmp=$zipPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        try {
            $zip=[IO.Compression.ZipFile]::Open($tmp,[IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($source in $sources) {
                    [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$source,[IO.Path]::GetFileName($source),[IO.Compression.CompressionLevel]::Optimal)
                }
            } finally { $zip.Dispose() }
            $check=[IO.Compression.ZipFile]::OpenRead($tmp)
            try {
                foreach ($source in $sources) {
                    $found=$false
                    foreach ($e in $check.Entries) {
                        if ($e.Name -eq [IO.Path]::GetFileName($source) -and $e.Length -eq ([IO.FileInfo]$source).Length) { $found=$true }
                    }
                    if (-not $found) { throw 'ZIP 验证失败，原文件仍保留。' }
                }
            } finally { $check.Dispose() }
            [IO.File]::Move($tmp,$zipPath)
        } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
    }
    if ([IO.File]::Exists($zipPath)) {
        $check=[IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            foreach ($source in $sources) {
                $found=$false
                foreach ($e in $check.Entries) {
                    if ($e.Name -eq [IO.Path]::GetFileName($source) -and $e.Length -eq ([IO.FileInfo]$source).Length) { $found=$true }
                }
                if (-not $found) { throw '归档与源数据不一致，拒绝删除。' }
            }
        } finally { $check.Dispose() }
        foreach ($source in $sources) { [IO.File]::Delete($source) }
    }
    # Monitoring quota does not touch audits or arbitrary files.
    $files=@(@('system','process','aggregates','archives') | ForEach-Object { Get-ChildItem -LiteralPath (Join-Path $State.Root $_) -File })
    $usage=[long]0; foreach($f in $files) { $usage+=$f.Length }
    if ($usage -gt [long]$State.Settings.DiskBudgetBytes) {
        foreach ($f in @(Get-ChildItem -LiteralPath $archiveDir -Filter 'raw-*.zip' -File|Sort-Object Name)) {
            if ($usage -le [long]$State.Settings.DiskBudgetBytes) { break }
            $usage-=$f.Length;[IO.File]::Delete($f.FullName)
            $State.Warning='磁盘预算不足，部分历史归档提前过期。'
        }
        if ($usage -gt [long]$State.Settings.DiskBudgetBytes) {
            $State.Warning='磁盘预算不足，已暂停持久化以防止继续增长。'
            $State.Healthy=$false
        }
    }
}
