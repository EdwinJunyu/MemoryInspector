#requires -Version 5.1
# v0.0.2 persistence regression test: disposable temp directory only.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Persistence.ps1')
$fixtureParent=Join-Path $PSScriptRoot 'test-artifacts'
[void][IO.Directory]::CreateDirectory($fixtureParent)
$root=Join-Path $fixtureParent ('mi-m2-test-'+[guid]::NewGuid().ToString('N'))
function Assert-Mi([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
$s=$null
try {
    $s=New-MiPersistence -Root $root
    Assert-Mi $s.Healthy ('Persistence init failed: '+$s.Warning)
    # 默认尾部接口保留完整JSON；内部投影逐行执行，坏行/未知schema仍不得成为有效记录。
    $projectionPath=Join-Path $root 'tail-projection.jsonl'
    [IO.File]::WriteAllLines($projectionPath,@('{"SchemaVersion":1,"Value":9007199254740993,"Extra":"preserve"}','{"SchemaVersion":99,"Value":2}','{"SchemaVersion":1,'),[Text.UTF8Encoding]::new($false))
    $plainTail=@(Read-MiJsonTail -Path $projectionPath -Count 10)
    $projectedTail=@(Read-MiJsonTail -Path $projectionPath -Count 10 -Projection {param($r) [pscustomobject]@{SchemaVersion=$r.SchemaVersion;Value=$r.Value}})
    Assert-Mi ($plainTail.Count -eq 1 -and $plainTail[0].Extra -eq 'preserve' -and
        $projectedTail.Count -eq 1 -and [long]$projectedTail[0].Value -eq [long]9007199254740993 -and
        $null -eq $projectedTail[0].Extra) 'Tail projection changed default API, exact Int64 or corrupt/schema rejection.'
    $t=[datetime]::UtcNow
    # Use timestamps in two distinct five-minute buckets.
    $bucketStart=[datetime]::new($t.Year,$t.Month,$t.Day,$t.Hour,([int][math]::Floor($t.Minute/5)*5),0,[DateTimeKind]::Utc)
    $t1=$bucketStart.AddMinutes(-4)
    $t2=$bucketStart.AddSeconds(2)
    foreach ($i in @(0,1)) {
        $stamp=if ($i -eq 0) {$t1} else {$t2}
        $sample=[pscustomobject]@{
            Sequence=$i+1; CaptureEndUtc=$stamp; DurationMs=15;Status='Success'
            ContinuityId='p2-fixture';TimeDiscontinuity=($i -eq 1);MonotonicSeconds=(100+$i*5)
            System=[pscustomobject]@{
                Status='Success';Error=$null;TotalPhysicalBytes=8589934592L
                AvailablePhysicalBytes=4294967296L;UsedPhysicalBytes=4294967296L
                CommittedBytes=(3221225472L+($i*104857600L));CommitLimitBytes=17179869184L
                PagedPoolBytes=1000000L;NonpagedPoolBytes=2000000L
            }
            Processes=[pscustomobject]@{
                Status='Success';Total=1;Incomplete=0;Error=$null
                Items=@([pscustomobject]@{
                    PID=321;Name='fixture';StartUtcTicks=123456789L
                    PrivateBytes=(1000000L+$i*1000L);WorkingBytes=1000000L;Status='Success'
                })
            }
        }
        Assert-Mi (Save-MiSnapshot -State $s -Snapshot $sample) ('Cannot save sample: '+$s.Warning)
        foreach ($type in @('system','process')) {
            $savedPath=Join-Path (Join-Path $s.Root $type) ($type+'-'+$stamp.ToString('yyyy-MM-dd')+'.jsonl')
            $savedRecord=@(Read-MiJsonTail $savedPath 1)[0]
            Assert-Mi ($savedRecord.SchemaVersion -eq 1 -and $savedRecord.ContinuityId -eq 'p2-fixture' -and
                $savedRecord.TimeDiscontinuity -eq ($i -eq 1) -and $savedRecord.MonotonicSeconds -eq (100+$i*5) -and
                ([datetime]$savedRecord.CaptureEndUtc).ToUniversalTime() -eq $stamp) 'P2 continuity metadata or UTC round trip failed.'
        }
    }
    $aggregateFile=Get-MiAggregatePath -State $s -Key (Get-MiBucketKey -Utc $t1)
    Assert-Mi ([IO.File]::Exists($aggregateFile)) 'Rolled five-minute bucket missing.'
    $agg=@(Read-MiJsonTail -Path $aggregateFile -Count 30)
    Assert-Mi ($agg.Count -ge 1) 'Cannot read aggregate.'
    Assert-Mi ([long]$agg[-1].SampleCount -eq 1) 'Aggregate sample count mismatch.'
    Assert-Mi ([long]$agg[-1].AverageCommittedBytes -eq 3221225472L) 'Aggregate byte mean mismatch.'

    $systemFile=Join-Path (Join-Path $root 'system') ('system-'+$t2.ToString('yyyy-MM-dd')+'.jsonl')
    [IO.File]::AppendAllText($systemFile,'{"SchemaVersion":1,"INCOMPLETE":',[Text.UTF8Encoding]::new($false))
    # Explicitly simulate restart repair before any new write.
    $s.Repaired.Remove($systemFile) | Out-Null
    Assert-Mi (Save-MiSnapshot -State $s -Snapshot $sample) 'Tail repair followed by append failed.'
    $lines=@(Get-Content -LiteralPath $systemFile -Encoding UTF8)
    foreach ($line in $lines) {
        $obj=ConvertFrom-Json -InputObject $line -ErrorAction Stop
        Assert-Mi ($obj.SchemaVersion -eq 1) 'Invalid row after tail repair.'
    }
    $readState=[pscustomobject]@{Root=$root}
    $history=@(Get-MiRecentSystemHistory -State $readState -Limit 180)
    Assert-Mi ($history.Count -ge 1) 'Restart history could not be recovered.'
    Close-MiPersistence -State $s
    $s=$null
    $reopened=New-MiPersistence -Root $root
    Assert-Mi $reopened.Healthy ('Reopen failed: '+$reopened.Warning)
    Close-MiPersistence -State $reopened
    # P1-02: 正常归档必须能完整解压，内容相同后才能移除原始 JSONL。
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveDate=[datetime]::UtcNow.Date.AddDays(-1).ToString('yyyy-MM-dd')
    $archiveContent="{`"SchemaVersion`":1,`"Payload`":`"A`"}`r`n"
    function New-ArchiveFixture([string]$Name) {
        $state=New-MiPersistence -Root (Join-Path $root $Name)
        Assert-Mi $state.Healthy ('Archive fixture init: '+$state.Warning)
        $path=Join-Path (Join-Path $state.Root 'system') ('system-'+$archiveDate+'.jsonl')
        [IO.File]::WriteAllText($path,$archiveContent,[Text.UTF8Encoding]::new($false))
        return [pscustomobject]@{State=$state;Source=$path;Zip=(Join-Path (Join-Path $state.Root 'archives') ('raw-'+$archiveDate+'.zip'))}
    }
    function Write-FixtureZip([string]$Path,[string]$EntryName,[string]$Text) {
        $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry=$zip.CreateEntry($EntryName)
            $stream=$entry.Open()
            try { $bytes=[Text.Encoding]::UTF8.GetBytes($Text);$stream.Write($bytes,0,$bytes.Length) }
            finally { $stream.Dispose() }
        } finally { $zip.Dispose() }
    }
    $fixture=New-ArchiveFixture 'archive-normal'
    try {
        Invoke-MiMaintenance -State $fixture.State
        Assert-Mi (-not [IO.File]::Exists($fixture.Source)) 'Verified archive did not remove raw source.'
        $zip=[IO.Compression.ZipFile]::OpenRead($fixture.Zip)
        try {
            $reader=[IO.StreamReader]::new($zip.Entries[0].Open(),[Text.Encoding]::UTF8)
            try { $restored=$reader.ReadToEnd() } finally { $reader.Dispose() }
            Assert-Mi ($restored -ceq $archiveContent) 'Archive did not restore original bytes.'
        } finally { $zip.Dispose() }
    } finally { Close-MiPersistence -State $fixture.State }
    foreach ($kind in @('hash','invalid-zip')) {
        $fixture=New-ArchiveFixture ('archive-'+$kind)
        try {
            if ($kind -eq 'hash') {
                Write-FixtureZip -Path $fixture.Zip -EntryName ([IO.Path]::GetFileName($fixture.Source)) -Text ($archiveContent.Replace('"A"','"B"'))
            } else { [IO.File]::WriteAllText($fixture.Zip,'not a valid ZIP',[Text.Encoding]::ASCII) }
            $failed=$false
            try { Invoke-MiMaintenance -State $fixture.State } catch { $failed=$true }
            Assert-Mi $failed ('Archive corruption was accepted: '+$kind)
            Assert-Mi ([IO.File]::ReadAllText($fixture.Source,[Text.Encoding]::UTF8) -ceq $archiveContent) 'Archive failure lost raw data.'
        } finally { Close-MiPersistence -State $fixture.State }
    }
    $fixture=New-ArchiveFixture 'archive-interrupted'
    $integrityImplementation=(Get-Item Function:Test-MiArchiveIntegrity).ScriptBlock
    try {
        function Test-MiArchiveIntegrity { param([string]$Path,[object[]]$Sources); throw [IO.IOException]::new('Injected failure after ZIP writing.') }
        $failed=$false
        try { Invoke-MiMaintenance -State $fixture.State } catch { $failed=$true }
        Assert-Mi $failed 'Injected archive failure was ignored.'
        Assert-Mi ([IO.File]::Exists($fixture.Source)) 'Interrupted archive lost raw source.'
        $failedFiles=@(Get-ChildItem -LiteralPath (Join-Path (Join-Path $fixture.State.Root 'archives') 'failed') -Filter '*.failed.zip' -File)
        Assert-Mi ($failedFiles.Count -eq 1) 'Failed temporary archive was not preserved with recognizable name.'
        Assert-Mi (@(Get-ChildItem -LiteralPath (Join-Path $fixture.State.Root 'archives') -Filter '*.tmp' -File).Count -eq 0) 'Unrecognized archive temporary file remained.'
    } finally {
        Set-Item Function:Test-MiArchiveIntegrity -Value $integrityImplementation
        Close-MiPersistence -State $fixture.State
    }

    # P1-04: 真实文件共享冲突模拟临时存储故障；恢复不能依赖重启或覆盖设置。
    $s=New-MiPersistence -Root (Join-Path $root 'recover-sharing')
    Assert-Mi $s.Healthy 'Recovery fixture init failed.'
    $s.NextMaintenanceUtc=[datetime]::UtcNow.AddDays(1)
    $sample | Add-Member -NotePropertyName IntervalSeconds -NotePropertyValue 5 -Force
    $sample.Sequence=101;$sample.CaptureEndUtc=[datetime]::UtcNow
    Assert-Mi (Save-MiSnapshot -State $s -Snapshot $sample) 'Recovery baseline save failed.'
    $settingsBefore=[IO.File]::ReadAllText((Join-Path $s.Root 'settings.json'),[Text.Encoding]::UTF8)
    $systemPath=Join-Path (Join-Path $s.Root 'system') ('system-'+$sample.CaptureEndUtc.ToString('yyyy-MM-dd')+'.jsonl')
    $processPath=Join-Path (Join-Path $s.Root 'process') ('process-'+$sample.CaptureEndUtc.ToString('yyyy-MM-dd')+'.jsonl')
    $sample.Sequence=102;$sample.CaptureEndUtc=$sample.CaptureEndUtc.AddSeconds(5)
    $exclusive=[IO.File]::Open($processPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        Assert-Mi (-not (Save-MiSnapshot -State $s -Snapshot $sample)) 'Exclusive sharing fault did not stop history writes.'
        Assert-Mi (-not $s.Healthy -and $s.FailureKind -eq 'Transient') 'Temporary failure classification mismatch.'
        Assert-Mi (-not (Resume-MiPersistence -State $s)) 'Recovery ignored low-frequency retry bound.'
        Assert-Mi ($s.RecoveryAttempts -eq 0) 'Recovery performed a premature disk retry.'
        $due=$s.NextRecoveryUtc.AddSeconds(1)
        Assert-Mi (-not (Resume-MiPersistence -State $s -NowUtc $due)) 'Recovery ignored file sharing conflict.'
        Assert-Mi ($s.RecoveryAttempts -eq 1 -and $s.RecoveryIntervalSeconds -ge 30 -and $s.RecoveryIntervalSeconds -le 300) 'Recovery retry is not bounded.'
        foreach ($retry in 1..5) {
            Assert-Mi (-not (Resume-MiPersistence -State $s -NowUtc $s.NextRecoveryUtc.AddSeconds(1))) 'Persistent fault unexpectedly recovered.'
            Assert-Mi ($s.RecoveryIntervalSeconds -ge 30 -and $s.RecoveryIntervalSeconds -le 300) 'Recovery backoff escaped its bound.'
        }
        Assert-Mi ($s.RecoveryIntervalSeconds -eq 300) 'Recovery retries did not reach low-frequency cap.'
    } finally { $exclusive.Dispose() }
    $s.NextRecoveryUtc=[datetime]::MinValue
    Assert-Mi (Save-MiSnapshot -State $s -Snapshot $sample) ('Storage did not automatically resume: '+$s.Warning)
    Assert-Mi ($s.Healthy -and $s.FailureKind -eq 'None' -and $null -ne $s.RecoveredUtc) 'Recovered status was not published.'
    Assert-Mi (@(Read-MiJsonTail -Path $systemPath).Count -eq 2) 'Recovery duplicated already committed system sample.'
    Assert-Mi (@(Read-MiJsonTail -Path $processPath).Count -eq 2) 'Recovery lost or duplicated process sample.'
    Assert-Mi ([int]@(Read-MiJsonTail -Path $systemPath)[-1].IntervalSeconds -eq 5) 'Saved interval metadata was not persisted.'
    Assert-Mi ([IO.File]::ReadAllText((Join-Path $s.Root 'settings.json'),[Text.Encoding]::UTF8) -ceq $settingsBefore) 'Recovery overwrote user settings.'

    # 在真实流写出少量字节后注入故障，验证追加回滚保护既有完整记录。
    $writerImplementation=(Get-Item Function:Write-MiJsonlBytes).ScriptBlock
    $bytesBefore=[Convert]::ToBase64String([IO.File]::ReadAllBytes($systemPath))
    try {
        function Write-MiJsonlBytes {
            param([IO.Stream]$Stream,[byte[]]$Bytes)
            $Stream.Write($Bytes,0,[math]::Min(11,$Bytes.Length))
            throw [IO.IOException]::new('Injected partial append failure.')
        }
        $sample.Sequence=103;$sample.CaptureEndUtc=$sample.CaptureEndUtc.AddSeconds(5)
        Assert-Mi (-not (Save-MiSnapshot -State $s -Snapshot $sample)) 'Partial append fault was ignored.'
        Assert-Mi ([Convert]::ToBase64String([IO.File]::ReadAllBytes($systemPath)) -ceq $bytesBefore) 'Failed append damaged previous records.'
    } finally { Set-Item Function:Write-MiJsonlBytes -Value $writerImplementation }
    $s.NextRecoveryUtc=[datetime]::MinValue
    Assert-Mi (Save-MiSnapshot -State $s -Snapshot $sample) ('Partial-append recovery failed: '+$s.Warning)
    Assert-Mi (@(Read-MiJsonTail -Path $systemPath).Count -eq 3) 'Partial-append recovery duplicated or lost committed records.'

    # 非法设置及未完整写入的原始数据均为人工处理项，自动恢复不得截断或覆盖。
    [IO.File]::WriteAllText((Join-Path $s.Root 'settings.json'),'{broken-settings',[Text.UTF8Encoding]::new($false))
    Set-MiPersistenceFailure -State $s -Failure ([IO.IOException]::new('Injected retry.'))
    $s.NextRecoveryUtc=[datetime]::MinValue
    Assert-Mi (-not (Resume-MiPersistence -State $s)) 'Invalid settings permitted recovery.'
    Assert-Mi ($s.FailureKind -eq 'Permanent') 'Invalid settings did not permanently fail closed.'
    Assert-Mi ([IO.File]::ReadAllText((Join-Path $s.Root 'settings.json')) -ceq '{broken-settings') 'Recovery changed corrupt user settings.'
    Close-MiPersistence -State $s;$s=$null
    $s=New-MiPersistence -Root (Join-Path $root 'recover-damaged-tail')
    $sample.Sequence=201;$sample.CaptureEndUtc=[datetime]::UtcNow
    Assert-Mi (Save-MiSnapshot -State $s -Snapshot $sample) 'Damaged-tail fixture baseline failed.'
    $damaged=Join-Path (Join-Path $s.Root 'system') ('system-'+$sample.CaptureEndUtc.ToString('yyyy-MM-dd')+'.jsonl')
    [IO.File]::AppendAllText($damaged,'{"interrupted":',[Text.UTF8Encoding]::new($false))
    $damagedBefore=[Convert]::ToBase64String([IO.File]::ReadAllBytes($damaged))
    Set-MiPersistenceFailure -State $s -Failure ([IO.IOException]::new('Injected retry.'))
    $s.NextRecoveryUtc=[datetime]::MinValue
    Assert-Mi (-not (Resume-MiPersistence -State $s)) 'Damaged tail permitted automatic recovery.'
    Assert-Mi ($s.FailureKind -eq 'Permanent') 'Damaged tail did not fail closed.'
    Assert-Mi ([Convert]::ToBase64String([IO.File]::ReadAllBytes($damaged)) -ceq $damagedBefore) 'Recovery truncated damaged original file.'
    Close-MiPersistence -State $s;$s=$null

    # 初始化期间存储路径不可用，恢复后可创建默认配置；已有配置永不重建。
    $blockedRoot=Join-Path $root 'initially-unavailable'
    [IO.File]::WriteAllText($blockedRoot,'temporary blocker')
    $s=New-MiPersistence -Root $blockedRoot
    Assert-Mi (-not $s.Healthy -and $s.FailureKind -eq 'Transient') 'Initial transient path fault classification failed.'
    [IO.File]::Move($blockedRoot,(Join-Path $root 'initial-blocker.preserved'))
    $s.NextRecoveryUtc=[datetime]::MinValue
    Assert-Mi (Resume-MiPersistence -State $s) ('Initial transient storage could not recover: '+$s.Warning)
    Close-MiPersistence -State $s;$s=$null

    # 真正的第二个 PowerShell 进程验证写锁；仅访问测试目录，不操作用户进程/服务。
    function Invoke-PersistenceChild([string]$ChildRoot,[switch]$Abandon) {
        $module=(Join-Path $PSScriptRoot 'Persistence.ps1').Replace("'","''")
        $target=$ChildRoot.Replace("'","''")
        $childScript=". '$module';`$x=New-MiPersistence -Root '$target';[pscustomobject]@{Healthy=`$x.Healthy;Locked=`$x.Locked;FailureKind=`$x.FailureKind}|ConvertTo-Json -Compress;"
        if ($Abandon) { $childScript+='[Environment]::Exit(0)' } else { $childScript+='Close-MiPersistence -State $x' }
        $start=[Diagnostics.ProcessStartInfo]::new()
        $start.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $start.Arguments='-NoProfile -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $child=[Diagnostics.Process]::new();$child.StartInfo=$start
        try {
            [void]$child.Start()
            Assert-Mi ($child.WaitForExit(15000)) 'Isolated persistence child timed out.'
            $output=$child.StandardOutput.ReadToEnd();$childError=$child.StandardError.ReadToEnd()
            Assert-Mi ($child.ExitCode -eq 0) ('Isolated persistence child failed: '+$childError)
            return ($output|ConvertFrom-Json -ErrorAction Stop)
        } finally { $child.Dispose() }
    }
    $s=New-MiPersistence -Root (Join-Path $root 'cross-process-lock')
    $childResult=Invoke-PersistenceChild -ChildRoot $s.Root
    Assert-Mi (-not $childResult.Healthy -and -not $childResult.Locked -and $childResult.FailureKind -eq 'Transient') 'Second process bypassed persistence writer mutex.'
    Close-MiPersistence -State $s;$s=$null
    $abandonedRoot=Join-Path $root 'abandoned-lock'
    $childResult=Invoke-PersistenceChild -ChildRoot $abandonedRoot -Abandon
    Assert-Mi $childResult.Healthy 'Isolated abandoned-lock writer failed to initialize.'
    $s=New-MiPersistence -Root $abandonedRoot
    Assert-Mi $s.Healthy ('Abandoned mutex caused permanent deadlock: '+$s.Warning)
    # 状态对象即使被错误转交其他线程，也不得只凭 Locked=true 继续恢复写入。
    Set-MiPersistenceFailure -State $s -Failure ([IO.IOException]::new('Injected cross-thread retry.'))
    $s.NextRecoveryUtc=[datetime]::MinValue
    $otherThread=[powershell]::Create()
    try {
        [void]$otherThread.AddScript('param($module,$storage);. $module;Resume-MiPersistence -State $storage').AddArgument((Join-Path $PSScriptRoot 'Persistence.ps1')).AddArgument($s)
        $threadResult=@($otherThread.Invoke())
        Assert-Mi ($threadResult.Count -eq 1 -and -not [bool]$threadResult[0]) 'Recovery used mutex owned by a different thread.'
        Assert-Mi ($s.FailureKind -eq 'Permanent') 'Unknown mutex ownership did not fail closed.'
    } finally { $otherThread.Dispose() }
    Close-MiPersistence -State $s;$s=$null

    # P1-01 配套：重启读取 5 秒采样的完整 30 分钟记录和可选采样周期字段。
    $s=New-MiPersistence -Root (Join-Path $root 'five-second-history')
    $historyFile=Join-Path (Join-Path $s.Root 'system') ('system-'+[datetime]::UtcNow.ToString('yyyy-MM-dd')+'.jsonl')
    $historyNow=[datetime]::UtcNow.AddSeconds(1)
    $historyRows=New-Object 'System.Collections.Generic.List[string]'
    foreach ($n in 0..360) {
        $record=[ordered]@{SchemaVersion=1;CaptureEndUtc=$historyNow.AddSeconds(($n-360)*5).ToString('o');SystemStatus='Success';CommittedBytes=1000000;IntervalSeconds=5}
        $historyRows.Add(($record|ConvertTo-Json -Compress))
    }
    [IO.File]::WriteAllText($historyFile,([string]::Join([Environment]::NewLine,$historyRows.ToArray())+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
    $history=@(Get-MiRecentSystemHistory -State $s)
    Assert-Mi ($history.Count -ge 360) 'History reader still truncates the 5-second 30-minute window.'
    Assert-Mi ([int]$history[-1].IntervalSeconds -eq 5) 'Optional interval metadata was not preserved.'
    Close-MiPersistence -State $s;$s=$null
    Write-Host 'PASS: M2 persistence plus P1 ZIP SHA-256, corruption/source preservation, bounded recovery, partial append rollback, cross-process lock and 5-second history.' -ForegroundColor Green
} finally {
    if ($s) { Close-MiPersistence -State $s }
    if ([IO.Directory]::Exists($root)) {
        # 从一开始就在项目内保留测试证据，不移动跨卷目录，也不删除受损数据。
        Write-Host ('Persistence test fixtures retained: '+$root)
    }
}
