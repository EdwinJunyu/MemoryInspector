#requires -Version 5.1
# v0.0.2 persistence regression test: disposable temp directory only.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Persistence.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('mi-m2-test-'+[guid]::NewGuid().ToString('N'))
function Assert-Mi([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
$s=$null
try {
    $s=New-MiPersistence -Root $root
    Assert-Mi $s.Healthy ('Persistence init failed: '+$s.Warning)
    $t=[datetime]::UtcNow
    # Use timestamps in two distinct five-minute buckets.
    $bucketStart=[datetime]::new($t.Year,$t.Month,$t.Day,$t.Hour,([int][math]::Floor($t.Minute/5)*5),0,[DateTimeKind]::Utc)
    $t1=$bucketStart.AddMinutes(-4)
    $t2=$bucketStart.AddSeconds(2)
    foreach ($i in @(0,1)) {
        $stamp=if ($i -eq 0) {$t1} else {$t2}
        $sample=[pscustomobject]@{
            Sequence=$i+1; CaptureEndUtc=$stamp; DurationMs=15;Status='Success'
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
    Write-Host 'PASS: M2 persistence, aggregation, tail repair and restart history.' -ForegroundColor Green
} finally {
    if ($s) { Close-MiPersistence -State $s }
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root,$true)
    }
}
