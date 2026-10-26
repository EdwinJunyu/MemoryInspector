#requires -Version 5.1
<#
Milestone 8 deterministic fail-closed acceptance checks.
Read-only: NEVER terminates a process, changes a service, or requests UAC.
Temporary fault fixtures are created only under the current user's TEMP.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$version = ([IO.File]::ReadAllText((Join-Path $root 'VERSION'))).Trim()
if ($version -cne '0.0.10') { throw ('Expected 0.0.10, found '+$version) }

$files = @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File)
foreach ($file in $files) {
    # PS5.1将无BOM脚本按本机旧编码读取；中文注释可能吞掉下一行，不能只依赖解析无错误。
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    $utf8=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    if($utf8 -match '[^\x00-\x7F]' -and ($bytes.Length -lt 3 -or $bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191)){
        throw ('Non-ASCII PowerShell script requires UTF-8 BOM on PS5.1: '+$file.Name)
    }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) {
        throw ('Windows PowerShell 5.1 parse failure in '+$file.Name+': '+($errors | Out-String))
    }
}
. (Join-Path $root 'PrivilegeSecurity.ps1')
. (Join-Path $root 'ServiceManagement.ps1')
. (Join-Path $root 'Persistence.ps1')

$id = [guid]::NewGuid().ToString('N')
foreach ($name in @('Stop-Process','RunCommand','ForceStop','Invoke-Expression','')) {
    if (Test-MiPrivilegedOperation -Operation $name -RequestId $id) {
        throw ('Unknown operation was permitted: '+$name)
    }
}
foreach ($bad in @('../Spooler','RpcSs; Stop-Service','',('A' * 129))) {
    if (Test-MiPrivilegedOperation -Operation 'StopApprovedService' -RequestId $id -ServiceName $bad) {
        throw 'Unsafe service identity was permitted.'
    }
}
foreach ($name in @('RpcSs','WinDefend','EventLog','PlugPlay')) {
    if (-not (Test-MiServiceDenied $name)) { throw ('Critical service not protected: '+$name) }
}
if (Test-MiPrivilegedOperation -Operation Probe -RequestId $id -ServiceName Spooler) {
    throw 'Probe unexpectedly accepted an operation target.'
}
if (Test-MiGuidN '../bad') { throw 'Malformed request ID passed validation.' }

# Injection: invalid retention settings must be preserved, NOT repaired by overwriting.
$fixture = Join-Path (Join-Path $root 'test-artifacts') ('MiM8Settings-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$state = $null
try {
    $settings = Join-Path $fixture 'settings.json'
    $invalid = '{"SchemaVersion":1,"RawDays":0,"AggregateDays":90,"DiskBudgetBytes":2147483648,"TopProcessCount":60,"OtherProcessIntervalSeconds":60}'
    [IO.File]::WriteAllText($settings,$invalid,[Text.UTF8Encoding]::new($false))
    $state = New-MiPersistence -Root $fixture
    if ($state.Healthy) { throw 'Invalid persistence settings accepted.' }
    if ($state.Locked) { throw 'Persistence lock was retained after failure.' }
    if ([IO.File]::ReadAllText($settings,[Text.Encoding]::UTF8) -cne $invalid) {
        throw 'Invalid settings were silently overwritten.'
    }
} finally {
    if ($null -ne $state) { Close-MiPersistence -State $state }
    Write-Host ('Damaged-settings fixture retained: '+$fixture)
}

# GUI is a display and dispatcher, never the direct privileged action executor.
foreach ($name in @('MemoryInspector.ps1','GuiV4.ps1')) {
    $source = [IO.File]::ReadAllText((Join-Path $root $name),[Text.Encoding]::UTF8)
    if ($source -match '(?im)^\s*(Stop-Process|Stop-Service|Start-Service|taskkill)\b' -or
        $source -match '(?i)\.Kill\s*\(') { throw ('Direct unsafe action in GUI: '+$name) }
}
Write-Host ('PASS: M8 parsing, fail-closed request validation, invalid settings and GUI separation ({0} scripts).' -f $files.Count) -ForegroundColor Green

# 正式入口必须保留 RemoteSigned；未知下载脚本拒绝，只有显式信任本测试自身创建的文件后可运行。
$launcher=[IO.File]::ReadAllText((Join-Path $root 'Run_MemoryInspector.cmd'))
if ($launcher -notmatch '-ExecutionPolicy RemoteSigned' -or $launcher -match '(?i)\b(Bypass|Unblock-File|Set-ExecutionPolicy)\b') {throw 'Launcher weakened execution policy or automatically trusted downloads.'}
$fixture=Join-Path (Join-Path $root 'test-artifacts') ('MiM8Observer-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$zoneFile=Join-Path $fixture 'downloaded-fixture.ps1'
[IO.File]::WriteAllText($zoneFile,"Write-Output 'MI_VERIFIED_FIXTURE'",[Text.UTF8Encoding]::new($true))
Set-Content -LiteralPath $zoneFile -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
$psExe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$previousPreference=$ErrorActionPreference
try {
    $ErrorActionPreference='Continue'
    $blockedOutput=& $psExe -NoProfile -ExecutionPolicy RemoteSigned -File $zoneFile 2>&1
    $blockedExit=$LASTEXITCODE
} finally {$ErrorActionPreference=$previousPreference}
if ($blockedExit -eq 0 -or [string]::Join(' ',[string[]]$blockedOutput) -match 'MI_VERIFIED_FIXTURE') {throw 'RemoteSigned accepted an untrusted Internet-zone script.'}
Unblock-File -LiteralPath $zoneFile
$trustedOutput=& $psExe -NoProfile -ExecutionPolicy RemoteSigned -File $zoneFile
if ($LASTEXITCODE -ne 0 -or $trustedOutput -cne 'MI_VERIFIED_FIXTURE') {throw 'Explicitly verified local fixture could not run under RemoteSigned.'}

# 复现 PS5.1 的多目标 JSON；完整、单目标、空/嵌套/重复/非法身份都要明确处理。
. (Join-Path $root 'AcceptanceGuiMonitor.ps1') -FunctionsOnly
$jobsFile=Join-Path $fixture 'jobs.json'
$ticks=[datetime]::UtcNow.Ticks
$jobs=@([pscustomobject]@{Pid=111;StartUtcTicks=$ticks;IntervalSeconds=5},[pscustomobject]@{Pid=222;StartUtcTicks=($ticks-1);IntervalSeconds=60})
[IO.File]::WriteAllText($jobsFile,($jobs|ConvertTo-Json),[Text.UTF8Encoding]::new($true))
$targets=@(Read-MiAcceptanceTargets -JobsPath $jobsFile)
if ($targets.Count -ne 2 -or $targets[0].Pid -ne 111 -or $targets[1].Pid -ne 222 -or $targets[0].StartUtcTicks -ne $ticks) {throw 'PS5.1 observer lost/combined targets or creation-time precision.'}
foreach($badJobs in @('[]','[[{"Pid":1,"StartUtcTicks":1}]]','[{"Pid":1,"StartUtcTicks":1},{"Pid":1,"StartUtcTicks":2}]','[{"Pid":-1,"StartUtcTicks":1}]','[{"Pid":1}]')) {
    [IO.File]::WriteAllText($jobsFile,$badJobs,[Text.UTF8Encoding]::new($true))
    $refused=$false
    try {[void](Read-MiAcceptanceTargets -JobsPath $jobsFile)}catch{$refused=$true}
    if (-not $refused) {throw ('Invalid observer targets accepted: '+$badJobs)}
}
$target=[pscustomobject]@{Pid=111;StartUtcTicks=$ticks;Name='fixture'}
$fake=[pscustomobject]@{Id=111;StartTime=[datetime]::new($ticks,[DateTimeKind]::Utc);ProcessName='fixture';TotalProcessorTime=[timespan]::FromSeconds(10);WorkingSet64=64MB;PrivateMemorySize64=128MB;MainWindowHandle=[intptr]::Zero}
$first=Get-MiAcceptanceObservation -Process $fake -Target $target -Elapsed 5 -Previous $null -ProcessorCount 2
if ($null -ne $first.CpuPercent -or $first.Responding -ne 'Unknown') {throw 'First observation fabricated CPU or window responsiveness.'}
$next=Get-MiAcceptanceObservation -Process $fake -Target $target -Elapsed 10 -Previous @{Elapsed=5;Cpu=8} -ProcessorCount 2
if ($next.CpuPercent -ne 20 -or $next.WorkingSetMiB -ne 64 -or $next.PrivateMiB -ne 128) {throw 'Observer CPU delta or memory units are wrong.'}
$culture=[Threading.Thread]::CurrentThread.CurrentCulture
try {
    [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('fr-FR')
    $csvRow=ConvertTo-MiAcceptanceCsvRow $next
    if (($csvRow -split ',').Count -ne 8 -or $csvRow -notmatch ',64\.00,128\.00,20\.0000,') {throw 'Locale-specific decimals corrupted observer CSV.'}
} finally {[Threading.Thread]::CurrentThread.CurrentCulture=$culture}
$target.StartUtcTicks=$ticks-1;$refused=$false
try {[void](Get-MiAcceptanceObservation -Process $fake -Target $target -Elapsed 10 -Previous $null)}catch{$refused=$true}
if (-not $refused) {throw 'Observer accepted a reused process identity.'}

# 零目标可用必须产生非空、可解析的失败摘要，不能静默输出空 JSON。
[IO.File]::WriteAllText($jobsFile,'[{"Pid":2147483647,"StartUtcTicks":1}]',[Text.UTF8Encoding]::new($true))
try {
    $ErrorActionPreference='Continue'
    $emptyOutput=& $psExe -NoProfile -ExecutionPolicy RemoteSigned -File (Join-Path $root 'AcceptanceGuiMonitor.ps1') -JobsPath $jobsFile -DurationMinutes 1 -OutputDirectory $fixture 2>&1
    $emptyExit=$LASTEXITCODE
} finally {$ErrorActionPreference=$previousPreference}
$summaryFile=Get-ChildItem -LiteralPath $fixture -Filter 'm8-gui-*.json' -File|Select-Object -First 1
if ($emptyExit -eq 0 -or $null -eq $summaryFile -or $summaryFile.Length -eq 0) {throw 'Unavailable observer targets silently succeeded or produced empty summary.'}
$emptySummary=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($summaryFile.FullName,[Text.Encoding]::UTF8))
if ($emptySummary.Observations -ne 0 -or $emptySummary.Targets.Count -ne 1 -or $emptySummary.FinishReason -eq 'Completed') {throw 'Unavailable observer target summary hid failure.'}
Write-Host ('PASS: RemoteSigned trust boundary and observer JSON/identity/CPU/locale/empty-result regressions. Retained: '+$fixture) -ForegroundColor Green
