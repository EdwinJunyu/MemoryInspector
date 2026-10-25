#requires -Version 5.1
<# M6 regression: source parsing, secure pure contracts, and disposable ACL fixture.
No UAC prompt, service modification, process termination, or install performed. #>
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$files=@('PrivilegeSecurity.ps1','PrivilegeBridge.ps1','ElevatedExecutor.ps1',
    'Installer.ps1','Uninstaller.ps1','MemoryInspector.ps1','GuiV4.ps1',
    'ServiceManagement.ps1','ServiceBridge.ps1')
foreach ($f in $files) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $f),[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { throw ('M6 parse failure '+$f+': '+($errors|Out-String)) }
}
. (Join-Path $root 'PrivilegeSecurity.ps1')
$id=[guid]::NewGuid().ToString('N')
if (-not (Test-MiGuidN $id)) { throw 'Valid GUID rejected.' }
foreach ($bad in @('', '00000000000000000000000000000000','../evil','xxxx',('a'*33))) {
    if (Test-MiGuidN $bad) { throw 'Invalid request ID accepted.' }
}
if (-not (Test-MiPrivilegedOperation -Operation 'Probe' -RequestId $id)) {
    throw 'Allowed harmless M6 probe was rejected.'
}
foreach ($forbidden in @('StopApprovedService','StartPreviouslyStoppedService','ApproveService',
    'RevokeServiceApproval','TerminateApprovedUserProcess','RunCommand','probe','')) {
    if (Test-MiPrivilegedOperation -Operation $forbidden -RequestId $id) {
        throw ('M6 unexpectedly unlocked an operation: '+$forbidden)
    }
}
$executor=Get-Content -LiteralPath (Join-Path $root 'ElevatedExecutor.ps1') -Raw -Encoding UTF8
if ($executor -match '(?i)\b(Stop-Service|Start-Service|Stop-Process|Invoke-Expression|Invoke-Command|Set-Service|sc\.exe|taskkill)\b') {
    throw 'Executor contains forbidden service/process commands.'
}
if ($executor -notmatch 'CreateNew' -or $executor -notmatch 'Assert-MiTrustedInstallation' -or
    $executor -notmatch 'Write-MiPrivilegedAudit' -or $executor -notmatch 'Test-MiPrivilegedOperation') {
    throw 'Executor lacks request replay/integrity/audit safeguards.'
}
$bridge=Get-Content -LiteralPath (Join-Path $root 'PrivilegeBridge.ps1') -Raw -Encoding UTF8
if ($bridge -notmatch 'Start-Process' -or $bridge -notmatch 'RunAs' -or
    $bridge -notmatch 'Test-MiPrivilegeBridgeInstalled') { throw 'GUI bridge is not limited to protected UAC installation.' }
$install=Get-Content -LiteralPath (Join-Path $root 'Installer.ps1') -Raw -Encoding UTF8
if ($install -notmatch 'Set-MiAdminDirectoryAcl' -or $install -notmatch 'Set-MiProtectedFileAcl' -or
    $install -notmatch 'Assert-MiTrustedInstallation') { throw 'Protected installer safeguards missing.' }
if ((Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim() -cne '0.0.9') {
    throw 'VERSION mismatch.'
}
# 版本升级必须执行真实信任函数，而非仅比较源码字符串。夹具仅模拟本目录的ACL，
# 不安装、不提权；文件/清单/哈希和M7必需项实际验证，不能替代管理员部署验收。
& {
    $fixture=Join-Path (Join-Path $root 'test-artifacts') ('VersionTrust-'+[guid]::NewGuid().ToString('N'))
    $versionPaths=[pscustomobject]@{
        Install=(Join-Path $fixture 'install');Data=(Join-Path $fixture 'data')
        Replay=(Join-Path $fixture 'data\replay');Results=(Join-Path $fixture 'data\results')
        PolicyFolder=(Join-Path $fixture 'data\policy');Policy=(Join-Path $fixture 'data\policy\approved.json')
        Audit=(Join-Path $fixture 'data\audit\audit.jsonl');Manifest=(Join-Path $fixture 'data\manifest.json')
        Recovery=(Join-Path $fixture 'data\policy\recovery.json')
    }
    foreach($directory in @($versionPaths.Install,$versionPaths.Data,$versionPaths.Replay,$versionPaths.Results,$versionPaths.PolicyFolder,(Split-Path -Parent $versionPaths.Audit))){[void][IO.Directory]::CreateDirectory($directory)}
    foreach($file in @($versionPaths.Policy,$versionPaths.Audit,$versionPaths.Recovery)){[IO.File]::WriteAllText($file,'fixture',[Text.UTF8Encoding]::new($false))}
    function Get-MiSecurityPaths {return $versionPaths}
    function Test-MiAclRestricted {
        param([string]$Path,[bool]$Directory=$false)
        return [IO.Path]::GetFullPath($Path).StartsWith($fixture+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
    }
    # 某些PS5.1执行环境没有自动加载Get-FileHash；测试适配器仍对真实夹具字节计算SHA-256。
    function Get-FileHash {
        param([string]$LiteralPath,[string]$Algorithm)
        if($Algorithm -cne 'SHA256'){throw 'Unexpected hash algorithm.'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try{return [pscustomobject]@{Hash=([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($LiteralPath)))).Replace('-','')}}finally{$sha.Dispose()}
    }
    $versionEntries=New-Object 'System.Collections.Generic.List[object]'
    foreach($name in @('ElevatedExecutor.ps1','PrivilegeSecurity.ps1','ServiceManagement.ps1','ServiceBridge.ps1','VERSION','Collector.ps1','GuiV4.ps1','Worker.ps1','Analyzer.ps1')){
        $file=Join-Path $versionPaths.Install $name
        [IO.File]::WriteAllText($file,'fixture',[Text.UTF8Encoding]::new($false))
        $versionEntries.Add([pscustomobject]@{Name=$name;Sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash})
    }
    function Write-VersionManifest {
        param([string]$Version,$Files)
        $manifest=[pscustomobject]@{SchemaVersion=1;Version=$Version;Files=@($Files)}
        [IO.File]::WriteAllText($versionPaths.Manifest,($manifest|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    }
    function Assert-VersionTrustRejected {
        param([string]$ExpectedMessage)
        $rejected=$false
        try{[void](Assert-MiTrustedInstallation)}catch{
            if(-not $_.Exception.Message.Contains($ExpectedMessage)){throw}
            $rejected=$true
        }
        if(-not $rejected){throw ('Version trust unexpectedly accepted: '+$ExpectedMessage)}
    }
    $allEntries=$versionEntries.ToArray()
    Write-VersionManifest '0.0.9' $allEntries
    [void](Assert-MiTrustedInstallation)
    foreach($oldVersion in @('0.0.7','0.0.8')){
        Write-VersionManifest $oldVersion $allEntries
        Assert-VersionTrustRejected 'Invalid installation manifest/version.'
        [void](Assert-MiTrustedInstallation -AllowedVersions @('0.0.7','0.0.8','0.0.9'))
    }
    foreach($unknownVersion in @('0.0.10','1.2.3','0.0.9.1','0.0.9 ')){
        Write-VersionManifest $unknownVersion $allEntries
        Assert-VersionTrustRejected 'Invalid installation manifest/version.'
    }
    foreach($essential in @('ElevatedExecutor.ps1','PrivilegeSecurity.ps1','ServiceManagement.ps1','ServiceBridge.ps1','VERSION')){
        Write-VersionManifest '0.0.9' @($allEntries|Where-Object Name -cne $essential)
        Assert-VersionTrustRejected ('Missing M7 component: '+$essential)
    }
    Write-VersionManifest '0.0.9' $allEntries
    $retainedLedger=Join-Path $versionPaths.PolicyFolder 'recovery.retained.json'
    [IO.File]::Move($versionPaths.Recovery,$retainedLedger)
    try{Assert-VersionTrustRejected 'Untrusted service recovery ledger.'}finally{[IO.File]::Move($retainedLedger,$versionPaths.Recovery)}
    [void](Assert-MiTrustedInstallation)
}
Write-Host 'PASS: 0.0.9 exact trust pin, explicit old-version upgrade, unknown-version rejection and unchanged M7 component/ledger requirements (ACL mocked only in fixture).'
# Lightweight ACL smoke test in a uniquely named throwaway temp directory.
# This is deliberately NOT an installation and never changes Windows services.
if (Test-MiAdminToken) {
    # 管理员测试只保护本次唯一夹具，保留证据；不安装应用或修改项目根目录的 ACL。
    $dir=Join-Path (Join-Path $root 'test-artifacts') ('MiM6AclTest-'+[guid]::NewGuid().ToString('N'))
    try {
        [void][IO.Directory]::CreateDirectory($dir)
        Set-MiAdminDirectoryAcl -Path $dir -AllowUsersRead $true
        if (-not (Test-MiAclRestricted $dir $true)) { throw 'Protected fixture directory is not restricted.' }
        $f=Join-Path $dir 'fixture.txt'
        [IO.File]::WriteAllText($f,'fixture',[Text.Encoding]::UTF8)
        Set-MiProtectedFileAcl -Path $f -AllowUsersRead $true
        if (-not (Test-MiAclRestricted $f $true)) { throw 'Protected fixture file is not restricted.' }
        if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -eq '') {
            throw 'SHA256 fixture failed.'
        }
    } finally {
        Write-Host ('ACL fixture retained: '+$dir)
    }
} else {
    Write-Host 'INFO: non-admin CI host; disposable ACL fixture skipped.'
}
Write-Host 'PASS: M6 safeguards retained and M7 service scope gated by exact target name.' -ForegroundColor Green
