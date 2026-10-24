#requires -Version 5.1
<#
Milestone 8 deterministic fail-closed acceptance checks.
Read-only: NEVER terminates a process, changes a service, or requests UAC.
Temporary fault fixtures are created only under the current user's TEMP.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$version = ([IO.File]::ReadAllText((Join-Path $root 'VERSION'))).Trim()
if ($version -cne '0.0.8') { throw ('Expected 0.0.8, found '+$version) }

$files = @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File)
foreach ($file in $files) {
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
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('MiM8Test-'+[guid]::NewGuid().ToString('N'))
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
    if ([IO.Directory]::Exists($fixture)) { [IO.Directory]::Delete($fixture,$true) }
}

# GUI is a display and dispatcher, never the direct privileged action executor.
foreach ($name in @('MemoryInspector.ps1','GuiV4.ps1')) {
    $source = [IO.File]::ReadAllText((Join-Path $root $name),[Text.Encoding]::UTF8)
    if ($source -match '(?im)^\s*(Stop-Process|Stop-Service|Start-Service|taskkill)\b' -or
        $source -match '(?i)\.Kill\s*\(') { throw ('Direct unsafe action in GUI: '+$name) }
}
Write-Host ('PASS: M8 parsing, fail-closed request validation, invalid settings and GUI separation ({0} scripts).' -f $files.Count) -ForegroundColor Green
