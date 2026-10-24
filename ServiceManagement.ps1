#requires -Version 5.1
<#
M7 Windows service management. Elevated executor only for mutations.
No process termination, forced stops, cascading dependencies, startup-type edits,
service recovery-setting changes, or automatic retries.
#>
Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
function Test-MiServiceName {
    param([string]$Name)
    return (-not [string]::IsNullOrWhiteSpace($Name) -and $Name -cmatch '^[A-Za-z0-9_.-]{1,128}$')
}
function Test-MiServiceDenied {
    param([string]$Name)
    $blocked=@(
        'RpcSs','RpcEptMapper','DcomLaunch','PlugPlay','EventLog','Winmgmt',
        'SamSs','ProfSvc','Power','BFE','MpsSvc','WinDefend','SecurityHealthService',
        'CryptSvc','Schedule','LSM','BrokerInfrastructure','SystemEventsBroker',
        'Appinfo','TrustedInstaller','LanmanWorkstation','Dhcp','Dnscache',
        'Netlogon','NlaSvc','W32Time','Wcmsvc','EventSystem','UserManager',
        'StateRepository','TokenBroker','TermService','gpsvc','SENS'
    )
    foreach ($v in $blocked) {
        if ([string]::Equals($v,$Name,[StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
function Get-MiServiceRecord {
    param([string]$Name)
    if (-not (Test-MiServiceName $Name)) { throw 'Invalid service name.' }
    $rows=@(Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$Name+"'") -ErrorAction Stop)
    if ($rows.Count -ne 1 -or -not [string]::Equals([string]$rows[0].Name,$Name,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Service identity missing or ambiguous.'
    }
    return $rows[0]
}
function Assert-MiServiceEligible {
    param($Service)
    $name=[string]$Service.Name
    if (-not (Test-MiServiceName $name) -or (Test-MiServiceDenied $name)) { throw 'Protected service denied.' }
    if ([string]$Service.ServiceType -cnotin @('Own Process','Share Process')) {
        throw 'Only Win32 own/shared process services are eligible; drivers are denied.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Service.PathName) -or
        [string]::IsNullOrWhiteSpace([string]$Service.StartName)) {
        throw 'Service executable or account is unknown.'
    }
    if ([string]$Service.StartMode -eq 'Disabled') { throw 'Disabled service requires manual management outside MemoryInspector.' }
    # Windows-hosted service operations require BOTH a built-in conservative scope
    # and the separately administrator-approved protected allowlist.
    $expanded=[Environment]::ExpandEnvironmentVariables([string]$Service.PathName).Trim([char[]]@('"',' '))
    $windowsRoot=[IO.Path]::GetFullPath($env:WINDIR).TrimEnd('\')
    $systemHosted=$expanded.StartsWith($windowsRoot+'\', [StringComparison]::OrdinalIgnoreCase) -or
        $expanded.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)
    if ($systemHosted -and $name -notin @('Spooler','WSearch','SysMain','WerSvc','DiagTrack','MapsBroker','Fax')) {
        throw 'This Windows-hosted service is outside the conservative M7 system-service scope.'
    }
    $registry='HKLM:\SYSTEM\CurrentControlSet\Services\'+$name
    $config=Get-ItemProperty -LiteralPath $registry -ErrorAction Stop
    if ($null -ne $config.LaunchProtected -and [int]$config.LaunchProtected -ne 0) {
        throw 'Protected Windows service configuration; operation forbidden.'
    }
}
function Get-MiServiceFingerprint {
    param($Service)
    return [pscustomobject]@{
        Name=[string]$Service.Name
        PathName=[string]$Service.PathName
        ServiceType=[string]$Service.ServiceType
        StartName=[string]$Service.StartName
    }
}
function Test-MiServiceFingerprint {
    param($Service,$Approved)
    if ($null -eq $Approved) { return $false }
    foreach ($key in @('Name','PathName','ServiceType','StartName')) {
        if (-not [string]::Equals([string]$Service.$key,[string]$Approved.$key,[StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}
function Read-MiServicePolicy {
    $paths=Get-MiSecurityPaths
    if (-not (Test-MiNoReparse $paths.Policy) -or -not (Test-MiAclRestricted $paths.Policy $true)) {
        throw 'Protected allowlist ACL/path is invalid.'
    }
    $policy=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Policy,[Text.Encoding]::UTF8)) -ErrorAction Stop
    if ([int]$policy.SchemaVersion -ne 1 -or $null -eq $policy.Services) { throw 'Invalid service allowlist schema.' }
    return $policy
}
function Write-MiServiceProtectedJson {
    param([string]$Destination,$Value)
    $paths=Get-MiSecurityPaths
    if (@($paths.Policy,$paths.Recovery) -cnotcontains $Destination) { throw 'Unrecognized protected output.' }
    if (-not (Test-MiNoReparse $Destination) -or -not (Test-MiAclRestricted $Destination $true)) {
        throw 'Untrusted destination for protected update.'
    }
    $temp=Join-Path (Split-Path -Parent $Destination) ('stage-'+[guid]::NewGuid().ToString('N')+'.tmp')
    try {
        [IO.File]::WriteAllText($temp,($Value | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        $publicRead=($Destination -ceq $paths.Policy)
        Set-MiProtectedFileAcl -Path $temp -AllowUsersRead $publicRead
        [IO.File]::Replace($temp,$Destination,$null)
        Set-MiProtectedFileAcl -Path $Destination -AllowUsersRead $publicRead
        if (-not (Test-MiAclRestricted $Destination $true)) { throw 'Protected update ACL failed.' }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}
function Get-MiServiceApproval {
    param([string]$Name)
    $policy=Read-MiServicePolicy
    $matches=@($policy.Services | Where-Object { [string]::Equals([string]$_.Name,$Name,[StringComparison]::OrdinalIgnoreCase) })
    if ($matches.Count -gt 1) { throw 'Ambiguous allowlist entry.' }
    if ($matches.Count -eq 0) { return $null }
    return $matches[0]
}
function Assert-MiServiceApproved {
    param($Service)
    Assert-MiServiceEligible $Service
    $approved=Get-MiServiceApproval ([string]$Service.Name)
    if ($null -eq $approved -or -not (Test-MiServiceFingerprint $Service $approved)) {
        throw 'Service not approved or its installation identity changed.'
    }
    return $approved
}
function Assert-MiServiceDependentsStopped {
    param([string]$Name)
    $controller=[System.ServiceProcess.ServiceController]::new($Name)
    try {
        $active=@($controller.DependentServices | Where-Object { $_.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped })
        if ($active.Count -gt 0) { throw 'Dependent services are not stopped. Cascading stop is forbidden.' }
    } finally { $controller.Dispose() }
}
function Assert-MiServicePrerequisitesRunning {
    param([string]$Name)
    $controller=[System.ServiceProcess.ServiceController]::new($Name)
    try {
        $missing=@($controller.ServicesDependedOn | Where-Object {
            $_.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running
        })
        if ($missing.Count -gt 0) { throw 'Required services are not running; implicit automatic dependency starts are forbidden.' }
    } finally { $controller.Dispose() }
}
function Confirm-MiServiceAction {
    param([string]$Operation,$Service)
    Write-Host ''
    Write-Host ('Service: '+$Service.Name+' / '+$Service.DisplayName) -ForegroundColor Yellow
    Write-Host ('State: '+$Service.State+'; StartMode: '+$Service.StartMode+'; PID: '+$Service.ProcessId)
    Write-Host ('Type: '+$Service.ServiceType+'; Account: '+$Service.StartName)
    Write-Host ('Binary command: '+$Service.PathName)
    Write-Host 'Changes may disrupt applications and cannot restore in-memory state.'
    $word=switch ($Operation) {
        'ApproveService' {'APPROVE'}
        'RevokeServiceApproval' {'REVOKE'}
        'StopApprovedService' {'STOP'}
        'StartPreviouslyStoppedService' {'START'}
        default {throw 'Unknown confirmation operation.'}
    }
    $expected=$word+' '+$Service.Name
    $value=Read-Host ('Elevated confirmation: type exactly '+$expected)
    if ($value -cne $expected) { throw 'Operator cancelled elevated service confirmation.' }
}
function Update-MiServiceApproval {
    param([string]$Operation,$Service)
    $policy=Read-MiServicePolicy
    $items=@($policy.Services | Where-Object { -not [string]::Equals([string]$_.Name,[string]$Service.Name,[StringComparison]::OrdinalIgnoreCase) })
    if ($Operation -eq 'ApproveService') {
        Assert-MiServiceEligible $Service
        $fp=Get-MiServiceFingerprint $Service
        $items+= [pscustomobject]@{
            Name=$fp.Name;PathName=$fp.PathName;ServiceType=$fp.ServiceType;StartName=$fp.StartName
            ApprovedUtc=[datetime]::UtcNow.ToString('o')
        }
    } elseif ($Operation -ne 'RevokeServiceApproval') { throw 'Unrecognized policy update.' }
    Write-MiServiceProtectedJson -Destination (Get-MiSecurityPaths).Policy -Value ([pscustomobject]@{
        SchemaVersion=1;Services=@($items | Sort-Object Name)
    })
}
function Read-MiServiceRecovery {
    $paths=Get-MiSecurityPaths
    if (-not (Test-MiNoReparse $paths.Recovery) -or -not (Test-MiAclRestricted $paths.Recovery $true)) {
        throw 'Untrusted protected service recovery record.'
    }
    $obj=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths.Recovery,[Text.Encoding]::UTF8)) -ErrorAction Stop
    if ($obj.SchemaVersion -ne 1 -or $null -eq $obj.Records) { throw 'Invalid recovery ledger.' }
    return $obj
}
function Write-MiRecoveryRecord {
    param($Service,[string]$RequestId,[string]$Status,[bool]$Remove=$false)
    $record=Read-MiServiceRecovery
    $records=@($record.Records | Where-Object { -not [string]::Equals([string]$_.Name,[string]$Service.Name,[StringComparison]::OrdinalIgnoreCase) })
    if (-not $Remove) {
        $f=Get-MiServiceFingerprint $Service
        $records+= [pscustomobject]@{
            Name=$f.Name;PathName=$f.PathName;ServiceType=$f.ServiceType;StartName=$f.StartName
            StopRequestId=$RequestId;Status=$Status;Utc=[datetime]::UtcNow.ToString('o')
        }
    }
    Write-MiServiceProtectedJson -Destination (Get-MiSecurityPaths).Recovery -Value ([pscustomobject]@{
        SchemaVersion=1;Records=@($records)
    })
}
function Get-MiServiceRecoveryEntry {
    param([string]$Name)
    $ledger=Read-MiServiceRecovery
    $matches=@($ledger.Records | Where-Object { [string]::Equals([string]$_.Name,$Name,[StringComparison]::OrdinalIgnoreCase) })
    if ($matches.Count -gt 1) { throw 'Ambiguous recovery records.' }
    if ($matches.Count -eq 0) { return $null }
    return $matches[0]
}
function Invoke-MiScControl {
    param([ValidateSet('stop','start')][string]$Verb,[string]$Name)
    if (-not (Test-MiServiceName $Name)) { throw 'Invalid service name for SCM.' }
    # Win32_Service methods target ONE service and do not cascade through dependents.
    $current=Get-MiServiceRecord $Name
    $method=if ($Verb -eq 'stop') {'StopService'} else {'StartService'}
    $response=Invoke-CimMethod -InputObject $current -MethodName $method -ErrorAction Stop
    if ($null -eq $response -or [int]$response.ReturnValue -ne 0) {
        throw ('SCM declined '+$method+' (code '+[string]$response.ReturnValue+'); state uncertain.')
    }
}
function Invoke-MiServiceMutation {
    param([string]$Operation,[string]$ServiceName,[string]$RequestId)
    $service=Get-MiServiceRecord $ServiceName
    Assert-MiServiceEligible $service
    if ($Operation -eq 'ApproveService') {
        if ($service.State -notin @('Running','Stopped')) { throw 'Service transition is in progress.' }
        Confirm-MiServiceAction $Operation $service
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'REQUESTED' -Reason 'Administrator reviewed service identity'
        $fresh=Get-MiServiceRecord $ServiceName
        Assert-MiServiceEligible $fresh
        if (-not (Test-MiServiceFingerprint $fresh $service)) { throw 'Service identity changed.' }
        Update-MiServiceApproval -Operation $Operation -Service $fresh
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'CONFIRMED' -Reason 'Service allowlist updated'
        return 'Confirmed'
    }
    if ($Operation -eq 'RevokeServiceApproval') {
        if ($null -ne (Get-MiServiceRecoveryEntry $ServiceName)) {
            throw 'Recovery record exists. Restore or resolve this service before revocation.'
        }
        Confirm-MiServiceAction $Operation $service
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'REQUESTED' -Reason 'Administrator revocation'
        $fresh=Get-MiServiceRecord $ServiceName
        Assert-MiServiceEligible $fresh
        if (-not (Test-MiServiceFingerprint $fresh $service)) { throw 'Service identity changed.' }
        Update-MiServiceApproval -Operation $Operation -Service $fresh
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'CONFIRMED' -Reason 'Service approval removed'
        return 'Confirmed'
    }
    [void](Assert-MiServiceApproved $service)
    if ($Operation -eq 'StopApprovedService') {
        if ($service.State -cne 'Running' -or -not [bool]$service.CanStop) { throw 'Service must be running and support STOP.' }
        Assert-MiServiceDependentsStopped $ServiceName
    } elseif ($Operation -eq 'StartPreviouslyStoppedService') {
        if ($service.State -cne 'Stopped') { throw 'Restore requires a stopped service.' }
        Assert-MiServicePrerequisitesRunning $ServiceName
        $entry=Get-MiServiceRecoveryEntry $ServiceName
        if ($null -eq $entry -or -not (Test-MiServiceFingerprint $service $entry) -or
            $entry.Status -cnotin @('StopRequested','Stopped')) { throw 'No matching previous stop record.' }
    } else { throw 'Unknown service mutation.' }
    Confirm-MiServiceAction $Operation $service
    # Confirmation can take arbitrarily long. Refresh ALL security-relevant facts.
    $fresh=Get-MiServiceRecord $ServiceName
    [void](Assert-MiServiceApproved $fresh)
    if (-not (Test-MiServiceFingerprint $fresh $service)) { throw 'Service identity changed during confirmation.' }
    if ($Operation -eq 'StopApprovedService') {
        if ($fresh.State -cne 'Running' -or -not [bool]$fresh.CanStop) { throw 'Service state changed before stop.' }
        Assert-MiServiceDependentsStopped $ServiceName
    } else {
        if ($fresh.State -cne 'Stopped') { throw 'Service state changed before restore.' }
        Assert-MiServicePrerequisitesRunning $ServiceName
        $entry=Get-MiServiceRecoveryEntry $ServiceName
        if ($null -eq $entry -or -not (Test-MiServiceFingerprint $fresh $entry) -or
            $entry.Status -cnotin @('StopRequested','Stopped')) { throw 'Recovery evidence changed.' }
    }
    Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'REQUESTED' -Reason ('Pre-state: '+$fresh.State)
    if ($Operation -eq 'StopApprovedService') {
        # Write recovery evidence before the non-reversible request.
        Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status 'StopRequested'
        Assert-MiServiceDependentsStopped $ServiceName
        Invoke-MiScControl -Verb stop -Name $ServiceName
        $desired=[System.ServiceProcess.ServiceControllerStatus]::Stopped
    } else {
        Invoke-MiScControl -Verb start -Name $ServiceName
        $desired=[System.ServiceProcess.ServiceControllerStatus]::Running
    }
    $controller=[System.ServiceProcess.ServiceController]::new($ServiceName)
    try {
        try { $controller.WaitForStatus($desired,[timespan]::FromSeconds(15)) }
        catch [System.ServiceProcess.TimeoutException] {
            Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'TIMED_OUT' -Reason 'No retry; service may still transition'
            return 'TimedOut'
        }
    } finally { $controller.Dispose() }
    if ($Operation -eq 'StopApprovedService') {
        Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status 'Stopped'
    } else {
        Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status 'Restored' -Remove $true
    }
    Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'CONFIRMED' -Reason ('Final state: '+$desired)
    return 'Confirmed'
}
