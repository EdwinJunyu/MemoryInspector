#requires -Version 5.1
<#
M7 Windows service management. Elevated executor only for mutations.
No process termination, forced stops, cascading dependencies, startup-type edits,
service recovery-setting changes, or automatic retries.
#>
Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
function Enter-MiServiceLock {
    param([ValidateSet('Target','Policy','Recovery')][string]$Kind,[string]$Name='',
        [ValidateRange(0,5000)][int]$TimeoutMilliseconds=1000)
    if (-not (Test-MiAdminToken)) { throw 'Administrator token required for protected operation locks.' }
    $paths=Get-MiSecurityPaths
    if (-not (Test-MiNoReparse $paths.PolicyFolder) -or
        -not (Test-MiAclRestricted $paths.PolicyFolder $true)) { throw 'Untrusted protected lock directory.' }
    if ($Kind -eq 'Target') {
        if (-not (Test-MiServiceName $Name)) { throw 'Invalid service lock target.' }
        $leaf='service-'+$Name.ToLowerInvariant()+'.lock'
    } else { $leaf=$Kind.ToLowerInvariant()+'.lock' }
    # 锁名仅取决于服务身份或共享文件，不包含 RequestId；锁文件长期保留，避免删除重建绕过已有句柄。
    # 独占文件句柄跨 Windows 会话生效，异常退出由操作系统释放；未知服务结果另由 Ledger 阻止重试。
    $path=Join-Path $paths.PolicyFolder $leaf
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        $handle=$null
        try {
            if ([IO.File]::Exists($path) -and (-not (Test-MiNoReparse $path) -or
                -not (Test-MiAclRestricted $path $true))) { throw 'Untrusted existing operation lock.' }
            $handle=[IO.File]::Open($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            Set-MiProtectedFileAcl -Path $path
            if (-not (Test-MiNoReparse $path) -or -not (Test-MiAclRestricted $path $true)) {
                throw 'Operation lock ACL validation failed.'
            }
            return $handle
        } catch [IO.IOException] {
            if ($null -ne $handle) { $handle.Dispose(); throw }
            if ($watch.ElapsedMilliseconds -ge $TimeoutMilliseconds) { throw 'Operation lock unavailable; request refused.' }
            Start-Sleep -Milliseconds 25
        } catch {
            if ($null -ne $handle) { $handle.Dispose() }
            throw
        }
    } while ($true)
}
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
        [IO.File]::Replace($temp,$Destination,[NullString]::Value)
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
    $stateLock=Enter-MiServiceLock -Kind Policy
    try {
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
    } finally { $stateLock.Dispose() }
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
    param($Service,[string]$RequestId,[string]$Status,[bool]$Remove=$false,[string]$Reason='')
    if ($Status -cnotin @('StopRequested','StopConfirmed','StopFailed','TimedOut','UnknownOutcome',
        'RestoreRequested','RestoreConfirmed','RestoreFailed')) { throw 'Unrecognized recovery transition.' }
    # Ledger 的读、修改、审计、原子替换处于同一独占锁内，避免不同服务的并发更新互相覆盖。
    $stateLock=Enter-MiServiceLock -Kind Recovery
    try {
        $record=Read-MiServiceRecovery
        $previous=@($record.Records | Where-Object {
            [string]::Equals([string]$_.Name,[string]$Service.Name,[StringComparison]::OrdinalIgnoreCase)
        })
        if ($previous.Count -gt 1) { throw 'Ambiguous recovery records.' }
        $records=@($record.Records | Where-Object { -not [string]::Equals([string]$_.Name,[string]$Service.Name,[StringComparison]::OrdinalIgnoreCase) })
        $f=Get-MiServiceFingerprint $Service
        $stopId=$RequestId
        if ($Status -like 'Restore*' -or ($Status -cin @('TimedOut','UnknownOutcome') -and
            $previous.Count -eq 1 -and $previous[0].Status -like 'Restore*')) {
            if ($previous.Count -eq 1) { $stopId=[string]$previous[0].StopRequestId }
        }
        $from=if ($previous.Count -eq 1) { [string]$previous[0].Status } else { 'None' }
        $action=if ($Status -like 'Restore*' -or $from -like 'Restore*') { 'StartPreviouslyStoppedService' } else { 'StopApprovedService' }
        # 先确保状态转换已写入受保护审计，再提交 Ledger；审计失败时保留上次状态并拒绝后续危险操作。
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $action -ServiceName $f.Name -State $Status -Reason ($from+' -> '+$Status+'; '+$Reason)
        $records+= [pscustomobject]@{
            Name=$f.Name;PathName=$f.PathName;ServiceType=$f.ServiceType;StartName=$f.StartName
            StopRequestId=$stopId;LastRequestId=$RequestId;Status=$Status;Utc=[datetime]::UtcNow.ToString('o')
        }
        # 保留 RestoreConfirmed 终态供核查；Remove 参数为旧调用兼容保留，不再抹除已完成操作证据。
        Write-MiServiceProtectedJson -Destination (Get-MiSecurityPaths).Recovery -Value ([pscustomobject]@{
            SchemaVersion=1;Records=@($records)
        })
    } finally { $stateLock.Dispose() }
}
function Test-MiRecoveryRestorable {
    param($Service,$Entry)
    # 兼容旧版本明确确认后的 Stopped，绝不把旧 StopRequested 或不明结果当作停止成功。
    return ($null -ne $Entry -and (Test-MiServiceFingerprint $Service $Entry) -and
        [string]$Entry.Status -cin @('StopConfirmed','Stopped') -and (Test-MiGuidN ([string]$Entry.StopRequestId)))
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
    # 每次调用只针对一个服务，不触发依赖项级联；CIM 异常代表结果未知，不能自动重试。
    $current=Get-MiServiceRecord $Name
    $method=if ($Verb -eq 'stop') {'StopService'} else {'StartService'}
    $response=Invoke-CimMethod -InputObject $current -MethodName $method -ErrorAction Stop
    if ($null -eq $response -or $null -eq $response.ReturnValue) { throw 'SCM response missing; outcome unknown.' }
    return [int]$response.ReturnValue
}
function Wait-MiServiceState {
    param([string]$Name,[System.ServiceProcess.ServiceControllerStatus]$Desired)
    $controller=[System.ServiceProcess.ServiceController]::new($Name)
    try { $controller.WaitForStatus($Desired,[timespan]::FromSeconds(15)) }
    finally { $controller.Dispose() }
}
function Invoke-MiServiceMutation {
    param([string]$Operation,[string]$ServiceName,[string]$RequestId)
    if (-not (Test-MiPrivilegedOperation -Operation $Operation -RequestId $RequestId -ServiceName $ServiceName) -or $Operation -eq 'Probe') {
        throw 'Invalid service mutation protocol.'
    }
    $targetLock=Enter-MiServiceLock -Kind Target -Name $ServiceName -TimeoutMilliseconds 0
    try {
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
            $existing=Get-MiServiceRecoveryEntry $ServiceName
            if ($null -ne $existing -and $existing.Status -cnotin @('StopFailed','RestoreConfirmed')) {
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
            $existing=Get-MiServiceRecoveryEntry $ServiceName
            if ($null -ne $existing -and $existing.Status -cnotin @('StopFailed','RestoreConfirmed')) {
                throw 'Previous stop/restore has unresolved or already confirmed evidence; manual resolution required.'
            }
            if ($service.State -cne 'Running' -or -not [bool]$service.CanStop) { throw 'Service must be running and support STOP.' }
            Assert-MiServiceDependentsStopped $ServiceName
        } elseif ($Operation -eq 'StartPreviouslyStoppedService') {
            if ($service.State -cne 'Stopped') { throw 'Restore requires a stopped service.' }
            Assert-MiServicePrerequisitesRunning $ServiceName
            $entry=Get-MiServiceRecoveryEntry $ServiceName
            if (-not (Test-MiRecoveryRestorable $service $entry)) { throw 'No matching previous stop record.' }
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
            if (-not (Test-MiRecoveryRestorable $fresh $entry)) { throw 'Recovery evidence changed.' }
        }
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'REQUESTED' -Reason ('Pre-state: '+$fresh.State)
        $isStop=($Operation -eq 'StopApprovedService')
        $requested=if ($isStop) { 'StopRequested' } else { 'RestoreRequested' }
        $failed=if ($isStop) { 'StopFailed' } else { 'RestoreFailed' }
        $confirmed=if ($isStop) { 'StopConfirmed' } else { 'RestoreConfirmed' }
        Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status $requested -Reason 'Confirmed administrator request; SCM not yet dispatched'
        try {
            if ($isStop) {
                Assert-MiServiceDependentsStopped $ServiceName
                $code=Invoke-MiScControl -Verb stop -Name $ServiceName
                $desired=[System.ServiceProcess.ServiceControllerStatus]::Stopped
            } else {
                Assert-MiServicePrerequisitesRunning $ServiceName
                $code=Invoke-MiScControl -Verb start -Name $ServiceName
                $desired=[System.ServiceProcess.ServiceControllerStatus]::Running
            }
            if ($code -ne 0) {
                Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status $failed -Reason ('SCM declined request; code '+$code)
                return 'Failed'
            }
            try { Wait-MiServiceState -Name $ServiceName -Desired $desired }
            catch [System.ServiceProcess.TimeoutException] {
                Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status 'TimedOut' -Reason 'No retry; service may still transition'
                return 'TimedOut'
            }
            # WaitForStatus 后仍检查身份和真实 SCM 状态，不能仅凭请求被接受就登记停止成功。
            $final=Get-MiServiceRecord $ServiceName
            if (-not (Test-MiServiceFingerprint $final $fresh) -or [string]$final.State -cne [string]$desired) {
                throw 'Final service identity/state cannot be confirmed.'
            }
        } catch {
            Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status 'UnknownOutcome' -Reason ([string]$_.Exception.Message)
            throw
        }
        Write-MiRecoveryRecord -Service $fresh -RequestId $RequestId -Status $confirmed -Reason ('Verified final state: '+$desired)
        Write-MiPrivilegedAudit -RequestId $RequestId -Action $Operation -ServiceName $ServiceName -State 'CONFIRMED' -Reason ('Final state: '+$desired)
        return 'Confirmed'
    } finally { $targetLock.Dispose() }
}
