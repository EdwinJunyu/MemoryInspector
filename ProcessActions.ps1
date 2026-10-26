#requires -Version 5.1
<#
Milestone 5: deliberately conservative local USER process actions only.
Never touches Windows services or admin elevation. All exit requests are manual.
A writable per-user action log is an operational record, NOT tamper-proof security audit.
#>
$script:MiActions = $null
$script:MiProcessJob = $null
$script:MiProcessCheck = $null
# V3-M6 的权限扩展独立验收。普通有窗口进程的既有安全路径保持可用。
function Get-MiActionGrantReleaseStatus {
    return [pscustomobject]@{Enabled=$false;IdentityAccepted=$false;ReplayAccepted=$false;WindowsAccepted=$false;
        Reason='M6WindowsIdentityAndSingleActionAcceptancePending';SafetyPolicyVersion='V3-M6-1'}
}
function Assert-MiActionGrantReleaseAccepted {
    $gate=Get-MiActionGrantReleaseStatus
    if (-not $gate.Enabled -or -not $gate.IdentityAccepted -or -not $gate.ReplayAccepted -or -not $gate.WindowsAccepted) {
        throw ('ActionGrant disabled: '+$gate.Reason)
    }
}
function Initialize-MiActionGrantNative {
    if ('MemoryInspector.ActionGrants' -as [type]) {return}
    # 原生句柄绑定精确实例，授权只存在当前执行上下文内；JSON/GUI 行对象不是授权凭证。
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Collections.Generic;
namespace MemoryInspector {
 public sealed class ActionTarget : IDisposable {
  IntPtr handle; FileStream image;
  public readonly int Pid; public readonly long StartTicks; public readonly string Path,Hash,OwnerSid; public readonly int Session;
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr p,out long start,out long end,out long kernel,out long user);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool QueryFullProcessImageNameW(IntPtr p,uint flags,StringBuilder name,ref uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessCritical(IntPtr p,out bool critical);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessInformation(IntPtr p,int cls,out uint value,uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int cls,IntPtr data,int size,out int needed);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr p,uint ms);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint code);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr p);
  static IntPtr TokenInfo(IntPtr token,int cls) {
   int size;GetTokenInformation(token,cls,IntPtr.Zero,0,out size);
   if(size<4 || size>65536)throw new InvalidOperationException("Token information unavailable");
   IntPtr data=Marshal.AllocHGlobal(size);
   if(!GetTokenInformation(token,cls,data,size,out size)){Marshal.FreeHGlobal(data);throw new Win32Exception();}return data;
  }
  string Identity(out string path,out string sid,out int session,out long ticks) {
   if(handle==IntPtr.Zero || WaitForSingleObject(handle,0)!=258)throw new InvalidOperationException("Target exited or outcome unknown");
   bool critical;uint protection;long start,end,kernel,user;
   if(!IsProcessCritical(handle,out critical)||critical||!GetProcessInformation(handle,7,out protection,4)||protection!=0xfffffffeu)throw new InvalidOperationException("Critical/protected state unverifiable");
   if(!GetProcessTimes(handle,out start,out end,out kernel,out user))throw new Win32Exception();ticks=DateTime.FromFileTimeUtc(start).Ticks;
   var text=new StringBuilder(32768);uint length=(uint)text.Capacity;
   if(!QueryFullProcessImageNameW(handle,0,text,ref length))throw new Win32Exception();path=text.ToString();
   IntPtr token;if(!OpenProcessToken(handle,8,out token))throw new Win32Exception();
   try {
    using(var identity=new WindowsIdentity(token)){sid=identity.User.Value;}
    IntPtr elevation=TokenInfo(token,20),integrity=IntPtr.Zero,sessionData=IntPtr.Zero;
    try {
     if(Marshal.ReadInt32(elevation)!=0)throw new InvalidOperationException("Elevated target refused");
     integrity=TokenInfo(token,25);var level=new SecurityIdentifier(Marshal.ReadIntPtr(integrity)).Value;
     if(uint.Parse(level.Substring(level.LastIndexOf('-')+1))>=0x3000)throw new InvalidOperationException("High integrity target refused");
     sessionData=TokenInfo(token,12);session=Marshal.ReadInt32(sessionData);
    }finally{Marshal.FreeHGlobal(elevation);if(integrity!=IntPtr.Zero)Marshal.FreeHGlobal(integrity);if(sessionData!=IntPtr.Zero)Marshal.FreeHGlobal(sessionData);}
   }finally{CloseHandle(token);}
   return path+"|"+sid+"|"+session+"|"+ticks;
  }
  public ActionTarget(int pid,long ticks,string owner,int session,bool force) {
   if(pid<=4||pid==Process.GetCurrentProcess().Id||session<=0)throw new InvalidOperationException("Invalid target");
   handle=OpenProcess(0x101000u|(force?1u:0u),false,pid);if(handle==IntPtr.Zero)throw new Win32Exception();
   try {
    string path,sid;int actualSession;long actualTicks;Identity(out path,out sid,out actualSession,out actualTicks);
    if(ticks!=actualTicks||owner!=sid||session!=actualSession)throw new InvalidOperationException("Target identity changed");
    for(string ancestor=path;!String.IsNullOrEmpty(ancestor);ancestor=System.IO.Path.GetDirectoryName(ancestor))
     if((File.GetAttributes(ancestor)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Reparse executable refused");
    image=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.Read);
    if(image.Length<=0||image.Length>268435456)throw new InvalidOperationException("Executable hash bound exceeded");
    using(var sha=SHA256.Create()){Hash=BitConverter.ToString(sha.ComputeHash(image)).Replace("-","");}
    Pid=pid;StartTicks=ticks;Path=path;OwnerSid=sid;Session=session;
   }catch{Dispose();throw;}
  }
  public void Verify() {
   string path,sid;int session;long ticks;Identity(out path,out sid,out session,out ticks);
   if(!String.Equals(path,Path,StringComparison.OrdinalIgnoreCase)||sid!=OwnerSid||session!=Session||ticks!=StartTicks)throw new InvalidOperationException("Target identity changed");
  }
  internal void Terminate() {if(!TerminateProcess(handle,1))throw new Win32Exception();}
  public string ExitState() {uint state=WaitForSingleObject(handle,0);return state==0?"Exited":state==258?"Running":"Unknown";}
  public void Dispose(){if(image!=null){image.Dispose();image=null;}if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
 }
 public sealed class GrantView {
  public readonly string GrantId,ActionType,OwnerSid,ExecutablePath,ExecutableSha256,ExecutableIdentity,SafetyPolicyVersion,ConfirmationId,GrantState;
  public readonly int TargetPid,SessionId;public readonly long TargetStartUtcTicks;public readonly DateTime IssuedUtc,ExpiresUtc;
  internal GrantView(string id,ActionTarget t,string action,string policy,string confirmation,string state,DateTime issued) {
   GrantId=id;ActionType=action;OwnerSid=t.OwnerSid;ExecutablePath=t.Path;ExecutableSha256=t.Hash;ExecutableIdentity=t.Path+"|SHA256:"+t.Hash;SafetyPolicyVersion=policy;ConfirmationId=confirmation;GrantState=state;
   TargetPid=t.Pid;TargetStartUtcTicks=t.StartTicks;SessionId=t.Session;IssuedUtc=issued;ExpiresUtc=issued.AddSeconds(15);
  }
 }
 public static class ActionGrants {
  sealed class Grant {internal ActionTarget Target;internal string Id,Action,Policy,Confirmation,State;internal DateTime Issued;internal Stopwatch Clock=Stopwatch.StartNew();}
  static readonly object sync=new object();static readonly Dictionary<string,Grant> grants=new Dictionary<string,Grant>();
  static readonly System.Threading.Timer expiry=new System.Threading.Timer(delegate(object unused){lock(sync){foreach(var g in grants.Values)Expire(g);}},null,1000,1000);
  static void Expire(Grant g){if(g.State=="UserConfirmed"&&(g.Clock.Elapsed.TotalSeconds>15||DateTime.UtcNow<g.Issued||DateTime.UtcNow>g.Issued.AddSeconds(15))){g.State="Expired";g.Target.Dispose();}}
  public static GrantView Create(ActionTarget target,string action,string policy,string confirmation) {
   lock(sync){var remove=new List<string>();foreach(var old in grants.Values){Expire(old);if(old.State=="Expired"||old.State=="Revoked"||old.State=="Rejected"||old.State=="OutcomeVerified"||old.State=="UnknownOutcome")remove.Add(old.Id);}foreach(string key in remove)grants.Remove(key);
    Guid id;if(grants.Count>=256||!Guid.TryParseExact(confirmation,"N",out id)||(action!="ForceTerminate"&&action!="CooperativeExit"))throw new InvalidOperationException("Invalid/bounded grant context");
    var g=new Grant{Id=Guid.NewGuid().ToString("N"),Target=target,Action=action,Policy=policy,Confirmation=confirmation,State="UserConfirmed",Issued=DateTime.UtcNow};grants.Add(g.Id,g);
    return new GrantView(g.Id,target,action,policy,confirmation,g.State,g.Issued);}
  }
  public static ActionTarget Consume(string id,string confirmation,string policy,string action) {
   lock(sync){Grant g;if(!grants.TryGetValue(id,out g))throw new InvalidOperationException("Unknown grant; JSON is not a credential");Expire(g);
    if(g.State!="UserConfirmed")throw new InvalidOperationException(g.State=="Revalidating"||g.State=="Consumed"||g.State=="Dispatched"||g.State=="OutcomeVerified"?"AlreadyConsumed":g.State);
    if(g.Policy!=policy||g.Confirmation!=confirmation||g.Action!=action){g.State="Revoked";g.Target.Dispose();throw new InvalidOperationException("Grant policy/confirmation/action changed");}
    g.State="Revalidating";return g.Target;}
  }
  public static void CheckDispatch(string id,string policy){lock(sync){var g=grants[id];if(g.Policy!=policy||g.State!="Revalidating"||g.Clock.Elapsed.TotalSeconds>15||DateTime.UtcNow<g.Issued||DateTime.UtcNow>g.Issued.AddSeconds(15))throw new InvalidOperationException("Expired or consumed grant cannot dispatch");g.State="Revalidated";g.State="Consumed";}}
  public static void DispatchForce(string id,string policy){lock(sync){var g=grants[id];if(g.Action!="ForceTerminate")throw new InvalidOperationException("Wrong action");g.Target.Verify();CheckDispatch(id,policy);g.Target.Terminate();g.State="Dispatched";}}
  public static void Finish(string id,string state){lock(sync){Grant g;if(!grants.TryGetValue(id,out g))return;
   if((g.State=="Consumed"&&state=="Dispatched")||(g.State=="Dispatched"&&state=="OutcomeVerified")||state=="UnknownOutcome"||state=="Rejected")g.State=state;}}
  public static void Revoke(string id){lock(sync){Grant g;if(grants.TryGetValue(id,out g)&&g.State=="UserConfirmed"){g.State="Revoked";g.Target.Dispose();}}}
 }
}
'@ -ReferencedAssemblies System.dll,System.Core.dll -ErrorAction Stop
}
function Initialize-MiActions {
    $folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MemoryInspector'
    $script:MiActions = [pscustomobject]@{
        AuditPath = (Join-Path $folder 'process-actions.jsonl')
        CanAudit = $false
        Pending = $null
        Busy = $false
        CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        CurrentSession = [int](Get-Process -Id $PID).SessionId
    }
    try {
        if (-not [IO.Directory]::Exists($folder)) { [void][IO.Directory]::CreateDirectory($folder) }
        $script:MiActions.CanAudit = $true
    } catch { $script:MiActions.CanAudit = $false }
}
function Test-MiElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $true }
}
function Test-MiProtectedProcess {
    param([string]$Name,[string]$Path)
    $protected = @('idle','system','registry','secure system','memory compression',
        'smss','csrss','wininit','winlogon','services','lsass','lsaiso','svchost',
        'dwm','explorer','conhost','cmd','powershell','pwsh','taskmgr','fontdrvhost',
        'sihost','taskhostw','spoolsv','dllhost','runtimebroker','backgroundtaskhost',
        'searchhost','searchindexer','textinputhost','ctfmon','audiodg','wmiprvse',
        'msiexec','msmpeng','nissrv','securityhealthservice','trustedinstaller','tiworker')
    if ([string]::IsNullOrWhiteSpace($Name) -or $protected -contains $Name.ToLowerInvariant()) { return $true }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { return $true }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $roots = @($env:WINDIR)
        if ($env:ProgramFiles) { $roots += (Join-Path $env:ProgramFiles 'WindowsApps') }
        foreach ($root in $roots) {
            if ([string]::IsNullOrWhiteSpace($root)) { return $true }
            $normalized = [IO.Path]::GetFullPath($root).TrimEnd('\')
            if ($full.StartsWith($normalized+'\',[StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    } catch { return $true }
}
function Test-MiActionSnapshot {
    param($Item,$Snapshot,[datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Item -or $null -eq $Snapshot -or $null -eq $Snapshot.Processes) { return 'MissingSnapshot' }
    if ($Snapshot.Processes.Status -eq 'Failed' -or $Item.Status -ne 'Success') { return 'IncompleteProcessData' }
    if ([int]$Item.PID -le 4 -or $null -eq $Item.StartUtcTicks -or [long]$Item.StartUtcTicks -le 0) { return 'InvalidIdentity' }
    if (Test-MiProtectedProcess -Name ([string]$Item.Name) -Path 'C:\placeholder\app.exe') { return 'ProtectedName' }
    try {
        $sampleUtc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
        $age = ($NowUtc - $sampleUtc).TotalSeconds
        if ($age -lt 0 -or $age -gt 90) { return 'StaleSnapshot' }
        $found = @($Snapshot.Processes.Items | Where-Object {
            $_.PID -eq $Item.PID -and $_.StartUtcTicks -eq $Item.StartUtcTicks -and $_.Name -ceq $Item.Name
        })
        if ($found.Count -ne 1) { return 'IdentityNotInSnapshot' }
        return 'Pass'
    } catch { return 'InvalidSnapshot' }
}
function Write-MiProcessAudit {
    param([string]$OperationId,[string]$State,[string]$Mode,[int]$TargetPid,[string]$Name,$Details)
    if (-not $script:MiActions.CanAudit) { return $false }
    try {
        $line = [pscustomobject]@{
            SchemaVersion=1; Utc=[datetime]::UtcNow.ToString('o')
            OperationId=$OperationId; State=$State; Mode=$Mode; PID=$TargetPid
            Process=$Name; Details=$Details
        } | ConvertTo-Json -Compress -Depth 6
        [IO.File]::AppendAllText($script:MiActions.AuditPath,$line+[Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        return $true
    } catch {
        $script:MiActions.CanAudit = $false
        return $false
    }
}
function Assert-MiProcessTarget {
    param($Item,$Snapshot,[switch]$AllowBackground)
    if ($AllowBackground) {Assert-MiActionGrantReleaseAccepted}
    $checkStarted=[Diagnostics.Stopwatch]::StartNew()
    $reason = Test-MiActionSnapshot -Item $Item -Snapshot $Snapshot
    if ($reason -ne 'Pass') { throw ('目标检查失败：'+$reason) }
    if (Test-MiElevated) { throw '当前 GUI 以管理员权限运行，禁止在本阶段执行进程操作。' }
    if ($null -eq $script:MiActions -or -not $script:MiActions.CanAudit) { throw '本地审计日志不可写。' }
    if ($script:MiActions.CurrentSession -le 0) { throw '当前会话无法验证。' }
    if ([int]$Item.PID -eq $PID) { throw '禁止关闭工具本身。' }
    $proc = Get-Process -Id ([int]$Item.PID) -ErrorAction Stop
    try {
        $proc.Refresh()
        $started = [long]$proc.StartTime.ToUniversalTime().Ticks
        $name = [string]$proc.ProcessName
        $path = [string]$proc.Path
        if ($started -ne [long]$Item.StartUtcTicks -or $name -cne [string]$Item.Name) { throw 'PID 已被复用或进程身份改变。' }
        if (Test-MiProtectedProcess -Name $name -Path $path) { throw '受保护进程名称、路径不可信或位于系统目录。' }
        if ([int]$proc.SessionId -ne $script:MiActions.CurrentSession -or
            (-not $AllowBackground -and [long]$proc.MainWindowHandle.ToInt64() -eq 0)) { throw '必须是当前会话具有可用主窗口的普通应用。' }

        $cim = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = {0}' -f $Item.PID) -OperationTimeoutSec 5 -ErrorAction Stop
        if ($null -eq $cim -or $null -eq $cim.CreationDate -or
            [string]::IsNullOrWhiteSpace([string]$cim.ExecutablePath)) { throw 'CIM 身份信息缺失。' }
        $cimTime = ([datetime]$cim.CreationDate).ToUniversalTime().Ticks
        if ([Math]::Abs([double]($cimTime-$started)) -gt [timespan]::FromSeconds(2).Ticks -or
            [int]$cim.SessionId -ne $script:MiActions.CurrentSession -or
            -not [string]::Equals([string]$cim.ExecutablePath,$path,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'CIM 身份、会话或可执行路径不一致。'
        }
        $owner = Invoke-CimMethod -InputObject $cim -MethodName GetOwnerSid -OperationTimeoutSec 5 -ErrorAction Stop
        if ($null -eq $owner -or [int]$owner.ReturnValue -ne 0 -or
            [string]$owner.Sid -cne $script:MiActions.CurrentSid) { throw '无法确认进程属于当前用户。' }
        $services = @(Get-CimInstance -ClassName Win32_Service -Filter ('ProcessId = {0}' -f $Item.PID) -OperationTimeoutSec 5 -ErrorAction Stop)
        if ($services.Count -gt 0) { throw '该 PID 承载 Windows 服务，禁止进程级关闭和 Kill。' }
        # 慢查询完成后再次核验原 Process 对象；超出总预算或实例改变均拒绝发送。
        $proc.Refresh()
        if ($checkStarted.Elapsed.TotalSeconds -gt 15 -or $proc.HasExited -or
            $proc.ProcessName -cne $Item.Name -or
            [long]$proc.StartTime.ToUniversalTime().Ticks -ne [long]$Item.StartUtcTicks) {
            throw '身份检查超时或目标进程实例已改变。'
        }
        return $proc
    } catch {
        $proc.Dispose()
        throw
    }
}
function Enter-MiProcessTargetLock {
    param($Item,[string]$Mode)
    if ($null -eq $Item -or [int]$Item.PID -le 4 -or [long]$Item.StartUtcTicks -le 0) { throw '目标进程锁身份无效。' }
    $folder=Split-Path -Parent $script:MiActions.AuditPath
    $path=Join-Path $folder ('process-'+[int]$Item.PID+'-'+[long]$Item.StartUtcTicks+'.lock')
    # CreateNew 原子区分首次创建与已有状态。已有空文件可能来自崩溃，不能把它当成首次请求。
    $created=$false;$stream=$null
    try {
        try {
            $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            $created=$true
        } catch [IO.IOException] {
            if (-not [IO.File]::Exists($path)) { throw }
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        }
        if ($created) {
            # 尚未执行目标检查或发送请求，先落盘允许重试的初始状态；初始化中断则保留未知状态并拒绝后续请求。
            Write-MiProcessTargetState -Stream $stream -OperationId '' -Mode $Mode -Status 'RejectedBeforeDispatch'
        } else {
            if ($stream.Length -le 0 -or $stream.Length -gt 16384) { throw '目标操作状态为空或过大，拒绝重试。' }
            $buffer=New-Object byte[] ([int]$stream.Length)
            $offset=0
            while ($offset -lt $buffer.Length) {
                $read=$stream.Read($buffer,$offset,$buffer.Length-$offset)
                if ($read -le 0) { throw '目标操作状态无法完整读取。' }
                $offset+=$read
            }
            # 状态仅追加完整 UTF-8 JSON 行。任意截断尾部、损坏字符或未知状态一律拒绝，不能回退到前一条宽松状态。
            $text=[Text.UTF8Encoding]::new($false,$true).GetString($buffer)
            if (-not $text.EndsWith([Environment]::NewLine,[StringComparison]::Ordinal)) { throw '目标操作状态尾部不完整，拒绝重试。' }
            $lines=$text.Split([string[]]@([Environment]::NewLine),[StringSplitOptions]::None)
            if ($lines.Count -gt 33) { throw '目标操作状态行数超出限制。' }
            $prior=$null
            foreach ($line in $lines[0..($lines.Count-2)]) {
                if ([string]::IsNullOrWhiteSpace($line)) { throw '目标操作状态包含空行。' }
                $prior=ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($prior.Mode -cnotin @('Graceful','Force') -or $prior.Status -cnotin @('RejectedBeforeDispatch',
                    'Dispatching','Requested','ObservationComplete','UnknownOutcome')) { throw '目标操作状态无法识别。' }
            }
            # Graceful 未能退出后仍允许用户明确启用 Force；普通重复关闭及任何未知结果都不自动重发。
            $escalation=($Mode -eq 'Force' -and $prior.Mode -ceq 'Graceful' -and $prior.Status -ceq 'ObservationComplete')
            if ($prior.Status -cne 'RejectedBeforeDispatch' -and -not $escalation) {
                throw '该进程实例已有关闭请求或结果未知，禁止重复发送。'
            }
        }
        return $stream
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}
function Write-MiProcessTargetState {
    param([IO.FileStream]$Stream,[string]$OperationId,[string]$Mode,[string]$Status)
    if ($Mode -cnotin @('Graceful','Force') -or $Status -cnotin @('RejectedBeforeDispatch',
        'Dispatching','Requested','ObservationComplete','UnknownOutcome')) { throw '目标操作状态写入参数无效。' }
    $state=[pscustomobject]@{OperationId=$OperationId;Mode=$Mode;Status=$Status;Utc=[datetime]::UtcNow.ToString('o')}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($state | ConvertTo-Json -Compress)+[Environment]::NewLine)
    if (($Stream.Length+$bytes.Length) -gt 16384) { throw '目标操作状态容量不足，拒绝发送请求。' }
    # 永不截断旧状态；即使追加过程中崩溃，之前的发送证据仍在，未完成的新行会阻止后续重复操作。
    $Stream.Position=$Stream.Length
    $Stream.Write($bytes,0,$bytes.Length);$Stream.Flush($true)
}
function Close-MiProcessTargetLock {
    param($Operation,[string]$Status)
    if ($null -ne $Operation.TargetLock) {
        try { Write-MiProcessTargetState -Stream $Operation.TargetLock -OperationId $Operation.OperationId -Mode $Operation.Mode -Status $Status }
        finally { $Operation.TargetLock.Dispose();$Operation.TargetLock=$null }
    }
}
function New-MiNativeActionTarget {
    param($Item,[bool]$Force)
    Initialize-MiActionGrantNative
    return [MemoryInspector.ActionTarget]::new([int]$Item.PID,[long]$Item.StartUtcTicks,
        $script:MiActions.CurrentSid,$script:MiActions.CurrentSession,$Force)
}
function New-MiActionGrant {
    param($Item,$Snapshot,[ValidateSet('Graceful','Force')][string]$Mode,[string]$ConfirmationId,[bool]$DangerEnabled)
    Assert-MiActionGrantReleaseAccepted
    if ($ConfirmationId -cnotmatch '^[a-f0-9]{32}$' -or ($Mode -ceq 'Force' -and -not $DangerEnabled)) {throw 'Separate process-action confirmation required.'}
    $proc=$null;$target=$null
    try {
        $proc=Assert-MiProcessTarget $Item $Snapshot -AllowBackground
        if ($Mode -ceq 'Graceful' -and $proc.MainWindowHandle.ToInt64() -eq 0) {throw 'No cooperative exit capability; force requires a separate confirmation.'}
        $target=New-MiNativeActionTarget $Item ($Mode -ceq 'Force')
        if (-not [string]::Equals($target.Path,$proc.Path,[StringComparison]::OrdinalIgnoreCase)) {throw 'Executable identity changed.'}
        $action=if ($Mode -ceq 'Force') {'ForceTerminate'} else {'CooperativeExit'}
        $grant=[MemoryInspector.ActionGrants]::Create($target,$action,(Get-MiActionGrantReleaseStatus).SafetyPolicyVersion,$ConfirmationId)
        $target=$null # 由内存授权上下文持有句柄，过期/撤销会释放；不能从 JSON 恢复。
        if (-not (Write-MiProcessAudit $grant.GrantId 'GRANT_USER_CONFIRMED' $Mode $Item.PID $Item.Name $grant)) {
            [MemoryInspector.ActionGrants]::Revoke($grant.GrantId);throw 'Grant confirmation audit unavailable.'
        }
        return $grant
    } finally {if ($null -ne $proc) {$proc.Dispose()};if ($null -ne $target) {$target.Dispose()}}
}
function Invoke-MiGrantedNativeAction {
    param($Target,$Process,[string]$Mode,[string]$GrantId)
    if ($Mode -ceq 'Force') {[MemoryInspector.ActionGrants]::DispatchForce($GrantId,(Get-MiActionGrantReleaseStatus).SafetyPolicyVersion)}
    else {
        $Target.Verify();[MemoryInspector.ActionGrants]::CheckDispatch($GrantId,(Get-MiActionGrantReleaseStatus).SafetyPolicyVersion)
        if (-not $Process.CloseMainWindow()) {throw 'Cooperative exit was not accepted; no automatic force.'}
    }
}
function Invoke-MiGrantedProcessAction {
    param($Item,$Snapshot,[string]$Mode,[bool]$DangerEnabled,[string]$GrantId,[string]$ConfirmationId)
    Assert-MiActionGrantReleaseAccepted
    $result=[pscustomobject]@{OperationId=$GrantId;GrantId=$GrantId;Mode=$Mode;PID=[int]$Item.PID;Name=$Item.Name;StartUtcTicks=$Item.StartUtcTicks;
        StartedUtc=[datetime]::UtcNow;Outcome='Rejected';Error=$null;TargetLock=$null;NativeTarget=$null;BeforePrivate=$Item.PrivateBytes;
        BeforeCommitted=$Snapshot.System.CommittedBytes;BeforeAvailable=$Snapshot.System.AvailablePhysicalBytes;
        Observations=(New-Object 'System.Collections.Generic.List[object]')}
    $target=$null;$proc=$null;$lock=$null;$consumed=$false;$dispatching=$false;$ownsBusy=$false
    try {
        if ($script:MiActions.Busy -or $null -ne $script:MiActions.Pending -or ($Mode -ceq 'Force' -and -not $DangerEnabled)) {throw 'Busy or dangerous action not confirmed.'}
        $script:MiActions.Busy=$true;$ownsBusy=$true
        $lock=Enter-MiProcessTargetLock $Item $Mode
        # 原子预约后不能再次领取；复核通过才标记 Revalidated/Consumed，失败也不恢复授权。
        $action=if ($Mode -ceq 'Force') {'ForceTerminate'} else {'CooperativeExit'}
        $target=[MemoryInspector.ActionGrants]::Consume($GrantId,$ConfirmationId,(Get-MiActionGrantReleaseStatus).SafetyPolicyVersion,$action);$consumed=$true
        if ($target.Pid -ne $Item.PID -or $target.StartTicks -ne $Item.StartUtcTicks -or
            $target.OwnerSid -cne $script:MiActions.CurrentSid -or $target.Session -ne $script:MiActions.CurrentSession) {throw 'Grant target identity changed.'}
        $proc=Assert-MiProcessTarget $Item $Snapshot -AllowBackground
        if (-not [string]::Equals($target.Path,$proc.Path,[StringComparison]::OrdinalIgnoreCase)) {throw 'Grant executable changed.'}
        if (-not (Write-MiProcessAudit $GrantId 'GRANT_CONSUMED' $Mode $Item.PID $Item.Name @{ConfirmationId=$ConfirmationId;ExecutableSha256=$target.Hash;Policy=(Get-MiActionGrantReleaseStatus).SafetyPolicyVersion})) {throw 'Audit unavailable; no dispatch.'}
        Write-MiProcessTargetState $lock $GrantId $Mode 'Dispatching';$dispatching=$true
        # Flush 可能很慢，意图落盘后重新核验服务/身份，再由原生授权上下文紧邻派发检查期限。
        $proc.Dispose();$proc=Assert-MiProcessTarget $Item $Snapshot -AllowBackground
        Invoke-MiGrantedNativeAction $target $proc $Mode $GrantId
        [MemoryInspector.ActionGrants]::Finish($GrantId,'Dispatched')
        [void](Write-MiProcessAudit $GrantId 'SENT_NOT_CONFIRMED_EXIT' $Mode $Item.PID $Item.Name @{Note='Separate handle and memory observations pending'})
        Write-MiProcessTargetState $lock $GrantId $Mode 'Requested'
        $result.Outcome='Requested';$result.TargetLock=$lock;$lock=$null;$result.NativeTarget=$target;$target=$null
        $script:MiActions.Pending=$result
    } catch {
        $result.Error=$_.Exception.Message
        if ($dispatching) {$result.Outcome='UnknownOutcome'}
        if ($consumed) {[MemoryInspector.ActionGrants]::Finish($GrantId,$(if ($dispatching) {'UnknownOutcome'} else {'Rejected'}))}
        [void](Write-MiProcessAudit $GrantId $result.Outcome $Mode $Item.PID $Item.Name @{Reason=$result.Error})
    } finally {
        if ($null -ne $target) {$target.Dispose()};if ($null -ne $proc) {$proc.Dispose()};if ($null -ne $lock) {$lock.Dispose()}
        if ($ownsBusy) {$script:MiActions.Busy=$false}
    }
    return $result
}
function Invoke-MiProcessAction {
    param([ValidateSet('Graceful','Force')][string]$Mode,$Item,$Snapshot,[bool]$DangerEnabled,[string]$GrantId='',[string]$ConfirmationId='')
    if ($GrantId) {return Invoke-MiGrantedProcessAction $Item $Snapshot $Mode $DangerEnabled $GrantId $ConfirmationId}
    $id = [guid]::NewGuid().ToString('N')
    $started = [datetime]::UtcNow
    $result = [pscustomobject]@{
        OperationId=$id; Mode=$Mode; PID=[int]$Item.PID; Name=[string]$Item.Name
        StartUtcTicks=$Item.StartUtcTicks; StartedUtc=$started
        Outcome='Rejected'; Error=$null;TargetLock=$null
        BeforeCommitted=$null; BeforeAvailable=$null; BeforePrivate=$Item.PrivateBytes
        Observations=(New-Object 'System.Collections.Generic.List[object]')
    }
    if ($null -ne $Snapshot -and $null -ne $Snapshot.System -and $Snapshot.System.Status -eq 'Success') {
        $result.BeforeCommitted=$Snapshot.System.CommittedBytes
        $result.BeforeAvailable=$Snapshot.System.AvailablePhysicalBytes
    }
    if ($null -ne $script:MiActions.Pending) { $result.Error='上一项操作仍在观察中。'; return $result }
    if ($script:MiActions.Busy) { $result.Error='已有操作正在执行。'; return $result }
    if ($Mode -eq 'Force' -and -not $DangerEnabled) { $result.Error='危险模式尚未明确启用。'; return $result }
    if ($null -eq $script:MiActions -or -not $script:MiActions.CanAudit) { $result.Error='审计未就绪。'; return $result }
    $targetLock=$null; $proc=$null; $definitelyNotSent=$false
    $script:MiActions.Busy=$true
    try {
        $targetLock=Enter-MiProcessTargetLock -Item $Item -Mode $Mode
        $proc=Assert-MiProcessTarget -Item $Item -Snapshot $Snapshot
        if (-not (Write-MiProcessAudit -OperationId $id -State 'REQUESTED' -Mode $Mode -TargetPid $Item.PID -Name $Item.Name -Details @{
            StartUtcTicks=$Item.StartUtcTicks; BeforeCommitted=$result.BeforeCommitted
            BeforeAvailable=$result.BeforeAvailable; BeforePrivate=$Item.PrivateBytes
        })) { throw '审计预记录失败，禁止操作。' }
        # Keep the validated Process object, revalidate its instance immediately before dispatch.
        $proc.Refresh()
        if ($proc.HasExited -or $proc.ProcessName -cne $Item.Name -or
            [long]$proc.StartTime.ToUniversalTime().Ticks -ne [long]$Item.StartUtcTicks) {
            throw '执行前目标身份已改变。'
        }
        # 先持久记录 Dispatching。若此后进程崩溃，其他 GUI 即使拿到释放的锁也会因未知结果拒绝重发。
        Write-MiProcessTargetState -Stream $targetLock -OperationId $id -Mode $Mode -Status 'Dispatching'
        if ($Mode -eq 'Graceful') {
            if (-not $proc.CloseMainWindow()) {
                $definitelyNotSent=$true
                throw '主窗口无法响应正常退出请求，未尝试强制终止。'
            }
            $result.Outcome='Requested'
        } else {
            $proc.Kill()
            $result.Outcome='Requested'
        }
        [void](Write-MiProcessAudit -OperationId $id -State 'SENT_NOT_CONFIRMED_EXIT' -Mode $Mode -TargetPid $Item.PID -Name $Item.Name -Details @{Note='等待后续采样核验，不声称已退出'})
        Write-MiProcessTargetState -Stream $targetLock -OperationId $id -Mode $Mode -Status 'Requested'
        $result.TargetLock=$targetLock
        $targetLock=$null
        $script:MiActions.Pending = $result
    } catch {
        $result.Error=[string]$_.Exception.Message
        if ($result.Error -like '*已改变*' -or $result.Error -like '*审计预记录*') { $result.Outcome='Rejected' }
        else { $result.Outcome='FailedOrUnknown' }
        if ($script:MiActions.CanAudit) {
            [void](Write-MiProcessAudit -OperationId $id -State $result.Outcome -Mode $Mode -TargetPid $Item.PID -Name $Item.Name -Details @{Reason=$result.Error})
        }
    } finally {
        if ($null -ne $proc) { $proc.Dispose() }
        if ($null -ne $targetLock) {
            try {
                if ($definitelyNotSent) { Write-MiProcessTargetState -Stream $targetLock -OperationId $id -Mode $Mode -Status 'RejectedBeforeDispatch' }
            } finally { $targetLock.Dispose() }
        }
        $script:MiActions.Busy=$false
    }
    return $result
}
function Update-MiActionObservation {
    param($Snapshot,[datetime]$NowUtc=[datetime]::UtcNow)
    if ($null -eq $script:MiActions -or $null -eq $script:MiActions.Pending) { return $null }
    $p=$script:MiActions.Pending
    $elapsed=($NowUtc-$p.StartedUtc).TotalSeconds
    $due=@(5,15,30,60)
    if ($null -ne $Snapshot) {
        $sampleUtc=([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
        foreach ($second in $due) {
            if ($elapsed -lt $second -or @($p.Observations | Where-Object { $_.TargetSecond -eq $second }).Count -gt 0) { continue }
            $targetUtc=$p.StartedUtc.AddSeconds($second)
            if ($sampleUtc -lt $targetUtc) { continue }
            # Never represent a 60-second sample as if it had been captured at 5/15/30.
            if (($sampleUtc-$targetUtc).TotalSeconds -gt 12) {
                $p.Observations.Add([pscustomobject]@{
                    TargetSecond=$second;SampleUtc=$null;CommittedBytes=$null
                    AvailablePhysicalBytes=$null;TargetPrivateBytes=$null;TargetStatus='MissingSample'
                })
                continue
            }
            $sys=$Snapshot.System
            $committed=$null;$available=$null;$observed='Unknown'
            if ($null -ne $sys -and $sys.Status -eq 'Success') {
                $committed=$sys.CommittedBytes;$available=$sys.AvailablePhysicalBytes
            }
            $targetPrivate=$null
            $exitState='Unknown'
            if ($null -ne $p.NativeTarget) {$exitState=$p.NativeTarget.ExitState()}
            if ($null -ne $Snapshot.Processes -and $Snapshot.Processes.Status -ne 'Failed') {
                $matching=@($Snapshot.Processes.Items | Where-Object { $_.PID -eq $p.PID -and $_.StartUtcTicks -eq $p.StartUtcTicks })
                if ($matching.Count -gt 0) {
                    $observed='Present'
                    $targetPrivate=$matching[0].PrivateBytes
                } else { $observed='NotObserved' }
            }
            $p.Observations.Add([pscustomobject]@{
                TargetSecond=$second; SampleUtc=$sampleUtc.ToString('o')
                CommittedBytes=$committed; AvailablePhysicalBytes=$available
                TargetPrivateBytes=$targetPrivate; TargetStatus=$observed;ExitState=$exitState
            })
        }
    }
    if ($elapsed -ge 60 -and @($p.Observations | Where-Object { $_.TargetSecond -eq 60 }).Count -gt 0) {
        $last=@($p.Observations | Where-Object { $_.TargetSecond -eq 60 })[0]
        $net=$null
        if ($null -ne $p.BeforeCommitted -and $null -ne $last.CommittedBytes) {
            $net=[long]($last.CommittedBytes-$p.BeforeCommitted)
        }
        $availableNet=$null
        if ($null -ne $p.BeforeAvailable -and $null -ne $last.AvailablePhysicalBytes) {$availableNet=[long]($last.AvailablePhysicalBytes-$p.BeforeAvailable)}
        $exitState=if ($null -ne $p.NativeTarget) {$p.NativeTarget.ExitState()} else {'Unknown'}
        $details=@{
            TargetStatus=$last.TargetStatus; NetSystemCommitBytes=$net
            NetAvailableRamBytes=$availableNet;ExitState=$exitState;TargetPrivateBytesNoLongerExists=if ($exitState -ceq 'Exited') {$true} else {$null}
            Attribution='Net system change only; concurrent workloads may contribute'
            Observations=@($p.Observations.ToArray())
        }
        [void](Write-MiProcessAudit -OperationId $p.OperationId -State 'OBSERVATION_COMPLETE' -Mode $p.Mode -TargetPid $p.PID -Name $p.Name -Details $details)
        Close-MiProcessTargetLock -Operation $p -Status 'ObservationComplete'
        if ($null -ne $p.NativeTarget) {
            [MemoryInspector.ActionGrants]::Finish($p.GrantId,$(if ($exitState -ceq 'Unknown') {'UnknownOutcome'} else {'OutcomeVerified'}))
            $p.NativeTarget.Dispose();$p.NativeTarget=$null
        }
        $script:MiActions.Pending=$null
        return [pscustomobject]@{State='Complete';Operation=$p;NetCommitBytes=$net;NetAvailableRamBytes=$availableNet;TargetStatus=$last.TargetStatus;ExitState=$exitState;
            SampleUtc=$last.SampleUtc;PrivateBytesNoLongerExists=if ($exitState -ceq 'Exited') {$true} else {$null}}
    }
    if ($elapsed -gt 120) {
        [void](Write-MiProcessAudit -OperationId $p.OperationId -State 'OBSERVATION_INCOMPLETE' -Mode $p.Mode -TargetPid $p.PID -Name $p.Name -Details @{
            Reason='Monitoring timeout or sampling gaps';Observations=@($p.Observations.ToArray())
        })
        Close-MiProcessTargetLock -Operation $p -Status 'UnknownOutcome'
        if ($null -ne $p.NativeTarget) {[MemoryInspector.ActionGrants]::Finish($p.GrantId,'UnknownOutcome');$p.NativeTarget.Dispose();$p.NativeTarget=$null}
        $script:MiActions.Pending=$null
        return [pscustomobject]@{State='Incomplete';Operation=$p;NetCommitBytes=$null;TargetStatus='Unknown'}
    }
    return $null
}

function Stop-MiActionObservation {
    if ($null -eq $script:MiActions -or $null -eq $script:MiActions.Pending) { return }
    $p=$script:MiActions.Pending
    [void](Write-MiProcessAudit -OperationId $p.OperationId -State 'OBSERVATION_INTERRUPTED' -Mode $p.Mode -TargetPid $p.PID -Name $p.Name -Details @{
        Reason='GUI exited before follow-up measurements were complete'
        Observations=@($p.Observations.ToArray())
    })
    Close-MiProcessTargetLock -Operation $p -Status 'UnknownOutcome'
    if ($null -ne $p.NativeTarget) {[MemoryInspector.ActionGrants]::Finish($p.GrantId,'UnknownOutcome');$p.NativeTarget.Dispose();$p.NativeTarget=$null}
    $script:MiActions.Pending=$null
}


function Get-MiProcessCheckKey {
    param($Item)
    if ($null -eq $Item) { return '' }
    return ('{0}:{1}:{2}' -f $Item.PID,$Item.StartUtcTicks,$Item.Name)
}
function Start-MiProcessJob {
    param([ValidateSet('Check','Execute')][string]$Kind,$Item,$Snapshot,
        [ValidateSet('Graceful','Force')][string]$Mode='Graceful',[bool]$DangerEnabled=$false,
        [string]$ModulePath=(Join-Path $PSScriptRoot 'ProcessActions.ps1'),[string]$ConfirmationId='')
    if ($null -ne $script:MiProcessJob) { throw '已有进程验证或执行任务，拒绝重复请求。' }
    $ps=$null
    try {
        # 独立状态副本：后台不修改 GUI 正在观察的 Pending，也不访问控件。
        $state=[pscustomobject]@{
            AuditPath=$script:MiActions.AuditPath;CanAudit=$script:MiActions.CanAudit
            CurrentSid=$script:MiActions.CurrentSid;CurrentSession=$script:MiActions.CurrentSession
            Busy=$false;Pending=$null
        }
        $target=$Item.PSObject.Copy()
        $ps=[Management.Automation.PowerShell]::Create()
        [void]$ps.AddScript(@'
param($ModulePath,$State,$Kind,$Item,$Snapshot,$Mode,$DangerEnabled,$ConfirmationId)
$ErrorActionPreference='Stop'
. $ModulePath
$script:MiActions=$State
if ($Kind -eq 'Check') {
    $proc=$null
    try {
        $expanded=(Get-MiActionGrantReleaseStatus).Enabled
        $proc=Assert-MiProcessTarget -Item $Item -Snapshot $Snapshot -AllowBackground:$expanded
        if ($expanded) {$native=New-MiNativeActionTarget $Item $true;try {$native.Verify()} finally {$native.Dispose()}}
        [pscustomobject]@{State='Verified';CanAudit=$State.CanAudit;HasWindow=($proc.MainWindowHandle.ToInt64() -ne 0)}
    } finally { if ($null -ne $proc) { $proc.Dispose() } }
} else {
    $grant=$null
    if ((Get-MiActionGrantReleaseStatus).Enabled) {$grant=New-MiActionGrant $Item $Snapshot $Mode $ConfirmationId $DangerEnabled}
    $result=Invoke-MiProcessAction -Mode $Mode -Item $Item -Snapshot $Snapshot -DangerEnabled $DangerEnabled -GrantId $grant.GrantId -ConfirmationId $ConfirmationId
    [pscustomobject]@{State=$result.Outcome;Result=$result;CanAudit=$State.CanAudit}
}
'@).AddArgument($ModulePath).AddArgument($state).AddArgument($Kind).AddArgument($target).
            AddArgument($Snapshot).AddArgument($Mode).AddArgument($DangerEnabled).AddArgument($ConfirmationId)
        $handle=$ps.BeginInvoke()
        $script:MiProcessJob=[pscustomobject]@{
            Kind=$Kind;Key=(Get-MiProcessCheckKey $target);Item=$target
            PowerShell=$ps;Handle=$handle;Clock=[Diagnostics.Stopwatch]::StartNew();TimeoutReported=$false
        }
    } catch { if ($null -ne $ps) { $ps.Dispose() };throw }
}
function Poll-MiProcessJob {
    param([double]$TimeoutSeconds=20)
    $job=$script:MiProcessJob
    if ($null -eq $job) { return $null }
    if (-not $job.Handle.IsCompleted) {
        if (-not $job.TimeoutReported -and $job.Clock.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
            $job.TimeoutReported=$true
            # 只异步取消预验证。正式执行结果未知时保留任务和互斥，不盲目停止后重发。
            if ($job.Kind -eq 'Check') { [void]$job.PowerShell.BeginStop($null,$null) }
            return [pscustomobject]@{Kind=$job.Kind;Key=$job.Key;State='TimedOut';Error='身份查询超时，未允许新的操作。';Result=$null}
        }
        return $null
    }
    try {
        $data=@($job.PowerShell.EndInvoke($job.Handle))
        if ($job.PowerShell.HadErrors -or $data.Count -ne 1) { throw ('后台身份验证或执行失败：'+($job.PowerShell.Streams.Error|Out-String)) }
        $payload=$data[0]
        if (-not $payload.CanAudit) { $script:MiActions.CanAudit=$false }
        if ($job.Kind -eq 'Execute' -and $null -ne $payload.Result -and $payload.Result.Outcome -eq 'Requested') {
            # 交接文件锁及观察对象，原跨进程锁在整个交接期间保持。
            $script:MiActions.Pending=$payload.Result
        }
        $state=[string]$payload.State
        if ($job.TimeoutReported) { $state=if ($job.Kind -eq 'Check') {'TimedOut'} else {'UnknownOutcome'} }
        return [pscustomobject]@{Kind=$job.Kind;Key=$job.Key;State=$state;Error=$payload.Result.Error;Result=$payload.Result;HasWindow=$payload.HasWindow}
    } catch {
        return [pscustomobject]@{Kind=$job.Kind;Key=$job.Key;State='Rejected';Error=$_.Exception.Message;Result=$null}
    } finally {
        $job.PowerShell.Dispose();$job.Clock.Stop();$script:MiProcessJob=$null
    }
}
function Close-MiProcessJob {
    if ($null -eq $script:MiProcessJob) { return }
    if ($script:MiProcessJob.Handle.IsCompleted) { [void](Poll-MiProcessJob);return }
    if ($script:MiProcessJob.Kind -eq 'Check') {
        try { [void]$script:MiProcessJob.PowerShell.BeginStop($null,$null) } catch {}
    }
    # 未确认执行的 Dispatching/Requested 仍受 P1 目标锁状态保护，退出不会允许重试。
}
