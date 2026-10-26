#requires -Version 5.1
<#
Milestone 3 / v0.0.3: READ-ONLY anomaly detection.
No target process/service actions. Private Bytes trends are heuristics, NOT leak proof.
Analyzes immutable scalar snapshots from Collector and historical JSONL from M2.
#>
$script:MiAnalyzerModulePath=$PSCommandPath
# V3-M5：适配器只在普通用户运行。表、单位、Profile 与版本必须在受审阅源码中固定。
function Get-MiWpaExportContract {
    param([ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType)
    # GUID 来源为 Microsoft 的实际 Profile；这里只构造最小表，不复制外部 Profile/插件配置。
    $tables=@{
        VirtualAlloc=@('e6a4a964-3a87-46ef-9762-f9d9b9208051','cfe19628-6612-4e45-ad6e-84b7423c8132','f3e2404e-9274-48de-ba7a-81b10ac0d8e3','355d0688-9ebd-41af-b2c4-0dc0f4294eaa')
        Heap=@('1a64d983-f796-45f8-aa64-ac50b95d0e45','06155709-500b-4182-8944-29665014b5c2','fe123e27-eca6-461a-9a1b-b98056a84feb','29a4dfc2-cd62-4de8-85c3-f580af6a47dd')
        Pool=@('bbc8f512-a49b-451a-90fc-8497f20cfad7','531557e0-ebf1-431c-b888-eec2c701c130',$null,'2bceca1e-67f0-4e41-b2d8-f1c8cad0dd4b')
    }
    $ids=$tables[$TraceType];$label=if ($TraceType -ceq 'Pool') {'Pool Tag'} else {'Process'}
    $columns='<Column Guid="'+$ids[1]+'" Name="'+$label+'" IsVisible="true"/>'
    if ($null -ne $ids[2]) {$columns+='<Column Guid="'+$ids[2]+'" Name="Type" IsVisible="true"/>'}
    $columns+='<Column Guid="'+$ids[3]+'" Name="Size" AggregationMode="Sum" IsVisible="true"/>'
    $keys=if ($TraceType -ceq 'Pool') {1} else {2}
    $xml='<?xml version="1.0" encoding="utf-8"?><WpaProfileContainer xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2" xmlns="http://tempuri.org/SerializableElement.xsd">'+
        '<Content xsi:type="WpaProfile2"><Sessions><Session Index="0"/></Sessions><Views><View Guid="9ab7a932-50f1-45d9-b053-ad00fa78a9b5" IsVisible="true" Title="MemoryInspector">'+
        '<Graphs><Graph Guid="'+$ids[0]+'" LayoutStyle="All" IsShown="true"><Preset Name="MiAllocatedBytes" GraphChartType="StackedLine" AggregationOverTime="OutstandingPeak" GraphColumnCount="'+($keys+1)+
        '" KeyColumnCount="'+$keys+'"><Columns>'+$columns+'</Columns></Preset></Graph></Graphs><SessionIndices><SessionIndex>0</SessionIndex></SessionIndices></View></Views><ModifiedGraphs/></Content></WpaProfileContainer>'
    return [pscustomobject]@{SchemaVersion=1;TraceType=$TraceType;ProfileId=('Mi'+$TraceType+'AllocatedBytesV1');Xml=$xml;
        # 未取得实际工具导出证据，不臆造可支持版本/表头/字节单位；候选 Profile 不能用于实际派发。
        AcceptedVersions=@();Headers=@();SizeColumn=$null;ByteMultiplier=$null;LabelColumn=$label;
        MetricName=($TraceType+'.ExportedAllocatedBytes');CsvPattern='Mi_*.csv'}
}
function Get-MiWpaExporterIdentity {
    $candidates=@((Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Windows Performance Toolkit\wpaexporter.exe'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\Windows Performance Toolkit\wpaexporter.exe'))
    foreach ($path in $candidates) {
        if (-not [IO.File]::Exists($path)) {continue}
        Assert-MiTracePath (Split-Path -Parent $path)
        if (-not (Test-MiNoReparse $path) -or -not (Test-MiAclRestricted $path $false)) {throw 'Untrusted WPAExporter binary.'}
        $signature=Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {throw 'WPAExporter Microsoft signature not verified.'}
        return [pscustomobject]@{SchemaVersion=1;Path=$path;Version=(Get-Item -LiteralPath $path).VersionInfo.FileVersion;
            Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    }
    return $null
}
function Get-MiAttributionExportAvailability {
    param([ValidateSet('VirtualAlloc','Pool','Heap')][string]$TraceType='VirtualAlloc')
    if (-not (Get-Command Get-MiExportReleaseStatus -ErrorAction SilentlyContinue)) {. (Join-Path $PSScriptRoot 'PrivilegeSecurity.ps1')}
    $tool=$null;$errorCode=$null
    try {$tool=Get-MiWpaExporterIdentity} catch {$errorCode=$_.Exception.Message}
    $contract=Get-MiWpaExportContract $TraceType
    $supported=$null -ne $tool -and $contract.AcceptedVersions -ccontains $tool.Version -and $contract.Headers.Count -gt 0 -and $contract.ByteMultiplier -eq 1
    $releaseReady=$true;try {Assert-MiExportReleaseAccepted} catch {$releaseReady=$false}
    return [pscustomobject]@{SchemaVersion=1;State=if ($supported -and $releaseReady) {'Available'} else {'AnalysisUnavailable'};Tool=$tool;ProfileSupported=$supported;ReleaseReady=$releaseReady;
        Release=(Get-MiExportReleaseStatus);ErrorCode=if ($errorCode) {$errorCode} elseif ($null -eq $tool) {'WPAExporterMissing'} elseif (-not $supported) {'ProfileOrVersionUnsupported'} else {$null};
        ManualGuidance='Keep the ETL. In a standard-user session, open the owned .etl from diagnostics/<OwnerSid> in Microsoft WPA and choose the matching memory table. No automatic launch, elevation, upload or symbol download.'}
}
function ConvertFrom-MiWpaCsv {
    param([string]$Path,$Descriptor,$Contract,[string]$SymbolStatus='NotRequested',[ValidateRange(1,16777216)][int]$MaxFindingBytes=16777216)
    if ($Contract.ByteMultiplier -ne 1 -or $Contract.Headers.Count -lt 2 -or $Contract.Headers[-1] -cne $Contract.SizeColumn -or
        $Contract.Headers -cnotcontains $Contract.LabelColumn) {throw 'Unverified export column/unit contract.'}
    $start=ConvertTo-MiTraceUtc $Descriptor.StartUtc;$end=ConvertTo-MiTraceUtc $Descriptor.EndUtc
    if ($end -lt $start) {throw 'Invalid ETL evidence time range.'}
    if (-not (Test-MiNoReparse $Path) -or (Get-Item -LiteralPath $Path).Length -gt 67108864) {throw 'CSV is untrusted or too large.'}
    Add-Type -AssemblyName Microsoft.VisualBasic
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true)
    $parser=[Microsoft.VisualBasic.FileIO.TextFieldParser]::new($reader)
    $parser.SetDelimiters(',');$parser.HasFieldsEnclosedInQuotes=$true;$parser.TrimWhiteSpace=$false
    $findings=New-Object 'System.Collections.Generic.List[object]';$seen=New-Object 'System.Collections.Generic.HashSet[string]';$rows=0;$findingBytes=0L
    try {
        $header=$parser.ReadFields()
        if ($null -eq $header -or ($header -join "`0") -cne ($Contract.Headers -join "`0") -or @($header|Select-Object -Unique).Count -ne $header.Count) {throw 'Unexpected/duplicate CSV columns; no guessed aliases or units.'}
        while (-not $parser.EndOfData) {
            $fields=$parser.ReadFields()
            if (++$rows -gt 100000 -or $fields.Count -ne $header.Count) {throw 'CSV row bound/shape invalid.'}
            if (@($fields|Where-Object {$_.Length -gt 4096 -or $_ -match '[\x00-\x1f]'}).Count -gt 0) {throw 'CSV field bound/control character invalid.'}
            $row=@{};for ($i=0;$i -lt $header.Count;$i++) {$row[$header[$i]]=$fields[$i]}
            $label=[string]$row[$Contract.LabelColumn];$raw=[string]$row[$Contract.SizeColumn];$size=0L
            if ($label.Length -eq 0 -or $label.Length -gt 4096 -or $label -match '[\x00-\x1f]' -or $label -match '^[=+@-]' -or
                $label -imatch '^(total|grand total)$' -or $raw -cnotmatch '^\d{1,19}$' -or
                -not [long]::TryParse($raw,[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$size)) {throw 'Invalid CSV label/integer bytes; reject totals, formulas, rounding and overflow.'}
            $key=($fields[0..($fields.Count-2)] -join "`0")
            if (-not $seen.Add($key)) {throw 'Duplicate/aggregate CSV scope; do not double-count.'}
            $scope=[ordered]@{};foreach ($name in $header[0..($header.Count-2)]) {$scope[$name]=$row[$name]}
            $loss=$Descriptor.EventLossStatus
            if ($loss -cnotin @('NoLossReported','LossReported')) {$loss='Unknown'}
            $finding=[pscustomobject]@{SchemaVersion=1;FindingId=[guid]::NewGuid().ToString('N');Category=$Descriptor.TraceType;
                TimeRangeUtc=[pscustomobject]@{StartUtc=$start.ToString('o');EndUtc=$end.ToString('o')};MetricName=$Contract.MetricName;
                ObservedBytes=$size;GrowthBytes=$null;SourceType='WPAExporter';ProcessInstanceId=$null;TraceSessionId=$Descriptor.TraceSessionId;
                MeasurementQuality=if ($loss -ceq 'NoLossReported') {'Complete'} else {'Partial'};AttributionConfidence='DirectlyObserved';EventLossStatus=$loss;
                SourceProcessLabel=$label;SourceScope=[pscustomobject]$scope;SymbolStatus=$SymbolStatus;Limitations=@('Only the accepted CSV table metric is observed; allocation totals are not current RAM or retained bytes.',
                    'CSV labels/PIDs are not verified process-instance identities. No live-process association or action authority.',
                    'Growth and leak status cannot be inferred from this table. Symbol resolution is not verified by exporter exit code.');
                SuggestedNextStep='Inspect the preserved ETL and matching WPA table; missing symbols do not mean no anomaly.'}
            # 小 CSV 的逐行说明可能放大成很大的结果；在积累对象前限制实际序列化 UTF-8 字节数。
            $findingBytes+=[Text.Encoding]::UTF8.GetByteCount(($finding|ConvertTo-Json -Compress -Depth 8))+1
            if ($findingBytes -gt $MaxFindingBytes) {throw 'Normalized Findings exceed the output budget; source CSV retained.'}
            $findings.Add($finding)
        }
    } finally {$parser.Dispose();$reader.Dispose();$stream.Dispose()}
    return [pscustomobject]@{SchemaVersion=1;State=if ($rows -eq 0) {'AnalysisPartial'} else {'Complete'};Findings=$findings.ToArray();RowCount=$rows}
}
function Initialize-MiExporterNative {
    if ('MemoryInspector.ExportNative' -as [type]) {return}
    if ([Environment]::Is64BitProcess -ne $true) {throw 'Exporter worker requires x64.'}
    # 只为本次创建的普通权限子进程建立 Job。先挂入 Job 再恢复线程，父进程崩溃不会遗留导出器。
    $source=@'
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace MemoryInspector {
 public static class ExportNative {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;public ushort Show,ReservedSize;public IntPtr ReservedPointer,Input,Output,Error;}
  [StructLayout(LayoutKind.Sequential)] struct Pi {public IntPtr Process,Thread;public uint Id,ThreadId;}
  [StructLayout(LayoutKind.Sequential)] struct Basic {public long ProcessTime,JobTime;public uint Flags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
  [StructLayout(LayoutKind.Sequential)] struct Io {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
  [StructLayout(LayoutKind.Sequential)] struct Extended {public Basic Basic;public Io Io;public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool CreateProcessW(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string dir,ref Startup si,out Pi pi);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern IntPtr CreateJobObjectW(IntPtr a,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int type,ref Extended value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
  [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr p,out uint code);
  [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr j,uint code);
  [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr p,uint code);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  static long Bytes(string root) {
   long size=0;int count=0;var folders=new System.Collections.Generic.Queue<string>();folders.Enqueue(root);
   while(folders.Count>0)foreach(string path in Directory.GetFileSystemEntries(folders.Dequeue())) {
    if(++count>10000)throw new IOException("Exporter file count limit");var attr=File.GetAttributes(path);
    if((attr&FileAttributes.ReparsePoint)!=0)throw new IOException("Exporter reparse output");
    if((attr&FileAttributes.Directory)!=0)folders.Enqueue(path);else size=checked(size+new FileInfo(path).Length);
   }return size;
  }
  public static int Run(string exe,string args,string directory,string env,string output) {
   IntPtr job=CreateJobObjectW(IntPtr.Zero,null),block=IntPtr.Zero;Pi pi=new Pi();bool assigned=false;
   if(job==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    Extended limit=new Extended();limit.Basic.Flags=0x2000|0x200|0x8;limit.Basic.Active=1;limit.JobMemory=new UIntPtr(1073741824u);
    if(!SetInformationJobObject(job,9,ref limit,(uint)Marshal.SizeOf(typeof(Extended))))throw new Win32Exception(Marshal.GetLastWin32Error());
    block=Marshal.StringToHGlobalUni(env);Startup startup=new Startup();startup.Size=(uint)Marshal.SizeOf(typeof(Startup));
    if(!CreateProcessW(exe,new StringBuilder("\""+exe+"\" "+args),IntPtr.Zero,IntPtr.Zero,false,0x08000404,block,directory,ref startup,out pi))throw new Win32Exception(Marshal.GetLastWin32Error());
    if(!AssignProcessToJobObject(job,pi.Process))throw new Win32Exception(Marshal.GetLastWin32Error());assigned=true;
    if(ResumeThread(pi.Thread)==uint.MaxValue)throw new Win32Exception(Marshal.GetLastWin32Error());
    Stopwatch timer=Stopwatch.StartNew();
    while(WaitForSingleObject(pi.Process,250)==258) {
     if(timer.Elapsed.TotalSeconds>120 || Bytes(output)>67108864 || new DriveInfo(Path.GetPathRoot(output)).AvailableFreeSpace<2147483648L)throw new IOException("Exporter time/output/disk budget limit");
    }
    uint code;if(!GetExitCodeProcess(pi.Process,out code) || code==259)throw new IOException("Exporter outcome unknown; no retry");
    if(Bytes(output)>67108864)throw new IOException("Exporter output budget exceeded");return unchecked((int)code);
   }finally{
    if(pi.Process!=IntPtr.Zero) {if(assigned)TerminateJobObject(job,125);else TerminateProcess(pi.Process,125);WaitForSingleObject(pi.Process,5000);CloseHandle(pi.Process);}
    if(pi.Thread!=IntPtr.Zero)CloseHandle(pi.Thread);CloseHandle(job);if(block!=IntPtr.Zero)Marshal.FreeHGlobal(block);
   }
  }
 }
}
'@
    Add-Type -TypeDefinition $source -ReferencedAssemblies System.dll -ErrorAction Stop
}
function Invoke-MiWpaExportProcess {
    param($Tool,[string]$Etl,[string]$Profile,[string]$Output,[string]$Cache,[switch]$Online)
    if (Test-MiAdminToken) {throw 'WPAExporter must not run elevated.'}
    foreach ($path in @($Tool.Path,$Etl,$Profile,$Output,$Cache)) {if ($path -match '["\r\n\x00]' -or $path.EndsWith('\')) {throw 'Unsafe fixed export argument.'}}
    $fresh=Get-MiWpaExporterIdentity
    if ($null -eq $fresh -or ($fresh|ConvertTo-Json -Compress) -cne ($Tool|ConvertTo-Json -Compress)) {throw 'Exporter identity changed.'}
    $args='-i "'+$Etl+'" -profile "'+$Profile+'" -delimiter , -prefix Mi_ -outputfolder "'+$Output+'"'
    if ($Online) {$args+=' -symbols'}
    $symbols=if ($Online) {'srv*'+$Cache+'*https://msdl.microsoft.com/download/symbols'} else {$Cache}
    $system=[Environment]::GetFolderPath('System');$windows=[Environment]::GetFolderPath('Windows')
    # 空 _NT_SYMBOL_PATH 会回落在线默认。使用非空本地目录并清除继承环境；不改用户/机器设置。
    $variables=New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($pair in @(@('PATH',$system),@('SystemRoot',$windows),@('TEMP',$Output),@('TMP',$Output),@('WINDIR',$windows),
        @('_NT_SYMBOL_PATH',$symbols),@('_NT_ALT_SYMBOL_PATH',$Cache),@('_NT_SYMCACHE_PATH',$Cache))) {$variables.Add($pair[0],$pair[1])}
    $environment=(($variables.Keys|ForEach-Object {$_+'='+$variables[$_]}) -join "`0")+"`0`0"
    Initialize-MiExporterNative
    return [MemoryInspector.ExportNative]::Run($Tool.Path,$args,(Split-Path -Parent $Profile),$environment,(Split-Path -Parent $Profile))
}
function Invoke-MiAttributionExport {
    param([string]$ArtifactId,[switch]$OnlineSymbols)
    if (-not (Get-Command Get-MiExportReleaseStatus -ErrorAction SilentlyContinue)) {. (Join-Path $PSScriptRoot 'PrivilegeSecurity.ps1')}
    # 门控、身份拒绝在任何写入/网络确认前发生；无参数可指定程序/Profile/目录/服务器。
    Assert-MiExportReleaseAccepted
    if (Test-MiAdminToken) {throw 'Use a standard-user session for attribution export.'}
    if (-not (Test-MiGuidN $ArtifactId)) {throw 'Invalid export artifact identity.'}
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($owner -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {throw 'Interactive user identity required.'}
    $paths=Get-MiSecurityPaths;$lease=$null;$descriptorHandle=$null;$etlHandle=$null;$claim=$null
    try {
        Assert-MiTracePath $paths.DeploymentLease
        $lease=[IO.File]::Open($paths.DeploymentLease,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $directory=Join-Path $paths.TraceArtifacts $owner;$descriptorPath=Join-Path $directory ($ArtifactId+'.export.json')
        Assert-MiTracePath $directory;Assert-MiTracePath $descriptorPath
        $descriptorHandle=[IO.File]::Open($descriptorPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if ($descriptorHandle.Length -gt 32768) {throw 'Export descriptor exceeds bound.'}
        $text=[IO.File]::ReadAllText($descriptorPath,[Text.UTF8Encoding]::new($false,$true));$descriptor=$text|ConvertFrom-Json -ErrorAction Stop
        if (($descriptor|ConvertTo-Json -Compress) -cne $text -or @($descriptor.PSObject.Properties).Count -ne 11 -or
            $descriptor.SchemaVersion -ne 1 -or $descriptor.ArtifactId -cne $ArtifactId -or $descriptor.OwnerSid -cne $owner -or
            -not (Test-MiGuidN $descriptor.TraceSessionId) -or $descriptor.Sha256 -cnotmatch '^[A-F0-9]{64}$' -or
            $descriptor.SizeBytes -le 0 -or $descriptor.SizeBytes -gt 8589934592) {throw 'Untrusted export descriptor.'}
        $source=[IO.Path]::GetFullPath($script:MiAnalyzerModulePath)
        if ([IO.Path]::GetDirectoryName($source) -ine $paths.Install -or $descriptor.AnalyzerSha256 -cnotmatch '^[A-F0-9]{64}$') {throw 'Analysis requires the protected installed component.'}
        Assert-MiTracePath $source # 描述中的摘要是准备者版本；当前受保护组件可兼容读取历史 Schema。
        $availability=Get-MiAttributionExportAvailability $descriptor.TraceType
        if ($availability.State -cne 'Available') {return $availability}
        $contract=Get-MiWpaExportContract $descriptor.TraceType
        $etl=Join-Path $directory ($ArtifactId+'.etl');Assert-MiTracePath $etl
        $etlHandle=[IO.File]::Open($etl,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $verified=Test-MiEtlArtifact $etl
        if ($verified.Sha256 -cne $descriptor.Sha256 -or $verified.SizeBytes -ne $descriptor.SizeBytes -or
            $verified.StartUtc -cne $descriptor.StartUtc -or $verified.EndUtc -cne $descriptor.EndUtc -or
            $descriptor.EventLossStatus -cne $(if ($verified.EventsLost -gt 0 -or $verified.BuffersLost -gt 0) {'LossReported'} else {'NoLossReported'})) {throw 'ETL integrity/time/loss changed; no trusted Findings.'}
        $outputRoot=Join-Path $directory ($ArtifactId+'.export')
        if (-not (Test-MiNoReparse $outputRoot) -or (Measure-MiProtectedTree $paths.TraceArtifacts) -gt (8589934592-67108864)) {throw 'Diagnostic output path/storage budget unavailable.'}
        $claim=[IO.File]::Open((Join-Path $outputRoot 'export.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $analysisId=[guid]::NewGuid().ToString('N');$online=$false
        if ($OnlineSymbols) {
            if (-not (Get-MiExportReleaseStatus).OnlineAccepted) {throw 'Online symbol policy acceptance pending.'}
            $answer=Read-Host ('Download symbols from https://msdl.microsoft.com/download/symbols into this attempt cache for stack analysis. Type SYMBOLS '+$analysisId+' to authorize once; Enter continues offline')
            $online=$answer -ceq ('SYMBOLS '+$analysisId)
        }
        $work=Join-Path $outputRoot $analysisId;[void][IO.Directory]::CreateDirectory($work)
        $profilePath=Join-Path $work 'memory.wpaProfile';[IO.File]::WriteAllText($profilePath,$contract.Xml,[Text.UTF8Encoding]::new($false))
        $cache=Join-Path $work 'symbols';$output=Join-Path $work 'csv'
        [void][IO.Directory]::CreateDirectory($cache);[void][IO.Directory]::CreateDirectory($output)
        $intent=[pscustomobject]@{SchemaVersion=1;AnalysisId=$analysisId;ArtifactId=$ArtifactId;State='DispatchIntent';OnlineAuthorized=$online;
            ProfileId=$contract.ProfileId;ProfileSha256=(Get-MiTraceHash $contract.Xml);Tool=$availability.Tool;Utc=[datetime]::UtcNow.ToString('o')}
        $intentFile=[IO.File]::Open((Join-Path $work 'intent.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($intent|ConvertTo-Json -Compress));$intentFile.Write($bytes,0,$bytes.Length);$intentFile.Flush($true)} finally {$intentFile.Dispose()}
        $symbolStatus=if ($online) {'OnlineRequestedUnverified'} else {'NotRequested'}
        try {
            $exitCode=Invoke-MiWpaExportProcess $availability.Tool $etl $profilePath $output $cache -Online:$online
            if ($exitCode -ne 0 -and $online) {
                # 仅在子进程已确认退出时，另存一次无符号结果；未知/超时异常不重派发。
                $output=Join-Path $work 'csv-offline';[void][IO.Directory]::CreateDirectory($output)
                $symbolStatus='OnlineFailedOfflineFallback'
                $exitCode=Invoke-MiWpaExportProcess $availability.Tool $etl $profilePath $output $cache
            }
            if ($exitCode -ne 0) {throw 'Exporter returned a known failure.'}
            $csv=@(Get-ChildItem -LiteralPath $output -Filter $contract.CsvPattern -File -ErrorAction Stop)
            if ($csv.Count -ne 1) {$result=[pscustomobject]@{SchemaVersion=1;State='AnalysisPartial';Findings=@();ErrorCode='ExpectedTableMissingOrAmbiguous'}}
            else {$result=ConvertFrom-MiWpaCsv $csv[0].FullName $descriptor $contract $symbolStatus}
        } catch {$result=[pscustomobject]@{SchemaVersion=1;State='AnalysisPartial';Findings=@();ErrorCode=$_.Exception.Message}}
        $result|Add-Member NoteProperty AnalysisId $analysisId
        $result|Add-Member NoteProperty ArtifactId $ArtifactId
        $result|Add-Member NoteProperty SymbolStatus $symbolStatus
        $result|Add-Member NoteProperty ResultTrust 'UserOwnedDiagnosticOnly'
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Compress -Depth 10))
        # 原生导出器退出后，归一化本身也消耗工作区/全局额度；写结果前重新测量，绝不先写大文件再删。
        $workBytes=Measure-MiExportOutput $work;$allBytes=Measure-MiProtectedTree $paths.TraceArtifacts
        $free=([IO.DriveInfo]::new([IO.Path]::GetPathRoot($work))).AvailableFreeSpace
        if ($bytes.Length -gt (67108864-$workBytes) -or $bytes.Length -gt (8589934592-$allBytes) -or $free -lt (2147483648L+$bytes.Length)) {
            return [pscustomobject]@{SchemaVersion=1;State='AnalysisPartial';AnalysisId=$analysisId;ArtifactId=$ArtifactId;Findings=@();
                ErrorCode='NormalizedResultStorageBudgetExceeded';ResultPersisted=$false;ResultTrust='UserOwnedDiagnosticOnly'}
        }
        $file=[IO.File]::Open((Join-Path $work 'result.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
        return $result
    } finally {foreach ($handle in @($claim,$etlHandle,$descriptorHandle,$lease)) {if ($null -ne $handle) {$handle.Dispose()}}}
}
function Get-MiMedian {
    param([object[]]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $middle = [int][math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle-1] + [double]$sorted[$middle]) / 2.0
}

function Get-MiInstanceKey {
    param([string]$BootId,$Process)
    $processId=0;$ticks=0L
    if ($null -eq $Process -or -not [int]::TryParse([string]$Process.PID,[ref]$processId) -or $processId -le 0 -or
        -not [long]::TryParse([string]$Process.StartUtcTicks,[ref]$ticks) -or $ticks -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$Process.Name)) { return $null }
    return ('{0}:{1}:{2}' -f $BootId,$processId,$ticks)
}

function Get-MiAnalysisParameters {
    param([ValidateRange(5,60)][int]$IntervalSeconds=5)
    # 窗口包含首尾采样点；不能把 1800 / 周期的近似值当成精确样本数。
    $expected = [int][math]::Floor(1800.0 / $IntervalSeconds) + 1
    return [pscustomobject]@{
        IntervalSeconds=$IntervalSeconds;WindowSeconds=1800;BinSeconds=300
        ExpectedSampleCount=$expected
        MinimumSampleCount=[int][math]::Ceiling($expected*0.85)
        HistoryCapacity=($expected+[int][math]::Ceiling($expected*0.20)+2)
        MinimumCoverageRatio=0.85
        BoundaryToleranceSeconds=($IntervalSeconds/2.0)
        MaximumGapSeconds=[math]::Max(60,3*$IntervalSeconds)
    }
}

function Initialize-MiAnalysisStorage {
    if ($null -ne ('MemoryInspector.AnalysisPoint' -as [type])) { return }
    # 每个实例保留完整30分钟证据；紧凑值类型只消除 PSObject 开销，不降采样、不改归槽规则。
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace MemoryInspector {
    public struct AnalysisPoint {
        public readonly DateTime Utc;
        public readonly long Bytes;
        public AnalysisPoint(DateTime utc, long bytes) { Utc=utc; Bytes=bytes; }
    }
    public struct SavedAnalysisProcess {
        public int PID;
        public string Name;
        public long StartUtcTicks;
        public string ProcessInstanceId;
        public long? PrivateBytes;
    }
    // 在紧凑标量列表上计算质量，避免每轮为每个进程复制数百个 PowerShell 对象。
    public sealed class AttributionWindow {
        public int ExpectedSampleCount, ValidSampleCount, RawSampleCount, MissingSampleCount;
        public double CoverageRatio, ActualSpanSeconds, MaximumGapSeconds;
        public double LatestAgeSeconds;
        public int[] SegmentExpectedSampleCounts, SegmentValidSampleCounts;
        public double[] SegmentMedians;
        public DateTime? StartUtc, EndUtc;
        public long? GrowthBytes;
        public bool SufficientTrend;
        public int UpwardSegments;
        public static AttributionWindow Measure(IList<AnalysisPoint> points, DateTime now, int interval) {
            return Measure(points, now, interval, 0);
        }
        // 旧诊断保留半周期边界容差和 double 中位数；新 Finding 使用严格观察窗口。
        // 两者共享遍历，绝不以性能优化改变原 85%/分段/缺口阈值。
        public static AttributionWindow Measure(IList<AnalysisPoint> points, DateTime now, int interval, double boundaryTolerance) {
            var result = new AttributionWindow();
            result.ExpectedSampleCount = 1800 / interval + 1;
            var slots = new Dictionary<int,AnalysisPoint>();
            if (points != null) foreach (var p in points) {
                double age = (now-p.Utc).TotalSeconds;
                if (age < 0 || age > 1800+boundaryTolerance) continue;
                result.RawSampleCount++;
                int slot = (int)Math.Round(age/interval, MidpointRounding.AwayFromZero);
                if (slot >= result.ExpectedSampleCount) continue;
                AnalysisPoint prior;
                if (!slots.TryGetValue(slot, out prior) || p.Utc > prior.Utc) slots[slot]=p;
            }
            var evidence = new List<AnalysisPoint>(slots.Values);
            evidence.Sort((a,b) => a.Utc.CompareTo(b.Utc));
            result.ValidSampleCount=evidence.Count;
            result.MissingSampleCount=result.ExpectedSampleCount-evidence.Count;
            result.CoverageRatio=(double)evidence.Count/result.ExpectedSampleCount;
            if (evidence.Count > 0) {
                result.StartUtc=evidence[0].Utc; result.EndUtc=evidence[evidence.Count-1].Utc;
                result.ActualSpanSeconds=(result.EndUtc.Value-result.StartUtc.Value).TotalSeconds;
                result.LatestAgeSeconds=(now-result.EndUtc.Value).TotalSeconds;
            }
            if (evidence.Count >= 2) result.GrowthBytes=evidence[evidence.Count-1].Bytes-evidence[0].Bytes;
            for (int i=1;i<evidence.Count;i++) result.MaximumGapSeconds=Math.Max(result.MaximumGapSeconds,
                (evidence[i].Utc-evidence[i-1].Utc).TotalSeconds);
            var bins=new List<long>[6]; var expected=new int[6];
            for (int i=0;i<6;i++) bins[i]=new List<long>();
            for (int slot=0;slot<result.ExpectedSampleCount;slot++) {
                int bin=Math.Min(5,(1800-slot*interval)/300); expected[bin]++;
                AnalysisPoint p; if (slots.TryGetValue(slot,out p)) bins[bin].Add(p.Bytes);
            }
            result.SegmentExpectedSampleCounts=expected;
            result.SegmentValidSampleCounts=new int[6]; result.SegmentMedians=new double[6];
            bool adequate=result.CoverageRatio>=0.85 && result.ActualSpanSeconds>=1800-interval &&
                result.LatestAgeSeconds<=interval && result.MaximumGapSeconds<=Math.Max(60,3*interval);
            decimal? previous=null;
            for (int i=0;i<6;i++) {
                result.SegmentValidSampleCounts[i]=bins[i].Count;
                if (bins[i].Count<Math.Ceiling(expected[i]*0.85)) adequate=false;
                if (bins[i].Count==0) { previous=null; continue; }
                bins[i].Sort(); int mid=bins[i].Count/2;
                result.SegmentMedians[i]=(bins[i].Count%2==1) ? (double)bins[i][mid] : ((double)bins[i][mid-1]+(double)bins[i][mid])/2;
                decimal median=(bins[i].Count%2==1) ? bins[i][mid] : ((decimal)bins[i][mid-1]+bins[i][mid])/2;
                if (previous.HasValue && median>previous.Value) result.UpwardSegments++;
                previous=median;
            }
            result.SufficientTrend=adequate;
            return result;
        }
    }
}
'@ -ErrorAction Stop
}
function New-MiAnalyzer {
    param([string]$BootId,[string]$Root,[int]$WindowMinutes=30,
        [ValidateRange(5,60)][int]$IntervalSeconds=5)
    if ($WindowMinutes -ne 30) { throw 'Milestone 3 uses a fixed 30-minute diagnostic window.' }
    Initialize-MiAnalysisStorage
    $usableBoot = -not [string]::IsNullOrWhiteSpace($BootId) -and $BootId -ne 'BootUnavailable'
    return [pscustomobject]@{
        BootId = $(if ($usableBoot) { $BootId } else { 'Session-'+[guid]::NewGuid().ToString('N') })
        CanRestore = $usableBoot
        Root = $Root
        Tracks = @{}
        PoolHistory = (New-Object 'System.Collections.Generic.List[object]')
        AttributionHistory = @{}
        Historical = @{}
        HistoricalLoadedUtc = [datetime]::MinValue
        LastCaptureUtc = [datetime]::MinValue
        LastSequence = $null
        LastMonotonicSeconds = $null
        ContinuityId = [guid]::NewGuid().ToString('N')
        WindowMinutes = $WindowMinutes
        Parameters = (Get-MiAnalysisParameters -IntervalSeconds $IntervalSeconds)
        IntervalSeconds = $IntervalSeconds
        ContinuityReason = $null
        WindowResetCount = 0
        GrowthThresholdBytes = [long]512MB
        GrowthThresholdRatio = [double]0.20
    }
}

function Set-MiAnalyzerInterval {
    param($Analyzer,[ValidateRange(5,60)][int]$IntervalSeconds)
    if ($Analyzer.IntervalSeconds -eq $IntervalSeconds) { return }
    # 改变周期后重新积累完整窗口，防止旧高密度样本伪装成新周期的充分证据。
    $Analyzer.ContinuityReason = ('采样周期由 {0} 秒变为 {1} 秒，已重新建立分析窗口。' -f $Analyzer.IntervalSeconds,$IntervalSeconds)
    $Analyzer.IntervalSeconds=$IntervalSeconds
    $Analyzer.Parameters=Get-MiAnalysisParameters -IntervalSeconds $IntervalSeconds
    $Analyzer.Tracks.Clear()
    $Analyzer.PoolHistory.Clear()
    $Analyzer.AttributionHistory.Clear()
    $Analyzer.LastCaptureUtc=[datetime]::MinValue
    $Analyzer.LastSequence=$null
    $Analyzer.LastMonotonicSeconds=$null
    $Analyzer.ContinuityId=[guid]::NewGuid().ToString('N')
    $Analyzer.WindowResetCount++
}

function Limit-MiAnalysisHistory {
    param($Analyzer,$Samples,[datetime]$NowUtc)
    $cutoff=$NowUtc.AddSeconds(-$Analyzer.Parameters.WindowSeconds-$Analyzer.Parameters.BoundaryToleranceSeconds)
    while ($Samples.Count -gt 0 -and $Samples[0].Utc -lt $cutoff) { $Samples.RemoveAt(0) }
    if ($Samples.Count -le $Analyzer.Parameters.HistoryCapacity) { return }
    # 旧文件没有周期字段时，按实际时间戳中最密的受支持周期增加容量，不能只留下当前周期的尾部数量。
    $retentionInterval=$Analyzer.IntervalSeconds
    for ($i=1;$i -lt $Samples.Count;$i++) {
        $delta=($Samples[$i].Utc-$Samples[$i-1].Utc).TotalSeconds
        if ($delta -gt 0 -and $delta -lt $retentionInterval) {
            $retentionInterval=[math]::Max(5,[int][math]::Floor($delta))
        }
    }
    $Analyzer.Parameters.HistoryCapacity=[math]::Max($Analyzer.Parameters.HistoryCapacity,
        (Get-MiAnalysisParameters -IntervalSeconds $retentionInterval).HistoryCapacity)
    if ($Samples.Count -le $Analyzer.Parameters.HistoryCapacity) { return }
    # 超过 5 秒上限密度的突发样本按固定 UTC 时间槽合并，避免随窗口锚点移动反复合并造成历史缺口。
    $slots=@{}
    foreach ($point in $Samples) {
        $slot=[long][math]::Floor($point.Utc.Ticks/([double][timespan]::TicksPerSecond*5))
        $slots[$slot]=$point
    }
    $Samples.Clear()
    foreach ($slot in @($slots.Keys | Sort-Object)) { $Samples.Add($slots[$slot]) }
}

function Add-MiTrackSample {
    param($Analyzer,$Snapshot,[bool]$Historical=$false)
    if ($null -eq $Snapshot -or $null -eq $Snapshot.Processes -or $Snapshot.Processes.Status -eq 'Failed') { return }
    try { $utc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime() } catch { return }
    if ($utc.Year -lt 2020) { return }
    foreach ($p in @($Snapshot.Processes.Items)) {
        if ($null -eq $p -or $null -eq $p.PrivateBytes) { continue }
        $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
        if ($null -eq $key) { continue }
        $bytes = Get-MiAttributionBytes $p.PrivateBytes
        if ($null -eq $bytes) { continue }
        if (-not $Analyzer.Tracks.ContainsKey($key)) {
            $Analyzer.Tracks[$key] = [pscustomobject]@{
                Name = [string]$p.Name
                PID = [int]$p.PID
                StartUtcTicks = [long]$p.StartUtcTicks
                Samples = (New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]')
            }
        }
        $list = $Analyzer.Tracks[$key].Samples
        if ($list.Count -gt 0 -and $utc -le $list[$list.Count-1].Utc) { continue }
        $list.Add([MemoryInspector.AnalysisPoint]::new($utc,$bytes))
        Limit-MiAnalysisHistory -Analyzer $Analyzer -Samples $list -NowUtc $utc
    }
    # A process can exit, but stale traces must not accumulate indefinitely.
    if (-not $Historical) {
        $cutoff = $utc.AddMinutes(-30)
        foreach ($key in @($Analyzer.Tracks.Keys)) {
            $trace = $Analyzer.Tracks[$key]
            if ($trace.Samples.Count -eq 0 -or $trace.Samples[$trace.Samples.Count-1].Utc -lt $cutoff) {
                $Analyzer.Tracks.Remove($key)
            }
        }
    }
}

function ConvertTo-MiCompactAnalysisRecord {
    param($Record)
    # 仅用于内部恢复；缺失身份不能成为证据。有效身份的null/负计数器仍须保留，
    # 让原恢复逻辑观察其连续段断点，再由Add-MiTrackSample拒绝无效数值，不能省掉断点。
    $rows=New-Object 'System.Collections.Generic.List[MemoryInspector.SavedAnalysisProcess]'
    foreach($p in @($Record.Items)) {
        if ($null -eq $p -or $null -eq $p.PID -or $null -eq $p.StartUtcTicks -or
            [long]$p.StartUtcTicks -le 0 -or [string]::IsNullOrWhiteSpace([string]$p.Name)) {continue}
        $row=[MemoryInspector.SavedAnalysisProcess]::new()
        $row.PID=[int]$p.PID;$row.Name=[string]$p.Name;$row.StartUtcTicks=[long]$p.StartUtcTicks
        $row.ProcessInstanceId=[string]$p.ProcessInstanceId;$row.PrivateBytes=$p.PrivateBytes
        $rows.Add($row)
    }
    return [pscustomobject]@{SchemaVersion=$Record.SchemaVersion;RecordType=$Record.RecordType
        CaptureEndUtc=$Record.CaptureEndUtc;IntervalSeconds=$Record.IntervalSeconds
        ProcessStatus=$Record.ProcessStatus;MonotonicSeconds=$Record.MonotonicSeconds
        ContinuityId=$Record.ContinuityId;Items=$rows.ToArray()}
}
function Get-MiRecentProcessRecords {
    param([string]$Root,[datetime]$NowUtc,[ValidateRange(5,60)][int]$IntervalSeconds=5,[switch]$Compact)
    if ([string]::IsNullOrWhiteSpace($Root)) { return @() }
    # 旧 schema=1 没有周期字段，恢复读取量按所有受支持周期中最密的 5 秒计算。
    $tailCapacity=(Get-MiAnalysisParameters -IntervalSeconds 5).HistoryCapacity
    $records = New-Object 'System.Collections.Generic.List[object]'
    $projection=$null
    if($Compact){Initialize-MiAnalysisStorage;$projection={param($r) ConvertTo-MiCompactAnalysisRecord $r}}
    foreach ($day in @($NowUtc.Date.AddDays(-1),$NowUtc.Date)) {
        $date = $day.ToString('yyyy-MM-dd')
        $filename = 'process-'+$date+'.jsonl'
        $raw = Join-Path (Join-Path $Root 'process') $filename
        $recent = @()
        if ([IO.File]::Exists($raw)) {
            $recent = @(Read-MiJsonTail -Path $raw -Count $tailCapacity -Projection $projection)
        } else {
            # M2 may compress yesterday's JSONL after midnight.
            $archive = Join-Path (Join-Path $Root 'archives') ('raw-'+$date+'.zip')
            if ([IO.File]::Exists($archive)) {
                Add-Type -AssemblyName System.IO.Compression
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [IO.Compression.ZipFile]::OpenRead($archive)
                try {
                    $entry = $zip.GetEntry($filename)
                    if ($entry) {
                        $stream = $entry.Open()
                        $reader = [IO.StreamReader]::new($stream,[Text.Encoding]::UTF8)
                        try {
                            $tail = New-Object 'System.Collections.Generic.Queue[string]'
                            while (-not $reader.EndOfStream) {
                                $line = $reader.ReadLine()
                                $tail.Enqueue($line)
                                if ($tail.Count -gt $tailCapacity) { [void]$tail.Dequeue() }
                            }
                            foreach ($line in $tail) {
                                try {
                                    $obj = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                                    if ([int]$obj.SchemaVersion -eq 1) {
                                        if($Compact){$recent += ConvertTo-MiCompactAnalysisRecord $obj}else{$recent += $obj}
                                    }
                                } catch {}
                            }
                        } finally { $reader.Dispose() }
                    }
                } finally { $zip.Dispose() }
            }
        }
        foreach ($r in $recent) {
            try {
                $utc = ([datetime]$r.CaptureEndUtc).ToUniversalTime()
                if ($utc -ge $NowUtc.AddSeconds(-1800-$IntervalSeconds/2.0) -and $utc -le $NowUtc -and $r.RecordType -eq 'ProcessSnapshot') {
                    $records.Add($r)
                }
            } catch {}
        }
    }
    # 保留 JSONL 的追加顺序；按 UTC 排序会掩盖回拨断点。
    return @($records.ToArray())
}

function Restore-MiAnalyzer {
    param($Analyzer,[datetime]$NowUtc=[datetime]::UtcNow)
    if (-not $Analyzer.CanRestore -or [string]::IsNullOrWhiteSpace($Analyzer.Root)) { return 0 }
    $count = 0
    $previousUtc=[datetime]::MinValue;$previousContinuity=$null;$previousMonotonic=$null
    $recent=@(Get-MiRecentProcessRecords -Root $Analyzer.Root -NowUtc $NowUtc -IntervalSeconds $Analyzer.IntervalSeconds -Compact)
    # UTC 跨日回拨会把新行写入前一天的文件；同一启动内的单调时间恢复真实采样顺序。
    # 旧记录没有此可选字段，仍保持原追加顺序，不猜测单调时间。
    $ordered=New-Object 'System.Collections.Generic.List[object]'
    $index=0
    foreach ($record in $recent) {
        $mono=-1.0
        if ($null -ne $record.MonotonicSeconds) {
            $parsed=0.0
            if (-not [double]::TryParse([string]$record.MonotonicSeconds,[Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,[ref]$parsed) -or
                [double]::IsNaN($parsed) -or [double]::IsInfinity($parsed) -or $parsed -lt 0) { continue }
            $mono=$parsed
        }
        $ordered.Add([pscustomobject]@{Record=$record;Monotonic=$mono;Index=$index})
        $index++
    }
    foreach ($orderedRecord in @($ordered | Sort-Object Monotonic,Index)) {
        $r=$orderedRecord.Record
        if ($r.ProcessStatus -eq 'Failed') { continue }
        if ($null -ne $r.IntervalSeconds) {
            $savedInterval=0
            if (-not [int]::TryParse([string]$r.IntervalSeconds,[ref]$savedInterval) -or $savedInterval -lt 5 -or $savedInterval -gt 60) { continue }
            if ($savedInterval -ne $Analyzer.IntervalSeconds) {
                # 持久化记录中的明确周期切换也是连续性边界，不能把切换前后同周期的两段历史拼接起来。
                $Analyzer.Tracks.Clear()
                $Analyzer.PoolHistory.Clear()
                $Analyzer.ContinuityReason='历史中检测到其他采样周期，已从该断点后重新建立分析窗口。'
                continue
            }
        }
        # Existing M2 ProcessInstanceId contains the boot id, PID and start time.
        $matching = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in @($r.Items)) {
            $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
            if ($null -ne $key -and $key -ceq [string]$p.ProcessInstanceId) { $matching.Add($p) }
        }
        if ($matching.Count -eq 0) { continue }
        # 新记录使用连续段 ID；旧 schema=1 仍可读，但必须按追加时间检测回拨，不能拼接两段趋势。
        $recordUtc=([datetime]$r.CaptureEndUtc).ToUniversalTime()
        if (($previousUtc -ne [datetime]::MinValue -and $recordUtc -le $previousUtc) -or
            ($null -ne $previousContinuity -and $r.ContinuityId -ne $previousContinuity)) {
            $Analyzer.Tracks.Clear();$Analyzer.PoolHistory.Clear();$count=0
            $Analyzer.ContinuityReason='历史记录存在时间断点，仅恢复最后连续段。'
        }
        $previousUtc=$recordUtc;$previousContinuity=$r.ContinuityId;$previousMonotonic=$r.MonotonicSeconds

        Add-MiTrackSample -Analyzer $Analyzer -Historical $true -Snapshot ([pscustomobject]@{
            CaptureEndUtc=$r.CaptureEndUtc
            Processes=[pscustomobject]@{Status=$r.ProcessStatus;Items=$matching.ToArray()}
        })
        $count++
    }
    if ($count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$previousContinuity)) {
        $Analyzer.ContinuityId=[string]$previousContinuity
        $Analyzer.LastCaptureUtc=$previousUtc
        $Analyzer.LastMonotonicSeconds=$previousMonotonic
    }
    return $count
}

function Update-MiHistoricalBaselines {
    param($Analyzer,[datetime]$NowUtc=[datetime]::UtcNow)
    if (($NowUtc-$Analyzer.HistoricalLoadedUtc).TotalMinutes -lt 30) { return }
    $Analyzer.HistoricalLoadedUtc = $NowUtc
    $Analyzer.Historical = @{}
    if ([string]::IsNullOrWhiteSpace($Analyzer.Root)) { return }
    $folder = Join-Path $Analyzer.Root 'aggregates'
    if (-not [IO.Directory]::Exists($folder)) { return }
    $earliest = $NowUtc.Date.AddDays(-90)
    $byProgram = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter 'summary-*.jsonl' -File -ErrorAction Stop | Sort-Object Name)) {
        if ($file.Name -notmatch '^summary-(\d{4}-\d{2}-\d{2})\.jsonl$') { continue }
        $day = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($Matches[1],'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$day)) { continue }
        if ($day -lt $earliest -or $day -ge $NowUtc.Date) { continue }
        # Deterministic 2-hour sampling: at most 12 aggregate rows per day.
        $index = 0
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            if ((($index++) % 24) -ne 0) { continue }
            try {
                $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ([int]$record.SchemaVersion -ne 1 -or $record.RecordType -ne 'FiveMinuteAggregate') { continue }
                foreach ($p in @($record.ProgramStatistics)) {
                    if ([string]::IsNullOrWhiteSpace([string]$p.Name) -or $null -eq $p.AveragePrivateBytes) { continue }
                    $name = [string]$p.Name
                    $bytes = [long]$p.AveragePrivateBytes
                    if ($bytes -lt 0) { continue }
                    if (-not $byProgram.ContainsKey($name)) {
                        $byProgram[$name] = [pscustomobject]@{
                            Values = (New-Object 'System.Collections.Generic.List[object]')
                            Days = @{}
                        }
                    }
                    $byProgram[$name].Values.Add([double]$bytes)
                    $byProgram[$name].Days[$day.ToString('yyyy-MM-dd')] = $true
                }
            } catch {} # A damaged aggregate line is never a valid baseline.
        }
    }
    foreach ($name in @($byProgram.Keys)) {
        $record = $byProgram[$name]
        if ($record.Values.Count -lt 6 -or $record.Days.Count -lt 2) { continue }
        $Analyzer.Historical[$name] = [pscustomobject]@{
            MedianProgramPrivateBytes=[long](Get-MiMedian -Values $record.Values.ToArray())
            BucketCount=$record.Values.Count
            DayCount=$record.Days.Count
            Scope='ProgramNameAggregate'
        }
    }
}

function Get-MiProcessAnomaly {
    param($Analyzer,$Process,[datetime]$NowUtc)
    $key = Get-MiInstanceKey -BootId $Analyzer.BootId -Process $Process
    $report = [ordered]@{
        PID = $Process.PID
        StartUtcTicks = $Process.StartUtcTicks
        ProcessInstanceId = $key
        AnomalyState = 'InsufficientEvidence'
        EvidenceQuality = 'Insufficient'
        ValidSampleCount = 0
        RawSampleCount = 0
        ExpectedSampleCount = $Analyzer.Parameters.ExpectedSampleCount
        MinimumSampleCount = $Analyzer.Parameters.MinimumSampleCount
        IntervalSeconds = $Analyzer.IntervalSeconds
        MaximumGapSeconds = $null
        SegmentExpectedSampleCounts = @()
        SegmentValidSampleCounts = @()
        ContinuityReason = $Analyzer.ContinuityReason
        CoverageRatio = 0.0
        AnalysisWindowMinutes = 30
        BaselinePrivateBytes = $null
        CurrentPrivateBytes = $Process.PrivateBytes
        GrowthBytes = $null
        GrowthPercentage = $null
        UpwardSegments = 0
        Explanation = '缺少足够的有效同实例采样，继续观察。'
        HistoricalProgramMedianBytes = $null
        HistoricalDeviationPercent = $null
        HistoricalScope = 'Unavailable'
    }
    if ($null -eq $key -or -not $Analyzer.Tracks.ContainsKey($key)) { return [pscustomobject]$report }
    # 已实测的热点是对每个进程历史反复创建管道/排序对象；复用原模块的紧凑计算。
    # 原诊断继续使用半周期端点容差、首末跨度、分段 double 中位数及原报告格式。
    $window=[MemoryInspector.AttributionWindow]::Measure($Analyzer.Tracks[$key].Samples,$NowUtc,
        $Analyzer.IntervalSeconds,$Analyzer.Parameters.BoundaryToleranceSeconds)
    $report.RawSampleCount=$window.RawSampleCount
    $report.ValidSampleCount=$window.ValidSampleCount
    $coverage=$window.CoverageRatio
    $report.CoverageRatio=[math]::Round($coverage,3)
    $expectedBins=$window.SegmentExpectedSampleCounts
    $report.SegmentExpectedSampleCounts=$expectedBins
    $report.SegmentValidSampleCounts=$window.SegmentValidSampleCounts
    if ($window.ValidSampleCount -eq 0) { return [pscustomobject]$report }
    $span=$window.ActualSpanSeconds
    $latestAge=$window.LatestAgeSeconds
    $largestGap=$window.MaximumGapSeconds
    $report.MaximumGapSeconds=$largestGap
    if ($coverage -lt $Analyzer.Parameters.MinimumCoverageRatio -or
        $span -lt ($Analyzer.Parameters.WindowSeconds-$Analyzer.IntervalSeconds) -or
        $latestAge -gt $Analyzer.IntervalSeconds) {
        $report.Explanation=('30 分钟窗口需 {0}/{1} 个独立时间槽且覆盖完整跨度；当前 {2}/{1}，跨度 {3:N0} 秒。' -f
            $Analyzer.Parameters.MinimumSampleCount,$Analyzer.Parameters.ExpectedSampleCount,$window.ValidSampleCount,$span)
        return [pscustomobject]$report
    }
    if ($largestGap -gt $Analyzer.Parameters.MaximumGapSeconds) {
        $report.Explanation=('采样存在 {0:N0} 秒时间缺口，超过当前周期允许的 {1:N0} 秒，继续收集连续证据。' -f
            $largestGap,$Analyzer.Parameters.MaximumGapSeconds)
        return [pscustomobject]$report
    }
    $medians = @()
    for ($i=0;$i -lt 6;$i++) {
        $minimum=[int][math]::Ceiling($expectedBins[$i]*$Analyzer.Parameters.MinimumCoverageRatio)
        if ($window.SegmentValidSampleCounts[$i] -lt $minimum) {
            $report.Explanation = '至少一个五分钟分段的有效样本不足，暂不判断增长趋势。'
            return [pscustomobject]$report
        }
        $medians += $window.SegmentMedians[$i]
    }
    $baseline = [double]$medians[0]
    $growth = [double]($medians[5]-$baseline)
    $report.BaselinePrivateBytes = [long]$baseline
    $report.GrowthBytes = [long]$growth
    if ($baseline -gt 0) { $report.GrowthPercentage = [math]::Round(($growth/$baseline)*100.0,1) }
    $upward = 0
    for($i=1;$i -lt 6;$i++) { if ($medians[$i] -gt $medians[$i-1]) { $upward++ } }
    $report.UpwardSegments = $upward
    $report.EvidenceQuality = $(if ($report.CoverageRatio -ge 0.95) {'High'} else {'Moderate'})
    if ($baseline -gt 0 -and $growth -ge [long]$Analyzer.GrowthThresholdBytes -and ($growth/$baseline) -ge [double]$Analyzer.GrowthThresholdRatio -and $upward -ge 4) {
        $report.AnomalyState = 'SuspectedSustainedGrowth'
        $report.Explanation = ('六段中 {0}/5 段上升，窗口中位数增长 {1:N0} MiB（{2:N1}%）；仅为疑似增长，不代表确认泄漏。' -f
            $upward,($growth/1MB),$report.GrowthPercentage)
    } else {
        $report.AnomalyState = 'NoSignificantGrowth'
        $report.Explanation = ('30 分钟证据有效；增长 {0:N0} MiB、上升段数 {1}/5，未同时满足全部疑似增长条件。' -f
            ($growth/1MB),$upward)
    }
    return [pscustomobject]$report
}

function Get-MiMemoryPressure {
    param($Analyzer,$System,[datetime]$NowUtc)
    $result = [ordered]@{
        State='Unknown';CommitRatio=$null;AvailableRamRatio=$null
        CommitHeadroomBytes=$null;NonpagedPoolTrend='InsufficientEvidence'
        Explanation='内存系统计数器缺失，无法判断系统压力。'
    }
    if ($null -eq $System -or $System.Status -eq 'Failed' -or
        $null -eq $System.CommittedBytes -or $null -eq $System.CommitLimitBytes -or
        $null -eq $System.AvailablePhysicalBytes -or $null -eq $System.TotalPhysicalBytes -or
        [double]$System.CommitLimitBytes -le 0 -or [double]$System.TotalPhysicalBytes -le 0) {
        return [pscustomobject]$result
    }
    $committed = [double]$System.CommittedBytes
    $limit = [double]$System.CommitLimitBytes
    $available = [double]$System.AvailablePhysicalBytes
    $total = [double]$System.TotalPhysicalBytes
    if ($committed -lt 0 -or $available -lt 0 -or $available -gt $total) { return [pscustomobject]$result }
    $commitRatio = $committed / $limit
    $ramRatio = $available / $total
    $result.CommitRatio = [math]::Round($commitRatio,3)
    $result.AvailableRamRatio = [math]::Round($ramRatio,3)
    $result.CommitHeadroomBytes = [long][math]::Max([double]0.0,([double]$limit-[double]$committed))
    if ($commitRatio -ge 0.90 -or $ramRatio -le 0.05) { $result.State='High' }
    elseif ($commitRatio -ge 0.80 -or $ramRatio -le 0.10) { $result.State='Elevated' }
    else { $result.State='Normal' }
    $result.Explanation = ('Commit {0:P1}，可用 RAM {1:P1}；仅表示系统压力，不代表存在可清理的垃圾内存。' -f $commitRatio,$ramRatio)

    if ($null -ne $System.NonpagedPoolBytes -and [double]$System.NonpagedPoolBytes -ge 0) {
        $list = $Analyzer.PoolHistory
        if ($list.Count -eq 0 -or $NowUtc -gt $list[$list.Count-1].Utc) {
            $list.Add([pscustomobject]@{Utc=$NowUtc;Bytes=[long]$System.NonpagedPoolBytes})
        }
        Limit-MiAnalysisHistory -Analyzer $Analyzer -Samples $list -NowUtc $NowUtc
        if ($list.Count -gt 1 -and ($NowUtc-$list[0].Utc).TotalMinutes -ge 20) {
            $poolDelta = [long]$System.NonpagedPoolBytes - [long]$list[0].Bytes
            $result.NonpagedPoolTrend = $(if ($poolDelta -ge 128MB) {'Rising'} else {'NotRising'})
        }
    }
    return [pscustomobject]$result
}

function Invoke-MiDiagnosis {
    param($Analyzer,$Snapshot)
    if ($null -ne $Snapshot.IntervalSeconds) {
        $interval=0
        if (-not [int]::TryParse([string]$Snapshot.IntervalSeconds,[ref]$interval) -or $interval -lt 5 -or $interval -gt 60) {
            return [pscustomobject]@{
                Status='InvalidCadence';Reports=@();Pressure=[pscustomobject]@{State='Unknown'}
                Error='采样周期无效，未使用该样本进行诊断。'
            }
        }
        Set-MiAnalyzerInterval -Analyzer $Analyzer -IntervalSeconds $interval
    }
    $utc = ([datetime]$Snapshot.CaptureEndUtc).ToUniversalTime()
    $sequence=$Snapshot.Sequence
    $monotonic=$Snapshot.MonotonicSeconds
    # 序号倒序属于迟到/重复消息，不应把旧消息误认为新时钟、清空有效窗口。
    if ($null -ne $sequence -and $null -ne $Analyzer.LastSequence -and $sequence -le $Analyzer.LastSequence) {
        return [pscustomobject]@{Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'};Error='忽略重复或倒序的采样序号。'}
    }
    $rollback=$false
    if ($Analyzer.LastCaptureUtc -ne [datetime]::MinValue) {
        $wallDelta=($utc-$Analyzer.LastCaptureUtc).TotalSeconds
        $rollback=($wallDelta -lt 0)
        if ($null -ne $monotonic -and $null -ne $Analyzer.LastMonotonicSeconds) {
            $elapsed=[double]$monotonic-[double]$Analyzer.LastMonotonicSeconds
            # 即使 UTC 仍在增加，也能发现采样期间被向后校正的明显时间差。
            $rollback=$rollback -or $elapsed -lt 0 -or
                ($wallDelta-$elapsed) -lt -[math]::Max(1,$Analyzer.IntervalSeconds/2.0)
        }
        if ($rollback) {
            $Analyzer.Tracks.Clear();$Analyzer.PoolHistory.Clear()
            $Analyzer.AttributionHistory.Clear()
            $Analyzer.LastCaptureUtc=[datetime]::MinValue
            $Analyzer.ContinuityId=[guid]::NewGuid().ToString('N')
            $Analyzer.ContinuityReason='检测到采样时间回拨，已重新建立分析窗口。'
            $Analyzer.WindowResetCount++
            # 历史基线的刷新节流也不能被旧的未来 UTC 时间永久阻塞。
            $Analyzer.HistoricalLoadedUtc=[datetime]::MinValue
        } elseif ($wallDelta -eq 0) {
            return [pscustomobject]@{Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'};Error='忽略重复采样时间。'}
        }
    }
    $Analyzer.LastSequence=$sequence
    $Analyzer.LastMonotonicSeconds=$monotonic
    $Snapshot | Add-Member -NotePropertyName ContinuityId -NotePropertyValue $Analyzer.ContinuityId -Force
    $Snapshot | Add-Member -NotePropertyName TimeDiscontinuity -NotePropertyValue $rollback -Force
    if ($rollback) {
        # 本轮只标记断点，下一轮从新的 UTC/单调时间锚点重新收集。
        return [pscustomobject]@{Status='Stale';Reports=@();Pressure=[pscustomobject]@{State='Unknown'};Error=$Analyzer.ContinuityReason}
    }
    $Analyzer.LastCaptureUtc=$utc
    Add-MiTrackSample -Analyzer $Analyzer -Snapshot $Snapshot
    $pressure = Get-MiMemoryPressure -Analyzer $Analyzer -System $Snapshot.System -NowUtc $utc
    $reports = New-Object 'System.Collections.Generic.List[object]'
    $top = @()
    if ($Snapshot.Processes.Status -ne 'Failed') {
        $top = @($Snapshot.Processes.Items | Where-Object {$null -ne $_.PrivateBytes} |
            Sort-Object -Property PrivateBytes -Descending | Select-Object -First 60)
    }
    $totals = @{}
    foreach ($p in @($Snapshot.Processes.Items)) {
        if ($null -eq $p.PrivateBytes -or [string]::IsNullOrWhiteSpace([string]$p.Name)) { continue }
        if (-not $totals.ContainsKey([string]$p.Name)) { $totals[[string]$p.Name]=[double]0 }
        $totals[[string]$p.Name] += [double]$p.PrivateBytes
    }
    foreach($p in $top) {
        $report = Get-MiProcessAnomaly -Analyzer $Analyzer -Process $p -NowUtc $utc
        if ($Analyzer.Historical.ContainsKey([string]$p.Name)) {
            $historical=$Analyzer.Historical[[string]$p.Name]
            $report.HistoricalProgramMedianBytes = $historical.MedianProgramPrivateBytes
            $report.HistoricalScope = 'ProgramNameAggregate'
            if ($historical.MedianProgramPrivateBytes -gt 0 -and $totals.ContainsKey([string]$p.Name)) {
                $report.HistoricalDeviationPercent = [math]::Round(
                    (($totals[[string]$p.Name] / $historical.MedianProgramPrivateBytes)-1.0)*100.0,1)
            }
        }
        $reports.Add($report)
    }
    return [pscustomobject]@{
        Status='Success'
        Reports=$reports.ToArray()
        Pressure=$pressure
        Attribution=(Get-MiSystemAttribution -Analyzer $Analyzer -Snapshot $Snapshot -NowUtc $utc)
        Error=$null
    }
}

function Get-MiAttributionBytes {
    param($Value)
    # 保留 null 与 0 的区别；拒绝负数、NaN、字符串小数及溢出，旧历史缺字段不能变成零。
    $number=0L
    if ($null -eq $Value -or $Value -is [bool] -or
        -not [long]::TryParse($Value.ToString(),[ref]$number) -or $number -lt 0) { return $null }
    return $number
}

function New-MiAttributionFinding {
    param($Analyzer,[string]$Category,[string]$MetricName,$Current,$Samples,[datetime]$NowUtc,
        [string]$ProcessInstanceId,[string]$SourceType='Counter',[string[]]$Limitations=@())
    $window=[MemoryInspector.AttributionWindow]::Measure($Samples,$NowUtc,$Analyzer.IntervalSeconds)
    $quality='Partial'
    if ($null -eq $Current) { $quality='Unavailable' }
    elseif ($window.MissingSampleCount -eq 0 -and $window.SufficientTrend) { $quality='Complete' }
    $limits=New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $Limitations) { $limits.Add($item) }
    if ($quality -ne 'Complete') { $limits.Add('观察窗口不完整；不插值、不补零，不将缺失样本视为有效证据。') }
    if ($Analyzer.ContinuityReason) { $limits.Add($Analyzer.ContinuityReason) }
    return [pscustomobject]@{
        SchemaVersion=1;FindingId=[guid]::NewGuid().ToString('N');Category=$Category
        TimeRangeUtc=[pscustomobject]@{StartUtc=$window.StartUtc;EndUtc=$window.EndUtc}
        MetricName=$MetricName;ObservedBytes=$Current
        GrowthBytes=$(if ($null -ne $Current) {$window.GrowthBytes} else {$null})
        SourceType=$SourceType;ProcessInstanceId=$ProcessInstanceId;TraceSessionId=$null
        MeasurementQuality=$quality
        AttributionConfidence=$(if ($null -ne $Current) {'DirectlyObserved'} else {'Unresolved'})
        EventLossStatus='NotApplicable';Limitations=$limits.ToArray()
        SuggestedNextStep='继续观察完整窗口；增长本身不能证明泄漏。'
        SamplingQuality=$window;TargetIntervalSeconds=$Analyzer.IntervalSeconds
        RequestedTimeRangeUtc=[pscustomobject]@{StartUtc=$NowUtc.AddMinutes(-30);EndUtc=$NowUtc}
        Trend='InsufficientEvidence'
    }
}

function Get-MiProcessGroups {
    param([object[]]$Processes,[string]$BootId,
        [ValidateSet('Instance','Executable','Parent','Logical')][string]$Mode='Executable',
        [string[]]$SelectedInstanceIds=@(),[string]$CollectionStatus='Success')
    # 诊断分组没有动作能力。路径只是本轮可执行文件路径口径，不是签名或文件哈希授权。
    $groups=@{};$seen=@{};$byKey=@{}
    foreach ($p in $Processes) {
        $key=Get-MiInstanceKey -BootId $BootId -Process $p
        if ($key) { $byKey[$key]=$p }
    }
    foreach ($p in $Processes) {
        $instance=Get-MiInstanceKey -BootId $BootId -Process $p
        if (-not $instance -or $seen.ContainsKey($instance)) { continue }
        $seen[$instance]=$true;$id=$instance;$label=('{0} · PID {1}' -f $p.Name,$p.PID)
        if ($Mode -eq 'Logical') {
            if ($instance -notin $SelectedInstanceIds) {continue}
            $id='UserSelection';$label='用户选定的精确进程实例'
        } elseif ($Mode -eq 'Executable') {
            if (-not [string]::IsNullOrWhiteSpace([string]$p.ExecutablePath)) {
                $id=([string]$p.ExecutablePath).ToUpperInvariant();$label=[string]$p.ExecutablePath
            } else { $label+='（路径未知，单独保留）' }
        } elseif ($Mode -eq 'Parent') {
            # 只合并当前可核验的根及后代；父进程已退出或 PID 被复用时不猜测旧关系。
            $ancestor=$p;$visited=@{$instance=$true}
            while ($null -ne $ancestor.ParentPid -and $null -ne $ancestor.ParentStartUtcTicks) {
                $parentKey='{0}:{1}:{2}' -f $BootId,$ancestor.ParentPid,$ancestor.ParentStartUtcTicks
                if (-not $byKey.ContainsKey($parentKey) -or $visited.ContainsKey($parentKey) -or
                    $ancestor.ParentStartUtcTicks -gt $ancestor.StartUtcTicks) {break}
                $visited[$parentKey]=$true;$ancestor=$byKey[$parentKey];$id=$parentKey
                $label=('{0} · 根 PID {1}' -f $ancestor.Name,$ancestor.PID)
            }
        }
        if (-not $groups.ContainsKey($id)) {
            $groups[$id]=[pscustomobject]@{SchemaVersion=1;GroupId=$id;GroupingKind=$Mode;Label=$label
                ProcessInstanceIds=(New-Object 'System.Collections.Generic.List[string]')
                ObservedPrivateBytes=[decimal]0;ValidMemberCount=0;MemberCount=0
                MeasurementQuality='Complete';AttributionConfidence='Correlated'
                Scope='当前采样中可验证实例的 Private Bytes 之和；不含共享内存，不等于 RAM 或可释放量。'
                Limitations='进程枚举非原子；路径/父子关系仅用于诊断，缺失身份不参与分组。'}
        }
        $g=$groups[$id];$g.MemberCount++;$g.ProcessInstanceIds.Add($instance)
        if (($Mode -eq 'Executable' -and [string]::IsNullOrWhiteSpace([string]$p.ExecutablePath)) -or
            ($Mode -eq 'Parent' -and $null -eq $p.ParentStartUtcTicks -and $p.ParentPid -ne 0)) {
            $g.MeasurementQuality='Partial'
        }
        $bytes=Get-MiAttributionBytes $p.PrivateBytes
        if ($null -ne $bytes) { $g.ObservedPrivateBytes+=[decimal]$bytes;$g.ValidMemberCount++ }
    }
    foreach ($g in $groups.Values) {
        if ($g.ValidMemberCount -eq 0 -or $g.ObservedPrivateBytes -gt [long]::MaxValue) {
            $g.ObservedPrivateBytes=$null;$g.MeasurementQuality='Unavailable'
        } else {
            $g.ObservedPrivateBytes=[long]$g.ObservedPrivateBytes
            if ($g.ValidMemberCount -ne $g.MemberCount -or $CollectionStatus -ne 'Success' -or
                ($Mode -eq 'Logical' -and $g.MemberCount -ne @($SelectedInstanceIds | Select-Object -Unique).Count)) {
                $g.MeasurementQuality='Partial'
            }
        }
        $g.ProcessInstanceIds=$g.ProcessInstanceIds.ToArray()
        $g
    }
}

function Get-MiSystemAttribution {
    param($Analyzer,$Snapshot,[datetime]$NowUtc)
    $findings=New-Object 'System.Collections.Generic.List[object]'
    $system=$Snapshot.System
    $values=[ordered]@{}
    foreach ($metric in @('CommittedBytes','CommitLimitBytes','PagedPoolBytes','NonpagedPoolBytes')) {
        $values[$metric]=$(if ($system.Status -ne 'Failed') {Get-MiAttributionBytes $system.$metric} else {$null})
    }
    $values['CommitHeadroomBytes']=$null
    if ($null -ne $values.CommittedBytes -and $null -ne $values.CommitLimitBytes -and
        $values.CommitLimitBytes -gt 0 -and $values.CommitLimitBytes -ge $values.CommittedBytes) {
        $values.CommitHeadroomBytes=$values.CommitLimitBytes-$values.CommittedBytes
    }
    $sum=[decimal]0;$valid=0;$unknown=0
    $processRows=@();$processFindings=New-Object 'System.Collections.Generic.List[object]';$identities=@{}
    if ($Snapshot.Processes.Status -ne 'Failed') {$processRows=@($Snapshot.Processes.Items)}
    foreach ($p in $processRows) {
        $bytes=Get-MiAttributionBytes $p.PrivateBytes
        $key=Get-MiInstanceKey -BootId $Analyzer.BootId -Process $p
        if ($key -and $identities.ContainsKey($key)) {$unknown++;continue}
        if ($key) {$identities[$key]=$true}
        if ($null -ne $bytes) {$sum+=[decimal]$bytes;$valid++}
        if (-not $key) {$unknown++;continue}
        $samples=$null
        if ($Analyzer.Tracks.ContainsKey($key)) {$samples=$Analyzer.Tracks[$key].Samples}
        $f=New-MiAttributionFinding $Analyzer ProcessPrivate PrivateBytes $bytes $samples $NowUtc -ProcessInstanceId $key -SourceType Snapshot
        $f | Add-Member -NotePropertyName Label -NotePropertyValue ('{0} · PID {1}' -f $p.Name,$p.PID)
        $processFindings.Add($f)
    }
    $values['ProcessPrivateBytes']=$null
    if ($valid -gt 0 -and $sum -le [long]::MaxValue) {$values.ProcessPrivateBytes=[long]$sum}
    $collectionComplete=$Snapshot.Processes.Status -eq 'Success' -and $valid -eq $processRows.Count -and $unknown -eq 0 -and $valid -gt 0
    foreach ($metric in $values.Keys) {
        if (-not $Analyzer.AttributionHistory.ContainsKey($metric)) {
            $Analyzer.AttributionHistory[$metric]=New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]'
        }
        $history=$Analyzer.AttributionHistory[$metric];$current=$values[$metric]
        # 全进程汇总缺成员时不写入完整趋势，避免退出/权限缺失造成假增长或假释放。
        if ($null -ne $current -and ($metric -ne 'ProcessPrivateBytes' -or $collectionComplete) -and
            ($history.Count -eq 0 -or $NowUtc -gt $history[$history.Count-1].Utc)) {
            $history.Add([MemoryInspector.AnalysisPoint]::new($NowUtc,$current))
        }
        Limit-MiAnalysisHistory $Analyzer $history $NowUtc
        $category='SystemCommit'
        if ($metric -like '*PoolBytes') {$category='KernelPool'}
        if ($metric -eq 'ProcessPrivateBytes') {$category='ProcessAggregate'}
        $source='Counter';if ($metric -eq 'ProcessPrivateBytes') {$source='Snapshot'}
        $f=New-MiAttributionFinding $Analyzer $category $metric $current $history $NowUtc -SourceType $source
        if ($metric -eq 'ProcessPrivateBytes' -and -not $collectionComplete) {
            $f.MeasurementQuality=$(if ($null -eq $current) {'Unavailable'} else {'Partial'})
            $f.GrowthBytes=$null;$f.Limitations+=('仅 {0}/{1} 个可读 Private Bytes；身份未知 {2} 个，枚举状态 {3}。' -f $valid,$processRows.Count,$unknown,$Snapshot.Processes.Status)
        }
        if ($category -eq 'KernelPool') {
            $f.Limitations+='Pool 计数器不能归属到具体驱动或 Pool Tag，也不能证明泄漏。'
            if ($null -ne $current -and $f.SamplingQuality.SufficientTrend) {
                $f.Trend=$(if ($f.GrowthBytes -ge 128MB -and $f.SamplingQuality.UpwardSegments -ge 4) {'SustainedGrowth'} else {'NoSustainedGrowth'})
            }
        }
        $findings.Add($f)
    }
    # 差额仅是两个不同统计口径的残差，绝不把 Pool/Working Set 再加进去凑成 Commit。
    $residualValue=$null
    if ($null -ne $values.CommittedBytes -and $null -ne $values.ProcessPrivateBytes) {
        $residualValue=$values.CommittedBytes-$values.ProcessPrivateBytes
    }
    if (-not $Analyzer.AttributionHistory.ContainsKey('Residual')) {
        $Analyzer.AttributionHistory['Residual']=New-Object 'System.Collections.Generic.List[MemoryInspector.AnalysisPoint]'
    }
    $residualHistory=$Analyzer.AttributionHistory['Residual']
    if ($null -ne $residualValue -and $collectionComplete -and
        ($residualHistory.Count -eq 0 -or $NowUtc -gt $residualHistory[$residualHistory.Count-1].Utc)) {
        $residualHistory.Add([MemoryInspector.AnalysisPoint]::new($NowUtc,$residualValue))
    }
    Limit-MiAnalysisHistory $Analyzer $residualHistory $NowUtc
    $residual=New-MiAttributionFinding $Analyzer UnresolvedCommit CommitMinusObservedPrivateBytes $residualValue $residualHistory $NowUtc -SourceType Snapshot
    $residual.AttributionConfidence='Unresolved'
    if ($null -ne $values.CommittedBytes -and $null -ne $values.ProcessPrivateBytes) {
        $residual.ObservedBytes=$values.CommittedBytes-$values.ProcessPrivateBytes
        $residual.MeasurementQuality='Partial';$residual.TimeRangeUtc=[pscustomobject]@{StartUtc=$NowUtc;EndUtc=$NowUtc}
    }
    if (-not $collectionComplete) {$residual.GrowthBytes=$null}
    elseif ($null -ne $residual.SamplingQuality.StartUtc) {
        $residual.TimeRangeUtc=[pscustomobject]@{StartUtc=$residual.SamplingQuality.StartUtc;EndUtc=$residual.SamplingQuality.EndUtc}
    }
    $residual.Limitations=@('系统 Commit 减去可读进程 Private Bytes；采集不同步且可能缺进程，差额可为负。','包含尚未归属的系统提交及统计差异，不代表泄漏；Pool 与进程指标不能保证完整分解 Commit。')
    $residual.SuggestedNextStep='结合进程及 Pool 趋势继续调查；高级 ETW 诊断尚未开放。'
    $findings.Add($residual)
    $ram=[ordered]@{SchemaVersion=1}
    foreach ($metric in @('TotalPhysicalBytes','AvailablePhysicalBytes','CacheBytes','StandbyBytes','CompressionBytes')) {
        $ram[$metric]=$(if ($system.Status -ne 'Failed') {Get-MiAttributionBytes $system.$metric} else {$null})
    }
    $ram['Limitations']='RAM 与 Commit 独立；Working Set 仅显示单进程，禁止求和作为物理占用。Cache/Standby 可能重叠；压缩量不可用时保持 null。'
    return [pscustomobject]@{
        SchemaVersion=1;CapturedUtc=$NowUtc;BootId=$Analyzer.BootId;Status='Success'
        Findings=$findings.ToArray();ProcessFindings=$processFindings.ToArray();Ram=[pscustomobject]$ram
        ProcessGroups=@(Get-MiProcessGroups $processRows $Analyzer.BootId -Mode Executable -CollectionStatus $Snapshot.Processes.Status)
        ParentGroups=@(Get-MiProcessGroups $processRows $Analyzer.BootId -Mode Parent -CollectionStatus $Snapshot.Processes.Status)
        UnassociatedProcessCount=$unknown;CollectionStatus=$Snapshot.Processes.Status
    }
}
