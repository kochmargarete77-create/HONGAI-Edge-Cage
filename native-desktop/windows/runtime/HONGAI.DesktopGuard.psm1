Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
Import-Module (Join-Path $PSScriptRoot 'Managed-Claude-Policy.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Native-Boundary-Bridge.psm1') -Force

function Test-HongAiPublicIpv4 {
    param([Parameter(Mandatory)][string]$Address)

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $parsed.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and ($b[1] -eq 0 -or $b[1] -eq 168)) { return $false }
    if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19 -or $b[1] -eq 51)) { return $false }
    if ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113) { return $false }
    return $true
}

function Assert-HongAiExactKeys {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    if ($null -eq $Object -or $Object -isnot [psobject]) { throw "${Label}_INVALID_OBJECT" }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if ($actual.Count -ne $wanted.Count) { throw "${Label}_FIELDS_INVALID" }
    for ($i = 0; $i -lt $wanted.Count; $i++) {
        if ($actual[$i] -cne $wanted[$i]) { throw "${Label}_FIELDS_INVALID" }
    }
}

function Read-HongAiClashHandoff {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow,
        [timespan]$MaximumAge = ([timespan]::FromMinutes(10))
    )

    if (-not [System.IO.Path]::IsPathRooted($Path) -or $Path.IndexOfAny([char[]]'*?') -ge 0) {
        throw 'HANDOFF_PATH_NOT_EXACT_ABSOLUTE'
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'HANDOFF_PATH_NOT_REGULAR_FILE'
    }
    if ($item.Length -lt 2 -or $item.Length -gt 16384) { throw 'HANDOFF_SIZE_INVALID' }

    try {
        $raw = Get-Content -LiteralPath $item.FullName -Raw -Encoding UTF8
        if ($raw -notmatch '"generatedAt"\s*:\s*"([^"]+)"') { throw 'missing generatedAt' }
        $generatedText = [string]$matches[1]
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch { throw 'HANDOFF_JSON_INVALID' }

    Assert-HongAiExactKeys -Object $data -Expected @('version','tool','loopback','expectedEgressIp','routeId','generatedAt') -Label 'HANDOFF'
    Assert-HongAiExactKeys -Object $data.loopback -Expected @('protocol','host','mixedPort') -Label 'HANDOFF_LOOPBACK'

    if ([int]$data.version -ne 1 -or [string]$data.tool -cne 'clash') { throw 'HANDOFF_VERSION_OR_TOOL_INVALID' }
    if ([string]$data.loopback.protocol -cne 'http' -or [string]$data.loopback.host -cne '127.0.0.1') {
        throw 'HANDOFF_PROXY_NOT_LOOPBACK_HTTP'
    }
    $port = [int]$data.loopback.mixedPort
    if ($port -lt 1024 -or $port -gt 65535) { throw 'HANDOFF_PORT_INVALID' }
    $exitIp = [string]$data.expectedEgressIp
    if (-not (Test-HongAiPublicIpv4 -Address $exitIp)) { throw 'HANDOFF_EGRESS_IP_INVALID' }
    if ([string]$data.routeId -cnotmatch '^[a-f0-9]{24}$') { throw 'HANDOFF_ROUTE_ID_INVALID' }

    $generated = [datetimeoffset]::MinValue
    $dateStyles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetimeoffset]::TryParse($generatedText, [Globalization.CultureInfo]::InvariantCulture, $dateStyles, [ref]$generated)) {
        throw 'HANDOFF_GENERATED_AT_INVALID'
    }
    if ($generated.Offset -ne [timespan]::Zero -or -not $generatedText.EndsWith('Z')) { throw 'HANDOFF_GENERATED_AT_NOT_UTC' }
    if ($generated -gt $Now.AddSeconds(30)) { throw 'HANDOFF_FROM_FUTURE' }
    if (($Now - $generated) -gt $MaximumAge) { throw 'HANDOFF_EXPIRED' }

    [pscustomobject]@{
        HandoffPath = $item.FullName
        ProxyUri = "http://127.0.0.1:$port"
        ProxyPort = $port
        ExpectedEgressIp = $exitIp
        RouteId = [string]$data.routeId
        GeneratedAt = $generated
    }
}

function Get-HongAiOfficialClaudePackage {
    [CmdletBinding()]
    param()

    $package = Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue |
        Where-Object { $_.Publisher -match 'Anthropic, PBC' } |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $package) { throw 'OFFICIAL_CLAUDE_PACKAGE_NOT_FOUND' }
    if ([string]$package.PackageFullName -notmatch '^Claude_.+__pzs8sxrjxfjjc$') { throw 'OFFICIAL_CLAUDE_PACKAGE_ID_MISMATCH' }

    $root = [System.IO.Path]::GetFullPath([string]$package.InstallLocation)
    $exe = Join-Path $root 'app\Claude.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'OFFICIAL_CLAUDE_EXECUTABLE_NOT_FOUND' }
    $signature = Get-AuthenticodeSignature -LiteralPath $exe
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) { throw 'OFFICIAL_CLAUDE_SIGNATURE_INVALID' }
    if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'Anthropic, PBC') {
        throw 'OFFICIAL_CLAUDE_SIGNER_MISMATCH'
    }

    $nativeInventory=Get-HongAiNativeInventory -PackageRoot $root
    $physicalMain=@($nativeInventory|Where-Object { [IO.Path]::GetFileName($_.Path) -ieq 'Claude.exe' })
    if($physicalMain.Count -ne 1){throw 'OFFICIAL_MAIN_IDENTITY_AMBIGUOUS'}
    $physicalRoot=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($physicalMain[0].Path))
    [pscustomobject]@{
        PackageFullName = [string]$package.PackageFullName
        Version = [string]$package.Version
        Architecture = [string]$package.Architecture
        Publisher = [string]$package.Publisher
        InstallRoot = $root
        PhysicalInstallRoot = $physicalRoot
        NativeExecutableCount = $nativeInventory.Count
        Executable = $exe
        Signer = $signature.SignerCertificate.Subject
        SignatureStatus = [string]$signature.Status
    }
}

function Test-HongAiLoopbackListener {
    param([Parameter(Mandatory)][int]$Port, [int]$TimeoutMilliseconds = 1500)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $task.Wait($TimeoutMilliseconds)) { return $false }
        return $client.Connected
    } catch { return $false }
    finally { $client.Dispose() }
}

function Get-HongAiObservedExit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProxyUri,
        [int]$TimeoutSeconds = 8,
        [string]$ProbeUri = 'https://api.ipify.org/?format=json'
    )

    if ($ProxyUri -cnotmatch '^http://127\.0\.0\.1:([0-9]{4,5})$') { throw 'PROBE_PROXY_NOT_LOOPBACK_HTTP' }
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $client = $null
    try {
        $handler.UseProxy = $true
        $handler.Proxy = [System.Net.WebProxy]::new($ProxyUri, $true)
        $client = [System.Net.Http.HttpClient]::new($handler, $true)
        $client.Timeout = [timespan]::FromSeconds($TimeoutSeconds)
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('HONGAI-Desktop-Guard-Pilot/0.1')
        $raw = $client.GetStringAsync($ProbeUri).GetAwaiter().GetResult()
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        $ip = [string]$parsed.ip
        if (-not (Test-HongAiPublicIpv4 -Address $ip)) { throw 'PROBE_EGRESS_IP_INVALID' }
        return $ip
    } catch {
        throw 'PROBE_FAILED'
    } finally {
        if ($null -ne $client) { $client.Dispose() }
    }
}

function Test-HongAiClashRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Handoff,
        [int]$Passes = 3,
        [int]$DelayMilliseconds = 600
    )
    if ($Passes -lt 1 -or $Passes -gt 5) { throw 'ROUTE_PASS_COUNT_INVALID' }
    $observed = @()
    for ($i = 1; $i -le $Passes; $i++) {
        if (-not (Test-HongAiLoopbackListener -Port $Handoff.ProxyPort)) { throw 'ROUTE_LOOPBACK_LISTENER_UNAVAILABLE' }
        $ip = Get-HongAiObservedExit -ProxyUri $Handoff.ProxyUri
        if ($ip -cne $Handoff.ExpectedEgressIp) { throw 'ROUTE_EGRESS_MISMATCH' }
        $observed += $ip
        if ($i -lt $Passes) { Start-Sleep -Milliseconds $DelayMilliseconds }
    }
    [pscustomobject]@{ Passed = $true; Count = $observed.Count; EgressIp = $observed[-1]; RouteId = $Handoff.RouteId }
}

function Get-HongAiClaudeProcesses {
    param([Parameter(Mandatory)][string]$InstallRoot,[string]$PhysicalInstallRoot)
    $prefix = [System.IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') + '\'
    $physicalPrefix=if($PhysicalInstallRoot){[IO.Path]::GetFullPath($PhysicalInstallRoot).TrimEnd('\')+'\'}else{$prefix}
    @(Get-CimInstance Win32_Process -Filter "Name='Claude.exe'" -ErrorAction SilentlyContinue | Where-Object {
        $_.ExecutablePath -and ([System.IO.Path]::GetFullPath([string]$_.ExecutablePath).StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFullPath([string]$_.ExecutablePath).StartsWith($physicalPrefix,[StringComparison]::OrdinalIgnoreCase))
    })
}

function Initialize-HongAiKillJobType {
    if ('HongAi.KillOnCloseJob' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;

namespace HongAi {
  public static class KillOnCloseJob {
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
      public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
      public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attrs, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct STARTUPINFO {
      public uint Size; public string Reserved,Desktop,Title; public uint X,Y,Width,Height,CountX,CountY,Fill,Flags;
      public ushort Show,ReservedSize; public IntPtr ReservedBytes,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {public IntPtr Process,Thread;public uint ProcessId,ThreadId;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUPINFO startup,out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
    public static IntPtr Create() {
      IntPtr job=CreateJobObject(IntPtr.Zero, null); if(job==IntPtr.Zero) throw new Win32Exception();
      var info=new JOBOBJECT_EXTENDED_LIMIT_INFORMATION(); info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      int size=Marshal.SizeOf(info); IntPtr ptr=Marshal.AllocHGlobal(size);
      try { Marshal.StructureToPtr(info,ptr,false); if(!SetInformationJobObject(job,9,ptr,(uint)size)) throw new Win32Exception(); }
      catch { CloseHandle(job); throw; } finally { Marshal.FreeHGlobal(ptr); }
      return job;
    }
    public static void Assign(IntPtr job, IntPtr process) { if(!AssignProcessToJobObject(job,process)) throw new Win32Exception(); }
    public static void Close(IntPtr job) { if(job!=IntPtr.Zero) CloseHandle(job); }
    public static Process StartSuspended(IntPtr job,string executable,string arguments,string directory) {
      if(job==IntPtr.Zero||executable.IndexOf('"')>=0)throw new ArgumentException("EXACT_JOB_AND_EXECUTABLE_REQUIRED");
      STARTUPINFO startup=new STARTUPINFO();startup.Size=(uint)Marshal.SizeOf(typeof(STARTUPINFO));PROCESS_INFORMATION child;
      if(!CreateProcess(executable,new StringBuilder("\""+executable+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,directory,ref startup,out child))throw new Win32Exception();
      try { if(!AssignProcessToJobObject(job,child.Process))throw new Win32Exception();if(ResumeThread(child.Thread)==UInt32.MaxValue)throw new Win32Exception();return Process.GetProcessById((int)child.ProcessId); }
      catch {TerminateProcess(child.Process,125);throw;}
      finally{CloseHandle(child.Thread);CloseHandle(child.Process);}
    }
  }
}
'@
}

function Get-HongAiDesktopLaunchPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Package, [Parameter(Mandatory)]$Handoff)
    $arguments = @(
        "--proxy-server=$($Handoff.ProxyUri)",
        '--proxy-bypass-list=<-loopback>',
        '--disable-quic'
    )
    [pscustomobject]@{
        Mode = 'DESKTOP_GUARD_PILOT'
        Executable = $Package.Executable
        Arguments = $arguments
        ProxyUri = $Handoff.ProxyUri
        ExpectedEgressIp = $Handoff.ExpectedEgressIp
        RouteId = $Handoff.RouteId
        GlobalNetworkChanges = 0
        FirewallRulesCreated = 0
        NativeRulesPlanned = $Package.NativeExecutableCount * 4
        KernelBoundaryRequired = $true
        LoginAttempted = $false
        SystemLevelIsolationAccepted = $false
    }
}

function Start-HongAiDesktopGuard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HandoffPath,
        [switch]$DryRun,
        [int]$MonitorIntervalSeconds = 4
    )

    $package = Get-HongAiOfficialClaudePackage
    $handoff = Read-HongAiClashHandoff -Path $HandoffPath
    $plan = Get-HongAiDesktopLaunchPlan -Package $package -Handoff $handoff
    Test-HongAiPolicyAvailability
    if (@(Get-HongAiClaudeProcesses -InstallRoot $package.InstallRoot -PhysicalInstallRoot $package.PhysicalInstallRoot).Count -gt 0) { throw 'CLAUDE_ALREADY_RUNNING_CLOSE_IT_FIRST' }
    $cowork = Get-Service -Name 'CoworkVMService' -ErrorAction SilentlyContinue
    if ($null -ne $cowork -and $cowork.Status -eq 'Running') { throw 'COWORK_SERVICE_RUNNING_NOT_ISOLATED_BY_PILOT' }
    if ($DryRun) {
        $null = Test-HongAiClashRoute -Handoff $handoff -Passes 3
        return $plan
    }

    $null = Test-HongAiClashRoute -Handoff $handoff -Passes 3

    Initialize-HongAiKillJobType
    $job = [HongAi.KillOnCloseJob]::Create()
    $old = @{}
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')) { $old[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $process = $null
    $policyApplied = $false
    $nativeApplied = $false
    $broker = $null
    try {
        if(-not ('HongAi.SessionProxy' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'resources\HONGAI-SessionProxy.dll')}
        $broker=[HongAi.SessionProxy]::new($handoff.ProxyPort,30000)
        $sessionUri="http://127.0.0.1:$($broker.Port)"
        $null=Invoke-HongAiNativeBoundary -Operation Install -ProxyPort $broker.Port
        $nativeApplied=$true
        Invoke-HongAiPilotPolicy -Operation Enable -ProxyUri $sessionUri
        $policyApplied = $true
        # UAC interaction can outlive the short network lease. Recheck before admission.
        $null=Test-HongAiClashRoute -Handoff $handoff -Passes 1 -DelayMilliseconds 0
        $broker.Refresh(16000)
        [Environment]::SetEnvironmentVariable('HTTP_PROXY', $sessionUri, 'Process')
        [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $sessionUri, 'Process')
        [Environment]::SetEnvironmentVariable('ALL_PROXY', $sessionUri, 'Process')
        [Environment]::SetEnvironmentVariable('NO_PROXY', '', 'Process')
        $arguments="--proxy-server=$sessionUri --proxy-bypass-list=<-loopback> --disable-quic"
        $process=[HongAi.KillOnCloseJob]::StartSuspended($job,$package.Executable,$arguments,$PSScriptRoot)
    } catch {
        if($null -ne $broker){$broker.Dispose()}
        [HongAi.KillOnCloseJob]::Close($job)
        if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        if ($policyApplied) { Invoke-HongAiPilotPolicy -Operation Restore }
        if ($nativeApplied) { $null=Invoke-HongAiNativeBoundary -Operation Rollback }
        throw
    } finally {
        foreach ($name in $old.Keys) { [Environment]::SetEnvironmentVariable($name, $old[$name], 'Process') }
    }

    try {
        while (-not $process.HasExited) {
            Start-Sleep -Seconds $MonitorIntervalSeconds
            $cowork = Get-Service -Name 'CoworkVMService' -ErrorAction SilentlyContinue
            if ($null -ne $cowork -and $cowork.Status -eq 'Running') { throw 'COWORK_SERVICE_STARTED_NOT_ISOLATED_BY_PILOT' }
            $registered=Get-AppxPackage -Name Claude -ErrorAction Stop|Select-Object -First 1
            if($null -eq $registered -or $registered.PackageFullName -cne $package.PackageFullName){throw 'OFFICIAL_PACKAGE_CHANGED_REVALIDATION_REQUIRED'}
            # The ten-minute limit is an admission rule. A valid running session must not expire after ten minutes.
            $current = Read-HongAiClashHandoff -Path $HandoffPath -MaximumAge ([timespan]::MaxValue)
            if ($current.RouteId -cne $handoff.RouteId -or $current.ExpectedEgressIp -cne $handoff.ExpectedEgressIp -or $current.ProxyUri -cne $handoff.ProxyUri) {
                throw 'ROUTE_IDENTITY_CHANGED'
            }
            $null = Test-HongAiClashRoute -Handoff $handoff -Passes 1 -DelayMilliseconds 0
            $broker.Refresh(16000)
        }
    } finally {
        if($null -ne $broker){$broker.Dispose()}
        [HongAi.KillOnCloseJob]::Close($job)
        if ($null -ne $process) { $null=$process.WaitForExit(5000) }
        if ($policyApplied) { Invoke-HongAiPilotPolicy -Operation Restore }
        if ($nativeApplied) { $null=Invoke-HongAiNativeBoundary -Operation Rollback }
    }
}

Export-ModuleMember -Function @(
    'Test-HongAiPublicIpv4','Read-HongAiClashHandoff','Get-HongAiOfficialClaudePackage',
    'Test-HongAiLoopbackListener','Get-HongAiObservedExit','Test-HongAiClashRoute',
    'Get-HongAiClaudeProcesses','Get-HongAiDesktopLaunchPlan','Start-HongAiDesktopGuard'
)
