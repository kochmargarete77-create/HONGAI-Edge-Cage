[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateRange(1, 1800)][int]$DurationSeconds = 300,
    [ValidateRange(1, 1800)][int]$IntervalSeconds = 10,
    [switch]$FunctionsOnly
)

# Loading this file with dot-source or -FunctionsOnly never starts collection.
# No command below elevates, changes network/account settings or sends traffic.

function Get-HongaiObservationRole {
    param([string]$Name)
    if ($Name -match '^(?i:claude(?:[-_].*)?)$') { return 'claude' }
    if ($Name -match '^(?i:cowork(?:[-_].*)?)$') { return 'cowork' }
    if ($Name -match '^(?i:clash(?:x(?: pro)?|[-_].*)?)$') { return 'clash' }
    if ($Name -match '^(?i:mihomo(?:[-_].*)?|verge[-_]mihomo)$') { return 'mihomo' }
    if ($Name -match '^(?i:todesk(?:[-_].*)?)$') { return 'todesk' }
    return $null
}

function Get-HongaiObservationAddressCategory {
    param([string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return 'other' }
    if ($parsed.IsIPv4MappedToIPv6) { $parsed = $parsed.MapToIPv4() }
    if ([Net.IPAddress]::IsLoopback($parsed)) { return 'loopback' }
    $b = $parsed.GetAddressBytes()
    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return 'linklocal' }
        if ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { return 'private' }
        if ($b[0] -eq 0 -or $b[0] -ge 224 -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -in @(0, 2)) -or ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) -or ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) { return 'reserved_or_benchmark' }
        return 'public'
    }
    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($parsed.IsIPv6LinkLocal) { return 'linklocal' }
        if (($b[0] -band 0xfe) -eq 0xfc -or $parsed.IsIPv6SiteLocal) { return 'private' }
        if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0d -and $b[3] -eq 0xb8) { return 'reserved_or_benchmark' }
        if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0 -and (($b[3] -eq 2 -and $b[4] -eq 0 -and $b[5] -eq 0) -or ($b[3] -ge 0x10 -and $b[3] -le 0x2f))) { return 'reserved_or_benchmark' }
        if (($b[0] -band 0xe0) -eq 0x20) { return 'public' }
    }
    return 'other'
}

function Get-HongaiObservationAddressFamily {
    param([string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return 'other' }
    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { return 'IPv4' }
    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { return 'IPv6' }
    return 'other'
}

function Get-HongaiObservationTcpState {
    param([string]$State)
    foreach ($known in @('Closed', 'Listen', 'SynSent', 'SynReceived', 'Established', 'FinWait1', 'FinWait2', 'CloseWait', 'Closing', 'LastAck', 'TimeWait', 'DeleteTCB', 'Bound')) {
        if ($known -ieq $State) { return $known }
    }
    return 'other'
}

function Get-HongaiObservationPortCategory {
    param($Port)
    $number = 0
    if ([int]::TryParse([string]$Port, [ref]$number)) {
        if ($number -eq 443) { return '443' }
        if ($number -eq 80) { return '80' }
    }
    return 'other'
}

function ConvertTo-HongaiObservationTcpAggregate {
    param([object[]]$Connections = @(), [int[]]$TargetProcessIds = @())
    $targets = @{}
    foreach ($identifier in $TargetProcessIds) { $targets[[string]$identifier] = $true }
    $groups = @{}
    $total = 0
    foreach ($connection in $Connections) {
        if (-not $targets.ContainsKey([string]$connection.OwningProcess)) { continue }
        $state = Get-HongaiObservationTcpState ([string]$connection.State)
        $family = Get-HongaiObservationAddressFamily ([string]$connection.RemoteAddress)
        $port = Get-HongaiObservationPortCategory $connection.RemotePort
        $category = Get-HongaiObservationAddressCategory ([string]$connection.RemoteAddress)
        $key = $state + '|' + $family + '|' + $port + '|' + $category
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [ordered]@{ state = $state; ipVersion = $family; remotePortClass = $port; remoteAddressClass = $category; count = 0 }
        }
        $groups[$key].count++
        $total++
    }
    $rows = @($groups.Keys | Sort-Object | ForEach-Object { [pscustomobject]$groups[$_] })
    return [pscustomobject]@{ status = $(if ($total -eq 0) { 'EMPTY' } else { 'OBSERVED' }); code = 'CLASSIFIED_EXISTING_TCP_ONLY'; scope = 'CLAUDE_ROLE_EXISTING_TCP_ONLY'; connectionsCount = $total; categories = $rows }
}

function ConvertTo-HongaiObservationProcessAggregate {
    param([object[]]$Snapshot = @(), [hashtable]$PreviousCpu = @{})
    $rows = [ordered]@{}
    foreach ($role in @('claude', 'cowork', 'mihomo', 'clash', 'todesk')) {
        $selected = @($Snapshot | Where-Object { $_.Role -ceq $role })
        $cpuObserved = 0; $cpuBaselines = 0; $memoryObserved = 0
        $cpuDelta = [double]0; $memoryTotal = [decimal]0
        foreach ($item in $selected) {
            if ($item.CpuObserved -and $null -ne $item.CpuSeconds) {
                $cpu = [double]$item.CpuSeconds
                if (-not [double]::IsNaN($cpu) -and -not [double]::IsInfinity($cpu) -and $cpu -ge 0) {
                    $cpuObserved++
                    $key = [string]$item.CpuIdentity
                    if ($key -and $PreviousCpu.ContainsKey($key) -and $cpu -ge [double]$PreviousCpu[$key]) {
                        $cpuBaselines++; $cpuDelta += $cpu - [double]$PreviousCpu[$key]
                    }
                }
            }
            if ($item.MemoryObserved -and $null -ne $item.WorkingSetBytes -and [decimal]$item.WorkingSetBytes -ge 0) {
                $memoryObserved++; $memoryTotal += [decimal]$item.WorkingSetBytes
            }
        }
        $cpuStatus = 'OBSERVED'; $cpuCode = 'ROLE_CPU_DELTA_OBSERVED'; $delta = [Math]::Round($cpuDelta, 3)
        if ($selected.Count -eq 0) { $cpuStatus = 'EMPTY'; $cpuCode = 'NO_ROLE_PROCESS' }
        elseif ($cpuBaselines -eq 0) { $cpuStatus = 'NOT_OBSERVED'; $cpuCode = 'CPU_BASELINE_OR_ACCESS_UNAVAILABLE'; $delta = $null }
        elseif ($cpuBaselines -lt $selected.Count) { $cpuStatus = 'PARTIAL'; $cpuCode = 'CPU_BASELINE_OR_ACCESS_PARTIAL' }
        $memoryStatus = 'OBSERVED'; $workingSet = $memoryTotal
        if ($selected.Count -eq 0) { $memoryStatus = 'EMPTY' }
        elseif ($memoryObserved -eq 0) { $memoryStatus = 'NOT_OBSERVED'; $workingSet = $null }
        elseif ($memoryObserved -lt $selected.Count) { $memoryStatus = 'PARTIAL' }
        if ($memoryTotal -gt [long]::MaxValue) { $memoryStatus = 'NOT_OBSERVED'; $workingSet = $null }
        elseif ($null -ne $workingSet) { $workingSet = [long]$workingSet }
        $rows[$role] = [pscustomobject]@{
            processCount = $selected.Count
            cpuDeltaSeconds = $delta; cpuStatus = $cpuStatus; cpuCode = $cpuCode
            cpuReadableProcesses = $cpuObserved; cpuBaselineProcesses = $cpuBaselines
            workingSetBytesTotal = $workingSet; memoryStatus = $memoryStatus; memoryReadableProcesses = $memoryObserved
        }
    }
    return $rows
}

function Get-HongaiObservationOutputPath {
    param([string]$Directory)
    if ([string]::IsNullOrWhiteSpace($Directory) -or $Directory -notmatch '^[DEde]:[\\/]') { throw 'OBS_EXPLICIT_D_OR_E_OUTPUT_REQUIRED' }
    if ($Directory.IndexOf([char]0) -ge 0 -or $Directory -match '[\r\n]') { throw 'OBS_OUTPUT_PATH_INVALID' }
    try { $full = [IO.Path]::GetFullPath($Directory).TrimEnd('\', '/') } catch { throw 'OBS_OUTPUT_PATH_INVALID' }
    if ($full -match '^[DEde]:$' -or [IO.Path]::GetFileName($full).Length -lt 4) { throw 'OBS_DEDICATED_NONROOT_OUTPUT_REQUIRED' }
    return $full
}

function Initialize-HongaiObservationOutputRoot {
    param([string]$Directory)
    $full = Get-HongaiObservationOutputPath $Directory
    try {
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable) -or -not $drive.IsReady) { throw 'OBS_OUTPUT_MUST_BE_LOCAL_READY_DRIVE' }
        $cursor = $full
        while ($cursor) {
            if ([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) {
                $entry = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
                if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'OBS_OUTPUT_LINK_OR_FILE_REJECTED' }
            }
            $parent = [IO.Path]::GetDirectoryName($cursor)
            if ($parent -eq $cursor) { break }; $cursor = $parent
        }
        [void][IO.Directory]::CreateDirectory($full)
    } catch {
        if ($_.Exception.Message -match '^OBS_[A-Z0-9_]+$') { throw $_.Exception.Message }
        throw 'OBS_OUTPUT_ROOT_UNAVAILABLE'
    }
    return $full
}

function Write-HongaiObservationLine {
    param([IO.Stream]$Stream, $Record, [long]$MaximumBytes = 5242880)
    $json = ConvertTo-Json -InputObject $Record -Depth 14 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    if ($bytes.Length -gt 65536 -or $Stream.Length + $bytes.Length -gt $MaximumBytes) { return $false }
    $Stream.Write($bytes, 0, $bytes.Length); $Stream.Flush()
    return $true
}

function New-HongaiObservationRecord {
    param(
        [Parameter(Mandatory)][ValidateSet('header', 'sample', 'footer')][string]$RecordType,
        [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{32}$')][string]$SessionId,
        [Parameter(Mandatory)][string]$UtcISO,
        [Parameter(Mandatory)][Collections.IDictionary]$Fields
    )
    # Explicit supplied time only: this constructor is also used by pure
    # contract fixtures and never reads the host clock or other host state.
    $parsed = [DateTimeOffset]::MinValue
    if ($UtcISO -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$' -or -not [DateTimeOffset]::TryParse($UtcISO, [ref]$parsed)) { throw 'OBS_RECORD_EXPLICIT_UTC_REQUIRED' }
    $type = $RecordType.ToLowerInvariant()
    $allowed = @{
        header = @('source', 'synthetic', 'os', 'collector', 'limits')
        sample = @('sampleIndex', 'elapsedSeconds', 'processes', 'tcp')
        footer = @('elapsedSeconds', 'samplesWritten', 'completionCode', 'containsRawIdentifiersOrPayloads')
    }
    $record = [ordered]@{ schema = 'hongai.passive-observation.v1'; recordType = $type; sessionId = $SessionId.ToLowerInvariant(); utcISO = $parsed.UtcDateTime.ToString('o') }
    foreach ($key in $Fields.Keys) {
        if ($key -notin $allowed[$type]) { throw 'OBS_RECORD_FIELDS_INVALID' }
        $record[$key] = $Fields[$key]
    }
    return [pscustomobject]$record
}

function Invoke-HongaiReadOnlyObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [ValidateRange(1, 1800)][int]$DurationSeconds = 300,
        [ValidateRange(1, 1800)][int]$IntervalSeconds = 10
    )
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'OBS_WINDOWS_ONLY' }
    $root = Initialize-HongaiObservationOutputRoot $OutputDirectory
    $sessionId = [guid]::NewGuid().ToString('N')
    $relative = 'session-' + $sessionId
    $session = Join-Path $root $relative
    if (Test-Path -LiteralPath $session) { throw 'OBS_NEW_SESSION_COLLISION_NO_OVERWRITE' }
    [void][IO.Directory]::CreateDirectory($session)
    $report = Join-Path $session 'observation.ndjson'
    try { $stream = [IO.File]::Open($report, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read) }
    catch { throw 'OBS_NEW_REPORT_CREATE_FAILED' }
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $previousCpu = @{}; $samples = 0; $completion = 'COLLECTOR_INTERRUPTED'
    $os = [ordered]@{ status = 'NOT_OBSERVED'; platform = 'windows'; versionStatus = 'NOT_OBSERVED'; versionCode = 'OS_VERSION_API_UNAVAILABLE'; productVersion = $null; kernelRelease = $null; architectureStatus = 'NOT_OBSERVED'; architectureCode = 'OS_ARCHITECTURE_API_UNAVAILABLE'; architecture = $null; source = 'RUNTIME_API_NO_RELEASE_NAME_ASSERTION' }
    try {
        $version = [Environment]::OSVersion.Version.ToString()
        if ($version -match '^\d{1,5}(\.\d{1,5}){1,3}$') { $os.versionStatus = 'OBSERVED'; $os.versionCode = 'RUNTIME_NUMERIC_VERSION_OBSERVED'; $os.kernelRelease = $version }
    } catch { }
    try {
        $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        if ($architecture -in @('X86', 'X64', 'Arm', 'Arm64')) { $os.architectureStatus = 'OBSERVED'; $os.architectureCode = 'OS_ARCHITECTURE_OBSERVED'; $os.architecture = $architecture }
    } catch { }
    if ($os.versionStatus -eq 'OBSERVED' -and $os.architectureStatus -eq 'OBSERVED') { $os.status = 'OBSERVED' }
    elseif ($os.versionStatus -eq 'OBSERVED' -or $os.architectureStatus -eq 'OBSERVED') { $os.status = 'PARTIAL' }
    $names = @('Claude', 'Claude-Desktop', 'cowork', 'cowork-svc', 'clash', 'clash-verge', 'clash-meta', 'ClashX', 'ClashX Pro', 'mihomo', 'verge-mihomo', 'ToDesk', 'ToDesk_Service', 'ToDesk_Lite', 'ToDesk_Desktop', 'ToDesk_Service_64')
    $tcpAvailable = $null -ne (Get-Command -Name Get-NetTCPConnection -CommandType Function, Cmdlet -ErrorAction SilentlyContinue)
    try {
        $header = New-HongaiObservationRecord -RecordType header -SessionId $sessionId -UtcISO ([DateTime]::UtcNow.ToString('o')) -Fields ([ordered]@{
            source = 'READ_ONLY_LOCAL_COMMAND'; synthetic = $false; os = $os
            collector = @{ platform = 'windows'; version = '0.1.0'; mode = 'PASSIVE_READ_ONLY'; roleClassification = 'NAME_HINT_NOT_SIGNATURE_VERIFICATION'; externalRequests = $false; hostNetworkModified = $false; accountRead = $false; packetPayloadCaptured = $false; elevationRequested = $false; tcpCapability = $(if ($tcpAvailable) { 'AVAILABLE_SUBJECT_TO_PERMISSION' } else { 'NOT_OBSERVED' }); cpuScope = 'DELTA_FOR_MATCHING_PROCESS_INSTANCE_IDENTITY'; samplingClock = 'MONOTONIC_STOPWATCH'; providerWallTimeGuarantee = 'OS_CALLS_MAY_DELAY_RETURN_NO_FORCED_PROCESS_TERMINATION' }
            limits = @{ durationSeconds = $DurationSeconds; intervalSeconds = $IntervalSeconds; maxSamples = 180; maxOutputBytes = 5242880; maximumDurationSeconds = 1800 }
        })
        if (-not (Write-HongaiObservationLine -Stream $stream -Record $header)) { throw 'OBS_HEADER_OUTPUT_LIMIT' }
        while ($samples -lt 180 -and $stopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) {
            $snapshot = [Collections.Generic.List[object]]::new()
            $seen = @{}; $discoveryCode = 'TARGET_PROCESS_ENUMERATION_OBSERVED'; $discoveryStatus = 'OBSERVED'; $successfulEnumerations = 0
            foreach ($name in $names) {
                try { $processes = [Diagnostics.Process]::GetProcessesByName($name); $successfulEnumerations++ }
                catch { $discoveryStatus = 'PARTIAL'; $discoveryCode = 'PROCESS_ENUMERATION_PERMISSION_OR_API_UNAVAILABLE'; continue }
                foreach ($process in $processes) {
                    try {
                        if ($snapshot.Count -ge 1000) { $discoveryStatus = 'PARTIAL'; $discoveryCode = 'PROCESS_SAMPLE_LIMIT'; continue }
                        $identifier = $process.Id
                        if ($seen.ContainsKey([string]$identifier)) { continue }
                        $seen[[string]$identifier] = $true
                        $role = Get-HongaiObservationRole $process.ProcessName
                        if (-not $role) { continue }
                        $cpu = $null; $memory = $null; $cpuObserved = $false; $memoryObserved = $false; $cpuIdentity = $null
                        try { $cpuIdentity = [string]$identifier + '|' + [string]$process.StartTime.ToUniversalTime().Ticks; $cpu = $process.TotalProcessorTime.TotalSeconds; $cpuObserved = $true } catch { }
                        try { $memory = $process.WorkingSet64; $memoryObserved = $true } catch { }
                        $snapshot.Add([pscustomobject]@{ Role = $role; ProcessId = $identifier; CpuIdentity = $cpuIdentity; CpuSeconds = $cpu; WorkingSetBytes = $memory; CpuObserved = $cpuObserved; MemoryObserved = $memoryObserved })
                    } catch { $discoveryStatus = 'PARTIAL'; $discoveryCode = 'PROCESS_EXITED_OR_ACCESS_UNAVAILABLE' }
                    finally { $process.Dispose() }
                }
            }
            $publicProcesses = ConvertTo-HongaiObservationProcessAggregate -Snapshot $snapshot.ToArray() -PreviousCpu $previousCpu
            if ($successfulEnumerations -eq 0) {
                $discoveryStatus = 'NOT_OBSERVED'; $discoveryCode = 'PROCESS_ENUMERATION_UNAVAILABLE'
                foreach ($role in $publicProcesses.Keys) {
                    $publicProcesses[$role].processCount = $null
                    $publicProcesses[$role].cpuStatus = 'NOT_OBSERVED'; $publicProcesses[$role].cpuDeltaSeconds = $null
                    $publicProcesses[$role].cpuCode = 'PROCESS_ENUMERATION_UNAVAILABLE'
                    $publicProcesses[$role].memoryStatus = 'NOT_OBSERVED'; $publicProcesses[$role].workingSetBytesTotal = $null
                }
            }
            if ($snapshot.Count -eq 0 -and $discoveryStatus -eq 'OBSERVED') { $discoveryStatus = 'EMPTY' }
            $previousCpu = @{}
            foreach ($item in $snapshot) { if ($item.CpuObserved -and $item.CpuIdentity -and $null -ne $item.CpuSeconds) { $previousCpu[[string]$item.CpuIdentity] = $item.CpuSeconds } }
            $claudeIds = @($snapshot | Where-Object Role -ceq 'claude' | ForEach-Object { [int]$_.ProcessId })
            $snapshot.Clear()
            $tcp = [pscustomobject]@{ status = 'NOT_OBSERVED'; scope = 'CLAUDE_ROLE_EXISTING_TCP_ONLY'; code = 'TCP_CMDLET_UNAVAILABLE'; connectionsCount = $null; categories = @() }
            if ($claudeIds.Count -eq 0) {
                $tcp = [pscustomobject]@{ status = 'NOT_OBSERVED'; scope = 'CLAUDE_ROLE_EXISTING_TCP_ONLY'; code = 'NO_OBSERVED_CLAUDE_PROCESS'; connectionsCount = $null; categories = @() }
            } elseif ($tcpAvailable) {
                try {
                    # Existing kernel connection table only. No connect, DNS
                    # lookup, packet capture, payload or external probe occurs.
                    $connections = @(Get-NetTCPConnection -OwningProcess ([uint32[]]$claudeIds) -ErrorAction Stop | Select-Object -First 20000)
                    $tcp = ConvertTo-HongaiObservationTcpAggregate -Connections $connections -TargetProcessIds $claudeIds
                    if ($connections.Count -ge 20000) { $tcp.status = 'PARTIAL'; $tcp.code = 'TCP_CONNECTION_SAMPLE_LIMIT' }
                } catch {
                    if ([string]$_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') {
                        $tcp = [pscustomobject]@{ status = 'EMPTY'; scope = 'CLAUDE_ROLE_EXISTING_TCP_ONLY'; code = 'NO_MATCHING_EXISTING_TCP'; connectionsCount = 0; categories = @() }
                    } else {
                        $code = 'TCP_PERMISSION_OR_API_UNAVAILABLE'
                        if ([string]$_.CategoryInfo.Category -eq 'PermissionDenied') { $code = 'TCP_PERMISSION_DENIED' }
                        $tcp = [pscustomobject]@{ status = 'NOT_OBSERVED'; scope = 'CLAUDE_ROLE_EXISTING_TCP_ONLY'; code = $code; connectionsCount = $null; categories = @() }
                    }
                } finally { $connections = $null }
            }
            $claudeIds = @()
            if ($stopwatch.Elapsed.TotalSeconds -ge $DurationSeconds) { $completion = 'DURATION_COMPLETE'; break }
            $record = New-HongaiObservationRecord -RecordType sample -SessionId $sessionId -UtcISO ([DateTime]::UtcNow.ToString('o')) -Fields ([ordered]@{
                sampleIndex = $samples + 1; elapsedSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                processes = @{ status = $discoveryStatus; code = $discoveryCode; scope = 'FIXED_NAMES_ONLY_NO_COMMAND_LINE_OR_PATH'; roles = $publicProcesses }
                tcp = $tcp
            })
            # Reserve space for a fixed completion record; discard a sample
            # rather than crossing the output cap or deleting any old file.
            if (-not (Write-HongaiObservationLine -Stream $stream -Record $record -MaximumBytes (5242880 - 2048))) { $completion = 'OUTPUT_LIMIT_REACHED'; break }
            $samples++
            if ($samples -ge 180) { $completion = 'SAMPLE_LIMIT_REACHED'; break }
            $remaining = $DurationSeconds - $stopwatch.Elapsed.TotalSeconds
            if ($remaining -le 0) { $completion = 'DURATION_COMPLETE'; break }
            $nextTarget = [double]($samples * $IntervalSeconds)
            $untilNext = [Math]::Max(0, $nextTarget - $stopwatch.Elapsed.TotalSeconds)
            Start-Sleep -Milliseconds ([Math]::Max(1, [int](1000 * [Math]::Min($untilNext, $remaining))))
        }
        if ($completion -eq 'COLLECTOR_INTERRUPTED') { $completion = 'DURATION_COMPLETE' }
    } catch { $completion = 'COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR' }
    finally {
        try {
            $footer = New-HongaiObservationRecord -RecordType footer -SessionId $sessionId -UtcISO ([DateTime]::UtcNow.ToString('o')) -Fields @{ elapsedSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3); samplesWritten = $samples; completionCode = $completion; containsRawIdentifiersOrPayloads = $false }
            [void](Write-HongaiObservationLine -Stream $stream -Record $footer)
        } finally { $stopwatch.Stop(); $stream.Dispose() }
    }
    return [pscustomobject]@{ status = 'LOCAL_REPORT_CREATED'; sessionId = $sessionId; relativeDirectory = $relative; fileName = 'observation.ndjson'; samplesWritten = $samples; completionCode = $completion; containsRawIdentifiersOrPayloads = $false }
}

function Get-HongaiObservationSyntheticContractFixture {
    # The same constructor and aggregate functions as production, supplied with
    # fixed metadata only. No clock/process/OS/TCP/filesystem query occurs.
    $session = '0123456789abcdef0123456789abcdef'
    $firstProcesses = @(
        [pscustomobject]@{ Role = 'claude'; ProcessId = 900001; CpuIdentity = 'SYNTHETIC_CLAUDE_A'; CpuSeconds = 2.0; WorkingSetBytes = 536870912; CpuObserved = $true; MemoryObserved = $true },
        [pscustomobject]@{ Role = 'mihomo'; ProcessId = 900010; CpuIdentity = 'SYNTHETIC_MIHOMO_A'; CpuSeconds = 0.5; WorkingSetBytes = 67108864; CpuObserved = $true; MemoryObserved = $true },
        [pscustomobject]@{ Role = 'clash'; ProcessId = 900020; CpuIdentity = 'SYNTHETIC_CLASH_A'; CpuSeconds = 0.25; WorkingSetBytes = 33554432; CpuObserved = $true; MemoryObserved = $true },
        [pscustomobject]@{ Role = 'todesk'; ProcessId = 900030; CpuIdentity = 'SYNTHETIC_TODESK_A'; CpuSeconds = 0.1; WorkingSetBytes = 33554432; CpuObserved = $true; MemoryObserved = $true }
    )
    $secondProcesses = @(
        [pscustomobject]@{ Role = 'claude'; ProcessId = 900001; CpuIdentity = 'SYNTHETIC_CLAUDE_A'; CpuSeconds = 3.25; WorkingSetBytes = 603979776; CpuObserved = $true; MemoryObserved = $true },
        [pscustomobject]@{ Role = 'mihomo'; ProcessId = 900010; CpuIdentity = 'SYNTHETIC_MIHOMO_A'; CpuSeconds = 1.0; WorkingSetBytes = 67108864; CpuObserved = $true; MemoryObserved = $true },
        [pscustomobject]@{ Role = 'clash'; ProcessId = 900020; CpuIdentity = 'SYNTHETIC_CLASH_A'; CpuSeconds = 0.5; WorkingSetBytes = 33554432; CpuObserved = $true; MemoryObserved = $true },
        [pscustomobject]@{ Role = 'todesk'; ProcessId = 900030; CpuIdentity = 'SYNTHETIC_TODESK_A'; CpuSeconds = 0.25; WorkingSetBytes = 33554432; CpuObserved = $true; MemoryObserved = $true }
    )
    $prior = @{}
    foreach ($item in $firstProcesses) { $prior[$item.CpuIdentity] = $item.CpuSeconds }
    $connections = @(
        [pscustomobject]@{ OwningProcess = 900001; State = 'Established'; RemoteAddress = '203.0.113.11'; RemotePort = 443 },
        [pscustomobject]@{ OwningProcess = 900001; State = 'Established'; RemoteAddress = '10.0.0.9'; RemotePort = 443 },
        [pscustomobject]@{ OwningProcess = 900001; State = 'Established'; RemoteAddress = '127.0.0.1'; RemotePort = 7890 }
    )
    $header = New-HongaiObservationRecord -RecordType header -SessionId $session -UtcISO '2026-11-27T00:00:00Z' -Fields ([ordered]@{
        source = 'SYNTHETIC_FIXED_FIXTURE'; synthetic = $true
        os = @{ status = 'OBSERVED'; platform = 'windows'; productVersion = $null; kernelRelease = '10.0.00000.0'; architecture = 'X64'; source = 'SYNTHETIC_FIXED_FIXTURE' }
        collector = @{ platform = 'windows'; version = '0.1.0'; mode = 'PASSIVE_READ_ONLY'; roleClassification = 'NAME_HINT_NOT_SIGNATURE_VERIFICATION'; cpuScope = 'DELTA_FOR_MATCHING_PROCESS_INSTANCE_IDENTITY'; samplingClock = 'SYNTHETIC_FIXED_ELAPSED'; externalRequests = $false; hostNetworkModified = $false; accountRead = $false; packetPayloadCaptured = $false; elevationRequested = $false }
        limits = @{ durationSeconds = 20; intervalSeconds = 10; maxSamples = 180; maxOutputBytes = 5242880 }
    })
    $first = New-HongaiObservationRecord -RecordType sample -SessionId $session -UtcISO '2026-11-27T00:00:00Z' -Fields ([ordered]@{
        sampleIndex = 1; elapsedSeconds = 0
        processes = @{ status = 'OBSERVED'; scope = 'FIXED_NAMES_ONLY_NO_COMMAND_LINE_OR_PATH'; code = 'SYNTHETIC_PROCESS_FIXTURE'; roles = (ConvertTo-HongaiObservationProcessAggregate -Snapshot $firstProcesses) }
        tcp = (ConvertTo-HongaiObservationTcpAggregate -Connections $connections -TargetProcessIds @(900001))
    })
    $second = New-HongaiObservationRecord -RecordType sample -SessionId $session -UtcISO '2026-11-27T00:00:10Z' -Fields ([ordered]@{
        sampleIndex = 2; elapsedSeconds = 10
        processes = @{ status = 'OBSERVED'; scope = 'FIXED_NAMES_ONLY_NO_COMMAND_LINE_OR_PATH'; code = 'SYNTHETIC_PROCESS_FIXTURE'; roles = (ConvertTo-HongaiObservationProcessAggregate -Snapshot $secondProcesses -PreviousCpu $prior) }
        tcp = @{ status = 'NOT_OBSERVED'; scope = 'CLAUDE_ROLE_EXISTING_TCP_ONLY'; code = 'TCP_PERMISSION_DENIED'; connectionsCount = $null; categories = @() }
    })
    $footer = New-HongaiObservationRecord -RecordType footer -SessionId $session -UtcISO '2026-11-27T00:00:20Z' -Fields @{ elapsedSeconds = 20; samplesWritten = 2; completionCode = 'DURATION_COMPLETE'; containsRawIdentifiersOrPayloads = $false }
    return @($header, $first, $second, $footer)
}

function Test-HongaiObservationHelpers {
    # Pure synthetic fixtures. Never calls Invoke, process enumeration, OS
    # collection, TCP cmdlets, path initialization or any filesystem writer.
    $checks = 0
    foreach ($fixture in @(@('8.8.8.8', 'public'), @('10.0.0.9', 'private'), @('127.0.0.1', 'loopback'), @('169.254.1.1', 'linklocal'), @('192.0.2.8', 'reserved_or_benchmark'), @('198.18.1.8', 'reserved_or_benchmark'), @('198.19.1.8', 'reserved_or_benchmark'), @('100.64.1.8', 'reserved_or_benchmark'), @('::1', 'loopback'), @('fc00::1', 'private'), @('fe80::1', 'linklocal'), @('2001:db8::7', 'reserved_or_benchmark'), @('::ffff:127.0.0.1', 'loopback'), @('::ffff:8.8.8.8', 'public'), @('not-a-host-lookup.invalid', 'other'))) {
        if ((Get-HongaiObservationAddressCategory $fixture[0]) -cne $fixture[1]) { throw 'OBS_FIXTURE_ADDRESS_CATEGORY_FAILED' }; $checks++
    }
    if ((Get-HongaiObservationRole 'verge-mihomo') -cne 'mihomo' -or (Get-HongaiObservationRole 'ToDesk_Service') -cne 'todesk' -or (Get-HongaiObservationRole 'ClashX Pro') -cne 'clash' -or (Get-HongaiObservationRole 'unrelated-app')) { throw 'OBS_FIXTURE_ROLES_FAILED' }; $checks++
    $processes = @([pscustomobject]@{ Role = 'claude'; ProcessId = 900001; CpuIdentity = 'SYNTHETIC_INSTANCE_A'; CpuSeconds = 4.5; WorkingSetBytes = 2000; CpuObserved = $true; MemoryObserved = $true }, [pscustomobject]@{ Role = 'claude'; ProcessId = 900002; CpuIdentity = $null; CpuSeconds = $null; WorkingSetBytes = $null; CpuObserved = $false; MemoryObserved = $false })
    $roles = ConvertTo-HongaiObservationProcessAggregate -Snapshot $processes -PreviousCpu @{ 'SYNTHETIC_INSTANCE_A' = 3.25 }
    $claude = $roles.claude
    if ($claude.processCount -ne 2 -or $claude.cpuDeltaSeconds -ne 1.25 -or $claude.cpuStatus -cne 'PARTIAL' -or $claude.memoryStatus -cne 'PARTIAL' -or $claude.workingSetBytesTotal -ne 2000) { throw 'OBS_FIXTURE_PROCESS_AGGREGATE_FAILED' }; $checks++
    $connections = @([pscustomobject]@{ OwningProcess = 900001; State = 'Established'; RemoteAddress = '8.8.8.8'; RemotePort = 443 }, [pscustomobject]@{ OwningProcess = 900001; State = 'Established'; RemoteAddress = '10.0.0.9'; RemotePort = 8443 }, [pscustomobject]@{ OwningProcess = 900002; State = 'Established'; RemoteAddress = 'private-fixture.invalid'; RemotePort = 80 })
    $tcp = ConvertTo-HongaiObservationTcpAggregate -Connections $connections -TargetProcessIds @(900001)
    if ($tcp.connectionsCount -ne 2 -or $tcp.categories.Count -ne 2 -or @($tcp.categories | Where-Object remotePortClass -ceq 'other').Count -ne 1) { throw 'OBS_FIXTURE_TCP_AGGREGATE_FAILED' }; $checks++
    $encoded = ConvertTo-Json @{ roles = $roles; tcp = $tcp } -Depth 12 -Compress
    foreach ($forbidden in @('900001', '900002', 'SYNTHETIC_INSTANCE_A', 'CpuIdentity', '8.8.8.8', '10.0.0.9', 'private-fixture.invalid', 'OwningProcess', 'ProcessId', 'RemoteAddress', 'CommandLine', 'UserName')) {
        if ($encoded.Contains($forbidden)) { throw 'OBS_FIXTURE_IDENTIFIER_EXPORTED' }; $checks++
    }
    $baseline = (ConvertTo-HongaiObservationProcessAggregate -Snapshot @($processes[0])).claude
    if ($baseline.cpuStatus -cne 'NOT_OBSERVED' -or $null -ne $baseline.cpuDeltaSeconds) { throw 'OBS_FIXTURE_MISSING_CPU_BASELINE_FAILED' }; $checks++
    $reused = ConvertTo-HongaiObservationProcessAggregate -Snapshot @($processes[0]) -PreviousCpu @{ 'SYNTHETIC_OLD_PROCESS_SAME_PID' = 3.25 }
    if ($reused.claude.cpuStatus -cne 'NOT_OBSERVED' -or $null -ne $reused.claude.cpuDeltaSeconds) { throw 'OBS_FIXTURE_PID_REUSE_BASELINE_FAILED' }; $checks++
    $emptyTcp = ConvertTo-HongaiObservationTcpAggregate -Connections @() -TargetProcessIds @(900001)
    if ($emptyTcp.status -cne 'EMPTY' -or $emptyTcp.connectionsCount -ne 0) { throw 'OBS_FIXTURE_EMPTY_TCP_FAILED' }; $checks++
    $memory = [IO.MemoryStream]::new()
    try {
        if (-not (Write-HongaiObservationLine -Stream $memory -Record @{ fixture = 'SYNTHETIC' } -MaximumBytes 128)) { throw 'OBS_FIXTURE_BOUNDED_WRITER_FAILED' }
        $before = $memory.Length
        if (Write-HongaiObservationLine -Stream $memory -Record @{ fixture = ('x' * 200) } -MaximumBytes 128) { throw 'OBS_FIXTURE_OUTPUT_LIMIT_FAILED' }
        if ($memory.Length -ne $before) { throw 'OBS_FIXTURE_OUTPUT_LIMIT_MUTATED_STREAM' }; $checks++
    } finally { $memory.Dispose() }
    $contract = @(Get-HongaiObservationSyntheticContractFixture)
    if ($contract.Count -ne 4 -or $contract[0].recordType -cne 'header' -or $contract[0].synthetic -ne $true -or $contract[0].source -cne 'SYNTHETIC_FIXED_FIXTURE' -or $contract[1].recordType -cne 'sample' -or $contract[2].processes.roles.claude.cpuDeltaSeconds -ne 1.25 -or $contract[2].tcp.status -cne 'NOT_OBSERVED' -or $contract[3].recordType -cne 'footer' -or $contract[3].samplesWritten -ne 2) { throw 'OBS_FIXTURE_RECORD_CONTRACT_FAILED' }; $checks++
    foreach ($entry in $contract) { if ($entry.schema -cne 'hongai.passive-observation.v1' -or $entry.sessionId -cne $contract[0].sessionId -or $entry.utcISO -notmatch 'Z$') { throw 'OBS_FIXTURE_RECORD_BASE_FIELDS_FAILED' }; $checks++ }
    $contractJson = ConvertTo-Json -InputObject $contract -Depth 14 -Compress
    foreach ($forbidden in @('900001', 'SYNTHETIC_CLAUDE_A', '203.0.113.11', '10.0.0.9', '127.0.0.1', 'ProcessId', 'RemoteAddress', 'CpuIdentity')) { if ($contractJson.Contains($forbidden)) { throw 'OBS_FIXTURE_CONTRACT_IDENTIFIER_EXPORTED' }; $checks++ }
    return [pscustomobject]@{ status = 'SYNTHETIC_HELPERS_PASS'; checks = $checks; hostObservationPerformed = $false; filesCreated = $false }
}

if ($FunctionsOnly -or $MyInvocation.InvocationName -eq '.') { return }
try {
    Invoke-HongaiReadOnlyObservation -OutputDirectory $OutputDirectory -DurationSeconds $DurationSeconds -IntervalSeconds $IntervalSeconds | ConvertTo-Json -Compress
} catch {
    $code = 'OBS_COLLECTOR_UNAVAILABLE'
    if ($_.Exception.Message -match '^OBS_[A-Z0-9_]+$') { $code = $_.Exception.Message }
    [pscustomobject]@{ status = 'FAILED'; code = $code; rawErrorsExported = $false } | ConvertTo-Json -Compress
    exit 1
}
