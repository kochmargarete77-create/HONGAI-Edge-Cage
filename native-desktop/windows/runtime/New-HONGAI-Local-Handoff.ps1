[CmdletBinding()]
param(
    [int]$MixedPort = 7897,
    [Parameter(Mandatory)][string]$ExpectedEgressIp,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'clash-handoff.json' }
Import-Module (Join-Path $root 'HONGAI.DesktopGuard.psm1') -Force

if (-not (Test-HongAiPublicIpv4 -Address $ExpectedEgressIp)) { throw 'EXPECTED_EGRESS_IP_INVALID' }
$proxyUri = "http://127.0.0.1:$MixedPort"
for ($i = 1; $i -le 3; $i++) {
    if (-not (Test-HongAiLoopbackListener -Port $MixedPort)) { throw 'LOOPBACK_PROXY_NOT_LISTENING' }
    $observed = Get-HongAiObservedExit -ProxyUri $proxyUri
    if ($observed -cne $ExpectedEgressIp) { throw "EGRESS_MISMATCH: expected=$ExpectedEgressIp observed=$observed" }
    if ($i -lt 3) { Start-Sleep -Milliseconds 600 }
}

$generatedAt = [datetimeoffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
$seed = "clash|127.0.0.1|$MixedPort|$ExpectedEgressIp|$generatedAt"
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($seed)) }
finally { $sha.Dispose() }
$routeId = (-join ($hash | ForEach-Object { $_.ToString('x2') })).Substring(0,24)

$handoff = [ordered]@{
    version = 1
    tool = 'clash'
    loopback = [ordered]@{ protocol = 'http'; host = '127.0.0.1'; mixedPort = $MixedPort }
    expectedEgressIp = $ExpectedEgressIp
    routeId = $routeId
    generatedAt = $generatedAt
}
$json = $handoff | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($OutputPath), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Write-Host "已生成十分钟有效的交接文件：$OutputPath" -ForegroundColor Green
Write-Host "最终出口：$ExpectedEgressIp；本地交接标识：$routeId（不代表已核验 Clash 内部链路）"
