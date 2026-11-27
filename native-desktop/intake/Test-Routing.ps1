[CmdletBinding()]
param([switch]$Json)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Routing-Policy.psm1') -Force
$suite=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'test-cases.json') -Raw -Encoding UTF8|ConvertFrom-Json
$results=@()
foreach($case in $suite.cases){
    $facts=@{};foreach($p in $suite.base.PSObject.Properties){$facts[$p.Name]=$p.Value};foreach($p in $case.set.PSObject.Properties){$facts[$p.Name]=$p.Value}
    $report=Get-HongAiDeviceRoute -Facts $facts
    if($report.state -cne $case.state){throw ('STATE_MISMATCH: '+$case.name)}
    $ids=@($report.findings|ForEach-Object {$_.id})
    if($case.PSObject.Properties.Name -contains 'has'){foreach($id in $case.has){if($ids -cnotcontains $id){throw ('MISSING_RULE: '+$case.name+':'+$id)}}}
    if($case.PSObject.Properties.Name -contains 'lacks'){foreach($id in $case.lacks){if($ids -ccontains $id){throw ('UNEXPECTED_RULE: '+$case.name+':'+$id)}}}
    foreach($key in @('fullDesktopAccepted','networkAccepted','automaticApplyAllowed','hostNetworkSettingsChanged','loginStateChanged','networkRequestsMade','remoteProcessPresenceProvesConnection')){if($report.$key -cne $false){throw ('UNSAFE_REPORT: '+$key)}}
    $results+=[pscustomobject]@{name=$case.name;report=$report}
}
if($Json){ConvertTo-Json -InputObject @($results) -Depth 10}else{'PASS '+$results.Count+' routing fixtures; no mutation or false acceptance'}
