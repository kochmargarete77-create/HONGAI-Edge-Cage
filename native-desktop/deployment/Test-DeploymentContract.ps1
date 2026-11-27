param([switch]$Json)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Deployment-Contract.psm1') -Force
$suite=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'test-cases.json') -Raw -Encoding UTF8|ConvertFrom-Json
$output=@()
foreach($case in $suite.cases){
    $request=$suite.request|ConvertTo-Json -Depth 5|ConvertFrom-Json;$report=$suite.report|ConvertTo-Json -Depth 5|ConvertFrom-Json;$handoff=$suite.handoff|ConvertTo-Json -Depth 5|ConvertFrom-Json
    foreach($name in @('request','report','handoff')){if($case.PSObject.Properties.Name -contains $name){$obj=Get-Variable $name -ValueOnly;foreach($p in $case.$name.PSObject.Properties){$obj|Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force}}}
    $when=[datetimeoffset]::UtcNow;switch($handoff.generatedAt){'TEST_OLD'{$when=$when.AddHours(-1)}'TEST_FUTURE'{$when=$when.AddHours(1)}};$handoff.generatedAt=$when.ToString('o')
    $actual='OK'
    try{$r=Test-HongAiDeploymentInputs $request $report $handoff;if($r.handoffRefreshRequired){$actual='OK_REFRESH'};if($r.networkAcceptedByThisCheck -or $r.fullDesktopAccepted){throw 'FALSE_ACCEPTANCE'}}catch{$actual=$_.Exception.Message}
    if($actual -cne $case.expected){throw ('CASE_FAILED '+$case.name+' expected='+$case.expected+' actual='+$actual)}
    $output+=[pscustomobject]@{name=$case.name;result=$actual}
}
if($Json){ConvertTo-Json -InputObject $output -Depth 5}else{'PASS '+$output.Count+' deployment contract cases'}
