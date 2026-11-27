Set-StrictMode -Version Latest
function Get-HongAiDeviceRoute {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Facts,[string]$PolicyPath=(Join-Path $PSScriptRoot 'routing-policy.json'))
    $policy=Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8|ConvertFrom-Json
    if($policy.schema -cne 'hongai.device-routing-policy.v1'){throw 'UNSUPPORTED_POLICY_SCHEMA'}
    $findings=@()
    foreach($rule in $policy.rules){
        $match=$true
        foreach($condition in $rule.when){
            $value=$null;if($Facts.ContainsKey([string]$condition.field)){$value=$Facts[[string]$condition.field]}
            $known=$null -ne $value
            $test=$false
            switch([string]$condition.op){
                'missing' {$test=-not $known}
                'eq' {$test=$known -and (Test-HongAiExactValue $value $condition.value)}
                'in' {$test=$false;foreach($allowed in $condition.value){if($known -and (Test-HongAiExactValue $value $allowed)){$test=$true}}}
                'notIn' {$test=$true;foreach($allowed in $condition.value){if($known -and (Test-HongAiExactValue $value $allowed)){$test=$false}}}
                'lt' {$test=(Test-HongAiNumber $value) -and $value -lt $condition.value}
                'gte' {$test=(Test-HongAiNumber $value) -and $value -ge $condition.value}
                default {throw 'UNKNOWN_POLICY_OPERATOR'}
            }
            if(-not $test){$match=$false;break}
        }
        if($match){$findings+=[pscustomobject][ordered]@{id=$rule.id;severity=$rule.severity;next=$rule.next}}
    }
    $state='UNVERIFIED_CANDIDATE'
    if(@($findings|Where-Object severity -eq 'REVIEW').Count){$state='REVIEW_REQUIRED'}
    if(@($findings|Where-Object severity -eq 'PRODUCT_GAP').Count){$state='PRODUCT_REVIEW_REQUIRED'}
    if(@($findings|Where-Object severity -eq 'BLOCK').Count){$state='BLOCKED'}
    [pscustomobject][ordered]@{
        schema='hongai.device-intake.v1';policyRevision=$policy.revision;state=$state
        facts=[pscustomobject]$Facts;findings=@($findings)
        fullDesktopAccepted=$false;networkAccepted=$false;automaticApplyAllowed=$false
        hostNetworkSettingsChanged=$false;loginStateChanged=$false;networkRequestsMade=$false
        remoteProcessPresenceProvesConnection=$false;signatureAndRuntimeAcceptance='NOT_PERFORMED'
    }
}
function Test-HongAiNumber($Value){
    if($null -eq $Value){return $false}
    $numeric=$Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]
    return $numeric -and -not [double]::IsNaN([double]$Value) -and -not [double]::IsInfinity([double]$Value)
}
function Test-HongAiExactValue($Left,$Right){
    if($Left -is [bool] -or $Right -is [bool]){return $Left -is [bool] -and $Right -is [bool] -and $Left -eq $Right}
    if($Left -is [string] -or $Right -is [string]){return $Left -is [string] -and $Right -is [string] -and $Left -ceq $Right}
    return (Test-HongAiNumber $Left) -and (Test-HongAiNumber $Right) -and $Left -eq $Right
}
Export-ModuleMember -Function Get-HongAiDeviceRoute
