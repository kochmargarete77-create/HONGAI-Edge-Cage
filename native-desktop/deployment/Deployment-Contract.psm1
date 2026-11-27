Set-StrictMode -Version Latest
function Test-HongAiDeploymentInputs {
    param([Parameter(Mandatory)]$Request,[Parameter(Mandatory)]$Report,[Parameter(Mandatory)]$Handoff)
    $fields=@('schema','caseId','environmentReport','handoffFile','workspace')
    $names=@($Request.PSObject.Properties.Name)
    if($names.Count -ne $fields.Count -or @($names|Where-Object {$_ -cnotin $fields}).Count -or $Request.schema -cne 'hongai.agent-deployment-request.v1'){throw 'INVALID_REQUEST_SCHEMA_OR_UNEXPECTED_FIELD'}
    if($Request.caseId -isnot [string] -or $Request.caseId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$'){throw 'INVALID_CASE_ID'}
    foreach($field in @('environmentReport','handoffFile','workspace')){if($Request.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($Request.$field) -or $Request.$field -match '[\x00-\x1f"]'){throw 'INVALID_REQUEST_PATH'}}
    foreach($key in @('schema','case_id','phase','desktop_stage','readiness_score','ready_for_handoff','host_ready_for_stage2','login_attempted','source_evidence_complete','local_evidence_complete','failed_hard_gates')){if($Report.PSObject.Properties.Name -cnotcontains $key){throw 'ENVIRONMENT_REPORT_FIELDS_MISSING'}}
    if($Report.schema -cne 'HONGAI-READINESS-RESULT-2.1' -or $Report.case_id -cne $Request.caseId -or $Report.phase -cne 'FINAL' -or $Report.desktop_stage -cne 'PREDEPLOY'){throw 'NEED_MATCHING_FINAL_PREDEPLOY_REPORT'}
    if(($Report.readiness_score -isnot [int] -and $Report.readiness_score -isnot [long] -and $Report.readiness_score -isnot [double] -and $Report.readiness_score -isnot [decimal]) -or $Report.readiness_score -ne 100){throw 'ENVIRONMENT_SCORE_MUST_BE_NUMERIC_100'}
    foreach($field in @('ready_for_handoff','host_ready_for_stage2','source_evidence_complete','local_evidence_complete')){if($Report.$field -isnot [bool] -or $Report.$field -ne $true){throw 'ENVIRONMENT_EVIDENCE_NOT_ACCEPTED'}}
    if($Report.login_attempted -isnot [bool] -or $Report.login_attempted -ne $false -or $Report.failed_hard_gates -isnot [array] -or $Report.failed_hard_gates.Count){throw 'ENVIRONMENT_HARD_GATE_NOT_ACCEPTED'}
    $handoffNames=@($Handoff.PSObject.Properties.Name)
    if($handoffNames.Count -ne 6 -or @($handoffNames|Where-Object {$_ -cnotin @('version','tool','loopback','expectedEgressIp','routeId','generatedAt')}).Count){throw 'INVALID_HANDOFF_FIELDS_NO_SUBSCRIPTIONS_OR_SECRETS'}
    $loopNames=@($Handoff.loopback.PSObject.Properties.Name)
    if($loopNames.Count -ne 3 -or @($loopNames|Where-Object {$_ -cnotin @('protocol','host','mixedPort')}).Count){throw 'INVALID_LOOPBACK_FIELDS'}
    if($Handoff.version -isnot [int] -or $Handoff.version -ne 1 -or $Handoff.tool -cne 'clash' -or $Handoff.loopback.host -cne '127.0.0.1' -or $Handoff.loopback.protocol -cne 'http' -or $Handoff.loopback.mixedPort -isnot [int] -or $Handoff.loopback.mixedPort -lt 1024 -or $Handoff.loopback.mixedPort -gt 65535 -or $Handoff.routeId -isnot [string] -or $Handoff.routeId -cnotmatch '^[a-f0-9]{24}$'){throw 'INVALID_HANDOFF_VALUES'}
    $ip=[string]$Handoff.expectedEgressIp
    if($ip -cnotmatch '^\d{1,3}(\.\d{1,3}){3}$'){throw 'INVALID_PUBLIC_IPV4'}
    $o=@($ip.Split('.')|ForEach-Object {[int]$_})
    if(@($o|Where-Object {$_ -gt 255}).Count -or $o[0] -eq 0 -or $o[0] -ge 224 -or $o[0] -in @(10,127) -or ($o[0] -eq 169 -and $o[1] -eq 254) -or ($o[0] -eq 192 -and $o[1] -eq 168) -or ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) -or ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127)){throw 'INVALID_PUBLIC_IPV4'}
    $date=[datetimeoffset]::MinValue
    if(-not [datetimeoffset]::TryParse([string]$Handoff.generatedAt,[ref]$date) -or ($date-[datetimeoffset]::UtcNow).TotalSeconds -gt 30){throw 'INVALID_HANDOFF_TIME'}
    # The native runtime enforces ten-minute freshness at first import. A slow
    # installer may outlive it; return a refresh step instead of reinstalling.
    [pscustomobject]@{handoffRefreshRequired=([datetimeoffset]::UtcNow-$date).TotalSeconds -gt 600;networkAcceptedByThisCheck=$false;fullDesktopAccepted=$false}
}
Export-ModuleMember -Function Test-HongAiDeploymentInputs
