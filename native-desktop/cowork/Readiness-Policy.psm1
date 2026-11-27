Set-StrictMode -Version Latest
function Get-HongAiCoworkReadiness {
    [CmdletBinding()]
    param([ValidateSet('Unknown','Cloud','LocalVM')][string]$Mode='Unknown',[Parameter(Mandatory)][hashtable]$Facts)
    $issues=[Collections.Generic.List[string]]::new()
    $state='MODE_CONFIRMATION_REQUIRED'
    if($Mode -eq 'Cloud'){
        $state='CLOUD_FEATURE_AND_ACCOUNT_VERIFICATION_REQUIRED'
    }elseif($Mode -eq 'LocalVM'){
        $state='READY_FOR_OFFICIAL_LOCAL_VM_CHECK'
        foreach($key in @('virtualMachinePlatformEnabled','hypervisorPresent','hnsPresent','vmcomputePresent','officialMsixPresent')){
            if(-not $Facts.ContainsKey($key) -or $null -eq $Facts[$key]){$issues.Add('UNKNOWN_'+$key)}elseif($Facts[$key] -ne $true){$issues.Add('MISSING_'+$key)}
        }
        if($issues.Count){$state='LOCAL_VM_PREREQUISITES_NOT_CONFIRMED'}
    }
    if($Facts.ContainsKey('freeMemoryGB') -and $null -ne $Facts.freeMemoryGB -and $Facts.freeMemoryGB -lt 1){$issues.Add('LOW_CURRENT_MEMORY_HEADROOM');$state='RESOURCE_HEADROOM_REVIEW_REQUIRED'}
    [pscustomobject][ordered]@{
        schema='hongai.cowork-readiness.v1';mode=$Mode;assessment=$state
        machineFacts=$Facts;issues=$issues.ToArray()
        coworkIsSeparateApplication=$false
        accountEntitlement='NOT_INSPECTED_CUSTOMER_CONFIRMS'
        officialReadinessCheckRequired=$true
        cageCoworkBoundaryAccepted=$false
        coworkEnabledByThisCheck=$false
        automaticInstallationAllowed=$false
        automaticRebootAllowed=$false
        hostNetworkSettingsChanged=$false
        cloudTaskOutboundUsesLocalProxy=$(if($Mode -eq 'Cloud'){$false}else{$null})
    }
}
Export-ModuleMember -Function Get-HongAiCoworkReadiness
