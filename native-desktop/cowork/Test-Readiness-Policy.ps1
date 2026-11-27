$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Readiness-Policy.psm1') -Force
$missing=@{virtualMachinePlatformEnabled=$false;hypervisorPresent=$false;hnsPresent=$false;vmcomputePresent=$false;officialMsixPresent=$false;freeMemoryGB=4}
$cloud=Get-HongAiCoworkReadiness -Mode Cloud -Facts $missing
if($cloud.assessment -ne 'CLOUD_FEATURE_AND_ACCOUNT_VERIFICATION_REQUIRED' -or $cloud.issues.Count -ne 0 -or $cloud.cloudTaskOutboundUsesLocalProxy){throw 'CLOUD_MODE_MUST_NOT_REQUIRE_LOCAL_VIRTUALIZATION_OR_CLAIM_LOCAL_EGRESS'}
$local=Get-HongAiCoworkReadiness -Mode LocalVM -Facts $missing
if($local.assessment -ne 'LOCAL_VM_PREREQUISITES_NOT_CONFIRMED' -or $local.issues.Count -ne 5){throw 'LOCAL_VM_REQUIREMENTS_MUST_BE_CHECKED'}
$unknown=Get-HongAiCoworkReadiness -Facts @{}
if($unknown.assessment -ne 'MODE_CONFIRMATION_REQUIRED'){throw 'UNKNOWN_MODE_MUST_NOT_TRIGGER_INSTALLATION'}
$low=Get-HongAiCoworkReadiness -Mode Cloud -Facts @{freeMemoryGB=0.4}
if($low.assessment -ne 'RESOURCE_HEADROOM_REVIEW_REQUIRED'){throw 'LOW_MEMORY_HEADROOM_MUST_BE_REPORTED'}
foreach($r in @($cloud,$local,$unknown,$low)){if($r.coworkEnabledByThisCheck -or $r.automaticInstallationAllowed -or $r.automaticRebootAllowed -or $r.hostNetworkSettingsChanged -or $r.cageCoworkBoundaryAccepted){throw 'READINESS_CHECK_MUST_NOT_AUTHORIZE_OR_CLAIM_ENABLEMENT'}}
'PASS cloud/local/unknown modes, resource headroom, no automatic install/reboot/network change and no false isolation acceptance'
