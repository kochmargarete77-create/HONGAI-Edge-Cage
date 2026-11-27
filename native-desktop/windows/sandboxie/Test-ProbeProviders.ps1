$ErrorActionPreference='Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\HONGAI.DesktopGuard.psm1') -Force
$module=Get-Module HONGAI.DesktopGuard
& $module {
    $script:mode='primaryDown';$script:calls=@()
    function script:Invoke-HongAiExitProbe {param($ProxyUri,$ProbeUri,$TimeoutSeconds)
        if($ProxyUri -cne 'http://127.0.0.1:17896'){throw 'TEST_PROXY_CHANGED'}
        $script:calls+= $ProbeUri
        if($script:mode -eq 'allDown'){throw 'MOCK_PROVIDER_OUTAGE'}
        if($ProbeUri -like '*ipify*'){if($script:mode -eq 'mismatch'){return '{"ip":"9.9.9.9"}'};throw 'MOCK_RATE_LIMIT'}
        return "ip=8.8.8.8`nloc=US"
    }
    if((Get-HongAiObservedExit -ProxyUri 'http://127.0.0.1:17896') -cne '8.8.8.8' -or $script:calls.Count -ne 2){throw 'BOUNDED_FALLBACK_FAILED'}
    $script:mode='mismatch';$script:calls=@()
    if((Get-HongAiObservedExit -ProxyUri 'http://127.0.0.1:17896') -cne '9.9.9.9' -or $script:calls.Count -ne 1){throw 'MISMATCH_WAS_HIDDEN_BY_FALLBACK'}
    $script:mode='allDown';$blocked=$false
    try{$null=Get-HongAiObservedExit -ProxyUri 'http://127.0.0.1:17896'}catch{if($_.Exception.Message -eq 'PROBE_FAILED'){$blocked=$true}}
    if(-not $blocked){throw 'ALL_PROVIDER_FAILURE_WAS_ACCEPTED'}
}
'PASS independent probe fallback stays on the same proxy, never masks a valid mismatch, and fails closed if all providers fail'
