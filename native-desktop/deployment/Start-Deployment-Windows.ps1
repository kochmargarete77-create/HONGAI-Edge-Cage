[CmdletBinding()]
param([Parameter(Mandatory)][string]$RequestFile,[switch]$LaunchInstaller)
$ErrorActionPreference='Stop'
$result=[ordered]@{schema='hongai.agent-deployment-plan.v1';platform='Windows';phase='CHECKING';nextAction='';fullDesktopAccepted=$false;networkAcceptedByThisCheck=$false;hostNetworkSettingsChanged=$false;loginStateChanged=$false;installerStarted=$false;humanOnlyActions=@('NORMAL_WINDOWS_UAC_IF_REQUIRED','CUSTOMER_ACCOUNT_LOGIN_LATER');writesPerformed=@()}
try{
    if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'USE_NATIVE_64BIT_WINDOWS_POWERSHELL_5_1'}
    $env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
    Import-Module (Join-Path $PSScriptRoot 'Deployment-Contract.psm1') -Force
    function Read-LocalJson([string]$Path){if($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '[\x00-\x1f"]' -or (Get-Item -LiteralPath $Path).Length -gt 262144){throw 'LOCAL_SMALL_JSON_REQUIRED'};try{Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json}catch{throw 'LOCAL_JSON_READ_OR_PARSE_FAILED_CONTENT_NOT_LOGGED'}}
    $request=Read-LocalJson $RequestFile
    $report=Read-LocalJson $request.environmentReport;$handoff=Read-LocalJson $request.handoffFile
    $validated=Test-HongAiDeploymentInputs -Request $request -Report $report -Handoff $handoff
    $workspace=Get-Item -LiteralPath $request.workspace
    if(-not $workspace.PSIsContainer -or $request.workspace -notmatch '^[A-Za-z]:\\' -or ($workspace.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'LOCAL_REAL_WORKSPACE_DIRECTORY_REQUIRED'}
    $work=[IO.Path]::GetFullPath($workspace.FullName).TrimEnd('\')
    $cursor=$work
    while($cursor.Length -gt 3){if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'WORKSPACE_LINK_PATH_REJECTED'};$cursor=Split-Path $cursor -Parent}
    foreach($protected in @($env:USERPROFILE,$env:WINDIR,$env:ProgramFiles,${env:ProgramFiles(x86)})){
        if($protected -and ($work.Length -lt 4 -or $work -ieq $protected -or $protected.StartsWith($work+'\',[StringComparison]::OrdinalIgnoreCase) -or $work.StartsWith($protected+'\',[StringComparison]::OrdinalIgnoreCase) -and $protected -ne $env:USERPROFILE)){throw 'SELECT_SPECIFIC_NON_SYSTEM_PROJECT_FOLDER'}
    }
    $cpu=Get-CimInstance Win32_Processor|Select-Object -First 1
    if($cpu.Architecture -ne 9){throw 'CURRENT_CAGE_INSTALLER_REQUIRES_X64_WINDOWS'}
    if([int](Get-CimInstance Win32_OperatingSystem).BuildNumber -lt 19041){throw 'WINDOWS_BUILD_NOT_SUPPORTED'}
    $setup=Join-Path $PSScriptRoot 'HONGAI-CAGE-Desktop-0.3.0-pilot.5-Windows-x64-Setup.exe'
    if((Get-FileHash -LiteralPath $setup).Hash -cne '61D2F37155B04E76AAFEC821E55B7F1947BE0AF57E7FBFBA5093FF51FA442176'){throw 'SETUP_HASH_MISMATCH_DO_NOT_RUN'}
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($owner -in @('S-1-5-18','S-1-5-19','S-1-5-20')){throw 'RUN_AS_CUSTOMER_USER_NOT_SYSTEM_SERVICE_IDENTITY'}
    $candidates=@('E:\HONGAI-CAGE\Desktop','D:\HONGAI-CAGE\Desktop',(Join-Path $env:ProgramFiles 'HONGAI-CAGE\Desktop'))
    $installed=@()
    foreach($path in $candidates){
        # Directory.Exists handles absent data drives without a PowerShell
        # provider exception. C-only client machines are valid candidates.
        if(-not [IO.Directory]::Exists($path)){continue}
        $file=Join-Path $path 'installation.json'
        if(Test-Path -LiteralPath $file){$receipt=Read-LocalJson $file;if($receipt.schema -cne 'hongai.cage.installation.v1' -or $receipt.installRoot -cne $path -or $receipt.ownerSid -cne $owner){throw 'EXISTING_INSTALLATION_REQUIRES_OWNER_REVIEW'};if($receipt.version -cnotin @('0.3.0-pilot.4','0.3.0-pilot.5')){throw 'INSTALLED_CAGE_VERSION_REVIEW_REQUIRED_NO_AUTOMATIC_REINSTALL'};$installed+= $receipt}
    }
    if($installed.Count -gt 1){throw 'MULTIPLE_CAGE_INSTALLATIONS_REVIEW_NO_AUTOMATIC_REINSTALL'}
    $result.caseId=$request.caseId
    if($installed.Count -eq 0 -or $installed[0].version -ceq '0.3.0-pilot.4'){
        $result.phase=if($installed.Count){'NEEDS_UPGRADE'}else{'NEEDS_INSTALLER'};$result.nextAction='RUN_SETUP_AND_USE_AVAILABLE_COMPUTER_USE_FOR_ORDINARY_UI_ONLY_PRESERVE_EXISTING_DATA'
        if($LaunchInstaller){
            if(@(Get-Process -ErrorAction SilentlyContinue|Where-Object {$_.ProcessName -in @('Claude','HONGAI-CAGE')}).Count){throw 'CLOSE_CLAUDE_AND_CAGE_NORMALLY_BEFORE_INSTALL_NO_FORCE_KILL'}
            $p=Start-Process -FilePath $setup -PassThru
            $result.installerStarted=$true;$result.phase='WAITING_INSTALLER_UI';$result.nextAction='COMPLETE_INSTALLER_UI_THEN_RERUN_WITHOUT_LAUNCH_SWITCH';$result.installerProcessId=$p.Id
        }
    }else{
        $receipt=$installed[0];$data=[IO.Path]::GetFullPath([string]$receipt.dataRoot).TrimEnd('\')
        if($data -cne (Join-Path (Split-Path $receipt.installRoot -Parent) 'DesktopData')){throw 'UNEXPECTED_CAGE_DATA_PATH'}
        $savedHandoff=Join-Path $data 'enrolled-handoff.json';$savedWorkspace=Join-Path $data 'workspace.json'
        $configured=$false
        if((Test-Path -LiteralPath $savedHandoff) -and (Test-Path -LiteralPath $savedWorkspace)){
            $saved=Read-LocalJson $savedHandoff;$folder=Read-LocalJson $savedWorkspace
            $configured=$saved.routeId -ceq $handoff.routeId -and $saved.expectedEgressIp -ceq $handoff.expectedEgressIp -and $saved.loopback.mixedPort -eq $handoff.loopback.mixedPort -and [IO.Path]::GetFullPath([string]$folder.workspace).TrimEnd('\') -ieq $work
        }
        if($configured){$result.phase='SAVED_CONFIGURATION_PRESENT';$result.nextAction='OPEN_CAGE_ONCE_AND_VERIFY_UNAUTHENTICATED_SESSION_STATUS'}
        elseif($validated.handoffRefreshRequired){$result.phase='NEEDS_FRESH_HANDOFF';$result.nextAction='REGENERATE_HANDOFF_USING_INSTALLED_GENERATOR_WITH_SAME_APPROVED_PORT_AND_IP_DO_NOT_REINSTALL'}
        else{$result.phase='NEEDS_FIRST_CONFIGURATION';$result.nextAction='USE_COMPUTER_USE_TO_IMPORT_HANDOFF_AND_SELECT_APPROVED_WORKSPACE_ONCE'}
        $result.launcher=Join-Path $receipt.installRoot 'HONGAI-CAGE.exe';$result.installRoot=$receipt.installRoot
        $result.handoffFile=$request.handoffFile;$result.workspace=$work
    }
}catch{$result.phase='BLOCKED';$result.nextAction='CLASSIFY_ONE_ERROR_DO_NOT_REPAIR_HOST_NETWORK_OR_RETRY_INSTALL_IN_A_LOOP';$result.error=$_.Exception.Message}
$result|ConvertTo-Json -Depth 6
if($result.phase -eq 'BLOCKED'){exit 2}
