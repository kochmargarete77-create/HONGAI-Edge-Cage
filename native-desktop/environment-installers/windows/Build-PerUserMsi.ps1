[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PayloadFile,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSHA256,
    [Parameter(Mandatory)][string]$ProductVersion,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$LicenseFile,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$PayloadValidationJson,
    [Parameter(Mandatory)][string]$IconFile
)
. (Join-Path $PSScriptRoot 'Msi-Common.ps1')
if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_BUILD_HOST_REQUIRED' }
if ($ProductVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'THREE_PART_MSI_VERSION_REQUIRED' }
$parts = $ProductVersion.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw 'MSI_VERSION_OUT_OF_RANGE' }
$output = Assert-DataDriveDirectory $OutputDirectory
[void][IO.Directory]::CreateDirectory($output)
$payload = (Resolve-Path -LiteralPath $PayloadFile).Path
$license = (Resolve-Path -LiteralPath $LicenseFile).Path
$icon = (Resolve-Path -LiteralPath $IconFile).Path
$sha = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sha -cne $ExpectedSHA256.ToLowerInvariant()) { throw 'PAYLOAD_SHA256_MISMATCH' }
$validation = Get-Content -LiteralPath $PayloadValidationJson -Raw | ConvertFrom-Json
if ($validation.schema -cne 'hongai.windows-payload-validation.v1' -or $validation.sha256 -cne $sha -or $validation.sourceCommit -cne $SourceCommit.ToLowerInvariant() -or $validation.nativeTestsPassed -ne $true -or $validation.cliSmokePassed -ne $true -or $validation.executableMode -cne 'console') { throw 'EXACT_CONSOLE_PAYLOAD_VALIDATION_REQUIRED' }
$bytes = [IO.File]::ReadAllBytes($payload)
if ($bytes.Length -lt 512 -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) { throw 'PE_IMAGE_REQUIRED' }
$pe = [BitConverter]::ToInt32($bytes, 60)
if ($pe -lt 64 -or $pe + 94 -gt $bytes.Length -or [BitConverter]::ToUInt32($bytes, $pe) -ne 17744 -or [BitConverter]::ToUInt16($bytes, $pe + 4) -ne 34404 -or [BitConverter]::ToUInt16($bytes, $pe + 92) -ne 3) { throw 'AMD64_CONSOLE_PE_REQUIRED_GUI_NEEDS_SEPARATE_VALIDATION' }
$stage = Join-Path $output ('stage-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
$oldTemp = $env:TEMP; $oldTmp = $env:TMP
$env:TEMP = $stage; $env:TMP = $stage
$installer = $null; $db = $null; $summary = $null
$msi = Join-Path $output ('HONGAI-Environment-Workbench-' + $ProductVersion + '-x64.msi')
if (Test-Path -LiteralPath $msi) { throw 'OUTPUT_MSI_ALREADY_EXISTS_USE_NEW_VERSION_OR_DIRECTORY' }
try {
    Copy-Item -LiteralPath $payload -Destination (Join-Path $stage 'hongai-environment.exe')
    Copy-Item -LiteralPath $license -Destination (Join-Path $stage 'Go-license.txt')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '安装与使用说明.txt') -Destination (Join-Path $stage 'Install-notes.txt')
    $cabDir = Join-Path $stage 'cab'; [void][IO.Directory]::CreateDirectory($cabDir)
    $ddf = @('.OPTION EXPLICIT', '.Set Cabinet=on', '.Set Compress=on', '.Set CompressionType=MSZIP', '.Set CabinetNameTemplate=payload.cab', '.Set MaxDiskSize=0', ('.Set DiskDirectoryTemplate="' + $cabDir + '"'), ('.Set RptFileName="' + (Join-Path $stage 'makecab.rpt') + '"'), ('.Set InfFileName="' + (Join-Path $stage 'makecab.inf') + '"'))
    $files = @(@('WorkbenchExe','hongai-environment.exe','HONGAI~1.EXE|hongai-environment.exe'), @('InstallNotes','Install-notes.txt','NOTES~1.TXT|Install-notes.txt'), @('GoLicense','Go-license.txt','GO-LIC~1.TXT|Go-license.txt'))
    foreach ($file in $files) { $ddf += '"' + (Join-Path $stage $file[1]) + '" ' + $file[0] }
    $ddfPath = Join-Path $stage 'payload.ddf'; [IO.File]::WriteAllLines($ddfPath, $ddf, [Text.Encoding]::Default)
    & "$env:SystemRoot\System32\makecab.exe" /F $ddfPath | Out-File -LiteralPath (Join-Path $stage 'makecab-output.txt')
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $cabDir 'payload.cab'))) { throw 'MAKECAB_FAILED' }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase([string]$msi, [int]3)
    $definitions = @(
        'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)',
        'CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)',
        'CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)',
        'CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)',
        'CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)',
        'CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` SHORT NOT NULL PRIMARY KEY `File`)',
        'CREATE TABLE `MsiFileHash` (`File_` CHAR(72) NOT NULL, `Options` SHORT NOT NULL, `HashPart1` LONG NOT NULL, `HashPart2` LONG NOT NULL, `HashPart3` LONG NOT NULL, `HashPart4` LONG NOT NULL PRIMARY KEY `File_`)',
        'CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)',
        'CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` CHAR(0) LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)',
        'CREATE TABLE `Shortcut` (`Shortcut` CHAR(72) NOT NULL, `Directory_` CHAR(72) NOT NULL, `Name` CHAR(128) NOT NULL LOCALIZABLE, `Component_` CHAR(72) NOT NULL, `Target` CHAR(255) NOT NULL, `Arguments` CHAR(255), `Description` CHAR(255) LOCALIZABLE, `Hotkey` SHORT, `Icon_` CHAR(72), `IconIndex` SHORT, `ShowCmd` SHORT, `WkDir` CHAR(72) PRIMARY KEY `Shortcut`)',
        'CREATE TABLE `Icon` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)',
        'CREATE TABLE `CreateFolder` (`Directory_` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Directory_`, `Component_`)',
        'CREATE TABLE `Upgrade` (`UpgradeCode` CHAR(38) NOT NULL, `VersionMin` CHAR(20), `VersionMax` CHAR(20), `Language` CHAR(255), `Attributes` LONG NOT NULL, `Remove` CHAR(255), `ActionProperty` CHAR(72) NOT NULL PRIMARY KEY `UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`)',
        'CREATE TABLE `LaunchCondition` (`Condition` CHAR(255) NOT NULL, `Description` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Condition`)',
        'CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)'
    )
    foreach ($definition in $definitions) { Invoke-MsiSql $db $definition }
    $productCode = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    $packageCode = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    $upgradeCode = '{EF7A0B99-5086-488B-B745-398685BA3555}'
    $componentCode = '{E8845AE0-DA5C-49A8-94E3-C38416F2E8AC}'
    $properties = [ordered]@{ProductCode=$productCode; ProductName='HONG AI Environment Workbench (Preview)'; ProductVersion=$ProductVersion; ProductLanguage='1033'; Manufacturer='HONG AI'; UpgradeCode=$upgradeCode; LIMITUI='1'; ARPNOMODIFY='1'; REBOOT='ReallySuppress'; MSIRESTARTMANAGERCONTROL='Disable'; SecureCustomProperties='OLDPRODUCTS;NEWERPRODUCTFOUND'; ARPCOMMENTS='Preparation and diagnostics component. Official Claude remains unchanged.'}
    foreach ($entry in $properties.GetEnumerator()) { Add-MsiRow $installer $db Property @('Property','Value') @($entry.Key,$entry.Value) }
    foreach ($row in @(@('TARGETDIR',$null,'SourceDir'), @('LocalAppDataFolder','TARGETDIR','.'), @('ProgramsDirectory','LocalAppDataFolder','Programs'), @('INSTALLFOLDER','ProgramsDirectory','HONGAI~1|HONG AI Environment Workbench'), @('ProgramMenuFolder','TARGETDIR','.'), @('ApplicationProgramsFolder','ProgramMenuFolder','HONGAI~1|HONG AI Environment'), @('DesktopFolder','TARGETDIR','.'))) { Add-MsiRow $installer $db Directory @('Directory','Directory_Parent','DefaultDir') $row }
    Add-MsiRow $installer $db Component @('Component','ComponentId','Directory_','Attributes','Condition','KeyPath') @('WorkbenchComponent',$componentCode,'INSTALLFOLDER',260,$null,'InstalledVersion')
    Add-MsiRow $installer $db Feature @('Feature','Feature_Parent','Title','Description','Display','Level','Directory_','Attributes') @('Main',$null,'Environment workbench','Preparation and diagnostics',1,1,'INSTALLFOLDER',0)
    Add-MsiRow $installer $db FeatureComponents @('Feature_','Component_') @('Main','WorkbenchComponent')
    $sequence=0
    foreach ($file in $files) {
        $sequence++; $path=Join-Path $stage $file[1]
        Add-MsiRow $installer $db File @('File','Component_','FileName','FileSize','Version','Language','Attributes','Sequence') @($file[0],'WorkbenchComponent',$file[2],[int](Get-Item -LiteralPath $path).Length,$null,$null,512,$sequence)
        $hash=Invoke-MsiMethod $installer FileHash @($path,0)
        try { Add-MsiRow $installer $db MsiFileHash @('File_','Options','HashPart1','HashPart2','HashPart3','HashPart4') @($file[0],0,(Get-MsiProperty $hash IntegerData @(1)),(Get-MsiProperty $hash IntegerData @(2)),(Get-MsiProperty $hash IntegerData @(3)),(Get-MsiProperty $hash IntegerData @(4))) } finally { Close-MsiObject $hash }
    }
    Add-MsiRow $installer $db Media @('DiskId','LastSequence','DiskPrompt','Cabinet','VolumeLabel','Source') @(1,3,$null,'#payload.cab',$null,$null)
    Add-MsiRow $installer $db _Streams @('Name','Data') @('payload.cab',(Join-Path $cabDir 'payload.cab')) @(1)
    Add-MsiRow $installer $db Registry @('Registry','Root','Key','Name','Value','Component_') @('InstalledVersion',1,'Software\HONGAI\EnvironmentWorkbenchInstaller','InstalledVersion',$ProductVersion,'WorkbenchComponent')
    Add-MsiRow $installer $db Icon @('Name','Data') @('HONGAI.ico',$icon) @(1)
    foreach ($shortcut in @(@('DesktopShortcut','DesktopFolder'),@('MenuShortcut','ApplicationProgramsFolder'))) {
        Add-MsiRow $installer $db Shortcut @('Shortcut','Directory_','Name','Component_','Target','Arguments','Description','Hotkey','Icon_','IconIndex','ShowCmd','WkDir') @($shortcut[0],$shortcut[1],'HONGAI~1|HONG AI Environment','WorkbenchComponent','[INSTALLFOLDER]hongai-environment.exe',$null,'Open saved environment workbench',$null,'HONGAI.ico',0,1,'INSTALLFOLDER')
    }
    foreach ($directory in @('INSTALLFOLDER','ApplicationProgramsFolder')) { Add-MsiRow $installer $db CreateFolder @('Directory_','Component_') @($directory,'WorkbenchComponent') }
    Add-MsiRow $installer $db Upgrade @('UpgradeCode','VersionMin','VersionMax','Language','Attributes','Remove','ActionProperty') @($upgradeCode,$null,$ProductVersion,$null,1,'ALL','OLDPRODUCTS')
    Add-MsiRow $installer $db Upgrade @('UpgradeCode','VersionMin','VersionMax','Language','Attributes','Remove','ActionProperty') @($upgradeCode,$ProductVersion,$null,$null,258,$null,'NEWERPRODUCTFOUND')
    Add-MsiRow $installer $db LaunchCondition @('Condition','Description') @('NOT ALLUSERS','Per-user installation only. Do not set ALLUSERS.')
    Add-MsiRow $installer $db LaunchCondition @('Condition','Description') @('VersionNT64','A 64-bit Windows operating system is required.')
    Add-MsiRow $installer $db LaunchCondition @('Condition','Description') @('Installed OR NOT NEWERPRODUCTFOUND','A same-version or newer workbench is installed. Uninstall it first only if a downgrade is intended.')
    $actions = @(@('FindRelatedProducts',25),@('LaunchConditions',100),@('ValidateProductID',700),@('CostInitialize',800),@('FileCost',900),@('CostFinalize',1000),@('MigrateFeatureStates',1200),@('InstallValidate',1400),@('InstallInitialize',1500),@('RemoveExistingProducts',1550),@('ProcessComponents',1600),@('UnpublishFeatures',1800),@('RemoveRegistryValues',2600),@('RemoveShortcuts',3200),@('RemoveFiles',3500),@('RemoveFolders',3600),@('CreateFolders',3700),@('InstallFiles',4000),@('CreateShortcuts',4500),@('WriteRegistryValues',5000),@('RegisterUser',6000),@('RegisterProduct',6100),@('PublishFeatures',6300),@('PublishProduct',6400),@('InstallExecute',6500),@('InstallFinalize',6600))
    foreach ($action in $actions) { $condition=$null; if($action[0] -eq 'RemoveExistingProducts'){$condition='OLDPRODUCTS'}; Add-MsiRow $installer $db InstallExecuteSequence @('Action','Condition','Sequence') @($action[0],$condition,[int]$action[1]) }
    $summary=Get-MsiProperty $db SummaryInformation @(20)
    foreach($item in @(@(1,1252),@(2,'Installation Database'),@(3,'HONG AI Environment Workbench'),@(4,'HONG AI'),@(5,'Installer;Preparation;Diagnostics'),@(6,'Per-user preview component; official Claude is not bundled.'),@(7,'x64;1033'),@(9,$packageCode),@(14,200),@(15,10),@(18,'HONG AI native MSI builder'))) { Set-MsiProperty $summary Property @($item[0],$item[1]) }
    [void](Invoke-MsiMethod $summary Persist); [void](Invoke-MsiMethod $db Commit)
    Close-MsiObject $summary; $summary=$null; Close-MsiObject $db; $db=$null
    $manifest=[ordered]@{schema='hongai.windows-msi.v1';productVersion=$ProductVersion;productCode=$productCode;upgradeCode=$upgradeCode;packageCode=$packageCode;sourceCommit=$SourceCommit.ToLowerInvariant();payloadSha256=$sha;msiSha256=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant();payloadMode='console';scope='per-user-component-preparation-and-diagnostics';installRelativePath='Programs\HONG AI Environment Workbench';privateDataRelativePath='HONGAI-Environment';uninstallKeepsPrivateData=$true;majorUpgradeRemoveExistingProductsSequence=1550;fullEnvironmentCustomerReady=$false;organizationSigning='NOT_PROVIDED';buildValidated=$true;installedValidated=$false;upgradeValidated=$false;uninstallValidated=$false}
    Write-JsonUtf8 ($msi+'.json') $manifest
    [pscustomobject]@{Msi=$msi;Manifest=$msi+'.json';SHA256=$manifest.msiSha256;LocalInstallationPerformed=$false}
} finally {
    Close-MsiObject $summary; Close-MsiObject $db; Close-MsiObject $installer
    $env:TEMP=$oldTemp; $env:TMP=$oldTmp
}
