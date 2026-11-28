Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-MsiMethod {
    param($Object, [string]$Name, [object[]]$Arguments = @())
    $plain = [object[]]::new($Arguments.Count)
    for ($i=0; $i -lt $Arguments.Count; $i++) { if($null -ne $Arguments[$i]){ $plain[$i]=$Arguments[$i].PSObject.BaseObject } }
    try { $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::InvokeMethod, $null, $Object, $plain) }
    catch { throw ('MSI_METHOD_' + $Name + '_FAILED_ARG_TYPES_' + (($Arguments | ForEach-Object { if($null -eq $_){'null'}else{$_.GetType().FullName} }) -join ',') + ': ' + $_.Exception.Message) }
}
function Get-MsiProperty {
    param($Object, [string]$Name, [object[]]$Arguments = @())
    $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::GetProperty, $null, $Object, $Arguments)
}
function Set-MsiProperty {
    param($Object, [string]$Name, [object[]]$Arguments)
    [void]$Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::SetProperty, $null, $Object, $Arguments)
}
function Close-MsiObject {
    param($Object)
    if ($null -ne $Object -and [Runtime.InteropServices.Marshal]::IsComObject($Object)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object)
    }
}
function Invoke-MsiSql {
    param($Database, [string]$Sql)
    $view = Invoke-MsiMethod $Database OpenView @($Sql)
    try { [void](Invoke-MsiMethod $view Execute) } finally {
        [void](Invoke-MsiMethod $view Close); Close-MsiObject $view
    }
}
function Add-MsiRow {
    param($Installer, $Database, [string]$Table, [string[]]$Columns, [object[]]$Values, [int[]]$StreamIndexes = @())
    if ($Columns.Count -ne $Values.Count) { throw 'MSI_ROW_LENGTH_MISMATCH' }
    if ($Table -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw 'INVALID_MSI_TABLE_NAME' }
    $quoted = foreach ($column in $Columns) {
        if ($column -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw 'INVALID_MSI_COLUMN_NAME' }
        '`' + $column + '`'
    }
    $sql = 'INSERT INTO `' + $Table + '` (' + ($quoted -join ',') + ') VALUES (' + ((@('?') * $Columns.Count) -join ',') + ')'
    # Backticks in this SQL are MSI identifier quoting, not PowerShell interpolation.
    $sql = $sql.Replace('\`', '`')
    $view = Invoke-MsiMethod $Database OpenView @($sql)
    $record = Invoke-MsiMethod $Installer CreateRecord @($Columns.Count)
    try {
        for ($i = 0; $i -lt $Values.Count; $i++) {
            if ($null -eq $Values[$i]) { continue }
            if ($StreamIndexes -contains $i) { [void](Invoke-MsiMethod $record SetStream @(($i + 1), [string]$Values[$i])) }
            elseif ($Values[$i] -is [int]) { Set-MsiProperty $record IntegerData @(($i + 1), $Values[$i]) }
            else { Set-MsiProperty $record StringData @(($i + 1), [string]$Values[$i]) }
        }
        [void](Invoke-MsiMethod $view Execute @($record))
    } finally { [void](Invoke-MsiMethod $view Close); Close-MsiObject $record; Close-MsiObject $view }
}
function Get-MsiRows {
    param($Database, [string]$Sql, [int]$ColumnCount)
    $view = Invoke-MsiMethod $Database OpenView @($Sql)
    try {
        [void](Invoke-MsiMethod $view Execute)
        while ($null -ne ($record = Invoke-MsiMethod $view Fetch)) {
            try {
                $row = @(); for ($i = 1; $i -le $ColumnCount; $i++) { $row += Get-MsiProperty $record StringData @($i) }
                ,$row
            } finally { Close-MsiObject $record }
        }
    } finally { [void](Invoke-MsiMethod $view Close); Close-MsiObject $view }
}
function Assert-DataDriveDirectory {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full -notmatch '^[DE]:\\' -or $full -match '[\r\n"]') { throw 'BUILD_OUTPUT_MUST_BE_AN_ABSOLUTE_D_OR_E_DIRECTORY' }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE_POINT_BUILD_PATH_REJECTED' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }; $cursor = $parent
    }
    $full
}
function Write-JsonUtf8 {
    param([string]$Path, $Value)
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
