[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$build=Join-Path $root 'build'
$env:TEMP=$build; $env:TMP=$build
$exe=Join-Path $build 'HONGAI-Wfp-SelfTest.exe'
$log=Join-Path $build 'kernel-self-test.log'
$status=Join-Path $build 'kernel-self-test-status.json'
try {
    & $exe --self-test *> $log
    $code=$LASTEXITCODE
    $result=[ordered]@{schema='hongai.kernel-selftest.v1';exitCode=$code;passed=($code -eq 0);scope='exact own test executable only';persistentFilters=$false;customerAcceptance=$false;utc=[datetime]::UtcNow.ToString('o')}
    [IO.File]::WriteAllText($status,($result|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    exit $code
} catch {
    [IO.File]::WriteAllText($status,(@{passed=$false;error=$_.Exception.Message}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    exit 1
}
