[CmdletBinding()]
param([switch]$PersistentTest)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$build=Join-Path $root 'build'
$env:TEMP=$build; $env:TMP=$build
$exe=Join-Path $build 'HONGAI-Wfp-SelfTest.exe'
$suffix=if($PersistentTest){'persistent-kernel-self-test'}else{'kernel-self-test'}
$log=Join-Path $build ($suffix+'.log')
$status=Join-Path $build ($suffix+'-status.json')
try {
    $mode=if($PersistentTest){'--persistent-self-test'}else{'--self-test'}
    & $exe $mode *> $log
    $code=$LASTEXITCODE
    $result=[ordered]@{schema='hongai.kernel-selftest.v1';exitCode=$code;passed=($code -eq 0);scope='exact own test executable only';testedPersistentRules=[bool]$PersistentTest;cleanupExecuted=$true;customerAcceptance=$false;utc=[datetime]::UtcNow.ToString('o')}
    [IO.File]::WriteAllText($status,($result|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    exit $code
} catch {
    [IO.File]::WriteAllText($status,(@{passed=$false;error=$_.Exception.Message}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    exit 1
}
