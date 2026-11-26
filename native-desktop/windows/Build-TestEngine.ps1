[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$out=Join-Path $root 'build'
$null=New-Item -ItemType Directory -Path $out -Force
$env:TEMP=$out; $env:TMP=$out
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path $compiler)){throw 'NET_FRAMEWORK_COMPILER_NOT_FOUND'}
& $compiler /nologo /platform:x64 /target:exe /optimize+ ("/out:"+(Join-Path $out 'HONGAI-Wfp-SelfTest.exe')) (Join-Path $root 'WfpBoundary.cs')
if($LASTEXITCODE -ne 0){throw 'COMPILE_FAILED'}
& (Join-Path $out 'HONGAI-Wfp-SelfTest.exe') --abi-test
if($LASTEXITCODE -ne 0){throw 'ABI_TEST_FAILED'}
