param($PackageVersion = "1.0.0", $OutLocation = "$PSScriptRoot/nuget")

$InvocationDirectory = (Resolve-Path .\)

Set-Location -Path "$PSScriptRoot/src"

msbuild /t:restore,build,pack /p:Configuration=Release /p:PackageVersion=$PackageVersion /p:PackageOutputPath=$OutLocation

Set-Location -Path $InvocationDirectory