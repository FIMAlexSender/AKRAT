param(
    [string]$ExecutablePath = (Join-Path $PSScriptRoot '..\target\release\akrat-app.exe')
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw 'PowerShell 7.4 or later is required for isolated process environments.'
}

$exe = (Resolve-Path $ExecutablePath).Path
$profileA = Join-Path $env:TEMP 'AKRAT-profile-A'
$profileB = Join-Path $env:TEMP 'AKRAT-profile-B'
New-Item -ItemType Directory -Force $profileA, $profileB | Out-Null
$first = Start-Process -FilePath $exe -Environment @{ LOCALAPPDATA = $profileA } -PassThru
$second = Start-Process -FilePath $exe -Environment @{ LOCALAPPDATA = $profileB } -PassThru
[PSCustomObject]@{
    AliceProcessId = $first.Id
    AliceProfile = $profileA
    BobProcessId = $second.Id
    BobProfile = $profileB
}
