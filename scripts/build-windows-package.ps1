$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repo
try {
    cargo build --release -p akrat-app
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$packageRoot = Join-Path $repo 'dist\AKRAT-0.1.2-windows-x64'
$archive = Join-Path $repo 'dist\AKRAT-0.1.2-windows-x64.zip'
New-Item -ItemType Directory -Force $packageRoot | Out-Null
Copy-Item (Join-Path $repo 'target\release\akrat-app.exe') $packageRoot -Force
Copy-Item (Join-Path $repo 'README.md') $packageRoot -Force
Copy-Item (Join-Path $repo 'LICENSE') $packageRoot -Force
Copy-Item (Join-Path $repo 'docs') $packageRoot -Recurse -Force
Compress-Archive -Path (Join-Path $packageRoot '*') -DestinationPath $archive -Force
Write-Output $archive
