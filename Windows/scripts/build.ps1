param([ValidateSet('amd64','arm64','all')][string]$Arch='all')
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try { python tools/build.py --arch $Arch; if ($LASTEXITCODE -ne 0) { throw 'Build failed' } } finally { Pop-Location }
