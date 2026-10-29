param([switch]$AdapterTest)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    Get-Content -LiteralPath 'SHA256SUMS.txt' -Encoding UTF8 | ForEach-Object {
        $expected,$path = $_ -split '  ',2
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw "Checksum failed: $path" }
    }
    $signature = Get-AuthenticodeSignature '.\wintun.dll'
    if ($signature.Status -ne 'Valid') { throw 'Wintun driver signature is invalid.' }
    & '.\Aster-Core-Tests.exe' -test.v
    if ($LASTEXITCODE -ne 0) { throw 'Windows core / DPAPI tests failed.' }
    Write-Host 'Package checksums, signed Wintun and Windows core/DPAPI tests passed.'
    if ($AdapterTest) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this adapter test in an elevated PowerShell window.' }
        $env:ASTER_WINDOWS_ADAPTER_TEST = '1'
        try {
            & '.\Aster-Network-Tests.exe' -test.v
            if ($LASTEXITCODE -ne 0) { throw 'Windows adapter configuration test failed.' }
        } finally { Remove-Item Env:ASTER_WINDOWS_ADAPTER_TEST -ErrorAction SilentlyContinue }
    }
    Write-Host 'Now follow VERIFICATION.md for the live adapter, routing, DNS and recovery checks.'
} finally { Pop-Location }
