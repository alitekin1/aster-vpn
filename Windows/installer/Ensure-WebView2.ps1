$ErrorActionPreference = 'Stop'
try {
    $client = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $keys = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$client", "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$client", "HKCU:\Software\Microsoft\EdgeUpdate\Clients\$client")
    foreach ($key in $keys) {
        $pv = (Get-ItemProperty -LiteralPath $key -Name pv -ErrorAction SilentlyContinue).pv
        if ($pv -and ([version]$pv -gt [version]'0.0.0.0')) { exit 0 }
    }
    $installer = Join-Path $PSScriptRoot 'MicrosoftEdgeWebview2Setup.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'The Microsoft WebView2 bootstrapper signature is invalid.' }
    $result = Start-Process -FilePath $installer -ArgumentList '/silent','/install' -Wait -PassThru
    if ($result.ExitCode -ne 0 -and $result.ExitCode -ne 3010) { throw "WebView2 installation failed ($($result.ExitCode))." }
    exit 0
} catch {
    Write-Error $_
    exit 1
}
