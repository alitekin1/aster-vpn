$ErrorActionPreference = 'Stop'
$installer = Join-Path $env:TEMP ('Aster-WebView2-' + [guid]::NewGuid().ToString() + '.exe')
try {
    Invoke-WebRequest -UseBasicParsing 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $installer
    $signature = Get-AuthenticodeSignature $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Microsoft installer signature could not be verified.' }
    $process = Start-Process $installer -ArgumentList '/silent','/install' -Wait -PassThru
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) { throw "WebView2 install failed ($($process.ExitCode))" }
    Write-Host 'WebView2 is installed. Open Aster.exe.'
} finally { Remove-Item $installer -Force -ErrorAction SilentlyContinue }
