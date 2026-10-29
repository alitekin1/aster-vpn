$ErrorActionPreference = 'Stop'
# Install the concrete package directly; the meta-package adds an unnecessary
# feed dependency lookup. Retry transient Chocolatey/CDN gateway failures.
for ($attempt = 1; $attempt -le 3; $attempt++) {
    choco upgrade nsis.install --version=3.13.0 -y --no-progress --execution-timeout=180
    if ($LASTEXITCODE -eq 0) { exit 0 }
    if ($attempt -lt 3) { Start-Sleep -Seconds (5 * $attempt) }
}
throw 'Could not install NSIS after three attempts.'
