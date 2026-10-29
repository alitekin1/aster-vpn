# Runs on an isolated Windows CI runner. No proxy credentials or capture routes.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$out = Join-Path $root 'build\windows'
$setup = Join-Path $out 'Aster-Setup-x64.exe'
$installed = Join-Path $env:ProgramW6432 'Aster'
$data = Join-Path $env:APPDATA 'Aster'
$fixture = Join-Path $out 'Installer-Fixture.exe'
Push-Location (Join-Path $root 'Windows')
try {
    go build -o $fixture ./tools/windows-smoke
    if ($LASTEXITCODE -ne 0) { throw 'Could not build state fixture' }
    & $fixture seed $data
    if ($LASTEXITCODE -ne 0) { throw 'Could not save encrypted fixture' }
    $p = Start-Process $setup -ArgumentList '/S' -PassThru
    if (-not $p.WaitForExit(180000)) { throw 'Setup timed out' }
    $p.Refresh()
    if ($p.ExitCode -ne 0) { throw "Setup failed ($($p.ExitCode))" }
    if (-not (Test-Path (Join-Path $installed 'Aster.exe'))) { throw 'Installed executable is missing' }
    $expected = (Select-String -Path 'internal/buildinfo/version.go' -Pattern 'const Version = "([0-9.]+)"').Matches[0].Groups[1].Value + '.0'
    $info = (Get-Item (Join-Path $installed 'Aster.exe')).VersionInfo
    $actual = "$($info.FileMajorPart).$($info.FileMinorPart).$($info.FileBuildPart).$($info.FilePrivatePart)"
    if ($actual -ne $expected) { throw "Installed app version is $actual; expected $expected" }
    Write-Host "Installed Aster file version: $actual"
    if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Aster')) { throw 'Uninstall registration is missing' }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AsterWindow {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string cls,string title);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr hwnd,uint msg,IntPtr wp,IntPtr lp,uint flags,uint timeout,out IntPtr result);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd,uint msg,IntPtr wp,IntPtr lp);
}
'@
    function Wait-Aster {
        for ($i=0; $i -lt 60; $i++) {
            $hwnd = [AsterWindow]::FindWindow('webview','Aster')
            if ($hwnd -ne [IntPtr]::Zero) {
                $result = [IntPtr]::Zero
                [void][AsterWindow]::SendMessageTimeout($hwnd,0x8030,[IntPtr]::Zero,[IntPtr]::Zero,2,1000,[ref]$result)
                if ($result.ToInt64() -eq 0x41535452) { return $hwnd }
            }
            Start-Sleep -Milliseconds 500
        }
        throw 'Aster did not start its native WebView2 window / installer handshake'
    }
    $first = Start-Process (Join-Path $installed 'Aster.exe') -PassThru
    [void](Wait-Aster)
    $p = Start-Process $setup -ArgumentList '/S','/UPDATE' -PassThru
    if (-not $p.WaitForExit(180000)) { throw 'Upgrade timed out' }
    $p.Refresh()
    if ($p.ExitCode -ne 0) { throw "Upgrade failed ($($p.ExitCode))" }
    [void](Wait-Aster)
    if (-not $first.HasExited) { throw 'Upgrade did not stop the old app gracefully' }
    & $fixture verify $data
    if ($LASTEXITCODE -ne 0) { throw 'Encrypted settings changed during update' }
    $hwnd = [AsterWindow]::FindWindow('webview','Aster')
    [void][AsterWindow]::PostMessage($hwnd,0x802f,[IntPtr]::Zero,[IntPtr]::Zero)
    Get-Process Aster -ErrorAction SilentlyContinue | Wait-Process -Timeout 30
    $p = Start-Process (Join-Path $installed 'Uninstall.exe') -ArgumentList '/S' -PassThru -Wait
    if ($p.ExitCode -ne 0) { throw 'Uninstall failed' }
    for ($i=0; $i -lt 30 -and (Test-Path (Join-Path $installed 'Aster.exe')); $i++) { Start-Sleep -Milliseconds 500 }
    if (Test-Path (Join-Path $installed 'Aster.exe')) { throw 'Uninstall left the app executable' }
    & $fixture verify $data
    if ($LASTEXITCODE -ne 0) { throw 'Uninstall removed saved settings' }
    Push-Location (Join-Path $out 'Aster-Windows-x64')
    try { & .\Aster-Core-Tests.exe -test.v; if ($LASTEXITCODE -ne 0) { throw 'Native Windows/DPAPI tests failed' } } finally { Pop-Location }
    Write-Host 'PASS: install, native WebView2 launch, graceful update/relaunch, DPAPI state preservation, uninstaller and native core tests.'
} finally { Pop-Location }
