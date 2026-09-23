#Requires -RunAsAdministrator
<#
install.ps1 — registers the Remote-Unlock Credential Provider.

Run this AFTER building with CMake/Visual Studio (see README-Windows.md
for the build command). This is the Windows equivalent of adding the
`auth optional pam_exec.so ...` line to /etc/pam.d — except registration
here is done through the registry/regsvr32 rather than a text file, so
there's no config file to hand-edit.
#>

param(
    [string]$DllPath = "$PSScriptRoot\build\bin\RemoteUnlockCredentialProvider.dll"
)

if (-not (Test-Path $DllPath)) {
    Write-Error "Built DLL not found at $DllPath. Build it first: `n  cmake -B build -A x64`n  cmake --build build --config Release"
    exit 1
}

$dest = "$env:SystemRoot\System32\RemoteUnlockCredentialProvider.dll"
Copy-Item $DllPath $dest -Force

& regsvr32.exe /s $dest
if ($LASTEXITCODE -ne 0) {
    Write-Error "regsvr32 failed. Try running 'regsvr32 $dest' without /s to see the error dialog."
    exit 1
}

Write-Host "Registered. The 'Remote-Unlock (phone)' tile should now appear" -ForegroundColor Green
Write-Host "alongside your normal password tile on the lock screen and login screen." -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT: test on the LOCK screen first (Win+L), not sign-out/reboot," -ForegroundColor Yellow
Write-Host "so you can immediately Ctrl+Alt+Del and use your password tile if" -ForegroundColor Yellow
Write-Host "anything looks wrong, without risking being unable to log in at all." -ForegroundColor Yellow
Write-Host ""
Write-Host "Also make sure listener_windows.py is running under YOUR user account" -ForegroundColor Yellow
Write-Host "(Task Scheduler: run at log on, or run whether logged on or not) --" -ForegroundColor Yellow
Write-Host "the tile has nothing to talk to otherwise, and will just time out." -ForegroundColor Yellow
