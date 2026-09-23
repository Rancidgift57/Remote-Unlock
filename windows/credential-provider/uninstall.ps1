#Requires -RunAsAdministrator
<#
uninstall.ps1 — removes the Remote-Unlock Credential Provider entirely.

Run this any time to fall back to password-only login, no different from
deleting the pam_exec.so line on Linux. It never touches your Windows
password itself (that lived encrypted in %LOCALAPPDATA%\remote-unlock\
pairing.json, delete that folder separately if you want to fully wipe
the pairing too).

If you ever get locked out of the GUI (e.g. the DLL fails to load and
somehow wedges the login screen — shouldn't happen since we never hide
other tiles, but just in case): boot into Safe Mode or use another admin
account, and run this script from there.
#>

$dest = "$env:SystemRoot\System32\RemoteUnlockCredentialProvider.dll"

& regsvr32.exe /u /s $dest
Remove-Item $dest -Force -ErrorAction SilentlyContinue

Write-Host "Unregistered. Password-only login is now the only login method." -ForegroundColor Green
Write-Host "(Pairing data, if you want to remove that too, is at" -ForegroundColor Yellow
Write-Host "  $env:LOCALAPPDATA\remote-unlock\ )" -ForegroundColor Yellow
