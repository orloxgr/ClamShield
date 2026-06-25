!ifndef BUILD_UNINSTALLER
  Var clamShieldFreshInstall
!endif

!macro customInit
  StrCpy $clamShieldFreshInstall "1"
  IfFileExists "$INSTDIR\ClamShield.exe" 0 +2
  StrCpy $clamShieldFreshInstall "0"

  DetailPrint "Checking for running ClamShield process..."
  ; Do not use taskkill /T here. App-triggered installers are descendants of
  ; ClamShield.exe, so killing the whole tree can terminate the installer too.
  nsExec::ExecToLog `"$SYSDIR\taskkill.exe" /IM "ClamShield.exe" /F`
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$$engineRoot = Join-Path $$env:ProgramData 'ClamShield\engine'; $$managedNames = @('clamd.exe', 'clamdscan.exe', 'clamscan.exe', 'freshclam.exe', 'yara64.exe'); Get-CimInstance Win32_Process | Where-Object { $$managedNames -contains $$_.Name -and $$_.ExecutablePath -and $$_.ExecutablePath.StartsWith($$engineRoot, [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Stop-Process -Id $$_.ProcessId -Force -ErrorAction SilentlyContinue }"`
  Sleep 1000
!macroend

!macro customInstall
  ExecWait `"$SYSDIR\schtasks.exe" /create /tn "ClamShield" /tr "\"$INSTDIR\ClamShield.exe\"" /sc onlogon /rl highest /f`
  ${if} $clamShieldFreshInstall == "1"
    ${ifNot} ${Silent}
      DetailPrint "Recording installer notice acceptance..."
      ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$$consentDir = Join-Path $$env:ProgramData 'ClamShield'; $$consentPath = Join-Path $$consentDir 'installer-consent.txt'; New-Item -ItemType Directory -Path $$consentDir -Force | Out-Null; @('noticeVersion=2026-06-25', ('acceptedAt=' + [DateTime]::UtcNow.ToString('o')), 'installerVersion=${VERSION}') | Set-Content -LiteralPath $$consentPath -Encoding UTF8"`
    ${endif}
  ${endif}
  ${if} ${Silent}
    DetailPrint "Launching ClamShield after silent install or update..."
    Exec `"$INSTDIR\ClamShield.exe" --minimized`
  ${endif}
!macroend

!macro customUnInstall
  ExecWait `"$SYSDIR\taskkill.exe" /IM "ClamShield.exe" /T /F`
  ${ifNot} ${isUpdated}
    ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Set-MpPreference -DisableRealtimeMonitoring $$false -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' -Name Enabled -Force -ErrorAction SilentlyContinue"`
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ClamShield"
    ExecWait `"$SYSDIR\schtasks.exe" /delete /tn "ClamShield" /f`
    IfSilent keepClamShieldData
    MessageBox MB_YESNO|MB_ICONQUESTION "Remove ClamShield data too? This deletes the ClamAV engine, signature databases, settings, logs, quarantine metadata, and shield cache from ProgramData." IDNO keepClamShieldData
    ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Remove-Item -LiteralPath (Join-Path $$env:ProgramData 'ClamShield') -Recurse -Force -ErrorAction SilentlyContinue"`
    keepClamShieldData:
  ${endif}
!macroend

!macro customRemoveFiles
  ${if} ${isUpdated}
    DetailPrint "Preparing in-place ClamShield update..."
    Delete "$INSTDIR\ClamShield.exe"
    Delete "$INSTDIR\resources\app.asar"
  ${else}
    SetOutPath $TEMP
    RMDir /r "$INSTDIR"
  ${endif}
!macroend
