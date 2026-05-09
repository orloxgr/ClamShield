!macro customInit
  DetailPrint "Checking for running ClamShield process..."
  nsExec::ExecToLog `"$SYSDIR\taskkill.exe" /IM "ClamShield.exe" /T /F`
  Sleep 1000
!macroend

!macro customInstall
  ExecWait `"$SYSDIR\schtasks.exe" /create /tn "ClamShield" /tr "\"$INSTDIR\ClamShield.exe\"" /sc onlogon /rl highest /f`
  ${if} ${isUpdated}
    DetailPrint "Restarting ClamShield after update..."
    Exec `"$INSTDIR\ClamShield.exe" --minimized`
  ${else}
    ${ifNot} ${Silent}
      DetailPrint "Launching ClamShield after install..."
      Exec `"$INSTDIR\ClamShield.exe"`
    ${endif}
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
