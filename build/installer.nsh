!include "nsDialogs.nsh"
!include "LogicLib.nsh"

!ifndef BUILD_UNINSTALLER
  Var clamShieldFreshInstall
  Var clamShieldOptionsDialog
  Var clamShieldStartMinimized
  Var clamShieldWindowsContextMenu
  Var clamShieldStartMinimizedCheckbox
  Var clamShieldWindowsContextMenuCheckbox

  !macro customPageAfterChangeDir
    Page custom ClamShieldOptionsPageCreate ClamShieldOptionsPageLeave
  !macroend

  Function ClamShieldOptionsPageCreate
    ${if} ${Silent}
      Abort
    ${endif}

    nsDialogs::Create 1018
    Pop $clamShieldOptionsDialog
    ${if} $clamShieldOptionsDialog == error
      Abort
    ${endif}

    ${NSD_CreateLabel} 0 0 100% 22u "Choose optional ClamShield integration settings."
    Pop $0

    ${NSD_CreateCheckbox} 0 34u 100% 12u "Start Minimized to Tray"
    Pop $clamShieldStartMinimizedCheckbox
    ${if} $clamShieldStartMinimized == "1"
      ${NSD_Check} $clamShieldStartMinimizedCheckbox
    ${endif}
    ${NSD_CreateLabel} 12u 50u 92% 18u "Open ClamShield as a tray icon without showing the main window."
    Pop $0

    ${NSD_CreateCheckbox} 0 78u 100% 12u "Enable Windows Context Menu"
    Pop $clamShieldWindowsContextMenuCheckbox
    ${if} $clamShieldWindowsContextMenu == "1"
      ${NSD_Check} $clamShieldWindowsContextMenuCheckbox
    ${endif}
    ${NSD_CreateLabel} 12u 94u 92% 24u "Adds ClamShield scan and exception actions to File Explorer right-click menus."
    Pop $0

    nsDialogs::Show
  FunctionEnd

  Function ClamShieldOptionsPageLeave
    ${NSD_GetState} $clamShieldStartMinimizedCheckbox $clamShieldStartMinimized
    ${NSD_GetState} $clamShieldWindowsContextMenuCheckbox $clamShieldWindowsContextMenu
  FunctionEnd
!endif

!macro customInit
  !ifndef BUILD_UNINSTALLER
    StrCpy $clamShieldFreshInstall "1"
    StrCpy $clamShieldStartMinimized "0"
    StrCpy $clamShieldWindowsContextMenu "0"
    IfFileExists "$INSTDIR\ClamShield.exe" 0 +2
    StrCpy $clamShieldFreshInstall "0"
    nsExec::ExecToStack `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$taskXml = & schtasks.exe /Query /TN 'ClamShield' /XML 2>$$null; if ($$LASTEXITCODE -eq 0 -and [string]::Join('', $$taskXml) -match '--minimized') { [Console]::Out.Write('1') } else { [Console]::Out.Write('0') }"`
    Pop $0
    Pop $clamShieldStartMinimized
    ${if} $clamShieldStartMinimized != "1"
      StrCpy $clamShieldStartMinimized "0"
    ${endif}
    nsExec::ExecToStack `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$enabled = $$false; $$statePath = Join-Path $$env:ProgramData 'ClamShield\windows-context-menu.json'; if (Test-Path -LiteralPath $$statePath) { try { $$state = Get-Content -LiteralPath $$statePath -Raw | ConvertFrom-Json; $$enabled = $$state.enabled -eq $$true } catch {} }; if (-not $$enabled) { $$enabled = [bool](Get-AppxPackage -Name 'Orlox.ClamShield' -ErrorAction SilentlyContinue) }; if (-not $$enabled) { $$enabled = Test-Path -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\ClamShield' }; if ($$enabled) { [Console]::Out.Write('1') } else { [Console]::Out.Write('0') }"`
    Pop $0
    Pop $clamShieldWindowsContextMenu
    ${if} $clamShieldWindowsContextMenu != "1"
      StrCpy $clamShieldWindowsContextMenu "0"
    ${endif}
  !endif

  DetailPrint "Checking for running ClamShield process..."
  ; Do not use taskkill /T here. App-triggered installers are descendants of
  ; ClamShield.exe, so killing the whole tree can terminate the installer too.
  nsExec::ExecToLog `"$SYSDIR\taskkill.exe" /IM "ClamShield.exe" /F`
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$$clamShieldRoot = Join-Path $$env:ProgramData 'ClamShield'; $$managedNames = @('clamd.exe', 'clamdscan.exe', 'clamscan.exe', 'freshclam.exe', 'yara64.exe', 'rsync.exe', 'gpg.exe', 'setup-x86_64.exe'); Get-CimInstance Win32_Process | Where-Object { $$managedNames -contains $$_.Name -and $$_.ExecutablePath -and $$_.ExecutablePath.StartsWith($$clamShieldRoot, [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Stop-Process -Id $$_.ProcessId -Force -ErrorAction SilentlyContinue }"`
  Sleep 1000
!macroend

!macro customInstall
  ${if} $clamShieldFreshInstall == "1"
    ExecWait `"$SYSDIR\schtasks.exe" /create /tn "ClamShield" /tr "\"$INSTDIR\ClamShield.exe\"" /sc onlogon /rl highest /f`
    ${ifNot} ${Silent}
      DetailPrint "Recording installer notice acceptance..."
      ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$$consentDir = Join-Path $$env:ProgramData 'ClamShield'; $$consentPath = Join-Path $$consentDir 'installer-consent.txt'; New-Item -ItemType Directory -Path $$consentDir -Force | Out-Null; @('noticeVersion=2026-06-25', ('acceptedAt=' + [DateTime]::UtcNow.ToString('o')), 'installerVersion=${VERSION}') | Set-Content -LiteralPath $$consentPath -Encoding UTF8"`
    ${endif}
  ${endif}
  ${ifNot} ${Silent}
    DetailPrint "Recording installer integration options..."
    ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$$optionsDir = Join-Path $$env:ProgramData 'ClamShield'; $$optionsPath = Join-Path $$optionsDir 'installer-options.txt'; New-Item -ItemType Directory -Path $$optionsDir -Force | Out-Null; @('startMinimized=$clamShieldStartMinimized', 'windowsContextMenuEnabled=$clamShieldWindowsContextMenu', 'installerVersion=${VERSION}') | Set-Content -LiteralPath $$optionsPath -Encoding UTF8"`
  ${endif}
  ${if} ${Silent}
    DetailPrint "Launching ClamShield after silent install or update..."
    Exec `"$INSTDIR\ClamShield.exe"`
  ${endif}
!macroend

!macro customUnInstall
  ExecWait `"$SYSDIR\taskkill.exe" /IM "ClamShield.exe" /T /F`
  ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Get-AppxPackage -Name 'Orlox.ClamShield' | Remove-AppxPackage -ErrorAction SilentlyContinue"`
  DeleteRegKey HKCU "Software\Classes\*\shell\ClamShield"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\ClamShield"
  ${ifNot} ${isUpdated}
    ExecWait `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Set-MpPreference -DisableRealtimeMonitoring $$false -DisableBehaviorMonitoring $$false -DisableIOAVProtection $$false -DisableScriptScanning $$false -DisableBlockAtFirstSeen $$false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ScanScheduleDay Everyday -DisableCatchupFullScan $$false -DisableCatchupQuickScan $$false -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' -Name Enabled -Force -ErrorAction SilentlyContinue; $$dnsBackupPath = Join-Path $$env:ProgramData 'ClamShield\dns-protection-backup.json'; if (Test-Path -LiteralPath $$dnsBackupPath) { try { $$dnsBackup = Get-Content -LiteralPath $$dnsBackupPath -Raw | ConvertFrom-Json; foreach ($$savedAdapter in @($$dnsBackup.adapters)) { $$networkAdapter = Get-NetAdapter -InterfaceIndex ([int]$$savedAdapter.interfaceIndex) -ErrorAction SilentlyContinue; if (-not $$networkAdapter) { $$networkAdapter = Get-NetAdapter -Name ([string]$$savedAdapter.interfaceAlias) -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($$networkAdapter) { $$addresses = @(@($$savedAdapter.ipv4) + @($$savedAdapter.ipv6) | Where-Object { $$_ }); if ($$addresses.Count -gt 0) { Set-DnsClientServerAddress -InterfaceIndex $$networkAdapter.InterfaceIndex -ServerAddresses $$addresses -ErrorAction SilentlyContinue } else { Set-DnsClientServerAddress -InterfaceIndex $$networkAdapter.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue } } }; Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {} }; Remove-Item -LiteralPath $$dnsBackupPath -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath (Join-Path $$env:ProgramData 'ClamShield\securiteinfo-token.bin') -Force -ErrorAction SilentlyContinue"`
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
