Option Explicit

Dim action, target, fallbackExe, installDir, scriptPath, command
action = ""
target = ""
fallbackExe = ""

If WScript.Arguments.Count > 0 Then action = WScript.Arguments.Item(0)
If WScript.Arguments.Count > 1 Then target = WScript.Arguments.Item(1)
If WScript.Arguments.Count > 2 Then fallbackExe = WScript.Arguments.Item(2)

installDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
scriptPath = installDir & "\ClamShieldContextMenu.ps1"

command = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " & _
  Quote(scriptPath) & " -Action " & Quote(action) & " -Target " & Quote(target) & " -FallbackExe " & Quote(fallbackExe)

CreateObject("WScript.Shell").Run command, 0, False

Function Quote(value)
  Quote = """" & Replace(CStr(value), """", """""") & """"
End Function
