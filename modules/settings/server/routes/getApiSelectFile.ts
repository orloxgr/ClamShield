import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { spawn } from "child_process";
import path from "path";
export function registerGetApiSelectFile(app: any, context: ApplicationContext) {
    app.get("/api/select-file", async (req, res) => {
        if (process.platform === "win32") {
            const script = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.windows.forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "Select a File"
$dialog.Filter = "All Files|*.*"
if ($dialog.ShowDialog() -eq 'OK') {
    Write-Output $dialog.FileName
}
`;
            try {
                const encoded = Buffer.from(script, "utf16le").toString("base64");
                const child = spawn("powershell", ["-STA", "-NoProfile", "-EncodedCommand", encoded], { windowsHide: true });
                let output = "";
                let errorOutput = "";
                child.stdout.on("data", data => output += data.toString());
                child.stderr.on("data", data => errorOutput += data.toString());
                child.on("close", () => {
                    const pathStr = output.trim();
                    if (pathStr && path.isAbsolute(pathStr) && !pathStr.startsWith("Error")) {
                        res.json({ path: pathStr });
                    }
                    else {
                        res.status(400).json({ error: pathStr || errorOutput || englishText("backend.settings.no_file_selected") });
                    }
                });
            }
            catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        }
        else {
            res.json({ path: "", simulated: true });
        }
    });
}
