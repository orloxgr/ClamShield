import { exec } from "child_process";
import { createRequire } from "module";
import path from "path";
import { promisify } from "util";

export const runtimeFileName = typeof __filename === "string" && path.isAbsolute(__filename) ? __filename : path.resolve(process.argv[1] || "server.ts");

export const runtimeDir = path.dirname(runtimeFileName);

export const nodeRequire = createRequire(runtimeFileName);

export const execAsync = promisify(exec);

// Path logic to handle default paths or user configurations
// Note: process.platform === "win32" is Node.js's identifier for ALL Windows systems, including 64-bit.
export const programDataDir = process.platform === "win32"
    ? path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "ClamShield")
    : path.join(process.cwd(), "data", "ClamShield");

export const engineBaseDir = path.join(programDataDir, "engine");

export const appTempDir = path.join(programDataDir, "temp");

export const defaultLogsDir = path.join(programDataDir, "logs");

export const falsePositiveExportsDir = path.join(programDataDir, "exports", "false-positives");

export const yaraBaseDir = path.join(programDataDir, "yara");

export const yaraForgeRulesDir = path.join(yaraBaseDir, "rules", "forge");

export const yaraCustomRulesDir = path.join(yaraBaseDir, "rules", "custom");

export const yaraCacheDir = path.join(yaraBaseDir, "cache");

export const legalNoticeVersion = "2026-06-25";

export const installerConsentPath = path.join(programDataDir, "installer-consent.txt");

export const installerOptionsPath = path.join(programDataDir, "installer-options.txt");

export const securiteInfoSecretPath = path.join(programDataDir, "securiteinfo-token.bin");

export const virusTotalApiKeySecretPath = path.join(programDataDir, "virustotal-api-key.bin");

export const windowsContextMenuStatePath = path.join(programDataDir, "windows-context-menu.json");

export const dnsProtectionBackupPath = path.join(programDataDir, "dns-protection-backup.json");

export const appStateDbPath = path.join(programDataDir, "app_state.sqlite");

export const legacySettingsPath = path.join(programDataDir, "settings.json");

export const legacyHistoryPath = path.join(programDataDir, "history.json");

export const legacyExceptionsPath = path.join(programDataDir, "exceptions.json");

export const legacyExceptionReportsPath = path.join(programDataDir, "exception-reports.json");

export const legacyQuarantineMapPath = path.join(programDataDir, "quarantine_map.json");

export const legacyScanResultsPath = path.join(programDataDir, "scan_results.json");

export const legacyResultsReminderPath = path.join(programDataDir, "results_reminder.json");
