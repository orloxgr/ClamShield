import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import { appStateDbPath, legacySettingsPath } from './core/paths';
import { defaultSettings } from '../modules/settings/server/schema';
import { syncDefenderCompatibilityExclusions } from './platform/defender';

const uninstallSettingsKeys = ['defenderCompatibilityExclusionsEnabled', 'yaraDir', 'yaraRulesDir', 'yaraCacheDir', 'yaraCustomRulesDir', 'quarantineDir'];

// A separate entry point: no HTTP listener, engine, scheduler or UI is started.
export async function cleanupDefenderForUninstall(options: {
    databasePath?: string;
    legacyPath?: string;
    syncExclusions?: typeof syncDefenderCompatibilityExclusions;
} = {}) {
    const settings = { ...defaultSettings };
    const databasePath = options.databasePath || appStateDbPath;
    const legacyPath = options.legacyPath || legacySettingsPath;
    const apply = (key: string, value: unknown) => {
        if (key === 'defenderCompatibilityExclusionsEnabled') {
            if (typeof value !== 'boolean') throw new Error('Invalid stored Defender compatibility setting.');
        } else if (typeof value !== 'string' || !value || value.length > 32767) {
            throw new Error(`Invalid stored uninstall path: ${key}`);
        }
        settings[key] = value;
    };
    if (fs.existsSync(databasePath)) {
        const db = new DatabaseSync(databasePath, { readOnly: true });
        try {
            const placeholders = uninstallSettingsKeys.map(() => '?').join(',');
            for (const row of db.prepare(`SELECT key, value FROM settings WHERE key IN (${placeholders})`).all(...uninstallSettingsKeys)) {
                apply(String(row.key), JSON.parse(String(row.value)));
            }
        } finally { db.close(); }
    } else if (fs.existsSync(legacyPath)) {
        if (fs.statSync(legacyPath).size > 1024 * 1024) throw new Error('Legacy settings are too large to read safely.');
        const legacy = JSON.parse(fs.readFileSync(legacyPath, 'utf8'));
        for (const key of uninstallSettingsKeys) if (Object.hasOwn(legacy, key)) apply(key, legacy[key]);
    }
    if (!settings.defenderCompatibilityExclusionsEnabled) return { Success: true, skipped: true };
    const result = await (options.syncExclusions || syncDefenderCompatibilityExclusions)({ ...settings, defenderCompatibilityExclusionsEnabled: false });
    if (result?.Success !== true) throw new Error(result?.Message || result?.Error || 'Windows blocked removal of ClamShield Defender exclusions.');
    return result;
}
