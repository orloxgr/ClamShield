import { insertExceptionReportRow, insertExceptionRow } from "../../../modules/exceptions/server/rows";
import { insertHistoryRow } from "../../../modules/history/server/rows";
import { insertQuarantineMapRow } from "../../../modules/quarantine/server/rows";
import { cleanupDuplicateScanResults, insertScanResultRow } from "../../../modules/results/server/rows";
import { saveSettingsRows } from "../../../modules/settings/server/storage";
import { legacyExceptionReportsPath, legacyExceptionsPath, legacyHistoryPath, legacyQuarantineMapPath, legacyResultsReminderPath, legacyScanResultsPath, legacySettingsPath } from "../paths";
import { runtimeState } from "../runtimeState";
import { assertScanResultsReminderSchema, assertScanResultsVirusTotalRefinementSchema, ensureScanResultsReminderSchema, getAppStateDb, migrateHistorySummarySchema, migrateScanResultsReminderSchema, migrateScanResultsVirusTotalRefinementSchema } from "./schema";
import { appStateRowCount, asRecord, normalizedStatePath, optionalNumber, readLegacyJsonState, runAppStateTransaction } from "./values";

export async function recoverLegacySettingsIfSettingsEmpty(db: any) {
    if (appStateRowCount(db, "settings") > 0)
        return false;
    const settings = asRecord(await readLegacyJsonState(legacySettingsPath, null));
    if (Object.keys(settings).length === 0)
        return false;
    saveSettingsRows(settings);
    return true;
}

export function isAppStateMigrationApplied(db: any, name: string) {
    return !!db.prepare("SELECT name FROM migrations WHERE name = ?").get(name);
}

export function markAppStateMigrationApplied(db: any, name: string) {
    db.prepare("INSERT OR REPLACE INTO migrations(name, applied_at) VALUES (?, ?)").run(name, Date.now());
}

export async function runAppStateMigration(db: any, name: string, work: () => Promise<void>) {
    if (isAppStateMigrationApplied(db, name))
        return;
    await work();
    markAppStateMigrationApplied(db, name);
}

export async function migrateAppStateSchema(db: any) {
    await runAppStateMigration(db, "schema.scan_results.virus_total_refinement.v1", async () => {
        migrateScanResultsVirusTotalRefinementSchema(db);
    });
    await runAppStateMigration(db, "schema.scan_results.results_reminder_at.v1", async () => {
        migrateScanResultsReminderSchema(db);
    });
    ensureScanResultsReminderSchema(db);
    await runAppStateMigration(db, "schema.history.summary_indexes.v1", async () => {
        migrateHistorySummarySchema(db);
    });
    assertScanResultsVirusTotalRefinementSchema(db);
    assertScanResultsReminderSchema(db);
}

export async function migrateLegacyAppState(db: any) {
    await runAppStateMigration(db, "settings.json", async () => {
        await recoverLegacySettingsIfSettingsEmpty(db);
    });
    await recoverLegacySettingsIfSettingsEmpty(db);
    await runAppStateMigration(db, "history.json", async () => {
        const history = await readLegacyJsonState(legacyHistoryPath, []);
        if (!Array.isArray(history) || history.length === 0)
            return;
        runAppStateTransaction(db, () => {
            history.forEach((entry, index) => insertHistoryRow(db, entry, index));
        });
    });
    await runAppStateMigration(db, "exceptions.json", async () => {
        const exceptions = await readLegacyJsonState(legacyExceptionsPath, []);
        if (!Array.isArray(exceptions) || exceptions.length === 0)
            return;
        runAppStateTransaction(db, () => {
            exceptions.forEach((exceptionPath, index) => insertExceptionRow(db, exceptionPath, Date.now() + index));
        });
    });
    await runAppStateMigration(db, "exception-reports.json", async () => {
        const reports = asRecord(await readLegacyJsonState(legacyExceptionReportsPath, {}));
        if (Object.keys(reports).length === 0)
            return;
        runAppStateTransaction(db, () => {
            for (const [key, report] of Object.entries(reports)) {
                insertExceptionReportRow(db, normalizedStatePath(key), report);
            }
        });
    });
    await runAppStateMigration(db, "quarantine_map.json", async () => {
        const map = asRecord(await readLegacyJsonState(legacyQuarantineMapPath, {}));
        if (Object.keys(map).length === 0)
            return;
        runAppStateTransaction(db, () => {
            for (const [fileName, metadata] of Object.entries(map)) {
                insertQuarantineMapRow(db, fileName, metadata);
            }
        });
    });
    await runAppStateMigration(db, "scan_results.json", async () => {
        const results = await readLegacyJsonState(legacyScanResultsPath, []);
        if (!Array.isArray(results) || results.length === 0)
            return;
        runAppStateTransaction(db, () => {
            results.forEach((result, index) => insertScanResultRow(db, result, index));
        });
    });
    await runAppStateMigration(db, "results_reminder.json", async () => {
        const state = asRecord(await readLegacyJsonState(legacyResultsReminderPath, {}));
        if (Object.keys(state).length === 0)
            return;
        const upsert = db.prepare("INSERT OR REPLACE INTO results_reminder(key, value) VALUES (?, ?)");
        runAppStateTransaction(db, () => {
            upsert.run("remindUntil", optionalNumber(state.remindUntil) || 0);
            upsert.run("forgottenUntil", optionalNumber(state.forgottenUntil) || 0);
        });
    });
}

export async function ensureAppStateReady() {
    const db = getAppStateDb();
    if (!runtimeState.appStateReadyPromise) {
        runtimeState.appStateReadyPromise = migrateAppStateSchema(db).then(() => {
            return migrateLegacyAppState(db);
        }).then(() => {
            return runAppStateMigration(db, "data.scan_results.cleanup_duplicates.v1", async () => {
                cleanupDuplicateScanResults(db);
            });
        }).catch(e => {
            runtimeState.appStateReadyPromise = null;
            throw e;
        });
    }
    await runtimeState.appStateReadyPromise;
}
