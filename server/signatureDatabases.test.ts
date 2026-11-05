import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs/promises";
import path from "node:path";
import { stateFixture, testModule } from "./testModule";
import { normalizeDatabaseSelection, saneSecurityDatabaseCatalog, securiteInfoDatabaseCatalog } from "../shared/signatureDatabases";
import { getConfiguredSecuriteInfoDatabaseNames, removeSecuriteInfoDatabaseFiles } from "../addons/securiteinfo/server/service";
import { getConfiguredSaneSecurityDatabaseNames, removeSaneSecurityDatabaseFiles } from "../addons/sanesecurity/server/status";
import { normalizeSettingsPatch } from "../modules/settings/server/validation";
import { defaultSettings } from "../modules/settings/server/schema";

test("database selection rejects filenames, URLs and payloads outside the trusted catalog", () => {
    for (const value of [["../main.cvd"], ["C:\\outside\\rules.yara"], ["https://example.org/malware.ndb"], ["securiteinfo.yara", {}], "securiteinfo.yara", null]) {
        assert.throws(() => normalizeDatabaseSelection(value, securiteInfoDatabaseCatalog), /Invalid signature database selection/);
        assert.throws(() => normalizeSettingsPatch({ securiteInfoDatabases: value }, defaultSettings));
    }
    assert.deepEqual(normalizeDatabaseSelection(["securiteinfo.yara", "securiteinfo.yara"], securiteInfoDatabaseCatalog), ["securiteinfo.yara"]);
    assert.deepEqual(normalizeSettingsPatch({ saneSecurityDatabases: [] }, defaultSettings).patch.saneSecurityDatabases, []);
});

test("fresh installations select every supported database while Basic stays within its plan", () => {
    assert.equal(getConfiguredSecuriteInfoDatabaseNames({ ...defaultSettings, securiteInfoPlan: "paid" }).length, 15);
    assert.equal(getConfiguredSaneSecurityDatabaseNames(defaultSettings).length, 20);
    assert.deepEqual(getConfiguredSecuriteInfoDatabaseNames(defaultSettings), ["securiteinfo.ign2", "securiteinfoold.hdb"]);
    assert.deepEqual(getConfiguredSecuriteInfoDatabaseNames({ securiteInfoPlan: "basic", securiteInfoDatabases: ["securiteinfo.yara"] }), []);
});

test("legacy choices migrate without enabling extra databases and explicit empty selections survive reload", async () => {
    const service = testModule("modules/settings/server/service.ts", { "../../../server/core/runtimeState": { runtimeState: {} } });
    const rows = (values: any) => Object.entries(values).map(([key, value]) => ({ key, value: JSON.stringify(value) }));
    const legacy = await service.buildLoadedSettingsFromRows(rows({ securiteInfoPlan: "paid", securiteInfoIncludePua: false, saneSecurityProfile: "malware" }), null, null, false);
    assert.equal(getConfiguredSecuriteInfoDatabaseNames(legacy).length, 13);
    assert.equal(getConfiguredSaneSecurityDatabaseNames(legacy).length, 9);
    const empty = await service.buildLoadedSettingsFromRows(rows({ securiteInfoPlan: "paid", securiteInfoDatabases: [], saneSecurityDatabases: [] }), null, null, false);
    assert.deepEqual(getConfiguredSecuriteInfoDatabaseNames(empty), []);
    assert.deepEqual(getConfiguredSaneSecurityDatabaseNames(empty), []);
});

test("deselection removes only provider-owned files, including auxiliary files, and reports deletion failures", async t => {
    const f = stateFixture(t);
    for (const file of ["main.cvd", "securiteinfo.yara", "securiteinfo.ign2", "securiteinfo.mdb", "phish.ndb", "sigwhitelist.ign2"]) await fs.writeFile(path.join(f.directory, file), "fixture");
    await removeSecuriteInfoDatabaseFiles(f.directory, ["securiteinfo.ign2"]);
    await removeSaneSecurityDatabaseFiles(f.directory, ["phish.ndb"]);
    assert.equal(await fs.readFile(path.join(f.directory, "main.cvd"), "utf8"), "fixture");
    for (const file of ["securiteinfo.yara", "securiteinfo.mdb", "sigwhitelist.ign2"]) await assert.rejects(fs.stat(path.join(f.directory, file)), { code: "ENOENT" });
    assert.equal(await fs.readFile(path.join(f.directory, "securiteinfo.ign2"), "utf8"), "fixture");
    assert.equal(await fs.readFile(path.join(f.directory, "phish.ndb"), "utf8"), "fixture");
    const denied = testModule("addons/securiteinfo/server/service.ts", { "fs/promises": { unlink: async () => { throw Object.assign(new Error("access denied"), { code: "EACCES" }); } } });
    await assert.rejects(denied.removeSecuriteInfoDatabaseFiles(f.directory), /access denied/);
});

test("selected databases persist through the real SQLite settings store", async t => {
    const f = stateFixture(t);
    const storage = testModule("modules/settings/server/storage.ts", f.dependencies);
    const selected = { securiteInfoDatabases: ["securiteinfo.ign2", "securiteinfo.hdb"], saneSecurityDatabases: [] };
    storage.saveSettingsPatchRows(selected, Object.keys(selected));
    const { DatabaseSync } = await import("node:sqlite");
    const reopened = new DatabaseSync(f.databasePath, { readOnly: true });
    try {
        for (const [key, value] of Object.entries(selected)) assert.deepEqual(JSON.parse(String(reopened.prepare("SELECT value FROM settings WHERE key=?").get(key).value)), value);
    } finally { reopened.close(); }
});

test("FreshClam receives only selected SecuriteInfo URLs and cleans up its private config", async t => {
    const f = stateFixture(t);
    const provider = testModule("addons/securiteinfo/server/service.ts");
    const freshclam = testModule("engines/clamav/server/freshclam.ts", {
        "../../../addons/securiteinfo/server/service": { ...provider, loadSecuriteInfoToken: async () => "fixture-token" },
        "../../../server/platform/processes": { ensureAppTempDir: async () => f.directory, runHiddenProcess: async () => ({ code: 0, stdout: "ok" }) },
        "../../../server/core/paths": { appTempDir: f.directory, defaultLogsDir: f.directory }
    }, { URL });
    const prepared = await freshclam.prepareFreshclamConfig({ ...defaultSettings, clamavDir: f.directory, freshclamConf: path.join(f.directory, "freshclam.conf"), databaseDir: f.directory,
        securiteInfoEnabled: true, securiteInfoPlan: "paid", securiteInfoDatabases: ["securiteinfo.ign2", "securiteinfo.yara"] }, { includeOfficial: false, includeSecuriteInfo: true });
    const config = await fs.readFile(prepared.configPath, "utf8");
    assert.equal(config.split("DatabaseCustomURL ").length - 1, 2);
    assert.ok(config.includes("/fixture-token/securiteinfo.yara"));
    assert.ok(!config.includes("javascript.ndb"));
    assert.ok(!prepared.redact(config).includes("fixture-token"));
    await prepared.cleanup();
    await assert.rejects(fs.stat(prepared.configPath), { code: "ENOENT" });
});

test("empty SaneSecurity selection never downloads tools or installs old staged databases", async t => {
    const f = stateFixture(t); await fs.writeFile(path.join(f.directory, "phish.ndb"), "old");
    const installer = testModule("addons/sanesecurity/server/install.ts", { "./tools": { ensureSaneSecurityTools: async () => { throw new Error("unexpected download"); } } });
    const result = await installer.downloadAndInstallSaneSecurityDatabases({ databaseDir: f.directory, saneSecurityDatabases: [] }, () => {});
    assert.equal(result.length, 0);
    await assert.rejects(fs.stat(path.join(f.directory, "phish.ndb")), { code: "ENOENT" });
});

test("configuration refuses concurrent updates before writing settings or removing databases", async () => {
    for (const [provider, flag] of [["securiteinfo", "freshclamUpdateInProgress"], ["sanesecurity", "saneSecurityUpdateInProgress"]]) {
        let handler: any; const runtimeState: any = { [flag]: true };
        const file = provider === "securiteinfo" ? "postApiSecuriteinfoConfigure" : "postApiSanesecurityConfigure";
        const route = testModule(`addons/${provider}/server/routes/${file}.ts`, { "../../../../server/core/runtimeState": { runtimeState }, "../../../../modules/settings/server/service": { saveConfig: async () => { throw new Error("must not save"); } } });
        const context: any = { settings: { marker: true } }; const original = context.settings;
        route[`register${file[0].toUpperCase()}${file.slice(1)}`]({ post: (_: any, h: any) => { handler = h; } }, context);
        const res: any = { code: 200, status(code: number) { this.code = code; return this; }, json(body: any) { this.body = body; } };
        await handler({ body: { databases: [] } }, res);
        assert.equal(res.code, 409); assert.equal(context.settings, original);
    }
});
