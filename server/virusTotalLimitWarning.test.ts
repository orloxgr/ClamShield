import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import ts from "typescript";
import { estimateVirusTotalScan, virusTotalLimitWarningsEnabled } from "./virusTotalLimitWarning";

const now = Date.UTC(2026, 9, 15, 12);
const usage = {
    rate: { spacingMs: 16_000, nextLookupAllowedAt: 0 },
    day: { limit: 500, remaining: 500, resetsAt: Date.UTC(2026, 9, 16) },
    month: { limit: 15500, remaining: 15500, resetsAt: Date.UTC(2026, 10, 1) }
};

test("missing, empty and checked warning values are on; explicit unchecked is off", () => {
    for (const value of [undefined, null, "", true]) assert.equal(virusTotalLimitWarningsEnabled(value), true);
    assert.equal(virusTotalLimitWarningsEnabled(false), false);
    assert.equal(virusTotalLimitWarningsEnabled(JSON.parse(JSON.stringify({ warning: false })).warning), false);
});

test("the actual settings route saves only this preference and preserves existing installation choices", async () => {
    const source = fs.readFileSync("server.ts", "utf8");
    const tree = ts.createSourceFile("server.ts", source, ts.ScriptTarget.Latest, true);
    let normalizer = "", handler = "";
    const visit = (node: ts.Node) => {
        if (ts.isFunctionDeclaration(node) && node.name?.text === "normalizeSettingsPatch") normalizer = node.getText(tree);
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "post" &&
            node.arguments[0] && ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === "/api/settings") handler = node.arguments[1].getText(tree);
        ts.forEachChild(node, visit);
    };
    visit(tree); assert.ok(normalizer); assert.ok(handler);
    for (const value of [undefined, null, "", true, false]) {
        const original = { startMinimized: false, startOnBoot: true, defenderCompatibilityExclusionsEnabled: false, virusTotalCloudEnabled: true };
        let persisted: any = {}, scheduled = 0;
        const context = vm.createContext({
            settings: { ...original }, virusTotalLimitWarningsEnabled,
            asRecord: (value: any) => value || {}, readOnlySettingKeys: new Set(),
            userWritableSettingKeys: new Set(["virusTotalShowLimitWarnings"]), pathSettingKeys: new Set(), pathListSettingKeys: new Set(),
            booleanSettingKeys: new Set(["virusTotalShowLimitWarnings"]), getSettingFallback: () => true,
            saveSettingsPatchRows: (settings: any, keys: string[]) => { persisted = Object.fromEntries(keys.map(key => [key, settings[key]])); },
            virusTotalScanQueue: { disableConfirmations: () => {} }, scheduleVirusTotalScan: () => { scheduled++; }
        });
        const javascript = ts.transpileModule(`${normalizer}\nglobalThis.handler = ${handler};`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
        vm.runInContext(javascript, context);
        let response: any;
        const res = { json: (data: any) => { response = data; }, status: () => res };
        await context.handler({ body: { virusTotalShowLimitWarnings: value } }, res);
        assert.equal(response.success, true);
        assert.deepEqual(persisted, { virusTotalShowLimitWarnings: value !== false });
        for (const [key, expected] of Object.entries(original)) assert.equal(response.settings[key], expected);
        assert.equal(scheduled, value === false ? 1 : 0);
    }
});

test("estimates use the app's real pacing, including an already reserved slot", () => {
    assert.deepEqual(estimateVirusTotalScan(40, usage, now), { files: 40, durationMs: 640_000, duration: "11 minutes" });
    assert.equal(estimateVirusTotalScan(5, usage, now).duration, "2 minutes");
    assert.equal(estimateVirusTotalScan(40, { ...usage, rate: { spacingMs: 16_000, nextLookupAllowedAt: now + 60_000 } }, now).durationMs, 700_000);
});

test("estimates include daily and monthly quota waits and keep zero allowance distinct", () => {
    const daily = estimateVirusTotalScan(40, { ...usage, day: { ...usage.day, remaining: 10 } }, now);
    assert.equal(daily.durationMs, 12 * 3600_000 + 30 * 16_000);
    const monthly = estimateVirusTotalScan(40, { ...usage, month: { ...usage.month, remaining: 0 } }, now);
    assert.equal(monthly.durationMs, usage.month.resetsAt - now + 40 * 16_000);
    assert.equal(estimateVirusTotalScan(40, { ...usage, day: { ...usage.day, limit: 0, remaining: 0 } }, now).durationMs, null);
    const large = estimateVirusTotalScan(1100, usage, now);
    assert.equal(large.durationMs, 36 * 3600_000 + 100 * 16_000);
});
