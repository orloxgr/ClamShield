import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { testModule } from './testModule';

function fixture(results: any[], platform = 'win32') {
    const scripts: string[] = [];
    const defender = testModule('server/platform/defender.ts', { './processes': { runPowerShellJson: async (script: string) => {
        scripts.push(script);
        const result = results.shift();
        if (result instanceof Error) throw result;
        return result;
    } } }, { process: { ...process, platform }, console: { warn() {} } });
    return { defender, scripts };
}
test('Tamper Protection refusal does not execute a Defender change', async () => {
    const f = fixture([{ IsTamperProtected: true, RealTimeProtectionEnabled: true }]);
    const result = await f.defender.requestDefenderPause();
    assert.equal(result.Success, false);
    assert.equal(result.SideBySideMode, true);
    assert.equal(result.NeedsManualAction, true);
    assert.equal(f.scripts.length, 1);
});
test('blocked pause, restore and exclusion changes remain failures with actionable status', async () => {
    const blocked = { Success: false, NeedsManualAction: true, Message: 'Device policy blocked the change' };
    const f = fixture([{ IsTamperProtected: false }, blocked, blocked, { ...blocked, PendingPaths: ['blocked'] }]);
    assert.equal((await f.defender.requestDefenderPause()).Success, false);
    assert.equal((await f.defender.restoreDefenderPreferences()).NeedsManualAction, true);
    const exclusions = await f.defender.syncDefenderCompatibilityExclusions({ yaraDir: "C:\\test's folder", defenderCompatibilityExclusionsEnabled: true });
    assert.equal(exclusions.Success, false);
    assert.deepEqual(exclusions.PendingPaths, ['blocked']);
    assert.ok(f.scripts[3].includes("test''s folder"));
});
test('PowerShell execution failure is not reported as successful protection change', async () => {
    const f = fixture([new Error('access denied')]);
    const result = await f.defender.autoDisableDefender();
    assert.equal(result.Success, false);
    assert.equal(result.Error, 'access denied');
});
test('unsupported platform never invokes PowerShell', async () => {
    const f = fixture([], 'linux');
    assert.equal((await f.defender.requestDefenderPause()).Supported, false);
    assert.equal((await f.defender.restoreDefenderPreferences()).Success, false);
    assert.equal((await f.defender.syncDefenderCompatibilityExclusions({ yaraDir: '/tmp/test' })).Supported, false);
    assert.equal(f.scripts.length, 0);
});

test('exclusion cleanup fails when Windows cannot verify the resulting preferences', { skip: process.platform !== 'win32' }, () => {
    const f = fixture([]);
    const script = `function Get-MpPreference { throw 'Preferences unavailable' }\n${f.defender.defenderCompatibilityExclusionsScript(['C:\\ClamShield-QA\\quarantine'], false)}`;
    const output = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true });
    const result = JSON.parse(output.split('CLAMSHIELD_JSON_START')[1].split('CLAMSHIELD_JSON_END')[0]);
    assert.equal(result.Success, false);
    assert.equal(result.NeedsManualAction, true);
    assert.match(result.Operations.Verify, /Preferences unavailable/);
});
