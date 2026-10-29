import assert from 'node:assert/strict';
import test from 'node:test';
import { dashboardProtectionState } from '../modules/dashboard/ui/protection';

test('a fresh Windows installation cannot report protection before its engine and signatures exist', () => {
    const enabled = { settings: { shieldEnabled: true }, isSimulated: false };
    assert.equal(dashboardProtectionState({ ...enabled, hasEngine: false, hasDb: false }), 'engine-missing');
    assert.equal(dashboardProtectionState({ ...enabled, hasEngine: true, hasDb: false }), 'definitions-missing');
    assert.equal(dashboardProtectionState({ ...enabled, hasEngine: true, hasDb: true }), 'protected');
});

test('missing status, simulation and a disabled Shield never report active protection', () => {
    assert.equal(dashboardProtectionState(null), 'engine-missing');
    assert.equal(dashboardProtectionState({ hasEngine: true, hasDb: true, isSimulated: true, settings: { shieldEnabled: true } }), 'engine-missing');
    assert.equal(dashboardProtectionState({ hasEngine: true, hasDb: true, settings: { shieldEnabled: false } }), 'shield-off');
});
