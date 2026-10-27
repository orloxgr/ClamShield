import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
const { validateAudit, verifyInstalledDependencies } = createRequire(import.meta.url)("../scripts/verify-release-security.cjs");

test("release security gate accepts only a complete zero-vulnerability audit", () => {
    assert.doesNotThrow(() => validateAudit({ metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: {} }));
    for (const report of [{}, { metadata: { vulnerabilities: { total: 0 } } }, { metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: { electron: {} } }]) {
        assert.throws(() => validateAudit(report), /Release blocked/);
    }
});

test("release security gate rejects vulnerable development dependencies at every severity", () => {
    for (const severity of ["low", "moderate", "high", "critical"]) {
        assert.throws(() => validateAudit({ metadata: { vulnerabilities: { total: 1, [severity]: 1 } }, vulnerabilities: { electron: { severity, isDirect: true } } }), /Release blocked/);
    }
});

test("a clean lockfile cannot hide a stale installed module or a missing required module", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "clamshield-release-gate-"));
    try {
        fs.mkdirSync(path.join(root, "node_modules", "example"), { recursive: true });
        fs.writeFileSync(path.join(root, "package-lock.json"), JSON.stringify({ packages: { "": {}, "node_modules/example": { version: "1.2.3" }, "node_modules/optional-platform": { version: "1.0.0", optional: true } } }));
        const manifest = path.join(root, "node_modules", "example", "package.json");
        fs.writeFileSync(manifest, JSON.stringify({ version: "1.2.2" }));
        assert.throws(() => verifyInstalledDependencies(root), /differs from lockfile/);
        fs.writeFileSync(manifest, JSON.stringify({ version: "1.2.3" }));
        assert.doesNotThrow(() => verifyInstalledDependencies(root));
        fs.unlinkSync(manifest);
        assert.throws(() => verifyInstalledDependencies(root), /Missing installed dependency/);
    } finally {
        const resolved = path.resolve(root);
        assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolved).startsWith("clamshield-release-gate-"));
        fs.rmSync(resolved, { recursive: true, force: true });
    }
});
