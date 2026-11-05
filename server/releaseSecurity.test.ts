import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
const { validateAudit, verifyInstalledDependencies } = createRequire(import.meta.url)("../scripts/verify-release-security.cjs");

test("final installer metadata uses the final signed bytes without modifying the installer", async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clamshield-release-metadata-"));
    t.after(() => {
        assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
        assert.ok(path.basename(directory).startsWith("clamshield-release-metadata-"));
        fs.rmSync(directory, { recursive: true, force: true });
    });
    const installer = path.join(directory, "ClamShield-Setup-fixture.exe");
    const unsigned = Buffer.from("unsigned fixture"), final = Buffer.from("fixture with final signature bytes");
    const hash = (bytes: Buffer) => createHash("sha512").update(bytes).digest("base64");
    fs.writeFileSync(installer, final);
    fs.writeFileSync(path.join(directory, "latest.yml"), `files:\n  - url: ClamShield-Setup-fixture.exe\n    sha512: ${hash(unsigned)}\n    size: ${unsigned.length}\nsha512: ${hash(unsigned)}\n`);
    const { refreshInstallerMetadata } = createRequire(import.meta.url)("../scripts/sign-windows-artifacts.cjs");
    await refreshInstallerMetadata(installer);
    const metadata = fs.readFileSync(path.join(directory, "latest.yml"), "utf8");
    assert.equal(metadata.split(hash(final)).length - 1, 2);
    assert.ok(metadata.includes(`size: ${final.length}`));
    assert.ok(!metadata.includes(hash(unsigned)));
    assert.deepEqual(fs.readFileSync(installer), final);
    assert.ok(fs.statSync(installer + ".blockmap").size > 0);
});

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
