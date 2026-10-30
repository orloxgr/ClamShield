import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
const { verifyOrApply } = createRequire(import.meta.url)("../scripts/patch-chokidar.cjs");

test("the Windows watcher fix is verified and refuses changed dependency code or versions", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "clamshield-dependency-patch-"));
    try {
        const directory = path.join(root, "node_modules", "chokidar");
        fs.mkdirSync(directory, { recursive: true });
        const manifest = path.join(directory, "package.json");
        const source = path.join(directory, "reconcile.js");
        fs.writeFileSync(manifest, JSON.stringify({ version: "6.0.0" }));
        fs.copyFileSync("node_modules/chokidar/reconcile.js", source);
        assert.doesNotThrow(() => verifyOrApply(root, true));
        assert.doesNotThrow(() => verifyOrApply(root));
        fs.appendFileSync(source, "\n// unexpected modification\n");
        assert.throws(() => verifyOrApply(root, true), /differs from pinned upstream/);
        assert.throws(() => verifyOrApply(root), /Refusing to patch/);
        fs.writeFileSync(manifest, JSON.stringify({ version: "6.0.1" }));
        assert.throws(() => verifyOrApply(root), /changed version/);
    } finally {
        const resolved = path.resolve(root);
        assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolved).startsWith("clamshield-dependency-patch-"));
        fs.rmSync(resolved, { recursive: true, force: true });
    }
});
