import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { FSWatcher } from "chokidar";

async function within<T>(promise: Promise<T>, message: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    try {
        return await Promise.race([promise, new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error(message)), 8000);
        })]);
    } finally {
        clearTimeout(timer!);
    }
}

test("Windows folder metadata changes during Shield startup do not turn existing files into downloads", {
    skip: process.platform !== "win32", timeout: 15000
}, async t => {
    const base = await fs.mkdtemp(path.join(os.tmpdir(), "clamshield-shield-startup-"));
    const root = path.join(base, "Downloads");
    await fs.mkdir(root);
    const oldFiles = Array.from({ length: 60 }, (_, i) => path.join(root, `old-${i}.txt`));
    await Promise.all(oldFiles.map(file => fs.writeFile(file, "already present")));
    const watcher: any = new FSWatcher({
        ignoreInitial: true, depth: 1, ignorePermissionErrors: true,
        awaitWriteFinish: { stabilityThreshold: 100, pollInterval: 50 }
    });
    t.after(async () => {
        await watcher.close();
        const resolved = path.resolve(base);
        assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolved).startsWith("clamshield-shield-startup-"));
        await fs.rm(resolved, { recursive: true, force: true });
    });

    // Slow only the first directory enumeration to reproduce startup on a busy
    // disk. Real Windows fs.watch notifications still drive reconciliation.
    const originalScan = watcher.createScanStream.bind(watcher);
    let delayed = false;
    let started!: () => void;
    const scanning = new Promise<void>(resolve => { started = resolve; });
    watcher.createScanStream = (folder: string, options: any) => {
        const stream = originalScan(folder, options);
        if (delayed || folder !== root || !stream) return stream;
        delayed = true;
        return Readable.from((async function* () {
            try {
                for await (const entry of stream) {
                    started();
                    await new Promise(resolve => setTimeout(resolve, 8));
                    yield entry;
                }
            } finally {
                stream.destroy();
            }
        })());
    };
    const additions: string[] = [];
    watcher.on("add", (file: string) => additions.push(file));
    let rootNotifications = 0;
    watcher.on("raw", (_event: string, filename: string) => {
        if (filename === "Downloads") rootNotifications++;
    });
    const ready = new Promise<void>((resolve, reject) => {
        watcher.once("ready", resolve);
        watcher.once("error", reject);
    });
    // Attach a rejection handler before waiting for the scan to begin.
    ready.catch(() => {});
    watcher.add(root);
    await within(scanning, "Initial directory enumeration did not start");
    await fs.utimes(root, new Date(), new Date());
    const downloadedDuringStartup = path.join(root, "new-during-startup.txt");
    const startupDownload = new Promise<void>(resolve => watcher.on("add", (file: string) => {
        if (file === downloadedDuringStartup) resolve();
    }));
    await fs.writeFile(downloadedDuringStartup, "a real new download");
    await within(ready, "Watcher never became ready after a folder metadata notification");
    await within(startupDownload, "A file downloaded during startup was missed");
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.ok(rootNotifications > 0, "The Windows root-parent notification must be exercised");
    assert.equal(additions.filter(file => oldFiles.includes(file)).length, 0, "Existing files must not be emitted as new downloads");
    assert.equal(additions.filter(file => file === downloadedDuringStartup).length, 1);

    const downloadedAfterStartup = path.join(root, "new-after-startup.txt");
    const next = new Promise<void>(resolve => watcher.on("add", (file: string) => {
        if (file === downloadedAfterStartup) resolve();
    }));
    await fs.writeFile(downloadedAfterStartup, "a later download");
    await within(next, "A file downloaded after startup was missed");

    const modified = new Promise<void>(resolve => watcher.on("change", (file: string) => {
        if (file === oldFiles[0]) resolve();
    }));
    await fs.writeFile(oldFiles[0], "changed after startup");
    await within(modified, "A real change to an existing file was missed");

    const unlinked = new Promise<void>(resolve => watcher.on("unlink", (file: string) => {
        if (file === downloadedAfterStartup) resolve();
    }));
    await fs.unlink(downloadedAfterStartup);
    await within(unlinked, "Removing a downloaded file was missed");
    const downloadedAgain = new Promise<void>(resolve => watcher.on("add", (file: string) => {
        if (file === downloadedAfterStartup) resolve();
    }));
    await fs.writeFile(downloadedAfterStartup, "a later download");
    await within(downloadedAgain, "Downloading the same file again was missed");
});
