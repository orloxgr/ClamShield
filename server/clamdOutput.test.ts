import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { parseClamFileDetection } from "../engines/clamav/server/output";

test("Shield accepts a real detection only for the file being scanned", () => {
    const file = path.resolve("test-downloads", "sample.zip");
    assert.deepEqual(parseClamFileDetection(`${file}: Eicar-Test-Signature FOUND`, file), {
        originalPath: file, threatName: "Eicar-Test-Signature"
    });
    assert.equal(parseClamFileDetection(`${path.resolve("other.zip")}: Eicar-Test-Signature FOUND`, file), null);
});

test("clamd startup diagnostics containing older FOUND lines cannot become threat notifications", () => {
    const file = path.resolve("test-downloads", "sample.zip");
    for (const line of [
        `clamd detail: Fri Oct 30 16:30:53 2026 -> ${file}: Old-Signature FOUND`,
        `Fri Oct 30 16:30:53 2026 -> ${file}: Old-Signature FOUND`,
        `clamd detail: ${file}: Old-Signature FOUND`,
        `${file}: OK`
    ]) assert.equal(parseClamFileDetection(line, file), null);
});
