const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

// Chokidar 6.0.0's Windows root-parent subscription can rescan a root before
// its initial enumeration finishes. That bypasses ignoreInitial and emits old
// files as new downloads. Keep this explicit, versioned patch until an upstream
// release fixes the race; do not silently apply it to a different dependency.
const upstreamHash = '4eae2746da12302e224a3aa1422a4852294fd00a1eb64604c5eb02aa6c0b0484';
const patchedHash = '9ea0de0f80c82d13be7d71d6f166803a06585e37066a995ba7bf4f4455a9811a';
const edits = [
    ['    watchRootParent(dir, wh) {',
     '    watchRootParent(dir, wh, runWhenInitialized = (run) => run()) {'],
    [`            if (trigger.kind !== 'native' || !matchesRoot(trigger.relativePath) || !isActive())
                return;
            void this.reconcileBackendTrigger(dir, false, trigger, async () => {`,
     `            if (trigger.kind !== 'native' || !matchesRoot(trigger.relativePath) || !isActive())
                return;
            runWhenInitialized(() => {
                if (!isActive())
                    return;
                void this.reconcileBackendTrigger(dir, false, trigger, async () => {`],
    [`            }, isActive);
        };
        const subscription = setFsWatchListener(parentPath`,
     `                }, isActive);
            });
        };
        const subscription = setFsWatchListener(parentPath`],
    ['            let initializing = !target;',
     '            let initializing = !target;\n            let pendingRootInvalidation;'],
    ['            const rootParentCloser = depth === 0 && !target ? this.watchRootParent(dir, wh) : undefined;',
     `            const rootParentCloser = depth === 0 && !target ? this.watchRootParent(dir, wh, (run) => {
                if (initializing)
                    pendingRootInvalidation = run;
                else
                    run();
            }) : undefined;`],
    [`                replayCreates.forEach((path) => this.fsw.tree.clearInitialCreate(path));
                initializing = false;`,
     `                replayCreates.forEach((path) => this.fsw.tree.clearInitialCreate(path));
                initializing = false;
                pendingRootInvalidation?.();
                pendingRootInvalidation = undefined;`]
];

function patchedSource(source) {
    for (const [before, after] of edits) {
        if (source.split(before).length !== 2)
            throw new Error('Chokidar startup patch context changed. Review the upstream fix before continuing.');
        source = source.replace(before, after);
    }
    // Keep the wrapped upstream callback indented without changing its logic.
    const start = source.indexOf('                void this.reconcileBackendTrigger(dir, false, trigger, async () => {');
    const end = source.indexOf('                }, isActive);', start);
    const bodyStart = source.indexOf('\n', start) + 1;
    source = source.slice(0, bodyStart) + source.slice(bodyStart, end).split('\n').map(line => line ? `    ${line}` : line).join('\n') + source.slice(end);
    return source;
}

const hash = source => createHash('sha256').update(source).digest('hex');

function verifyOrApply(root = path.resolve(__dirname, '..'), checkOnly = false) {
    const directory = path.join(root, 'node_modules', 'chokidar');
    const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
    if (manifest.version !== '6.0.0')
        throw new Error('Chokidar changed version. Review/remove the Windows startup patch before building.');
    const file = path.join(directory, 'reconcile.js');
    const source = fs.readFileSync(file, 'utf8');
    if (hash(source) === patchedHash) {
        return;
    }
    if (hash(source) !== upstreamHash)
        throw new Error('Chokidar source differs from pinned upstream 6.0.0. Refusing to patch it.');
    if (checkOnly)
        throw new Error('Missing Chokidar Windows startup fix. Run npm install before building.');
    const patched = patchedSource(source);
    if (hash(patched) !== patchedHash)
        throw new Error('Chokidar startup patch did not produce the reviewed source.');
    fs.writeFileSync(file, patched);
    console.log('Applied Chokidar 6.0.0 Windows startup fix.');
}

module.exports = { verifyOrApply };
if (require.main === module) {
    try { verifyOrApply(undefined, process.argv.includes('--check')); }
    catch (error) { console.error(error.message); process.exitCode = 1; }
}
