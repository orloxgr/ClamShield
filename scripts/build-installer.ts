import path from 'node:path';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { installNativeTools } from '../addons/sanesecurity/server/tools';

// Use the same current, verified 7-Zip as the application instead of the
// older extractor bundled by the packaging tool. Do not modify global tools.
const root = path.resolve(import.meta.dirname, '..');
if (process.platform === 'win32') {
    const directory = path.join(root, 'build', 'native-tools');
    await installNativeTools(directory, path.join(root, 'build', 'native-tools-cache'), console.log);
    process.env.ELECTRON_BUILDER_7ZIP_PATH = path.join(directory, 'archive', 'ucrt64', 'bin', '7z.exe');
}
const require = createRequire(import.meta.url);
const child = spawn(process.execPath, [require.resolve('electron-builder/out/cli/cli.js'), ...process.argv.slice(2)], {
    cwd: root, env: process.env, stdio: 'inherit', windowsHide: true
});
child.once('error', error => { console.error(error); process.exitCode = 1; });
child.once('exit', code => { process.exitCode = code ?? 1; });
