const { execFile } = require("child_process");
const fs = require("fs/promises");
const path = require("path");

if (process.platform !== "win32") {
  process.exit(0);
}

function run(command, args) {
  return new Promise((resolve) => {
    execFile(command, args, { windowsHide: true }, (error, stdout, stderr) => {
      resolve({ error, stdout, stderr });
    });
  });
}

async function main() {
  const list = await run("tasklist.exe", ["/FI", "IMAGENAME eq ClamShield.exe", "/NH"]);
  if (!list.stdout || !list.stdout.toLowerCase().includes("clamshield.exe")) {
    await prepareOutputDir();
    return;
  }

  console.log("Closing running ClamShield.exe before packaging...");
  await run("taskkill.exe", ["/IM", "ClamShield.exe", "/T", "/F"]);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  await prepareOutputDir();
}

async function prepareOutputDir() {
  const pkg = require("../package.json");
  const releaseDir = path.resolve(__dirname, "..", "release");
  const unpackedDir = path.join(releaseDir, pkg.version, "win-unpacked");

  try {
    await fs.rm(unpackedDir, { recursive: true, force: true });
  } catch (error) {
    const staleDir = path.join(releaseDir, pkg.version, `win-unpacked-stale-${Date.now()}`);
    console.warn(`Could not remove win-unpacked directly (${error.code || error.message}). Moving it aside.`);
    await fs.rename(unpackedDir, staleDir);
  }
}

main().catch((error) => {
  console.warn(`Release preparation warning: ${error.message}`);
});
