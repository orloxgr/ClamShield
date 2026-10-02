const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const { buildBlockMap } = require("app-builder-lib/out/targets/blockmap/blockmap");

const root = path.resolve(__dirname, "..");
const certSubject = process.env.CLAMSHIELD_CODESIGN_SUBJECT || "ClamShield Local Code Signing";
const certSha1 = process.env.CLAMSHIELD_CODESIGN_SHA1;

function findSigntool() {
  const candidates = [
    process.env.SIGNTOOL_EXE,
    path.join(
      process.env.LOCALAPPDATA || "",
      "electron-builder",
      "Cache",
      "winCodeSign",
      "winCodeSign-2.6.0",
      "windows-10",
      "x64",
      "signtool.exe"
    ),
    "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe",
    "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.22621.0\\x64\\signtool.exe",
    "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.22000.0\\x64\\signtool.exe"
  ].filter(Boolean);

  return candidates.find((candidate) => fs.existsSync(candidate));
}

function existing(paths) {
  return paths.filter((file) => file && fs.existsSync(file));
}

function signFile(signtool, file) {
  const selector = certSha1 ? ["/sha1", certSha1] : ["/n", certSubject];
  const args = [
    "sign",
    "/fd",
    "SHA256",
    "/s",
    "My",
    ...selector,
    "/v",
    file
  ];

  console.log(`Signing ${path.relative(root, file) || file}`);
  const result = spawnSync(signtool, args, {
    cwd: root,
    encoding: "utf8",
    stdio: "pipe"
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.status !== 0) {
    throw new Error(`signtool failed for ${file}`);
  }
}

function signFiles(files) {
  if (process.platform !== "win32") return;

  const signtool = findSigntool();
  if (!signtool) {
    const message = "signtool.exe was not found; Windows artifacts were not signed.";
    if (process.env.CLAMSHIELD_REQUIRE_SIGNING === "1") throw new Error(message);
    console.warn(message);
    return;
  }

  const targets = existing(files);
  if (targets.length === 0) return;
  for (const file of targets) signFile(signtool, file);
}

function sha512Base64(file) {
  return crypto.createHash("sha512").update(fs.readFileSync(file)).digest("base64");
}

async function refreshInstallerMetadata(installerPath) {
  if (!/\.exe$/i.test(installerPath) || !/setup/i.test(path.basename(installerPath))) return;
  const blockMapPath = `${installerPath}.blockmap`;
  await buildBlockMap(installerPath, "gzip", blockMapPath);

  const latestPath = path.join(path.dirname(installerPath), "latest.yml");
  if (!fs.existsSync(latestPath)) return;

  const hash = sha512Base64(installerPath);
  const size = fs.statSync(installerPath).size;
  const latest = fs.readFileSync(latestPath, "utf8")
    .replace(/sha512: .+/g, `sha512: ${hash}`)
    .replace(/size: \d+/, `size: ${size}`);
  fs.writeFileSync(latestPath, latest);
}

module.exports = async function signWindowsArtifacts(context) {
  if (context && context.appOutDir) {
    signFiles([
      path.join(context.appOutDir, "ClamShield.exe"),
      path.join(context.appOutDir, "shell", "ClamShieldShellExt.dll")
    ]);
    return;
  }

  if (context && Array.isArray(context.artifactPaths)) {
    const artifactsToSign = context.artifactPaths.filter((file) => /\.(exe|msi|msix)$/i.test(file));
    signFiles(artifactsToSign);
    for (const file of artifactsToSign) {
      await refreshInstallerMetadata(file);
    }
    return context.artifactPaths;
  }

  const manualTargets = [
    path.join(root, "shell", "ClamShieldShellExt.dll"),
    path.join(root, "release", require("../package.json").version, "win-unpacked", "ClamShield.exe"),
    path.join(root, "release", require("../package.json").version, "win-unpacked", "shell", "ClamShieldShellExt.dll"),
    path.join(root, "release", require("../package.json").version, `ClamShield-Setup-${require("../package.json").version}.exe`)
  ];
  signFiles(manualTargets);
  for (const file of manualTargets) {
    if (fs.existsSync(file)) await refreshInstallerMetadata(file);
  }
};

if (require.main === module) {
  module.exports().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
