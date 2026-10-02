const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const project = path.join(root, "native", "ClamShieldShellExt", "ClamShieldShellExt.vcxproj");

const candidates = [
  process.env.MSBUILD_EXE,
  "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe",
  "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe",
  "C:\\Program Files\\Microsoft Visual Studio\\2019\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe",
  "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe"
].filter(Boolean);

const msbuild = candidates.find(candidate => fs.existsSync(candidate));
if (!msbuild) {
  console.error("MSBuild was not found. Install Visual Studio Build Tools with the C++ desktop workload, or set MSBUILD_EXE.");
  process.exit(1);
}

const result = spawnSync(msbuild, [
  project,
  "/p:Configuration=Release",
  "/p:Platform=x64",
  "/m",
  "/nologo"
], {
  cwd: root,
  stdio: "inherit"
});

if (result.status !== 0) process.exit(result.status || 1);

const output = path.join(root, "shell", "ClamShieldShellExt.dll");
if (!fs.existsSync(output)) {
  console.error(`Native shell extension build completed, but ${output} was not created.`);
  process.exit(1);
}
