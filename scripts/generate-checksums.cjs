const { createHash } = require("crypto");
const { createReadStream } = require("fs");
const fs = require("fs/promises");
const path = require("path");

const hashAlgorithm = "sha256";

function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash(hashAlgorithm);
    const stream = createReadStream(filePath);
    stream.on("data", chunk => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function getReleaseDir() {
  if (process.argv[2]) {
    return path.resolve(process.argv[2]);
  }
  const pkg = require("../package.json");
  return path.resolve(__dirname, "..", "release", pkg.version);
}

async function main() {
  const releaseDir = await getReleaseDir();
  const entries = await fs.readdir(releaseDir, { withFileTypes: true });
  const files = entries
    .filter(entry => entry.isFile())
    .map(entry => entry.name)
    .filter(name => !/^sha256sums\.txt$/i.test(name))
    .filter(name => {
      const lower = name.toLowerCase();
      return lower === "latest.yml" || lower.endsWith(".exe") || lower.endsWith(".exe.blockmap");
    })
    .sort((a, b) => a.localeCompare(b));

  if (files.length === 0) {
    throw new Error(`No files found in ${releaseDir}`);
  }

  const lines = [];
  for (const fileName of files) {
    const filePath = path.join(releaseDir, fileName);
    const digest = await hashFile(filePath);
    lines.push(`${digest}  ${fileName}`);
  }

  const outputPath = path.join(releaseDir, "SHA256SUMS.txt");
  await fs.writeFile(outputPath, `${lines.join("\n")}\n`, "utf8");
  console.log(`Wrote ${outputPath}`);
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
