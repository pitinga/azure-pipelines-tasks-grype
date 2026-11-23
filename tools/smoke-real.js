'use strict';
// Manual CI smoke test: run actual, SHA256-verified downloads of both Anchore
// binaries, then check a real Syft->Grype SBOM scan (when enabled).
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const { installTool } = require('../lib/installer');
const { execute } = require('../lib/cli');

async function main() {
  if (Number(process.versions.node.split('.')[0]) !== 24) {
    throw new Error('O smoke test deve executar exclusivamente em Node 24.');
  }
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'grype-syft-real-'));
  try {
    const versions = {
      grype: process.env.GRYPE_VERSION_REQUESTED || 'latest',
      syft: process.env.SYFT_VERSION_REQUESTED || 'latest',
    };
    const binaries = {};
    for (const tool of ['grype', 'syft']) {
      const found = await installTool(tool, versions[tool], directory);
      binaries[tool] = found.binary;
      await execute(found.binary, ['version']);
      console.log(`PASS: ${tool} ${found.version} ${process.platform}/${process.arch} (checksum verificado).`);
    }

    if (process.env.SMOKE_FULL_SCAN === 'true') {
      const project = path.resolve(__dirname, '..');
      const sbom = path.join(directory, 'project-sbom.json');
      const report = path.join(directory, 'grype-results.json');
      await execute(binaries.syft, [`dir:${project}`, '-o', `syft-json=${sbom}`]);
      if (!fs.existsSync(sbom) || fs.statSync(sbom).size < 2) {
        throw new Error('Syft não gerou SBOM válida no smoke test.');
      }
      await execute(binaries.grype, ['--output', 'json', '--file', report, '--', `sbom:${sbom}`]);
      const parsed = JSON.parse(await fsp.readFile(report, 'utf8'));
      if (!Array.isArray(parsed.matches)) throw new Error('Grype não produziu JSON com matches.');
      console.log(`PASS: Syft->Grype com banco real (${parsed.matches.length} ocorrências).`);
    }
  } finally {
    await fsp.rm(directory, { recursive: true, force: true });
  }
}

if (require.main === module) main().catch(error => {
  console.error(`ERRO no smoke test: ${error.message}`);
  process.exitCode = 1;
});
module.exports = { main };
