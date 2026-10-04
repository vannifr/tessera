'use strict';
// Spike S1 scratch: writes /opt/tessera/manifest.json at image build time. Not production code.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const [baseRef, builtAt, revision] = process.argv.slice(2);
const root = '/opt/tessera';
const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const ver = (bin, args) => execFileSync(bin, args, { encoding: 'utf8' }).trim().split('\n')[0];

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
}

const [ref, digest] = baseRef.split('@');
const rules = fs
  .readdirSync(path.join(root, 'rules'))
  .filter((f) => f.endsWith('.yaml'))
  .sort()
  .map((f) => {
    const p = path.join(root, 'rules', f);
    return {
      name: 'p/' + f.replace(/^p-/, '').replace(/\.yaml$/, ''),
      path: p,
      sha256: sha(p),
      bytes: fs.statSync(p).size,
      fetchedAt: fs.readFileSync(p.replace(/\.yaml$/, '.fetchedAt'), 'utf8').trim(),
    };
  });
const files = {};
for (const p of walk(root).filter((p) => !p.endsWith('.fetchedAt')).sort()) files[p] = sha(p);

const manifest = {
  schema: 'tessera.scanner-image/v1',
  builtAt: builtAt || new Date().toISOString(),
  frameworkRevision: revision || 'unknown',
  base: { ref, digest },
  tools: {
    git: ver('/usr/bin/git', ['--version']),
    node: process.version,
    npm: ver('/usr/bin/npm', ['--version']),
    semgrep: ver('/usr/bin/semgrep', ['--version']),
    gitleaks: ver('/usr/local/bin/gitleaks', ['version']),
  },
  rules,
  files,
};
fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
process.stdout.write(JSON.stringify(manifest) + '\n');
