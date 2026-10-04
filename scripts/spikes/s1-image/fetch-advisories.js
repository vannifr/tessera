'use strict';
// Spike S1 scratch host step (contracts/advisory-data.ts, FetchAdvisories). Not production code.
// Usage: node fetch-advisories.js <captured-request.json> <snapshot-out.json> <meta-out.json>
const fs = require('node:fs');
const zlib = require('node:zlib');
const crypto = require('node:crypto');

const URL_BULK = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

async function main() {
  const [reqPath, outPath, metaPath] = process.argv.slice(2);
  const raw = fs.readFileSync(reqPath);
  const body = JSON.parse(raw.toString('utf8'));
  const names = Object.keys(body).length;
  const versions = Object.values(body).reduce((n, v) => n + v.length, 0);
  const canonical = Buffer.from(JSON.stringify(body));
  const res = await fetch(URL_BULK, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
    body: zlib.gzipSync(canonical),
    signal: AbortSignal.timeout(60_000),
    redirect: 'error',
  });
  const bytes = Buffer.from(await res.arrayBuffer());
  const parsed = JSON.parse(bytes.toString('utf8'));
  const ok = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) && Object.values(parsed).every(Array.isArray);
  fs.writeFileSync(outPath, bytes);
  const meta = {
    url: URL_BULK,
    fetchedAt: new Date().toISOString(),
    requestSha256: sha(canonical),
    names,
    versions,
    httpStatus: res.status,
    responseSha256: sha(bytes),
    responseBytes: bytes.length,
    objectOfArrays: ok,
    advisoryPackages: Object.keys(parsed).sort(),
  };
  fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2) + '\n');
  process.stdout.write(JSON.stringify(meta) + '\n');
  process.exit(res.status === 200 && ok ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`fetch failed: ${e.message}\n`);
  process.exit(1);
});
