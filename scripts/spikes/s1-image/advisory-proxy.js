'use strict';
// Spike S1 scratch version of config/isolation/bin/advisory-proxy.js (contracts/advisory-data.ts).
// Node built-ins only. Not production code.
const http = require('node:http');
const zlib = require('node:zlib');
const { spawn } = require('node:child_process');

const MAX_BODY = 5 * 1024 * 1024;
const MAX_SNAPSHOT = 32 * 1024 * 1024;
const BULK = '/-/npm/v1/security/advisories/bulk';

const mode = process.argv[2];
const sep = process.argv.indexOf('--');
if ((mode !== 'record' && mode !== 'replay') || sep !== 3 || process.argv.length < 5) {
  process.stderr.write('usage: advisory-proxy.js record|replay -- <npm> <args...>\n');
  process.exit(2);
}
const cmd = process.argv[4];
const cmdArgs = process.argv.slice(5);

function readAll(stream, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('too-large'));
        stream.destroy();
        return;
      }
      chunks.push(c);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

function isObjectOfArrays(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && Object.values(v).every(Array.isArray);
}

const requests = [];

async function main() {
  let snapshot = null;
  if (mode === 'replay') {
    let raw;
    try {
      raw = await readAll(process.stdin, MAX_SNAPSHOT);
    } catch {
      process.exit(4);
    }
    let parsed;
    try {
      parsed = raw.length > 0 ? JSON.parse(raw.toString('utf8')) : null;
    } catch {
      parsed = null;
    }
    if (!isObjectOfArrays(parsed)) {
      process.stderr.write('tessera: advisory snapshot empty or invalid\n');
      process.exit(4);
    }
    snapshot = raw;
  }

  let captured = null;
  const server = http.createServer((req, res) => {
    const path = (req.url || '').split('?')[0];
    requests.push(`${req.method} ${path}`);
    const isBulk = req.method === 'POST' && path.endsWith(BULK);
    if (mode === 'record') {
      if (isBulk && captured === null) {
        const src = /gzip/i.test(req.headers['content-encoding'] || '') ? req.pipe(zlib.createGunzip()) : req;
        readAll(src, MAX_BODY)
          .then((buf) => {
            try {
              if (isObjectOfArrays(JSON.parse(buf.toString('utf8')))) captured = buf;
            } catch {}
          })
          .catch(() => {})
          .finally(() => {
            res.writeHead(503).end();
          });
        return;
      }
      req.resume();
      res.writeHead(503).end();
      return;
    }
    req.resume();
    if (isBulk) {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': snapshot.length });
      res.end(snapshot);
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' }).end('{}');
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const child = spawn(cmd, [...cmdArgs, `--registry=http://127.0.0.1:${port}/`], {
    stdio: ['ignore', mode === 'replay' ? 'inherit' : 'ignore', mode === 'replay' ? 'inherit' : 'pipe'],
  });
  if (child.stderr) child.stderr.resume();
  const code = await new Promise((r) => {
    child.on('exit', (c, s) => r(c === null ? 128 + (s === 'SIGKILL' ? 9 : 15) : c));
    child.on('error', () => r(127));
  });
  server.close();
  if (process.env.TESSERA_PROXY_TRACE === '1') process.stderr.write(`tessera-proxy: ${JSON.stringify(requests)}\n`);
  if (mode === 'record') {
    if (captured === null) {
      process.stderr.write('tessera: npm sent no bulk advisory request\n');
      process.exit(3);
    }
    process.stdout.write(captured);
    process.exit(0);
  }
  process.exit(code);
}

main().catch(() => process.exit(70));
