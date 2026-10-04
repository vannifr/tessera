import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Connection, Client } = require('@temporalio/client');
const { NativeConnection, Worker } = require('@temporalio/worker');

const dir = process.argv[2];
const address = process.argv[3] ?? '127.0.0.1:7233';
if (!dir) {
  console.error('usage: node connect.mts <pki-dir> [address]');
  process.exit(2);
}
const read = (f: string) => readFileSync(join(dir, f));
const tlsFor = (base: string | null) => ({
  serverRootCACertificate: read('ca.pem'),
  serverNameOverride: 'localhost',
  ...(base ? { clientCertPair: { crt: read(`${base}.pem`), key: read(`${base}-key.pem`) } } : {}),
});

const results: Array<[string, boolean, string]> = [];
const record = (name: string, pass: boolean, detail: string) => {
  results.push([name, pass, detail]);
  console.log(`${pass ? 'PASS' : 'FAIL'} ${name}: ${detail}`);
};
const short = (e: unknown) => String((e as Error)?.message ?? e).split('\n')[0].slice(0, 200);

async function clientProbe(tls: unknown) {
  const conn = await Connection.connect({ address, tls, connectTimeout: '5s' });
  try {
    await conn.workflowService.getSystemInfo({});
  } finally {
    await conn.close();
  }
}

async function nativeProbe(tls: unknown) {
  const conn = await NativeConnection.connect({ address, tls });
  await conn.close();
}

async function expectRefused(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    record(name, false, 'connected (expected refusal)');
  } catch (e) {
    record(name, true, `refused: ${short(e)}`);
  }
}

await expectRefused('client plaintext (tls: false)', () => clientProbe(false));
await expectRefused('client TLS without client cert', () => clientProbe(tlsFor(null)));
await expectRefused('client expired cert', () => clientProbe(tlsFor('client-expired')));
await expectRefused('client rogue-CA cert', () => clientProbe(tlsFor('client-rogue')));
await expectRefused('worker (native) plaintext', () => nativeProbe(undefined));
await expectRefused('worker (native) TLS without client cert', () => nativeProbe(tlsFor(null)));
await expectRefused('worker (native) expired cert', () => nativeProbe(tlsFor('client-expired')));

try {
  const workerConn = await NativeConnection.connect({ address, tls: tlsFor('worker') });
  const worker = await Worker.create({
    connection: workerConn,
    namespace: 'default',
    taskQueue: 's2-spike',
    workflowsPath: join(dirname(fileURLToPath(import.meta.url)), 'workflows.ts'),
    activities: { echo: async (s: string) => `echo:${s}` },
    bundlerOptions: { ignoreModules: [] },
  });
  const clientConn = await Connection.connect({ address, tls: tlsFor('client') });
  const client = new Client({ connection: clientConn, namespace: 'default' });
  const out = await worker.runUntil(
    client.workflow.execute('s2Spike', { taskQueue: 's2-spike', workflowId: `s2-${Date.now()}`, args: ['mtls'] }),
  );
  record('client + worker mTLS round trip', out === 'echo:mtls', `workflow result ${JSON.stringify(out)}`);
  await clientConn.close();
  await workerConn.close();
} catch (e) {
  record('client + worker mTLS round trip', false, short(e));
}

process.exit(results.every(([, p]) => p) ? 0 : 1);
