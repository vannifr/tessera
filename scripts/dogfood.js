#!/usr/bin/env node
const { spawn, execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const ROOT = path.resolve(__dirname, '..');
const { Connection, Client } = require(path.join(ROOT, 'node_modules/@temporalio/client'));

const REPO_URL = process.env.DOGFOOD_REPO_URL || 'https://github.com/vannifr/tessera';
const TEMPORAL_PORT = 7233;
const UI_PORT = 8233;
const RUN_TIMEOUT_MS = Number(process.env.DOGFOOD_RUN_TIMEOUT_MS || 900000);
const HOME_DIR = path.join(os.homedir(), '.tessera');
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT_DIR = path.join(HOME_DIR, 'dogfood', STAMP);
const DOC_DIR = path.join(ROOT, 'docs', 'dogfood');

const children = [];

function log(msg) {
  console.log(`[dogfood] ${msg}`);
}

function portFree(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port, '127.0.0.1');
  });
}

function waitFor(predicate, timeoutMs, label) {
  const begin = Date.now();
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        if (await predicate()) return resolve();
      } catch (_) {}
      if (Date.now() - begin > timeoutMs) return reject(new Error(`timeout waiting for ${label}`));
      setTimeout(tick, 500);
    };
    tick();
  });
}

function track(child) {
  children.push(child);
  return child;
}

function startTemporal(cwd, logFile) {
  const out = fs.openSync(logFile, 'a');
  return track(spawn('temporal', ['server', 'start-dev', '--headless', '--ip', '127.0.0.1', '--port', '7233', '--ui-port', '8233'], { cwd, detached: true, stdio: ['ignore', out, out] }));
}

function startWorker(env, logFile) {
  const out = fs.openSync(logFile, 'a');
  return track(spawn('npx', ['ts-node', 'src/worker.ts'], { cwd: ROOT, env, detached: true, stdio: ['ignore', out, out] }));
}

function cleanup() {
  for (const child of children) {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch (_) {}
  }
}

function sourceRevision() {
  return execFileSync('git', ['ls-remote', REPO_URL, 'HEAD'], { encoding: 'utf-8' }).split('\t')[0];
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.mkdirSync(path.join(HOME_DIR, 'keys'), { recursive: true, mode: 0o700 });
  for (const tool of ['git', 'node', 'temporal', 'gitleaks', 'semgrep']) {
    try {
      execFileSync('sh', ['-c', `command -v ${tool}`], { stdio: 'pipe' });
    } catch (_) {
      throw new Error(`required tool missing: ${tool}`);
    }
  }
  if (!(await portFree(TEMPORAL_PORT))) throw new Error(`port ${TEMPORAL_PORT} is busy`);
  if (!(await portFree(UI_PORT))) throw new Error(`port ${UI_PORT} is busy`);

  const keyPath = path.join(HOME_DIR, 'keys', 'ed25519.pem');
  if (!fs.existsSync(keyPath)) execFileSync('npx', ['ts-node', 'src/cli/evidence-keygen.ts', keyPath], { cwd: ROOT, stdio: 'pipe' });
  const pubKeyPath = `${keyPath}.pub`;
  const evidenceRoot = path.join(OUT_DIR, 'evidence');
  const reportDir = path.join(OUT_DIR, 'report');
  fs.mkdirSync(reportDir, { recursive: true });

  log(`audited source: ${REPO_URL} at ${sourceRevision()}`);
  log('starting temporal dev server');
  startTemporal(OUT_DIR, path.join(OUT_DIR, 'temporal.log'));
  await waitFor(async () => !(await portFree(TEMPORAL_PORT)), 60000, 'temporal server');
  await new Promise((r) => setTimeout(r, 3000));

  const workerLog = path.join(OUT_DIR, 'worker.log');
  startWorker({ ...process.env, TEMPORAL_ADDRESS: `localhost:${TEMPORAL_PORT}`, TESSERA_EVIDENCE_ROOT: evidenceRoot, TESSERA_SIGNING_KEY: keyPath, TESSERA_REQUIRE_SIGNATURE: '1' }, workerLog);
  await waitFor(() => fs.existsSync(workerLog) && /Worker configured/.test(fs.readFileSync(workerLog, 'utf-8')), 90000, 'worker');

  const connection = await Connection.connect({ address: `localhost:${TEMPORAL_PORT}` });
  const client = new Client({ connection });
  const workflowId = `dogfood-${Date.now()}`;
  log(`starting audit ${workflowId}`);
  const handle = await client.workflow.start('applicationAudit', {
    taskQueue: 'audit',
    workflowId,
    args: [{ repoUrl: REPO_URL, skipApproval: true, outputDir: reportDir }],
    workflowExecutionTimeout: RUN_TIMEOUT_MS,
  });
  const result = await handle.result();
  await connection.close();

  const bundles = fs.existsSync(evidenceRoot) ? fs.readdirSync(evidenceRoot, { withFileTypes: true }).filter((e) => e.isDirectory()) : [];
  const verifications = bundles.map((b) => {
    const dir = path.join(evidenceRoot, b.name);
    const run = spawnSync('npx', ['ts-node', 'src/cli/verify-evidence.ts', '--pubkey', pubKeyPath, dir], { cwd: ROOT, encoding: 'utf-8' });
    return { bundle: b.name, exit: run.status === null ? 2 : run.status, firstLine: (run.stdout || '').split('\n')[0] };
  });

  const findings = result.findings || [];
  const bySeverity = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
  fs.mkdirSync(DOC_DIR, { recursive: true });
  const day = STAMP.slice(0, 10);
  const reportCopy = path.join(DOC_DIR, `${day}-report.md`);
  if (result.reportPath && fs.existsSync(result.reportPath)) fs.copyFileSync(result.reportPath, reportCopy);
  fs.copyFileSync(pubKeyPath, path.join(DOC_DIR, 'tessera-dogfood.pub'));
  const summary = [
    `# Dogfooding run ${day}`,
    '',
    `Tessera audited its own repository (${REPO_URL}) with the framework as built in this commit.`,
    '',
    `- Outcome: ${result.outcome}`,
    `- Findings: ${findings.length} ${JSON.stringify(bySeverity)}`,
    `- Evidence bundles: ${bundles.length}; verification with the published public key: ${verifications.map((v) => v.firstLine).join('; ') || 'none'}`,
    `- Approval: skipped explicitly (skipApproval) for this run, as recorded in the report`,
    `- Full report: \`${day}-report.md\`; public key: \`tessera-dogfood.pub\``,
    '- The evidence bundle stays outside the repository; verify with `npm run evidence:verify -- <bundle> --pubkey docs/dogfood/tessera-dogfood.pub`.',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(DOC_DIR, `${day}-summary.md`), summary);
  console.log('\n' + summary);
  log(`artifacts kept in ${OUT_DIR}`);
  return verifications.length > 0 && verifications.every((v) => v.exit === 0) ? 0 : 1;
}

let exiting = false;
function finish(code) {
  if (exiting) return;
  exiting = true;
  cleanup();
  process.exit(code);
}
process.on('SIGINT', () => finish(130));
process.on('SIGTERM', () => finish(143));

main().then(finish, (err) => {
  console.error(`[dogfood] error: ${err.message}`);
  finish(2);
});
