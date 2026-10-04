import { constants } from 'node:fs';
import type { Dirent, Stats } from 'node:fs';
import { chmod, link, lstat, open, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { EvidenceManifest, ManifestEntry, Sha256Hex } from './types';
import {
  MANIFEST_FILE,
  MAX_RECORD_BYTES,
  SUMS_FILE,
  chainGenesis,
  chainLink,
  compareBytes,
  hashHandle,
  isSafeName,
  openRegular,
  readManifest,
  renderSums,
  verifyEvidenceBundle,
} from './verify';

export interface SealOptions {
  bundleDir: string;
  runId: string;
  workflowId: string;
  temporalRunId: string;
  source: { repoUrl: string; revision: string | null };
  frameworkVersion: string;
  usedRecordIds: string[];
  clock: () => Date;
}

export interface SealEvidenceResult {
  bundlePath: string;
  rootHash: Sha256Hex;
  recordCount: number;
  artifactCount: number;
  abandonedCount: number;
  selfVerified: boolean;
}

const PARTIAL_FILE = '.manifest.json.partial';
const RETENTION_MS = 365 * 24 * 60 * 60 * 1000;
const FILE_MODE = 0o400;
const SEALED_DIR_MODE = 0o500;

interface ScannedFile {
  path: string;
  kind: 'record' | 'artifact';
  recordId: string;
  bytes: number;
  sha256: Sha256Hex;
}

interface ScannedBundle {
  files: ScannedFile[];
  abandoned: { path: string; bytes: number; sha256: Sha256Hex }[];
}

function fail(message: string): never {
  throw new Error(`evidence seal: ${message}`);
}

function isErrno(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === code;
}

async function lstatOrNull(p: string): Promise<Stats | null> {
  try {
    return await lstat(p);
  } catch (err) {
    if (isErrno(err, 'ENOENT')) return null;
    throw err;
  }
}

async function assertOwnedDir(dir: string): Promise<void> {
  const st = await lstatOrNull(dir);
  if (st === null) fail(`bundle directory does not exist: ${dir}`);
  if (st.isSymbolicLink()) fail(`refusing symlink at ${dir}`);
  if (!st.isDirectory()) fail(`not a directory: ${dir}`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) fail(`${dir} is not owned by the current user`);
}

async function hashFile(bundleDir: string, rel: string, keep: number): Promise<{ sha256: Sha256Hex; bytes: number; content: Buffer | null }> {
  const opened = await openRegular(path.join(bundleDir, rel));
  if ('problem' in opened) {
    if (opened.problem === 'symlink') fail(`refusing symlink at ${rel}`);
    fail(`${rel} is not a regular file`);
  }
  try {
    const hashed = await hashHandle(opened.fh, keep);
    if ((opened.stat.mode & 0o777) !== FILE_MODE) await opened.fh.chmod(FILE_MODE);
    return hashed;
  } finally {
    await opened.fh.close();
  }
}

async function listDir(bundleDir: string, rel: string): Promise<Dirent[]> {
  const dirents = await readdir(path.join(bundleDir, rel), { withFileTypes: true });
  for (const d of dirents) {
    if (d.isSymbolicLink()) fail(`refusing symlink at ${rel}/${d.name}`);
  }
  return dirents.sort((a, b) => compareBytes(a.name, b.name));
}

function artifactRecordId(name: string, referenced: Map<string, string>, recordIds: string[]): string {
  const ref = referenced.get(`artifacts/${name}`);
  if (ref !== undefined && name.startsWith(`${ref}.`)) return ref;
  let best: string | undefined;
  for (const id of recordIds) {
    if (name.startsWith(`${id}.`) && (best === undefined || id.length > best.length)) best = id;
  }
  if (best !== undefined) return best;
  const attempt = /^(.+\.a[1-9]\d*)\./.exec(name);
  if (attempt !== null && isSafeName(attempt[1])) return attempt[1];
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(0, dot) : name;
}

function rootLayout(root: Dirent[]): { hasRecords: boolean; hasArtifacts: boolean } {
  let hasRecords = false;
  let hasArtifacts = false;
  for (const d of root) {
    if (d.name === 'records' && d.isDirectory()) hasRecords = true;
    else if (d.name === 'artifacts' && d.isDirectory()) hasArtifacts = true;
    else fail(`unexpected entry ${d.name} in the bundle`);
  }
  return { hasRecords, hasArtifacts };
}

async function scanStaging(bundleDir: string, rel: string, abandoned: ScannedBundle['abandoned']): Promise<void> {
  for (const s of await listDir(bundleDir, rel)) {
    const srel = `${rel}/${s.name}`;
    if (!s.isFile() || !isSafeName(s.name)) fail(`unexpected entry ${srel}`);
    const hashed = await hashFile(bundleDir, srel, 0);
    abandoned.push({ path: srel, bytes: hashed.bytes, sha256: hashed.sha256 });
  }
}

function parseRecord(rel: string, content: Buffer | null): Record<string, unknown> {
  if (content === null) fail(`record ${rel} is too large`);
  let rec: Record<string, unknown>;
  try {
    rec = JSON.parse(content.toString('utf8')) as Record<string, unknown>;
  } catch {
    fail(`record ${rel} is not valid JSON`);
  }
  return rec;
}

function checkRecord(rec: Record<string, unknown>, rel: string, runId: string, stem: string): void {
  if (typeof rec !== 'object' || rec?.schema !== 'tessera.evidence/v1') fail(`record ${rel} is not a tessera.evidence/v1 record`);
  if (rec.runId !== runId) fail(`record ${rel} runId mismatch: expected ${runId}`);
  if (rec.id !== stem) fail(`record ${rel} id does not match its file name`);
}

function noteReferences(rec: Record<string, unknown>, stem: string, referenced: Map<string, string>): void {
  for (const ref of [rec.output, rec.stderr]) {
    if (typeof ref === 'object' && ref !== null && typeof (ref as { path?: unknown }).path === 'string') {
      const refPath = (ref as { path: string }).path;
      if (!referenced.has(refPath)) referenced.set(refPath, stem);
    }
  }
}

async function scanRecord(bundleDir: string, d: Dirent, runId: string, referenced: Map<string, string>): Promise<ScannedFile> {
  const rel = `records/${d.name}`;
  const stem = d.name.endsWith('.json') ? d.name.slice(0, -'.json'.length) : '';
  if (!d.isFile() || !isSafeName(d.name) || !isSafeName(stem)) fail(`unexpected entry ${rel}`);
  const hashed = await hashFile(bundleDir, rel, MAX_RECORD_BYTES);
  const rec = parseRecord(rel, hashed.content);
  checkRecord(rec, rel, runId, stem);
  noteReferences(rec, stem, referenced);
  return { path: rel, kind: 'record', recordId: stem, bytes: hashed.bytes, sha256: hashed.sha256 };
}

async function scanRecords(bundleDir: string, runId: string, scan: ScannedBundle & { referenced: Map<string, string>; recordIds: string[] }): Promise<void> {
  for (const d of await listDir(bundleDir, 'records')) {
    if (d.name === '.staging' && d.isDirectory()) {
      await scanStaging(bundleDir, `records/${d.name}`, scan.abandoned);
      continue;
    }
    const file = await scanRecord(bundleDir, d, runId, scan.referenced);
    scan.recordIds.push(file.recordId);
    scan.files.push(file);
  }
}

async function scanArtifacts(bundleDir: string, files: ScannedFile[], referenced: Map<string, string>, recordIds: string[]): Promise<void> {
  for (const d of await listDir(bundleDir, 'artifacts')) {
    const rel = `artifacts/${d.name}`;
    if (!d.isFile() || !isSafeName(d.name)) fail(`unexpected entry ${rel}`);
    const hashed = await hashFile(bundleDir, rel, 0);
    files.push({ path: rel, kind: 'artifact', recordId: artifactRecordId(d.name, referenced, recordIds), bytes: hashed.bytes, sha256: hashed.sha256 });
  }
}

async function scanBundle(bundleDir: string, runId: string): Promise<ScannedBundle> {
  const { hasRecords, hasArtifacts } = rootLayout(await listDir(bundleDir, '.'));
  const scan = { files: [] as ScannedFile[], abandoned: [] as ScannedBundle['abandoned'], referenced: new Map<string, string>(), recordIds: [] as string[] };
  if (hasRecords) await scanRecords(bundleDir, runId, scan);
  if (hasArtifacts) await scanArtifacts(bundleDir, scan.files, scan.referenced, scan.recordIds);
  scan.files.sort((a, b) => compareBytes(a.path, b.path));
  scan.abandoned.sort((a, b) => compareBytes(a.path, b.path));
  return { files: scan.files, abandoned: scan.abandoned };
}

async function removeStale(bundleDir: string, name: string): Promise<void> {
  const file = path.join(bundleDir, name);
  const st = await lstatOrNull(file);
  if (st === null) return;
  if (st.isSymbolicLink()) fail(`refusing symlink at ${name}`);
  if (!st.isFile()) fail(`unexpected entry ${name} in the bundle`);
  await unlink(file);
}

async function writeExclusive(file: string, content: string): Promise<void> {
  const fh = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, FILE_MODE);
  try {
    await fh.writeFile(content, 'utf8');
    await fh.sync();
  } finally {
    await fh.close();
  }
}

async function syncDir(dir: string): Promise<void> {
  const fh = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

function validateOptions(opts: SealOptions): void {
  if (typeof opts?.bundleDir !== 'string' || !path.isAbsolute(opts.bundleDir)) fail('bundleDir must be an absolute path');
  if (typeof opts.runId !== 'string' || opts.runId.length === 0) fail('runId is required');
  if (typeof opts.workflowId !== 'string' || typeof opts.temporalRunId !== 'string') fail('workflowId and temporalRunId are required');
  if (typeof opts.source?.repoUrl !== 'string' || (opts.source.revision !== null && typeof opts.source.revision !== 'string')) fail('invalid source');
  if (!Array.isArray(opts.usedRecordIds) || !opts.usedRecordIds.every((id) => typeof id === 'string')) fail('usedRecordIds must be strings');
  if (typeof opts.clock !== 'function') fail('clock is required');
}

function issueSummary(issues: readonly { problem: string; path: string }[]): string {
  const summary = issues.slice(0, 5).map((i) => `${i.problem} ${i.path}`).join(', ');
  return summary.length > 0 ? `: ${summary}` : '';
}

function resultFrom(bundlePath: string, manifest: EvidenceManifest): SealEvidenceResult {
  return {
    bundlePath,
    rootHash: manifest.rootHash,
    recordCount: manifest.entries.filter((e) => e.kind === 'record').length,
    artifactCount: manifest.entries.filter((e) => e.kind === 'artifact').length,
    abandonedCount: manifest.abandoned.length,
    selfVerified: true,
  };
}

export async function sealEvidenceBundle(opts: SealOptions): Promise<SealEvidenceResult> {
  validateOptions(opts);
  const bundleDir = path.resolve(opts.bundleDir);
  await assertOwnedDir(bundleDir);
  if ((await lstatOrNull(path.join(bundleDir, MANIFEST_FILE))) !== null) fail(`bundle is already sealed: ${bundleDir}`);
  await removeStale(bundleDir, SUMS_FILE);
  await removeStale(bundleDir, PARTIAL_FILE);

  const scanned = await scanBundle(bundleDir, opts.runId);
  const used = new Set(opts.usedRecordIds);
  const recordIds = new Set(scanned.files.filter((f) => f.kind === 'record').map((f) => f.recordId));
  for (const id of used) {
    if (!recordIds.has(id)) fail(`used record ${id} is not in the bundle`);
  }

  const genesis = chainGenesis(opts.runId);
  let prev = genesis;
  const entries: ManifestEntry[] = scanned.files.map((f, i) => {
    const seq = i + 1;
    const chainHash = chainLink(prev, seq, f.path, f.sha256);
    prev = chainHash;
    return { seq, path: f.path, kind: f.kind, recordId: f.recordId, bytes: f.bytes, sha256: f.sha256, chainHash, used: used.has(f.recordId) };
  });
  const sealedAt = opts.clock();
  const manifest: EvidenceManifest = {
    schema: 'tessera.manifest/v1',
    runId: opts.runId,
    workflowId: opts.workflowId,
    temporalRunId: opts.temporalRunId,
    source: { repoUrl: opts.source.repoUrl, revision: opts.source.revision },
    sealedAt: sealedAt.toISOString(),
    retainUntil: new Date(sealedAt.getTime() + RETENTION_MS).toISOString(),
    framework: { name: 'tessera', version: opts.frameworkVersion },
    hashAlgorithm: 'sha256',
    entries,
    abandoned: scanned.abandoned,
    chain: { algorithm: 'tessera-chain/v1', genesis, head: prev },
    rootHash: prev,
  };

  await writeExclusive(path.join(bundleDir, SUMS_FILE), renderSums(entries));
  const partial = path.join(bundleDir, PARTIAL_FILE);
  await writeExclusive(partial, `${JSON.stringify(manifest, null, 2)}\n`);
  try {
    await link(partial, path.join(bundleDir, MANIFEST_FILE));
  } catch (err) {
    await unlink(partial).catch(() => undefined);
    if (isErrno(err, 'EEXIST')) fail(`bundle is already sealed: ${bundleDir}`);
    throw err;
  }
  await unlink(partial);
  await syncDir(bundleDir);
  await chmod(bundleDir, SEALED_DIR_MODE);

  const report = await verifyEvidenceBundle(bundleDir, { expectRootHash: manifest.rootHash });
  if (!report.ok) fail(`self-verification failed${issueSummary(report.issues)}`);
  return resultFrom(bundleDir, manifest);
}

export async function openSealedBundle(bundleDir: string, runId: string): Promise<SealEvidenceResult> {
  const dir = path.resolve(bundleDir);
  await assertOwnedDir(dir);
  const partial = await lstatOrNull(path.join(dir, PARTIAL_FILE));
  if (partial !== null) {
    if (!partial.isFile()) fail(`unexpected entry ${PARTIAL_FILE} in the bundle`);
    await chmod(dir, 0o700);
    await unlink(path.join(dir, PARTIAL_FILE));
  }
  if (((await lstat(dir)).mode & 0o777) !== SEALED_DIR_MODE) await chmod(dir, SEALED_DIR_MODE);
  const report = await verifyEvidenceBundle(dir);
  if (!report.ok || report.runId !== runId) fail(`existing seal does not verify${issueSummary(report.issues)}`);
  const manifest = await readManifest(dir);
  if (manifest?.rootHash !== report.rootHash) fail('existing seal does not verify');
  return resultFrom(dir, manifest);
}
