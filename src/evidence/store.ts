import { constants } from 'node:fs';
import type { Stats } from 'node:fs';
import { link, lstat, mkdir, open, unlink } from 'node:fs/promises';
import path from 'node:path';
import { sha256Hex } from './hash';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from './types';

const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/;
const MAX_SEGMENT = 128;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const DIR_MODE = 0o700;
const STAGING_MODE = 0o600;
const PUBLISHED_MODE = 0o400;

function assertSafeSegment(value: string, label: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_SEGMENT ||
    !SAFE_SEGMENT.test(value) ||
    value.startsWith('.') ||
    value.includes('..') ||
    value.includes('/')
  ) {
    throw new Error(`evidence store: invalid ${label} ${JSON.stringify(value)}`);
  }
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

async function ensurePrivateDir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { mode: DIR_MODE });
  } catch (err) {
    if (!isErrno(err, 'EEXIST')) throw err;
  }
  const st = await lstat(dir);
  if (st.isSymbolicLink()) throw new Error(`evidence store: refusing symlink at ${dir}`);
  if (!st.isDirectory()) throw new Error(`evidence store: not a directory: ${dir}`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) throw new Error(`evidence store: ${dir} is not owned by the current user`);
  const fh = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW).catch((err: unknown) => {
    if (isErrno(err, 'ELOOP')) throw new Error(`evidence store: refusing symlink at ${dir}`);
    throw err;
  });
  try {
    const fst = await fh.stat();
    if (fst.ino !== st.ino || fst.dev !== st.dev) throw new Error(`evidence store: ${dir} changed during check`);
    if ((fst.mode & 0o777) !== DIR_MODE) await fh.chmod(DIR_MODE);
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

async function readPublished(file: string): Promise<Buffer> {
  const st = await lstat(file);
  if (st.isSymbolicLink()) throw new Error(`evidence store: refusing symlink at ${file}`);
  if (!st.isFile()) throw new Error(`evidence store: not a regular file: ${file}`);
  const fh = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW).catch((err: unknown) => {
    if (isErrno(err, 'ELOOP')) throw new Error(`evidence store: refusing symlink at ${file}`);
    throw err;
  });
  try {
    const fst = await fh.stat();
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) throw new Error(`evidence store: ${file} changed during read`);
    return await fh.readFile();
  } finally {
    await fh.close();
  }
}

async function assertNotSymlink(p: string): Promise<void> {
  const st = await lstatOrNull(p);
  if (st?.isSymbolicLink()) throw new Error(`evidence store: refusing symlink at ${p}`);
}

async function writeStaging(staging: string, bytes: Buffer): Promise<void> {
  const fh = await open(
    staging,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    STAGING_MODE,
  ).catch((err: unknown) => {
    if (isErrno(err, 'EEXIST')) throw new Error(`evidence store: staging file already exists: ${staging}`);
    throw err;
  });
  try {
    await fh.chmod(STAGING_MODE);
    await fh.writeFile(bytes);
    await fh.sync();
    await fh.chmod(PUBLISHED_MODE);
  } catch (err) {
    await fh.close().catch(() => undefined);
    await unlink(staging).catch(() => undefined);
    throw err;
  }
  await fh.close();
}

async function publish(staging: string, target: string, bytes: Buffer): Promise<'created' | 'exists'> {
  await assertNotSymlink(target);
  await writeStaging(staging, bytes);
  let outcome: 'created' | 'exists';
  try {
    await link(staging, target);
    outcome = 'created';
  } catch (err) {
    if (!isErrno(err, 'EEXIST')) {
      await unlink(staging).catch(() => undefined);
      throw err;
    }
    outcome = 'exists';
  }
  await unlink(staging);
  await syncDir(path.dirname(target));
  await syncDir(path.dirname(staging));
  return outcome;
}

export function createEvidenceStore(root: string, runId: string): EvidenceStore {
  assertSafeSegment(runId, 'runId');
  const bundleDir = path.join(path.resolve(root), runId);
  const recordsDir = path.join(bundleDir, 'records');
  const stagingDir = path.join(recordsDir, '.staging');
  const artifactsDir = path.join(bundleDir, 'artifacts');

  async function prepare(dirs: string[]): Promise<void> {
    await mkdir(path.resolve(root), { recursive: true, mode: DIR_MODE });
    await ensurePrivateDir(bundleDir);
    if (await lstatOrNull(path.join(bundleDir, 'manifest.json'))) {
      throw new Error(`evidence store: bundle ${bundleDir} is sealed`);
    }
    for (const dir of dirs) await ensurePrivateDir(dir);
  }

  async function writeArtifact(
    recordId: string,
    suffix: string,
    bytes: Buffer,
    meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>,
  ): Promise<ArtifactRef> {
    assertSafeSegment(recordId, 'record id');
    assertSafeSegment(suffix, 'artifact suffix');
    const name = `${recordId}.${suffix}`;
    assertSafeSegment(name, 'artifact name');
    if (!Buffer.isBuffer(bytes)) throw new Error('evidence store: artifact bytes must be a Buffer');
    if (!SHA256_HEX.test(meta.rawSha256)) throw new Error('evidence store: rawSha256 must be 64 lowercase hex characters');
    if (!Number.isSafeInteger(meta.rawBytes) || meta.rawBytes < 0) throw new Error('evidence store: invalid rawBytes');
    if (!Number.isSafeInteger(meta.redactions) || meta.redactions < 0) throw new Error('evidence store: invalid redactions');

    await prepare([recordsDir, stagingDir, artifactsDir]);
    const target = path.join(artifactsDir, name);
    const staging = path.join(stagingDir, `${name}.artifact`);
    const sha256 = sha256Hex(bytes);
    const outcome = await publish(staging, target, bytes);
    if (outcome === 'exists') {
      const existing = await readPublished(target);
      if (sha256Hex(existing) !== sha256) {
        throw new Error(`evidence store: artifact ${name} already exists with different content`);
      }
    }
    return {
      path: `artifacts/${name}`,
      mediaType: meta.mediaType,
      bytes: bytes.length,
      sha256,
      rawBytes: meta.rawBytes,
      rawSha256: meta.rawSha256,
      redactions: meta.redactions,
      truncated: meta.truncated,
    };
  }

  async function writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    if (!Number.isSafeInteger(record.attempt) || record.attempt < 1) {
      throw new Error(`evidence store: invalid attempt ${String(record.attempt)}`);
    }
    assertSafeSegment(record.stepId, 'step id');
    const id = `${record.stepId}.a${record.attempt}`;
    assertSafeSegment(id, 'record id');
    if (record.id !== id) throw new Error(`evidence store: record id ${JSON.stringify(record.id)} must be ${id}`);
    if (record.runId !== runId) throw new Error(`evidence store: record runId ${JSON.stringify(record.runId)} does not match ${runId}`);

    await prepare([recordsDir, stagingDir]);
    const target = path.join(recordsDir, `${id}.json`);
    const staging = path.join(stagingDir, `${id}.json`);
    const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
    const outcome = await publish(staging, target, bytes);
    const recordSha256 = outcome === 'created' ? sha256Hex(bytes) : sha256Hex(await readPublished(target));
    return { recordId: id, recordSha256 };
  }

  return { bundleDir, writeArtifact, writeRecord };
}
