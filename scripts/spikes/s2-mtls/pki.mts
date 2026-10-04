import { createHash, generateKeyPairSync, randomBytes, sign, createPrivateKey, X509Certificate, KeyObject } from 'node:crypto';
import { mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { isIP } from 'node:net';

type Profile = {
  kind: 'ca' | 'server' | 'client';
  commonName: string;
  validDays: number;
  notBefore?: Date;
  subjectAltNames?: { dns?: string[]; ip?: string[] };
};

type Issuer = { certPem: string; keyPem: string } | null;

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(value.length), value]);
}

const seq = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]) => tlv(0x31, Buffer.concat(items));
const octet = (b: Buffer) => tlv(0x04, b);
const bitString = (b: Buffer, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));
const bool = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, 'utf8'));
const ctx = (n: number, b: Buffer, constructed: boolean) => tlv((constructed ? 0xa0 : 0x80) | n, b);

function integer(b: Buffer): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0x00 && (b[i + 1] & 0x80) === 0) i++;
  let v = b.subarray(i);
  if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
  return tlv(0x02, v);
}

function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  const out: number[] = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) {
    const stack: number[] = [p & 0x7f];
    let v = p >>> 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

function time(d: Date): Buffer {
  const y = d.getUTCFullYear();
  const p = (n: number) => String(n).padStart(2, '0');
  const rest = `${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  if (y >= 1950 && y < 2050) return tlv(0x17, Buffer.from(`${p(y % 100)}${rest}`, 'ascii'));
  return tlv(0x18, Buffer.from(`${y}${rest}`, 'ascii'));
}

function ipBytes(ip: string): Buffer {
  if (isIP(ip) === 4) return Buffer.from(ip.split('.').map(Number));
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

const OID = {
  ecdsaSha256: '1.2.840.10045.4.3.2',
  cn: '2.5.4.3',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  ski: '2.5.29.14',
  aki: '2.5.29.35',
  san: '2.5.29.17',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
};

const name = (cn: string) => seq(set(seq(oid(OID.cn), utf8(cn))));
const ext = (id: string, critical: boolean, value: Buffer) =>
  seq(oid(id), ...(critical ? [bool(true)] : []), octet(value));

function keyId(spkiDer: Buffer): Buffer {
  const point = spkiDer.subarray(spkiDer.length - 65);
  return createHash('sha1').update(point).digest();
}

function toPem(der: Buffer): string {
  const b64 = der.toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

export function issueCertificate(profile: Profile, issuer: Issuer): { certPem: string; keyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const ski = keyId(spki);

  let issuerName: Buffer;
  let issuerKey: KeyObject;
  let aki: Buffer | null = null;
  if (issuer) {
    const ic = new X509Certificate(issuer.certPem);
    issuerName = name(ic.subject.replace(/^CN=/, ''));
    issuerKey = createPrivateKey(issuer.keyPem);
    aki = keyId(ic.publicKey.export({ type: 'spki', format: 'der' }));
  } else {
    issuerName = name(profile.commonName);
    issuerKey = privateKey;
  }

  const serial = randomBytes(16);
  serial[0] = (serial[0] & 0x7f) | 0x40;
  const notBefore = profile.notBefore ?? new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore.getTime() + profile.validDays * 86_400_000);
  const sigAlg = seq(oid(OID.ecdsaSha256));

  const exts: Buffer[] = [];
  if (profile.kind === 'ca') {
    exts.push(ext(OID.basicConstraints, true, seq(bool(true))));
    exts.push(ext(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)));
  } else {
    exts.push(ext(OID.basicConstraints, false, seq()));
    exts.push(ext(OID.keyUsage, true, bitString(Buffer.from([0x80]), 7)));
    exts.push(ext(OID.extKeyUsage, false, seq(oid(profile.kind === 'server' ? OID.serverAuth : OID.clientAuth))));
  }
  exts.push(ext(OID.ski, false, octet(ski)));
  if (aki) exts.push(ext(OID.aki, false, seq(ctx(0, aki, false))));
  const san = profile.subjectAltNames;
  if (san && ((san.dns?.length ?? 0) + (san.ip?.length ?? 0)) > 0) {
    const names = [
      ...(san.dns ?? []).map((d) => ctx(2, Buffer.from(d, 'ascii'), false)),
      ...(san.ip ?? []).map((i) => ctx(7, ipBytes(i), false)),
    ];
    exts.push(ext(OID.san, false, seq(...names)));
  }

  const tbs = seq(
    ctx(0, integer(Buffer.from([2])), true),
    integer(serial),
    sigAlg,
    issuerName,
    seq(time(notBefore), time(notAfter)),
    name(profile.commonName),
    spki,
    ctx(3, seq(...exts), true),
  );
  const signature = sign('sha256', tbs, { key: issuerKey, dsaEncoding: 'der' });
  const cert = seq(tbs, sigAlg, bitString(signature));
  return {
    certPem: toPem(cert),
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function write(dir: string, base: string, pair: { certPem: string; keyPem: string }) {
  writeFileSync(join(dir, `${base}.pem`), pair.certPem, { mode: 0o600 });
  writeFileSync(join(dir, `${base}-key.pem`), pair.keyPem, { mode: 0o600 });
}

export function generatePki(dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const today = new Date().toISOString().slice(0, 10);
  const ca = issueCertificate({ kind: 'ca', commonName: `Tessera local CA ${today}`, validDays: 365 }, null);
  const server = issueCertificate(
    { kind: 'server', commonName: 'localhost', validDays: 90, subjectAltNames: { dns: ['localhost'], ip: ['127.0.0.1', '::1'] } },
    ca,
  );
  const worker = issueCertificate({ kind: 'client', commonName: 'tessera-worker', validDays: 90 }, ca);
  const client = issueCertificate({ kind: 'client', commonName: 'tessera-client', validDays: 90 }, ca);
  const systemWorker = issueCertificate({ kind: 'client', commonName: 'temporal-system-worker', validDays: 90 }, ca);
  const expired = issueCertificate(
    { kind: 'client', commonName: 'tessera-client', validDays: 1, notBefore: new Date(Date.now() - 10 * 86_400_000) },
    ca,
  );
  const rogueCa = issueCertificate({ kind: 'ca', commonName: 'Rogue CA', validDays: 365 }, null);
  const rogue = issueCertificate({ kind: 'client', commonName: 'tessera-client', validDays: 90 }, rogueCa);

  for (const [b, p] of Object.entries({ ca, server, worker, client, 'system-worker': systemWorker, 'client-expired': expired, 'client-rogue': rogue })) {
    write(dir, b, p);
  }

  const caX = new X509Certificate(ca.certPem);
  const checks: Record<string, boolean> = { 'ca self-signed': caX.verify(caX.publicKey) && caX.ca };
  for (const [b, p] of Object.entries({ server, worker, client, 'client-expired': expired })) {
    const x = new X509Certificate(p.certPem);
    checks[`${b} signed by ca`] = x.verify(caX.publicKey) && x.checkIssued(caX) && !x.ca;
  }
  checks['server SAN'] = new X509Certificate(server.certPem).checkHost('localhost') === 'localhost' &&
    new X509Certificate(server.certPem).checkIP('127.0.0.1') === '127.0.0.1';
  checks['rogue not signed by ca'] = !new X509Certificate(rogue.certPem).verify(caX.publicKey);
  return checks;
}

const out = process.argv[2];
if (out) {
  const checks = generatePki(out);
  for (const [k, v] of Object.entries(checks)) console.log(`${v ? 'ok  ' : 'FAIL'} ${k}`);
  if (Object.values(checks).some((v) => !v)) process.exit(1);
}
