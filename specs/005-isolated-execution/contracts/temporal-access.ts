// Contract: local-only, authenticated orchestration access (FR-012, FR-013)
// Target modules: src/temporal/access.ts, src/temporal/pki.ts, src/cli/temporal-pki.ts, src/cli/temporal-local.ts
// Users: src/worker.ts, src/client.ts, demo/run-demo.js, scripts/dogfood.js

// ---------- PKI (Node crypto only, ECDSA P-256, SHA-256 signatures) ----------

export interface PkiPaths {
  dir: string;              // default ~/.config/tessera/temporal-pki (0700); demo/dogfood: private run dir
  caCert: 'ca.pem'; caKey: 'ca-key.pem';
  serverCert: 'server.pem'; serverKey: 'server-key.pem';
  workerCert: 'worker.pem'; workerKey: 'worker-key.pem';
  clientCert: 'client.pem'; clientKey: 'client-key.pem';
}

export interface CertProfile {
  kind: 'ca' | 'server' | 'client';
  commonName: string;                    // 'Tessera local CA <yyyy-mm-dd>' | 'localhost' | 'tessera-worker' | 'tessera-client'
  validDays: number;                     // ca 365, server 90, client 90
  notBefore?: Date;                      // tests only: issue already-expired certificates
  subjectAltNames?: { dns?: string[]; ip?: string[] };   // server: localhost, 127.0.0.1, ::1
}
// Extensions: CA → basicConstraints CA:true (critical), keyUsage keyCertSign+cRLSign (critical), SKI.
// Leaf → basicConstraints CA:false, keyUsage digitalSignature (critical), extKeyUsage serverAuth|clientAuth, SKI, AKI.
// Serial: 16 random bytes, first bit cleared.

export type IssueCertificate = (profile: CertProfile, issuer: { certPem: string; keyPem: string } | null) => { certPem: string; keyPem: string };

// Writes all files with mode 0600 into a 0700 dir; refuses a dir inside the repository, inside TESSERA_EVIDENCE_ROOT,
// or a dir that is a link or not owned by the current user. --rotate replaces everything; there is no CRL.
export type GeneratePki = (paths: PkiPaths, opts: { rotate: boolean; clock: () => Date }) => Promise<void>;

// ---------- Connection helper ----------

export interface TemporalAccessEnv {
  TESSERA_TEMPORAL_ADDRESS?: string;     // default '127.0.0.1:7233'
  TESSERA_TEMPORAL_TLS_DIR?: string;     // default ~/.config/tessera/temporal-pki
  TESSERA_TEMPORAL_REMOTE?: string;      // '1' allows a non-loopback host (still mTLS)
  TESSERA_TEMPORAL_NAMESPACE?: string;   // default 'default'
}

export type Identity = 'worker' | 'client';

export interface TemporalAccess {
  address: string;
  namespace: string;
  tls: {
    serverRootCACertificate: Buffer;
    clientCertPair: { crt: Buffer; key: Buffer };
    serverNameOverride: 'localhost';
  };
}

export type AccessErrorCode =
  | 'no-credentials'        // certificate or key file missing or unreadable
  | 'insecure-key-file'     // key file mode wider than 0600 or not owned by the current user
  | 'non-loopback'          // host is not 127.0.0.1, ::1 or localhost and TESSERA_TEMPORAL_REMOTE !== '1'
  | 'invalid-address';

// Exact error messages (TemporalAccessError.message), asserted by the connection-helper tests:
//   no-credentials    'client certificate or key file missing or unreadable'
//   insecure-key-file 'key file mode is wider than 0600 or not owned by the current user'
//   non-loopback      'non-loopback address requires TESSERA_TEMPORAL_REMOTE=1'
//   invalid-address   'address is not a valid host:port'

// Pure resolution plus file reads; throws TemporalAccessError(code) — the worker exits non-zero, the client prints
// the code. There is no option for plaintext or for skipping the client certificate.
export type ResolveTemporalAccess = (identity: Identity, env: TemporalAccessEnv) => Promise<TemporalAccess>;
// Worker: NativeConnection.connect({ address, tls }); client: Connection.connect({ address, tls }).

// ---------- Local server launcher ----------

export interface TemporalLocalOptions {
  image: string;              // 'docker.io/temporalio/server@sha256:<pinned>' (version 1.32.0), never a tag alone
  port: number;               // default 7233
  bind: '127.0.0.1' | '::1' | string;   // anything else requires expose === bind
  expose?: string;            // explicit opt-in for a non-loopback bind; mTLS stays required
  pkiDir: string;
  runtime: 'podman' | 'docker';
}
// Generated server config (mounted read-only): SQLite in memory; services frontend, history, matching, worker;
// global.tls.frontend.server { certFile, keyFile, requireClientAuth: true, clientCaFiles: [ca] };
// the system worker's client certificate (global.tls.systemWorker or internode, settled by spike S2);
// pprof disabled; metrics not published; HTTP API not published. Only `-p <bind>:<port>:7233` is published.
// Refusals (exit 2, message names the rule): bind not loopback without expose; missing PKI; image without digest.
export type StartTemporalLocal = (opts: TemporalLocalOptions) => Promise<{ containerName: string; stop: () => Promise<void> }>;
