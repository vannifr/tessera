// Contract: offline advisory data for npm audit (FR-004, FR-019, FR-020)
// Target modules: src/scan/tools/npm-advisories.ts (host), src/scan/tools/npm-audit.ts (two passes),
//                 config/isolation/bin/advisory-proxy.js (inside the scan container)

// ---------- Inside the container: advisory-proxy.js ----------
// Invocation (built by the isolated runner for helper modes):
//   /usr/bin/node /opt/tessera/bin/advisory-proxy.js record  -- /usr/bin/npm audit --json <framework flags>
//   /usr/bin/node /opt/tessera/bin/advisory-proxy.js replay  -- /usr/bin/npm audit --json <framework flags>
// The proxy listens on 127.0.0.1:<ephemeral> (loopback of the container's own network namespace) and appends
// `--registry=http://127.0.0.1:<port>/` as the last npm argument.
//
// record: captures the first POST /-/npm/v1/security/advisories/bulk body (gunzip when content-encoding gzip,
//   ≤ 5 MiB uncompressed), answers 503 to every request, waits for npm to exit, and writes ONLY the captured
//   JSON body to stdout. No body captured → exit 3, nothing on stdout.
// replay: reads the snapshot from stdin (≤ 32 MiB), refuses to start (exit 4) when stdin is empty or not a JSON
//   object of arrays; serves it as 200 application/json for POST …/advisories/bulk and 404 for everything else
//   (packument GETs and the quick-audit fallback); (spike S1) packuments are therefore 404: `fixAvailable` is true/false,
//   `range` is empty and remediation reads "Update <pkg> to latest" without a version, a stated limit the report must show;
//   stdin reaches the container through `create --interactive` plus `start --attach --interactive`; an empty snapshot exits 4
//   and never starts npm; streams npm's stdout and stderr unchanged; exits with npm's code.

// ---------- Host: validation and fetch ----------

export interface AdvisoryRequestLimits {
  maxBodyBytes: 5_242_880;
  maxNames: 20_000;
  maxVersionsPerName: 1_000;
  maxVersionLength: 256;
  nameRe: RegExp;      // /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/, length ≤ 214
  versionRe: RegExp;   // /^[0-9A-Za-z.+_-]{1,256}$/
}

export interface ValidatedAdvisoryRequest {
  body: Record<string, string[]>;   // only valid entries
  names: number;
  versions: number;
  droppedEntries: number;           // > 0 → npm-audit partial/advisory-request-filtered
  requestSha256: string;            // over the canonical JSON of `body`
}

export type ValidateAdvisoryRequest = (raw: Buffer) =>
  | { ok: true; value: ValidatedAdvisoryRequest }
  | { ok: false; error: 'not-json' | 'not-object' | 'too-large' | 'too-many-names' | 'empty' };

export const ADVISORY_BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';

export interface AdvisoryFetchDeps {
  fetch: typeof globalThis.fetch;   // injected; tests use a fake
  clock: () => Date;
  timeoutMs: 60_000;
  maxResponseBytes: 33_554_432;
}

export interface AdvisorySnapshot {
  fetchedAt: string;
  httpStatus: number;
  responseSha256: string;
  responseBytes: number;
  bytes: Buffer;                    // exact response bytes, passed to replay via stdin and stored as artifact
}

// POST with content-type application/json and content-encoding gzip; never follows a registry from the source;
// never sends credentials. Errors are values, never throws.
export type FetchAdvisories = (req: ValidatedAdvisoryRequest, deps: AdvisoryFetchDeps) => Promise<
  | { ok: true; snapshot: AdvisorySnapshot }
  | { ok: false; cause: 'advisory-data-missing'; detail: 'network' | 'timeout' | 'http-status' | 'too-large' | 'not-json' | 'not-object-of-arrays' }
>;

// ---------- npm-audit step sequence ----------
// 1. existing preparation (004): package.json and lockfile copied into <WORK>/npm-audit (lstat, no links)
// 2. runTool step 'npm-audit.record'  (helper advisory-record, scan profile, policy npmAdvisoryRequestPolicy)
//      record failure → npm-audit failed/tool-error, no fetch
// 3. in-process step 'npm-audit.advisories' (record kind in-process, artifact advisories.json)
//      failure → npm-audit unavailable/advisory-data-missing, NO replay (never an empty, clean result)
// 4. runTool step 'npm-audit' (helper advisory-replay, stdin = snapshot.bytes, existing npm-audit policy unchanged)
//      inputs add advisorySnapshotSha256 and advisoryFetchedAt
// Hermetic tests (fake npm) for both request orderings: bulk first, quick first. A capture holding only a
//   quick-audit request (no bulk body): record exits 3, step 2 is a failure that yields
//   unavailable/advisory-data-missing with the diagnostic 'npm sent no bulk advisory request (quick audit only)';
//   replay never runs and the result is never zero vulnerabilities.
// ScanStepResult.evidence points at the replay record; all three record ids are in status.evidenceRecordIds.

// ---------- Semgrep rules freshness ----------
export interface RulesFreshness {
  packs: { name: string; sha256: string; fetchedAt: string }[];   // from the image manifest
  maxAgeDays: number;                                              // TESSERA_RULES_MAX_AGE_DAYS, default 90, 1..365
}
// Oldest fetchedAt older than maxAgeDays at scan time → semgrep partial/rules-stale (findings kept).
