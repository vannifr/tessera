// Contract: isolated runner behind the existing ProcessRunner interface (FR-001..FR-011, FR-015)
// Target modules: src/isolation/{profiles,path-map,container-args,observe,isolated-runner,runtime}.ts
// Additive changes: src/scan/tool-types.ts, src/scan/process-runner.ts, src/scan/run-tool.ts
// The only module that touches child_process stays src/scan/process-runner.ts (defaultProcessRunner).

import type { IsolationObservation } from './isolation-record';

// ---------- Additive fields on the 004 types ----------

export type ProfileName = 'fetch' | 'scan';
export type HelperMode = 'none' | 'bounded-fetch' | 'advisory-record' | 'advisory-replay';

export interface IsolationHint {
  profile: ProfileName;
  runId: string;                 // ^[A-Za-z0-9_-]{1,128}$
  sourceDir: string;             // absolute, inside <tmp>/tessera-<runId>/, exists, not a link
  helper: HelperMode;            // bounded-fetch only with fetch; advisory-* only with scan and file 'npm'
  mirrorDir?: string;            // fetch only, development only (refused when NODE_ENV=production)
}

// ToolInvocation gains:   isolation?: IsolationHint        (copied by runTool into both the version probe and the run)
// ProcessRequest gains:   isolation?: IsolationHint; stdin?: Buffer   (stdin ≤ 32 MiB, written then closed)
// ProcessOutcome gains:   isolation?: IsolationObservation; limitHit?: 'memory' | 'pids'
// EvidenceRecord gains:   isolation?: IsolationRecord        (see isolation-record.ts)
//
// runTool.override() precedence (first match wins), new entries marked +:
//   ENOENT → unavailable/not-installed
// + spawnErrorCode 'EISOLATION' → failed/isolation-unavailable (unavailable when raised by checkIsolation)
//   other spawn error → failed/spawn-error
//   timedOut → failed/timeout   (spike S1: also set when inspect shows ExitCode -1 after the runtime's --timeout; never derived from a message)
// + limitHit 'memory' → failed/limit-memory   (spike S1: limitHit comes from the memory.events oom_kill counter, not from inspect OOMKilled)
//   truncated → partial/output-truncated
// + limitHit 'pids' → partial/limit-pids if the policy classified completed, else failed/limit-pids
//   exitCode null → failed/killed
//   parse error → failed/parse-error
//   otherwise the policy's classification

// ---------- Profiles ----------

export interface IsolationProfile {
  name: ProfileName;
  network: 'egress' | 'none';
  sourceAccess: 'read-write' | 'read-only';
  memoryMiB: number;             // 512..16384
  pids: number;                  // 64..4096
  cpus: number;                  // 0.5..16
  scratchMiB: number;            // 64..4096 (fetch: TESSERA_MAX_SOURCE_MB)
  tmpMiB: 64;
}

export interface ProfileEnv {
  TESSERA_ISOLATION_MEMORY_MB?: string;
  TESSERA_ISOLATION_PIDS?: string;
  TESSERA_ISOLATION_CPUS?: string;
  TESSERA_ISOLATION_SCRATCH_MB?: string;
  TESSERA_MAX_SOURCE_MB?: string;
}

// Throws IsolationConfigError for non-numeric, out-of-bounds, zero or "unlimited" values. No value disables a limit.
export type LoadProfiles = (env: ProfileEnv) => Record<ProfileName, IsolationProfile>;

// ---------- Path translation (pure) ----------

export interface MountTable {
  source: { host: string; container: '/src'; access: 'ro' | 'rw' };
  mirror?: { host: string; container: '/mirror'; access: 'ro' };
  scratchAliases: { host: string; container: string }[];   // <WORK>/home → /scratch, <WORK>/tmp → /scratch (spike S1: HOME and TMPDIR are both /scratch)
  workDir: string;                                           // as cwd → /scratch
  configDir: { host: string; container: '/opt/tessera/config' };
}

export type TranslationResult =
  | { ok: true; args: string[]; cwd: string; env: Record<string, string> }
  | { ok: false; reason: 'unmapped-host-path'; where: 'arg' | 'env' | 'cwd'; index: number | string };

// Rule: a value is translated when it equals a mapped host path or starts with it followed by "/",
// also after the first "=" of an "--opt=value" argument. Any other absolute path that starts with "/" and
// names an existing host location or the work dir is refused. PATH, PYTHONUSERBASE are dropped;
// proxy variables are kept for the fetch profile only.
export type TranslateRequest = (req: { args: readonly string[]; cwd: string; env: Readonly<Record<string, string>> }, mounts: MountTable, profile: ProfileName) => TranslationResult;

// ---------- Container argv (pure) ----------

export type RuntimeName = 'podman' | 'docker';

export interface RuntimeFacts {
  name: RuntimeName;
  version: string;
  rootless: boolean;
  cgroupVersion: 1 | 2;
  controllers: string[];         // must include memory and pids for limit observation
  selinux: boolean;
  hostUid: number;
  hostGid: number;
}

export interface ContainerSpec {
  name: string;                  // tessera-<run>-<step>-a<attempt>
  imageId: string;               // ^sha256:[0-9a-f]{64}$ ; tags and names refused
  entrypoint: string;            // absolute, from TOOL_ENTRYPOINTS; helper modes use /usr/bin/node + /opt/tessera/bin/<helper>.js
  args: string[];                // translated
  workdir: string;               // translated cwd
  envNames: string[];            // request-derived values: passed as --env NAME; values in the CLI process env only. Refused by name (spike S1): HOME, TMPDIR, XDG_*, PATH, CONTAINERS_*, REGISTRY_AUTH_FILE, DOCKER_*, CONTAINER_HOST (they steer the runtime CLI)
  envValues: Record<string, string>;   // (spike S1) fixed framework values passed by value as --env NAME=value: HOME=/scratch, TMPDIR=/scratch, NPM_CONFIG_*; never secrets
  profile: IsolationProfile;
  mounts: MountTable;
  labels: Record<string, string>;   // tessera.run, tessera.step, tessera.attempt, tessera.created
  cgroupParent: string;          // tessera-<run32>-<stepSlug>a<attempt>.slice; (spike S1) stepSlug contains no '-' (systemd reads '-' as nesting), e.g. npmaudit, npmauditrecord; the attempt is in the name so counters do not add up across retries
  selinuxLevel: string | null;   // s0:cA,cB per audit
  timeoutSeconds: number;        // podman --timeout = ceil(host timeout / 1000) + 30
  interactive: boolean;          // true when stdin is supplied
}

export const TOOL_ENTRYPOINTS: Readonly<Record<string, string>> = {
  git: '/usr/bin/git',
  gitleaks: '/usr/local/bin/gitleaks',
  semgrep: '/usr/bin/semgrep',   // (spike S1) was /usr/local/bin/semgrep
  npm: '/usr/bin/npm',
  node: '/usr/bin/node',
};

// (spike S1) The entrypoint creates the directories the tools expect below /scratch (the runner cannot, the tool is the entrypoint).
// Produces the argv for `<runtime> create …`. Always includes, for both profiles:
//   --pull=never --read-only --read-only-tmpfs=false (podman) --tmpfs /tmp:size=64m,noexec,nosuid,nodev
//   --tmpfs /scratch:size=<n>m,mode=0700,noexec,nosuid,nodev,U (podman) | ...,mode=0700,uid=<uid>,gid=<gid> (docker, to verify in S3)   (spike S1: mode=1700 was root-owned and unusable by the non-root user; podman rejects uid=/gid=)
//   --cap-drop all --security-opt no-new-privileges
//   --init --pids-limit <n> --memory <n>m --memory-swap <n>m --cpus <n> --log-driver none
//   --userns keep-id --user <uid>:<gid> (podman) | --user <uid>:<gid> (docker)  --hostname tessera   (spike S1: the image USER overrides keep-id; the image ends with USER 65534:65534 so a missing --user fails closed)
//   --env HOME=/scratch --env TMPDIR=/scratch (by value, spike S1)
//   --cgroup-parent <slice> --label … --name … --workdir … --entrypoint <abs> -v <source>:/src:<ro|rw>[,Z]
//   --security-opt label=level:<level> (when SELinux) --timeout <s> (podman)
//   scan: --network none        fetch: no --network flag (runtime default egress; pasta for rootless podman)
// Fetch profile additionally (review fix): environment overrides GIT_CONFIG_GLOBAL=/dev/null and
//   GIT_CONFIG_SYSTEM=/dev/null set for the git process, and the clone argv starts with
//   `-c core.fsmonitor=false -c protocol.file.allow=never` (protocol.file.allow=never is lifted only for the
//   development mirror, where the mirror path is the one allowed file URL). No filter, hook or attribute
//   from the audited repository runs during fetch (no checkout-time filter drivers are configured).
// SELinux level (review fix): allocateSelinuxLevel(runId) = `s0:c<A>,c<B>`, A != B, both 0..1023. sha256(runId) gives the
//   starting pair (first 10 bits, next 10 bits, B = (A + 1) mod 1024 when equal); a host-wide registry of active labels,
//   held under a lock, hands out the first free pair from that start, so concurrent audits never share a pair even when
//   hashes collide. releaseSelinuxLevel(level) frees it at teardown; a crashed audit's label is reclaimed when its work
//   directory is found stale. Hashing alone cannot guarantee distinctness (birthday collisions on 20 bits).
export type AllocateSelinuxLevel = (runId: string) => Promise<string>;
export type ReleaseSelinuxLevel = (level: string) => Promise<void>;
// Never includes: --privileged, --cap-add, --device, --pid host, --network host, --ipc host, -v other than source/mirror,
//   --security-opt seccomp=unconfined, --security-opt label=disable.
export type BuildCreateArgs = (spec: ContainerSpec, runtime: RuntimeFacts) => string[];

// ---------- The runner ----------

export interface CgroupReader {
  // (spike S1) the slice path is resolved with `systemctl --user show -p ControlGroup --value <slice>`, never by string building;
  // memory.events oom_kill is the OOM observation: inspect says OOMKilled=false even after a kernel OOM kill
  read(slice: string, runtime: RuntimeFacts): Promise<{ oomKill: number; pidsMax: number } | null>; // null: not observable
}

export interface IsolatedRunnerDeps {
  inner: import('../../004-reliable-scan-core/contracts/run-tool').ProcessRunner; // defaultProcessRunner in production
  runtime: RuntimeFacts;
  imageId: string;
  imageManifestSha256: string;
  profiles: Record<ProfileName, IsolationProfile>;
  configDir: string;
  cgroups: CgroupReader;
  clock: () => Date;
  nodeEnv: string | undefined;
}

// Per request:
//  1. validate hint (else outcome { spawnErrorCode: 'EISOLATION' }) and translate (else 'EISOLATION', detail names the index)
//  2. `<rt> create …` via inner runner (fail → 'EISOLATION', detail runtime stderr first line, tokenized)
//  3. `<rt> inspect <name>` → observe restrictions (isolation-record.ts); a mandatory restriction not applied →
//     `<rt> rm --force`, outcome 'EISOLATION' with detail mandatory-restriction-missing:<id>
//  4. `<rt> start --attach [--interactive] <name>` via inner runner with the request's timeout, maxOutputBytes, stdin
//     (spike S1) podman --timeout kill ends with ExitCode -1, attach rc 255, no message, OOMKilled=false: classification of a
//     timeout relies on the host timer or on ExitCode -1, never on a runtime message
//  5. on timeout or stdout overflow: `<rt> rm --force --time 0 <name>` before anything else
//  6. read slice counters → limitHit
//  7. `<rt> rm --force <name>`; failure is kept in the observation (residue candidate), never thrown
// The runner never throws; every problem is a field of ProcessOutcome (004 R1 rule).
export type CreateIsolatedRunner = (deps: IsolatedRunnerDeps) => import('../../004-reliable-scan-core/contracts/run-tool').ProcessRunner;

// ---------- Runtime detection ----------

export type RuntimeChoice = 'podman' | 'docker' | 'auto';   // TESSERA_ISOLATION_RUNTIME; there is no 'none'

export type DetectRuntime = (choice: RuntimeChoice, inner: IsolatedRunnerDeps['inner']) => Promise<
  | { ok: true; facts: RuntimeFacts }
  | { ok: false; detail: 'no-runtime' | 'runtime-unusable'; message: string }
>;
