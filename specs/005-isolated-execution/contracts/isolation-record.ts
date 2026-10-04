// Contract: isolation evidence, restriction states and the computed isolation level (FR-015..FR-018, FR-021)
// Target modules: src/isolation/observe.ts, src/isolation/level.ts, src/evidence/types.ts, src/evidence/manifest.ts

export type RestrictionId =
  // mandatory: a step does not start when one of these is not applied
  | 'source-mount-only'
  | 'source-read-only'          // scan profile
  | 'source-private-write'      // fetch profile (rw, but only the run's own source dir)
  | 'network-none'              // scan profile
  | 'network-egress'            // fetch profile (expected for fetch, named in the limits)
  | 'rootfs-read-only'
  | 'non-root-user'
  | 'capabilities-dropped'
  | 'no-new-privileges'
  | 'image-pinned'
  | 'time-limit'
  | 'output-limit'
  // resource: not applied lowers the level to partial
  | 'memory-limit'
  | 'pids-limit'
  | 'cpu-limit'
  | 'scratch-size-limit'
  | 'seccomp-default'
  | 'selinux-label'
  | 'rootless-runtime'
  | 'limit-observation';

export type RestrictionClass = 'mandatory' | 'resource';
export type RestrictionState = 'applied' | 'not-applied' | 'violated';

export interface IsolationRestriction {
  id: RestrictionId;
  class: RestrictionClass;
  state: RestrictionState;      // violated only for memory, pids, time, output, scratch limits
  expected: string;
  observed: string;             // tokenized, ≤ 200 chars
  source: 'inspect' | 'selftest' | 'cgroup' | 'host' | 'runtime-info';
}

export interface BlockedAttempt {
  kind: 'network' | 'write' | 'fork' | 'memory' | 'link-outside-source';
  count: number;
  observedBy: 'cgroup' | 'stderr-pattern' | 'probe';   // stderr-pattern is reported as heuristic
  path?: string;                                         // link-outside-source only; relative, tokenized, no target
}

export interface IsolationObservation {
  container: { name: string; slice: string };
  argv: string[];
  mounts: { target: '/src' | '/mirror'; access: 'ro' | 'rw' }[];
  restrictions: IsolationRestriction[];
  limitEvents: { oomKill: number; pidsMax: number } | null;
  blockedAttempts: BlockedAttempt[];
  removal: 'removed' | 'failed';
}

export interface IsolationRecord extends Omit<IsolationObservation, 'removal'> {
  schema: 'tessera.isolation/v1';
  profile: 'fetch' | 'scan';
  helper: 'none' | 'bounded-fetch' | 'advisory-record' | 'advisory-replay';
  runtime: { name: 'podman' | 'docker'; version: string; rootless: boolean };
  image: { id: string; manifestSha256: string };
}

// Inspect fields used by observe.ts (podman and docker share these names):
//   HostConfig.ReadonlyRootfs, HostConfig.NetworkMode, HostConfig.CapDrop / CapAdd, HostConfig.SecurityOpt,
//   HostConfig.PidsLimit, HostConfig.Memory, HostConfig.MemorySwap, HostConfig.NanoCpus, HostConfig.Privileged,
//   HostConfig.Binds / Mounts, HostConfig.Tmpfs, Config.User, Image, HostConfig.CgroupParent
// Anything unexpected (Privileged true, CapAdd non-empty, an extra mount, a network other than the profile's)
// makes the matching mandatory restriction not-applied.

// ---------- Level ----------

export type IsolationLevel = 'none' | 'partial' | 'contained';

export interface LevelInputRecord {
  id: string;
  kind: 'tool-run' | 'in-process' | 'source-probe' | 'lifecycle';
  stepId: string;
  status: string;
  isolation?: IsolationRecord;
}

export interface IsolationStatement {
  level: IsolationLevel;
  computedFrom: string[];                                 // all tool-run record ids plus environment.check
  restrictionsNotApplied: { recordId: string; restriction: RestrictionId }[];
  limits: string[];                                       // fixed text set, see LIMIT_TEXTS
  runtime: { name: 'podman' | 'docker'; version: string; rootless: boolean } | null;
  imageId: string | null;
}

// Rules (pure, deterministic, order-independent):
//  none      — no tool-run record, or any tool-run record without isolation, or environment.check missing or
//              failed with isolation-unavailable, or any mandatory restriction not applied in any record
//  partial   — otherwise, when any resource restriction is not-applied in any tool-run record or in environment.check
//  contained — otherwise
// Verification (review fix): if any tool-run record carries an isolation block while the environment.check record
//   is absent from the manifest, verify emits 'isolation-record-invalid' (not only a recomputed 'none').
// violated never lowers the level. In-process, source-probe and lifecycle records other than environment.check
// do not affect the level; they appear in limits ('host-side-readers').
export type ComputeIsolationLevel = (records: readonly LevelInputRecord[]) => IsolationStatement;

export const LIMIT_TEXTS = {
  'shared-kernel': 'Software isolation on a shared host kernel; no hardware or VM isolation.',
  'local-signing-key': 'The signing key is held locally by the operator.',
  'host-side-readers': 'Tessera\'s own readers (source probe, license check, tech-stack detection, heuristic review) read the source on the host as data, without following links; they execute nothing.',
  'fetch-egress': 'The fetch step had outbound network access to clone the source; scanning steps had none.',
  'advisory-egress': 'The package list from the lockfile was sent to the npm registry to obtain advisories.',
  'attempts-observable': 'Blocked attempts are recorded when observable; refusals a payload hides are contained but not recorded.',
  'rootful-runtime': 'The container runtime ran with a root daemon (docker); a container escape would reach root.',
  'no-limit-observation': 'Memory and process limit events could not be read from the kernel; limit hits are inferred from exit codes.',
} as const;
