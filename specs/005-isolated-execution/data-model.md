# Data Model: Isolated Execution

**Feature**: 005-isolated-execution | **Date**: 2026-10-04
Types are in `contracts/`; this document describes fields, relations, validation and state transitions. Times are ISO-8601 UTC; hashes are lowercase sha256 hex (64 characters). Entities from 004 (`AuditRun`, `EvidenceRecord`, `EvidenceManifest`, `ScannerStatusEntry`) are extended additively.

## Relations

```
AuditRun 1 ──── 1 IsolatedEnvironment ──── 1 EnvironmentCheck (record kind lifecycle, step environment.check)
   │                    │ 1..*                    1 EnvironmentTeardown (record kind lifecycle, step environment.teardown)
   │                    ▼
   │            StepContainer 1 ──── 1 EvidenceRecord (kind tool-run) ──── 1 IsolationRecord (record.isolation)
   │                                                                          │ 1..*
   │                                                                          ▼
   │                                                               IsolationRestriction, BlockedAttempt
   │
   ├──── 0..1 AdvisorySnapshot (record kind in-process, step npm-audit.advisories)
   │
   └──── 1 EvidenceManifest ──── 0..1 IsolationStatement (manifest.isolation, computed, signed)

ClientCredential (CA, server, worker, client certificates) ── used by ── TemporalAccessConfig (worker, client, demo, dogfood)
AttackFixture 1 ──── 1 ExpectedContainment (demo/attack/EXPECTED.md)
WorkflowActivities (registry) ── registered by ── Worker
```

## IsolationProfile

Static configuration per step kind.

| Field | Type | Validation |
|-------|------|------------|
| `name` | `'fetch' \| 'scan'` | fixed set |
| `network` | `'egress' \| 'none'` | `fetch` → `egress`, `scan` → `none`; not configurable |
| `sourceAccess` | `'read-write' \| 'read-only'` | `fetch` → `read-write`, `scan` → `read-only`; not configurable |
| `memoryMiB` | integer | 512 ≤ n ≤ 16384; defaults fetch 2048, scan 2048; env `TESSERA_ISOLATION_MEMORY_MB` |
| `pids` | integer | 64 ≤ n ≤ 4096; defaults fetch 256, scan 512; env `TESSERA_ISOLATION_PIDS` |
| `cpus` | number | 0.5 ≤ n ≤ 16; default 2; env `TESSERA_ISOLATION_CPUS` |
| `scratchMiB` | integer | 64 ≤ n ≤ 4096; fetch = `TESSERA_MAX_SOURCE_MB` (default 1024), scan default 512; env `TESSERA_ISOLATION_SCRATCH_MB` |
| `tmpMiB` | integer | fixed 64 |

An env value outside its bounds, non-numeric, or an attempt to set a limit to `0` or `unlimited` stops the worker at start with a configuration error. There is no field or value that disables isolation.

## IsolationHint

Carried from the scan step through `ToolInvocation.isolation` into `ProcessRequest.isolation`.

| Field | Type | Validation |
|-------|------|------------|
| `profile` | `'fetch' \| 'scan'` | required |
| `runId` | string | `^[A-Za-z0-9_-]{1,128}$` (004 rule) |
| `sourceDir` | absolute host path | inside `<tmp>/tessera-<runId>/`; must exist; not a link (lstat) |
| `helper` | `'none' \| 'bounded-fetch' \| 'advisory-record' \| 'advisory-replay'` | `bounded-fetch` only with `fetch`; advisory modes only with `scan` and `file === 'npm'` |
| `mirrorDir` | absolute host path, optional | only with `fetch`; refused when `NODE_ENV=production`; must not be inside the work dir |

A request without a hint, or with a hint that fails validation, is refused with `spawnErrorCode: 'EISOLATION'`.

## IsolatedEnvironment

The per-audit environment (one per `AuditRun`).

| Field | Type | Notes |
|-------|------|-------|
| `runId` | string | Temporal run id |
| `runtime` | `{ name: 'podman' \| 'docker'; version: string; rootless: boolean; cgroupVersion: 1 \| 2; controllers: string[] }` | from runtime detection |
| `image` | `{ id: Sha256Hex; manifestSha256: Sha256Hex; builtAt: string; rulesFetchedAt: string }` | `id` is the image ID, never a tag |
| `label` | string | `tessera.run=<runId>` |
| `slice` | string | `tessera-<run32>.slice`, run id without hyphens |
| `selinuxLevel` | string \| null | `s0:cA,cB`: two categories c0..c1023 with c1 != c0, allocated from a host-wide registry of active labels held under a lock: sha256(runId) (first 10 bits and next 10 bits) gives the starting pair and the first free pair from there is taken, released at teardown; null when SELinux is not enabled. Unit test: 200 concurrent allocations are pairwise distinct even when all run ids map to the same starting pair, and a released label can be allocated again |
| `workDir` | absolute path | 004 private work directory |

State transitions:

```
absent ──initAuditRun──▶ prepared (work dir) ──checkIsolation ok──▶ ready ──first step──▶ active
   prepared ──checkIsolation fails──▶ unavailable ──teardown──▶ removed | residue
   active ──teardownEnvironment──▶ removed | residue
   any ──workflow terminated──▶ orphaned ──sweeper──▶ removed | residue
```

`residue` lists what remained (`containers[]`, `slices[]`, `paths[]`, tokenized).

## StepContainer

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | `tessera-<run>-<stepId>-a<attempt>`, characters outside `[A-Za-z0-9_.-]` replaced by `_` |
| `slice` | string | `tessera-<run32>-<stepSlug>.slice` |
| `argv` | string[] | container-side command after translation (recorded) |

State transitions (driven by the isolated runner):

```
built (argv) ──create──▶ created ──inspect──▶ checked
   checked ──mandatory restriction not applied──▶ refused ──rm──▶ removed
   checked ──start --attach──▶ running ──exit──▶ exited ──read counters──▶ observed ──rm──▶ removed
   running ──host timeout / output overflow──▶ killed ──rm --force──▶ removed
   any ──rm fails──▶ leftover (reported in teardown)
```

## IsolationRestriction

| Field | Type | Validation |
|-------|------|------------|
| `id` | `RestrictionId` | fixed set (contract `isolation-record.ts`) |
| `class` | `'mandatory' \| 'resource'` | fixed per id |
| `state` | `'applied' \| 'not-applied' \| 'violated'` | `violated` only for `memory-limit`, `pids-limit`, `time-limit`, `output-limit`, `scratch-size-limit` |
| `expected` | string | for example `none`, `2048MiB`, `512` |
| `observed` | string | from inspect, self-test or counters; tokenized, ≤ 200 characters |
| `source` | `'inspect' \| 'selftest' \| 'cgroup' \| 'host' \| 'runtime-info'` | where the state comes from |

Rules: a `mandatory` restriction that is `not-applied` prevents the container from starting. `violated` means the limit was reached and enforced.

## BlockedAttempt

| Field | Type | Notes |
|-------|------|-------|
| `kind` | `'network' \| 'write' \| 'fork' \| 'memory' \| 'link-outside-source'` | |
| `count` | integer ≥ 1 | |
| `observedBy` | `'cgroup' \| 'stderr-pattern' \| 'probe'` | `stderr-pattern` is labeled heuristic in the report |
| `path` | string, optional | only for `link-outside-source`: the link's relative path in the source, tokenized; the target is never stored |

## IsolationRecord (`EvidenceRecord.isolation`)

Present on every `tool-run` record produced after this feature.

| Field | Type |
|-------|------|
| `schema` | `'tessera.isolation/v1'` |
| `profile` | `'fetch' \| 'scan'` |
| `helper` | as in `IsolationHint` |
| `runtime` | `{ name, version, rootless }` |
| `image` | `{ id, manifestSha256 }` |
| `container` | `{ name, slice }` |
| `argv` | string[] (container side, tokenized, redacted) |
| `mounts` | `{ target: '/src' \| '/mirror'; access: 'ro' \| 'rw' }[]` |
| `restrictions` | `IsolationRestriction[]` |
| `limitEvents` | `{ oomKill: number; pidsMax: number }` or `null` when not observable |
| `blockedAttempts` | `BlockedAttempt[]` |

Validation in `verify`: present on every `tool-run` record of a bundle whose manifest has an isolation statement; `image.id` matches `^sha256:[0-9a-f]{64}$`; all `RestrictionId` values known; every mandatory restriction `applied`.

## EnvironmentCheck (record `environment.check`)

`kind: 'lifecycle'`, `tool: { name: 'tessera-isolation-check', version: <framework> }`. `action.inputs`: runtime, runtime version, rootless, image id, manifest sha256, config hash comparison result. `isolation` block from the self-test container. `status`: `completed` (ready), `partial` (resource restrictions missing), `failed` with cause `isolation-unavailable` and detail (`no-runtime`, `runtime-unusable`, `image-missing`, `image-id-mismatch`, `image-outdated`, `mandatory-restriction-missing:<id>`, `selftest-failed:<check>`).

## EnvironmentTeardown (record `environment.teardown`)

`kind: 'lifecycle'`. `action.inputs`: `containersRemoved`, `slicesRemoved`, `workDirRemoved` (`true`/`false`), `residue` (`none` \| `present`). `causeDetail` lists leftovers (tokenized). `status`: `completed` when residue is `none`, `partial` with cause `residue` otherwise.

## AdvisorySnapshot (record `npm-audit.advisories`)

`kind: 'in-process'`, `scanner: 'npm-audit'`.

| Field (`action.inputs` or artifact) | Notes |
|--------------------------------------|-------|
| `registry` | fixed `https://registry.npmjs.org/-/npm/v1/security/advisories/bulk` |
| `requestSha256`, `packages`, `versions`, `droppedEntries` | from the validated record-pass body |
| `fetchedAt` | host clock |
| `httpStatus`, `responseSha256`, `responseBytes` | |
| artifact `advisories.json` | the response as received (no secrets; stored for replay and review) |

Status: `completed`; `unavailable` with `advisory-data-missing` (network, timeout, HTTP ≠ 200, invalid JSON, oversize); `partial` with `advisory-request-filtered` when entries were dropped. The npm-audit replay record names `advisorySnapshotSha256` and `advisoryFetchedAt` in its inputs.

Validation limits: body ≤ 5 MiB uncompressed; ≤ 20 000 names; name matches `^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$` and ≤ 214 characters; ≤ 1 000 versions per name; version ≤ 256 characters of `[0-9A-Za-z.+_-]`; response ≤ 32 MiB, a JSON object whose values are arrays.

## IsolationStatement (`EvidenceManifest.isolation`)

| Field | Type | Notes |
|-------|------|-------|
| `level` | `'none' \| 'partial' \| 'contained'` | computed by `computeIsolationLevel` at seal |
| `computedFrom` | string[] | record ids of all `tool-run` records and `environment.check` |
| `restrictionsNotApplied` | `{ recordId, restriction }[]` | the reasons for `partial` (FR-018) |
| `limits` | string[] | fixed text set: shared kernel, local signing key, host-side readers, fetch egress, attempts recorded when observable, plus runtime-specific lines (rootful docker) |
| `runtime`, `imageId` | | for the report |

Level rules are in research R9 and in `contracts/isolation-record.ts`. The statement is inside the signed manifest bytes.

## StatusCause additions

`isolation-unavailable`, `limit-memory`, `limit-pids`, `source-too-large`, `advisory-data-missing`, `advisory-request-filtered`, `rules-stale`, `residue`. Mapping to status:

| Cause | Status | Required scanner effect |
|-------|--------|-------------------------|
| `isolation-unavailable` | `unavailable` (at start) or `failed` (during a step) | INCOMPLETE |
| `limit-memory` | `failed` | INCOMPLETE |
| `limit-pids` | `partial` if the tool's own result was usable, else `failed` | INCOMPLETE |
| `source-too-large` | source `failed` (non-retryable) | INCOMPLETE, no scans |
| `advisory-data-missing` | `unavailable` | INCOMPLETE when npm-audit is required |
| `advisory-request-filtered` | `partial` | INCOMPLETE |
| `rules-stale` | `partial` | INCOMPLETE |
| `residue` | teardown record `partial` | outcome unchanged; report shows residue and the evidence is not marked clean of residue |

The 004 outcome rule (`computeOutcome`) is unchanged: any required scanner not `completed` makes the audit INCOMPLETE.

## ClientCredential and TemporalAccessConfig

| Item | Content | Validation |
|------|---------|------------|
| CA | ECDSA P-256, `CN=Tessera local CA <date>`, basicConstraints CA, keyUsage keyCertSign, 365 days | key 0600 in a 0700 directory outside the repository and any evidence root |
| Server certificate | SAN `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`; EKU serverAuth; 90 days | |
| Client certificates | `CN=tessera-worker`, `CN=tessera-client`; EKU clientAuth; 90 days | expired → refused by the server handshake |
| `TemporalAccessConfig` | `address` (default `127.0.0.1:7233`), `tlsDir`, `identity` (`worker` \| `client`), `allowRemote` (only `TESSERA_TEMPORAL_REMOTE=1`) | no certificate files → refuse; host not loopback and not `allowRemote` → refuse |

Rotation: `temporal:pki --rotate` writes a new CA and certificates; the server is restarted with the new client CA; every older certificate is refused.

## WorkflowActivities

A frozen object with exactly 16 keys (`contracts/worker-registry.ts`). Validation: key set equals the fixed list; no key from `LEGACY_ACTIVITY_NAMES`; the worker passes this object, never a module namespace.

## AttackFixture and ExpectedContainment

| Field | Notes |
|-------|-------|
| `id` | `A01`…, stable |
| `layer` | `environment` (payload executed inside the scan profile) or `audit` (full audit of a hostile repository) |
| `threat` | path traversal, link to host file, process flood, memory hog, oversized output, network at scan time, write outside workspace, source size bomb, cross-audit read, steering of tools |
| `build` | function in `demo/attack/build-fixtures.js` creating the repository or payload in a private temp directory |
| `expected` | step status and cause, restriction states, blocked attempts, `environment gone`, host canary unchanged |

`demo/attack/EXPECTED.md` is written before the first run and is not edited to make a run green (same rule as `demo/EXPECTED.md`).
