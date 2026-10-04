# Implementation Plan: Isolated Execution

**Branch**: `005-isolated-execution` (trunk-based, commits on `main`) | **Date**: 2026-10-04 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/005-isolated-execution/spec.md`
**Project**: Tessera (internal codename)

## Summary

A scan can still run third-party programs on hostile source inside the framework's trust zone, the orchestration service accepts anyone who can reach it, and the worker registers every legacy command-text check (review #1, #3, #6; roadmap items 006, 008, 012). This feature closes those three openings and makes the isolation that was actually applied part of the signed evidence:

1. Every external program that opens audited content (git fetch, gitleaks, semgrep, npm audit, their version probes) runs in a throwaway rootless container per step, through an isolated runner that sits behind the existing `ProcessRunner` interface. `runTool`, policies, redaction and evidence logic stay as they are. Read-only source, no network while scanning, non-root, no capabilities, read-only root filesystem, pinned image, limits on time, output, memory, processes, CPU and scratch.
2. Scanner data is prepared offline: semgrep packs live in the pinned image; npm advisories are captured by a record pass, fetched by the host with a validated package list, and replayed.
3. Isolation is checked before the first step and fails closed; a missing mandatory restriction never degrades into an unisolated run. Each isolated step records the restrictions as the runtime and the kernel applied them; the isolation level (`none`, `partial`, `contained`) is computed from those records at sealing, signed, printed in the report and recomputed by `evidence:verify`.
4. Temporal runs with mutual TLS and is published on loopback only; worker and clients refuse to connect without certificates.
5. The worker registers an explicit allowlist of workflow activities; the legacy checks become unreachable.

Decisions and measurements: [research.md](./research.md) (R1 to R20). Types: [contracts/](./contracts/). Entities: [data-model.md](./data-model.md). Test scenarios: [quickstart.md](./quickstart.md).

## Technical Context

**Language/Version**: TypeScript 5.x (strict), Node.js ≥ 20.3 (CI image `node:22-alpine`, digest-pinned); helper scripts in the scanner image are plain Node (CommonJS, no dependencies); the scanner image runtime is Node 24.18.1, not 22 (spike S1: Alpine 3.23 has no Node 22)
**Primary Dependencies**: existing `@temporalio/*` ^1.24 (TLS options on `Connection` and `NativeConnection`), `pino` ^10. New npm dependencies: none. Node built-ins: `crypto` (ECDSA P-256 keys, signatures, `X509Certificate`), `fetch`, `zlib`, `http`, `tls`, `child_process.execFile` (only in `process-runner.ts`). New host prerequisites: podman ≥ 5 rootless with cgroup v2 `memory` and `pids` delegated (preferred) or Docker ≥ 25 (fallback, lower level); the scanner image built by `npm run isolation:build`; the Temporal server image `temporalio/server:1.32.0` pinned by digest (replaces `temporal server start-dev`)
**Storage**: unchanged from 004 (private work directory under `os.tmpdir()`, evidence bundle under `TESSERA_EVIDENCE_ROOT`, report under `outputDir`). New local, non-versioned files: `~/.config/tessera/isolation.json` (pinned image ID), `~/.config/tessera/temporal-pki/` (CA and certificates, 0700/0600)
**Testing**: vitest 5 hermetic unit and integration tests with fake `ProcessRunner` and recorded `inspect`/cgroup fixtures (in `npm run verify` and CI); `npm run test:isolation` with a real runtime and the image (local release gate); `npm run test:tools` (unchanged); cucumber scenarios from `/iikit-04-testify`; `npm run demo` and `npm run dogfood` as ground-truth gates; `npm run release:gate` runs all local gates
**Target Platform**: Linux worker host with rootless podman (developed on Fedora, kernel 7.2, SELinux enforcing, podman 5.8.7); Temporal server in a rootless container on the same host
**Project Type**: single project (`src/`, `tests/`, `config/`, `demo/`, `scripts/`)
**Performance Goals**: isolation overhead ≤ 20 s per demo audit and ≤ 25 % of the audit's wall time, computed from record durations; one container start measured at 0.69 s
**Constraints**: no unisolated fallback by default or by configuration (FR-011); no new npm dependency; no host mount other than the declared source directory (and, in development only, the read-only source mirror); the source never reaches the host disk beyond `TESSERA_MAX_SOURCE_MB` (default 1024); scanners have no network while scanning; existing limits stay (stdout 64 MiB, stderr 1 MiB, per-tool timeouts, ≤ 2000 findings per step); a worker with 4 parallel steps needs about 8 GiB for audit containers
**Scale/Scope**: one repository per audit, about 12 container runs per audit, 4 parallel activities per worker; 16 registered activities instead of every export of the 2739-line `src/activities/index.ts`

## Constitution Check

*GATE: checked before research and again after the design (Step 6). Outcome per principle.*

| Principle | How this plan complies | Pre | Post |
|-----------|------------------------|-----|------|
| I Security-First | Closes the remaining execution of third-party tools on hostile input in the trust zone (R1) and the unauthenticated orchestration service (R12). Input validation at the new boundaries: path translation refuses unmapped host paths (R4), the advisory request body is validated before it leaves the host (R7), the image is pinned by ID and its framework files are hash-checked (R6). Secure defaults: no plaintext Temporal mode, no unisolated mode, limits cannot be switched off. Security review checkpoint in the migration table | PASS | PASS |
| II TDD | Test specs first via `/iikit-04-testify`; every FR has a test level (traceability table). Coverage floor unchanged globally; `src/isolation/**` and `src/temporal/**` join the stricter critical-path thresholds, proven to fail once. Mutation loop on every Tier C task (R18). Hermetic tests for everything a fake runner can prove; real-runtime tests are a separate, non-skippable gate | PASS | PASS |
| III Enterprise Compliance | Not changed in substance. The report states the isolation level and its limits, so compliance statements built on the audit name what isolation covered | PASS | PASS |
| IV Traceability | FR → design → test table below; architecture diagram; every isolated step has its own record linking environment, restrictions and blocked attempts | PASS | PASS |
| V Reliability & Observability | Timeouts on every step, enforced by host and container runtime; forced container removal after timeout or overflow; teardown on every exit path with a residue record and a sweeper for terminated workflows (R10); log line per isolated step with run, step, container, profile, restriction summary, limit events. Heartbeats remain roadmap 007 and are not made worse | PASS | PASS |
| VI Evidence-First | Each isolated step records the container argv, image ID, runtime version and restriction states as applied (inspect and kernel counters, R9); the advisory snapshot is an artifact with hashes (R7); the isolation statement is in the signed manifest | PASS | PASS |
| VII No False Comfort | Isolation unavailable means INCOMPLETE with the cause and every required scanner `unavailable` (R8); missing advisory data never becomes "0 vulnerabilities" (R7); stale rules make semgrep `partial`; limit hits are `partial` or `failed` with the limit named; blocked attempts are labeled "recorded when observable", heuristic stderr detection is labeled heuristic | PASS | PASS |
| VIII Untrusted Input Isolation | Core of the feature: audited code, configuration and metadata are only handled by tools inside the container; arguments as arrays end to end; working locations private, unpredictable, size-limited (scratch and source limit) and removed on every exit path; network exposure of Temporal explicit and authenticated (mTLS, loopback publish) | PASS | PASS |
| IX Human Accountability | Not touched. Approval flow unchanged | PASS | PASS |
| X Claims Match Reality | The report states only the computed level and its limits (shared kernel, local key, host-side readers, egress during fetch, observation limits); CI's inability to prove containment is written in the README instead of a green check that does not test it (R16) | PASS | PASS |
| XI Independent Verification | Attack fixtures with expected outcomes next to the ground truth (R14); demo recall gate ≥ 8 of 18 with D05 to D07 under isolation; second-family review and security review per Tier C task | PASS | PASS |
| XII Assurance Ratchet | The isolation level is computed from records, signed and recomputed by verification; nothing lowers an existing gate. The assurance level shown stays 0 or 1 until all level-2 exit criteria are met; isolation is reported as its own computed line | PASS | PASS |
| Quality Gates / CI | All hermetic tests run in `npm run verify`, the pre-commit hook and CI. Real-runtime containment cannot run in Woodpecker's unprivileged Docker steps (measured, R16); it is a local release gate that fails when skipped, recorded under "Known deviations". Every CI run prints one line in its summary, `Containment: local release gate only, not proven in CI`, until a CI backend that can run containers exists (R16). Local `verify` and CI stay equivalent | PASS | PASS |

**Gate outcome: PASS** before and after the design. No violations; Complexity Tracking stays empty. The CI limit is a stated limit of what a container-based CI can prove, not a weakened gate.

## Architecture

```
                         mTLS (client cert)                     ┌────────────────────────────┐
  ┌──────────────┐  127.0.0.1:7233 only    ┌───────────────────┐ │ Temporal History           │
  │ Audit Client │ ──────────────────────▶ │ Temporal Server   │─│ (rootHash, statuses,       │
  └──────────────┘                         │ (rootless podman, │ │  isolation level)          │
  ┌──────────────┐  certificates           │  mTLS required)   │ └────────────────────────────┘
  │ Local PKI    │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶└────────┬──────────┘
  └──────────────┘                                  │ task queue "audit" (mTLS)
                                                    ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
  │ Audit Worker (host, trusted zone)                                                            │
  │  ┌───────────────────────────┐  proxyActivities<WorkflowActivities>  ┌────────────────────┐  │
  │  │ applicationAudit Workflow │ ────────────────────────────────────▶ │ Workflow Activity  │  │
  │  │ init → checkIsolation →   │                                       │ Registry (16 only) │  │
  │  │ fetch → scans → teardown  │ ◀──────────── ScanStepResult ──────── └─────────┬──────────┘  │
  │  │ → seal(level) → sign →    │                                                 │             │
  │  │ report                    │        ┌──────────────────┐   ┌─────────────────▼──────────┐  │
  │  └───────────────────────────┘        │ Host-side Readers│   │ runTool Wrapper            │  │
  │                                       │ probe, license,  │   │ (policy, redact, evidence) │  │
  │  ┌──────────────────┐                 │ tech stack,      │   └──────────┬─────────────────┘  │
  │  │ Advisory Fetcher │                 │ review (no-follow│              │ ProcessRequest     │
  │  │ (validated body) │                 └────────┬─────────┘              │ + IsolationHint    │
  │  └───────┬──────────┘                          │ lstat/O_NOFOLLOW       ▼                    │
  │          │        ┌────────────────┐  ┌────────▼─────────┐   ┌────────────────────────────┐  │
  │          │        │ Evidence Store │◀─│ Private Work Dir │   │ Isolated Runner            │  │
  │          │        └──────┬─────────┘  │ (0700, per audit)│   │ create→inspect→start→      │  │
  │          │               │            └────────┬─────────┘   │ counters→rm (execFile)     │  │
  │          │   ┌───────────▼──┐ ┌─────────────┐  │             └──────────┬─────────────────┘  │
  │          │   │ Signing Key  │ │ Report File │  │                        │ podman/docker CLI  │
  │          │   └──────────────┘ └─────────────┘  │                        ▼                    │
  └──────────┼───────────────────────────────────── ┼ ────────────────────────────────────────────┘
             │                                     │ one mount: source dir    ┌──────────────────┐
             │ HTTPS POST (package list)           │ (rw fetch, ro scan)      │ Container Runtime│
             ▼                                     ▼                          │ (rootless podman)│
  ┌──────────────────┐            ┌───────────────────────────────────────┐  └────────┬─────────┘
  │ npm Registry     │            │ Fetch Container (egress, bounded      │◀─────────┤ per-step
  └──────────────────┘            │ scratch clone, copy to source dir)    │          │ slice, labels
  ┌──────────────────┐   clone    └───────────────────────────────────────┘          │
  │ Source Repository│ ─────────▶ ┌───────────────────────────────────────┐          │
  └──────────────────┘            │ Scan Containers (network none, ro src,│◀─────────┘
  ┌──────────────────┐ image ID   │ gitleaks, semgrep, npm record/replay) │
  │ Scanner Image    │ ─────────▶ └───────────────────────────────────────┘
  └──────────────────┘            ┌──────────────┐
                                  │ Verify CLI   │ ── reads Evidence Bundle, recomputes level
                                  └──────────────┘    ┌─────────────────┐
                                                      │ Evidence Bundle │
                                                      └─────────────────┘
```

Workflow sequence (only what the spec requires changes; phases, signals and queries stay):

```
run = initAuditRun()
try
  env = checkIsolation(run)            ── new; unavailable → seal check record → INCOMPLETE (isolation-unavailable), no fetch
  source = fetchSource(run, url)       ── clone in fetch container (bounded scratch → copy), rev-parse in scan container, probe on host
  detectTechStack / generateScopeDocument   ── host, no-follow reads
  steps = settle(4 scans)              ── gitleaks, semgrep in scan containers; npm: record → host fetch → replay; license in-process
  if any step isolation-unavailable → review skipped, else settle(review)
  teardown = teardownEnvironment(run)  ── containers by label, audit slice, work dir; residue record
  decision = computeOutcome(…)         ── unchanged rule + new causes
  sealed = sealEvidence(…)             ── computes manifest.isolation from the sealed records
  sign → mapToCompliance / crossValidate / approval → generateReport(+ isolation block)
on failure paths: teardown first, then seal best-effort
finally
  teardownEnvironment(run)             ── idempotent
```

## Traceability FR → design → test

| FR | Design element | Test level |
|----|----------------|-----------|
| FR-001 | per-step containers labeled per run, audit slice, `teardownEnvironment` on every path, sweeper (R10) | unit (teardown with fake runner), isolation gate (exit paths incl. cancel, worker kill) |
| FR-002 | R1 boundary: all external tools via isolated runner; runner refuses requests without a hint; architecture test | unit (wiring, refusal), architecture test |
| FR-003 | scan profile `:ro` mount, restriction `source-read-only`, EROFS attempts recorded (heuristic) | unit (argv, inspect fixture), isolation gate (write payloads) |
| FR-004 | scan profile `--network none`, restriction `network-none`; npm via record/replay (R7) | unit, isolation gate (host listener sees 0 connections) |
| FR-005 | time/output (host + runtime; a runtime `--timeout` kill is ExitCode -1 without message, spike S1), memory/pids from slice counters (`oom_kill` in `memory.events`, not inspect `OOMKilled`, spike S1), causes `limit-memory`, `limit-pids` (R5) | unit (counter fixtures → status), isolation gate (flood, hog, output) |
| FR-006 | container namespace; probe records `link-outside-source`; `detectTechStack` no-follow (R11) | unit (probe, tech stack), audit-layer fixture with host canary |
| FR-007 | only the source dir mounted; outputs only via stdout; evidence written by host | isolation gate (canary tree hash, sibling audit, earlier bundle verifies) |
| FR-008 | per-run work dir, per-run labels, per-audit SELinux level (two categories, allocated from a host-wide registry of active labels under a lock so concurrent audits never share a pair), one mount per container | unit (argv; allocator gives distinct labels for 200 concurrent allocations even when every run id hashes to the same start pair; released labels are reusable), isolation gate (10 distinct concurrent pairs, staggered starts) |
| FR-009 | `/scratch` tmpfs sized (`mode=0700,U`, spike S1), `HOME`/`TMPDIR` set by value to `/scratch` (spike S1) | unit (argv), self-test record |
| FR-010 | `checkIsolation` before fetch, fail-closed runner, stop after isolation loss (R8) | unit, workflow integration (fake activities), isolation gate (runtime made unavailable) |
| FR-011 | no plain runner wiring, no config value for "none" | architecture test, unit (config parser has no such value) |
| FR-012 | `temporal:local` publishes 127.0.0.1 only; `connectTemporal` refuses non-loopback without explicit flag (R12) | unit (guards, static config check), local gate (LAN address refused) |
| FR-013 | frontend `requireClientAuth`, no plaintext mode, launcher refuses exposure without `--expose`; expired certificate refused; rotation = revocation | unit (PKI, node:tls handshakes, guards), local gate (Temporal CLI without and with certificate, expired certificate) |
| FR-014 | `workflowActivities` registry, `buildWorkerOptions` (R13) | unit (key set, no legacy name), local gate (legacy workflow name runs nothing) |
| FR-015 | `record.isolation` with restrictions and blocked attempts; `environment.check` record (R9) | unit (record from fixtures), isolation gate |
| FR-016 | `manifest.isolation` computed at seal; report isolation block | unit (level function, report), demo |
| FR-017 | verify recomputes, `isolation-level-mismatch`, `--report` comparison | unit (tamper matrix) |
| FR-018 | resource restriction `not-applied` → `partial`, named | unit (level function), isolation gate (docker run) |
| FR-019 | unchanged policies and parsers; npm replay; packs in image (R7, R15) | demo (≥ 8/18, D05–D07, VERIFIED), dogfood (COMPLETE) |
| FR-020 | advisory snapshot record with freshness; `advisory-data-missing`; `rules-stale` (R7) | unit, demo |
| FR-021 | teardown record with `residue`, sweeper, report line | unit, isolation gate (removal failure injected via fake runner; real leftovers swept) |
| FR-022 | `demo/attack/build-fixtures.js`, `demo/attack/EXPECTED.md`, `test:isolation` in `release:gate` (R14) | isolation gate |

## Implementation Phases and Migration Path

Each row is one commit per constitution (Development Workflow, Quality Gates), with test specs from `/iikit-04-testify` shown red before implementation (principle II). Verification per step: `npm run verify` locally and the CI status after push; rows marked *gate* also run `npm run test:isolation` locally. New modules stay unused until they are wired in, so unfinished work is dark without a runtime toggle. The Tier column is a proposal for `/iikit-05-tasks` (A mechanical, B judgment inside a fixed design, C architecture or high blast radius). **Mutation loop**: every Tier C row.

**Phase 0: spikes (no production code; results appended to research.md as addenda)**

| # | Spike | Exit criterion | Tier |
|---|-------|----------------|------|
| S1 | Build the scanner image from the Containerfile draft; rerun the R3 smoke test with it; run semgrep, gitleaks and the npm record/replay on the demo inside it | image ID recorded; demo npm replay yields the 9 packages; semgrep packs present and hashed; `--log-driver none` with `start --attach` streams output; parallel containers with a shared SELinux level work with `:Z`; podman `--timeout` kills a sleeping container | C |
| S2 | Run `temporalio/server:1.32.0` rootless with generated SQLite and frontend mTLS config, publish only `127.0.0.1:7233` | Temporal CLI without certificate refused; with certificate `operator namespace list` works; TS client and worker connect; `podman port` shows only 127.0.0.1:7233; connection via the host's LAN address refused; expired client certificate refused | C |
| S3 | Docker fallback with the same image | profile works with `--user`; record which restrictions are observable | B |

Order: run S2 first, with certificates generated by Node's crypto (the planned encoder in `src/temporal/pki.ts`), before writing the encoder's tests; if the server rejects them, the recorded fallback is openssl inside the scanner/tool image, justified in research.md (R12 addendum).

Re-plan triggers:
- S1 fails on any exit criterion: stop and re-plan R6 and R7 before Phase 1 (with the product owner for R7 when the npm replay does not reproduce the findings).
- S2 fails: US3 is not delivered in this feature; the report and README state "Temporal access control: not delivered" and the isolation work continues (the host-binary fallback of R12 is recorded as the decision).
- S3 fails: docker is partial-only (never `contained`).

**Phase 1: isolation core (dark)**

| # | Commit (conventional) | Content | Verification | Tier |
|---|-----------------------|---------|--------------|------|
| 1 | `feat(isolation): profiles, path translation and container argv (pure)` | `src/isolation/profiles.ts`, `path-map.ts`, `container-args.ts`; bounds parsing of env limits | unit: both profiles × both runtimes, refusal of unmapped paths, env by name, no limit can be disabled | C |
| 2 | `feat(isolation): restriction observation and isolation level (pure)` | `observe.ts` (inspect JSON, slice counters → restriction states, limit events), `level.ts` | unit with recorded inspect and counter fixtures from S1 | C |
| 3 | `feat(scan): stdin and isolation pass-through in the process runner and runTool` | `ProcessRequest.stdin`, `.isolation`; `ProcessOutcome.isolation`; `record.isolation`; `override()` mappings; new causes in `status.ts` | unit: precedence of new causes, record contains the block, no change for existing outcomes | C |
| 4 | `feat(isolation): isolated runner` | `isolated-runner.ts` (create, inspect, start, counters, forced rm, fail closed) with injected inner runner and clock | unit: call sequence, rm after timeout and overflow, `EISOLATION` without hint, mandatory restriction missing → not started; SELinux label derivation (two distinct 10-bit categories from sha256(runId), c1 != c0) with a unit test that 1000 synthetic run ids yield pairwise distinct labels | C |
| 5 | `feat(isolation): scanner image, helpers and build script` | `config/isolation/Containerfile`, `bin/advisory-proxy.js`, `bin/bounded-fetch.js`, `bin/selftest.js`, npm rc files; `src/cli/isolation-build.ts`, scripts `isolation:build`, `isolation:check` | unit for helpers' pure parts (body capture, snapshot validation, copy with links kept); *gate*: image builds, self-test passes | C (helpers), B (Containerfile) |
| 6 | `feat(isolation): runtime detection, checkIsolation and teardown with sweeper` | `runtime.ts`, `check.ts`, `teardown.ts`, `image-manifest.ts`; script `isolation:sweep`; worker-start sweep | unit with fake runner (podman, docker, missing, cgroup v1, outdated image); *gate* | C |

**Phase 2: wire the scan path (US1, US2, US4)**

| # | Commit | Content | Verification | Tier |
|---|--------|---------|--------------|------|
| 7 | `feat(scan): fetch in a bounded container and rev-parse isolated` | `lifecycle.ts`: clone via fetch profile and `bounded-fetch`, `source-too-large`, `TESSERA_SOURCE_MIRROR` (dev only); rev-parse via scan profile; clone argv `-c core.fsmonitor=false -c protocol.file.allow=never`, env `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null` (R3) | unit (argv and env, mirror refused in production); hermetic test that a hostile `.gitattributes` filter cannot run during fetch; *gate* (zip-bomb fixture, filter fixture) | C |
| 8 | `fix(scan): host-side readers never follow links; probe records escaping links` | `detectTechStack` via `readSourceFile`; `source-probe.ts` `link-outside-source` | unit with link fixtures | C |
| 9 | `feat(scan): gitleaks and semgrep in the scan profile with offline packs` | `tools/gitleaks.ts`, `tools/semgrep.ts` hints and image paths; `rules-stale` | unit; *gate* | B |
| 10 | `feat(scan): npm audit record, host advisory fetch and replay` | `tools/npm-advisories.ts` (validation, fetch, snapshot record), `tools/npm-audit.ts` two passes | unit (body validation matrix, fetch failures → `advisory-data-missing`, empty snapshot never replayed); hermetic proxy tests for both orderings (bulk first, quick first); a quick-only capture ends as `advisory-data-missing` with a clear diagnostic, never zero vulnerabilities; *gate*; **demo: D05–D07** | C |
| 11 | `feat(activities): wire the isolated runner, checkIsolation and teardown activities` | `src/scan/activities.ts`, `src/activities/index.ts` factory deps | architecture test (Tier C wiring): asserts the production wiring in the activity factory (the code that builds the activities for the worker), that no scan module imports the default process runner, and that `import * as activities` cannot be reintroduced in `src/worker.ts` | C |
| 12 | `feat(workflow): fail closed on isolation, stop after isolation loss, teardown before seal` | `src/workflows/index.ts` | workflow integration with mocked `@temporalio/workflow`: unavailable at start, lost between steps, teardown order, residue; teardown succeeds but sealing throws: audit INCOMPLETE, residue `none`, no sealed bundle, evidence loss reported (never silent) | C |
| 13 | `feat(evidence): isolation statement in the manifest and verify recomputation` | `manifest.ts`, `verify.ts`, `types.ts`, `src/cli/verify-evidence.ts` (`--report`) | unit: tamper matrix (level edited, block removed, statement removed, pre-005 bundle, isolation blocks present with `environment.check` absent → `isolation-record-invalid`) | C |
| 14 | `feat(report): isolation level and limits in the outcome block` | `src/report/outcome-block.ts`, `AuditResult.isolation` | unit (contained, partial with named restriction, none) | C |

**Phase 3: orchestration access and reachability (US3, US5)**

| # | Commit | Content | Verification | Tier |
|---|--------|---------|--------------|------|
| 15 | `feat(worker): explicit activity registry; legacy checks unregistered` | `src/activities/registry.ts`, `src/worker.ts` (`buildWorkerOptions`), workflow proxy type | unit (key set, legacy names absent) | C |
| 16 | `feat(temporal): local PKI with Node crypto` | `src/temporal/pki.ts`, `src/cli/temporal-pki.ts`, script `temporal:pki` (`--rotate`); five leaves incl. `temporal-system-worker`, positive minimal DER serial (spike S2) | unit: X509 parse, chain, SAN, EKU, expiry; `node:tls` mTLS handshake accepted with, refused without and with expired client certificate | C |
| 17 | `feat(temporal): mTLS connection helper with loopback guard` | `src/temporal/access.ts`; `src/worker.ts`, `src/client.ts` use it; `TEMPORAL_ADDRESS` superseded (review #21) | unit: no certificates → refuse, non-loopback without flag → refuse | C |
| 18 | `feat(temporal): temporal:local launcher on loopback with mTLS` | `src/cli/temporal-local.ts`, generated server config (frontend `bindOnIP 0.0.0.0`, `--userns=keep-id`, `global.tls.systemWorker`, `TEMPORAL_ALLOW_NO_AUTH=true`, `default` namespace registered at start; in-memory SQLite loses state on restart; no Web UI; spike S2), pinned image digest | unit (config generation, exposure refusal); local gate (S2 checks as tests) | C |
| 19 | `chore: remove docker-compose and worker Dockerfile` | delete `docker-compose.yml`, `Dockerfile`; README topology section | static test: no committed config binds Temporal beyond loopback | A (**needs orchestrator confirmation: deletes tracked files**) |

**Phase 4: fixtures, gates and documentation (US1, US2, US6)**

| # | Commit | Content | Verification | Tier |
|---|--------|---------|--------------|------|
| 20 | `test(isolation): attack fixtures and containment gate` | `demo/attack/build-fixtures.js`, `demo/attack/EXPECTED.md`, `tests/isolation/**`, `npm run test:isolation` | *gate*: SC-001, SC-005, SC-008, SC-009; static test (in `verify`): `demo/attack/EXPECTED.md` lists at least one fixture per threat named in FR-022, and the fixture build script exits non-zero when any fixture cannot be created, so the gate cannot pass vacuously | B (review by C) |
| 21 | `test(demo): demo and dogfood isolated with mTLS; release gate` | `demo/run-demo.js`, `scripts/dogfood.js` (preflight, `temporal:local`, throwaway PKI, mirror, level line), `npm run release:gate` | demo ≥ 8/18 with D05–D07, VERIFIED, `contained`; dogfood COMPLETE; overhead budget | B |
| 22 | `docs: isolation, Temporal access, Tier C list, roadmap and deviations` | README (topology, prerequisites, scripts, known deviation R16), AGENTS.md commands, working agreement Tier C list (R18), roadmap items 006 and 008 status, 012 note | doc review | A |
| 23 | Security review checkpoint (no commit unless findings) | isolated runner, path translation, image helpers, advisory fetch, Temporal access, PKI, registry; payloads from R14 | structured review plus second model family; findings fixed before done | C |

Security review (principle I, Pre-Merge Checks): after row 6 (runner and teardown) and after row 18 (access), plus the final checkpoint 23.

Backward compatibility: records stay `tessera.evidence/v1` with an optional `isolation` block; the manifest stays `tessera.manifest/v1` with an optional `isolation` statement (pre-005 bundles verify with "isolation: not stated"); `AuditResult` and the report only gain fields and lines; `cleanupRun` becomes `teardownEnvironment` with the same path guards. Workflow code changes break replay of running audits: drain the worker before deploying rows 12 and 15 (as in 004 R17).

## Test Strategy

Per constitution II (test specs first, shown red, then implementation):

- **At least one test per FR** (table above); SC-005 as a parameterized workflow integration test over each way isolation can be missing (no runtime, image missing, image outdated, mandatory restriction not applied, lost between steps).
- **Hermetic** (`npm run verify`, CI): fake inner `ProcessRunner` that returns recorded CLI output (`podman version`, `info`, `inspect`, `start` results) and a fake cgroup reader with recorded `memory.events` and `pids.events` (fixtures captured during S1 in `tests/fixtures/isolation/`). No test in `test:coverage` calls podman, docker or the network.
- **Workflow integration** without a server: mocked `@temporalio/workflow` as in 004 (R16 there).
- **Real runtime gate** (`npm run test:isolation`, own vitest config): environment and audit layers of R14. A missing runtime or image is a failure, not a skip, when run through `release:gate`; run directly, it skips with recorded cause and owner (`vannifr`) so developers without podman can still run `verify`.
- **Ground truth**: `npm run demo` and `npm run dogfood` isolated, criteria in R15.
- **Coverage floor**: the global floor is not lowered. `src/isolation/**` and `src/temporal/**` get the critical-path thresholds of `src/scan/**` and `src/evidence/**` (90/85/90/90) via per-glob thresholds; the new glob is shown failing once in a scratch copy.
- **Mutation loop**: every Tier C row; the mutants that matter most are listed in the tasks (for example: drop `--network none`, accept a tag reference, translate a prefix without the `/` boundary, treat `not-applied` mandatory as `partial`, replay with an empty snapshot, accept a non-loopback address, accept a client without certificate, register `import *`).

## Non-functional Considerations

| NFR | Consideration and measure |
|-----|----------------------------|
| Performance | About 12 container runs per audit at 0.7 to 1.5 s each, scans in parallel; budget ≤ 20 s and ≤ 25 % of wall time on the demo, computed from record durations and printed by the demo. Memory 2048 MiB per container, 4 parallel activities: ~8 GiB sizing note. Cache of version probes per image ID only if the budget is missed. |
| Security | Rootless runtime, non-root uid, no capabilities, no new privileges, default seccomp, read-only root and source, no network while scanning, one mount, per-audit SELinux level, image by ID with hash-checked framework files, env by name, refusal of unmapped paths, forced removal after limits, fail closed everywhere; mTLS with loopback publish and no plaintext mode; certificates and keys outside repo and evidence; advisory body validated, fixed registry URL. Residual risks: shared kernel, local signing key, host-side readers parse hostile data, egress during fetch, rootful docker fallback (lower level), no CRL. |
| Observability | One structured log line per isolated step (run id, step, container name, profile, runtime, image ID short, restrictions not applied, limit events, duration); worker start logs the registered activity names and the isolation check summary; sweeper logs each removal. No tool output in logs (004 rule). |
| Error handling | Isolation problems are statuses with causes (`isolation-unavailable`, `limit-memory`, `limit-pids`, `source-too-large`, `advisory-data-missing`, `advisory-request-filtered`, `rules-stale`), never exceptions that hide the cause; `IsolationUnavailableError` is non-retryable; container CLI failures during teardown become residue, not a crash; a failing advisory fetch never yields an empty clean result. |
| Accessibility of the report | Isolation stated as text in the outcome block ("Isolation: contained", "Isolation: partial: memory-limit not applied"), limits as a plain list, no colour-only signals; verify CLI prints `isolation: <level> (recomputed: <level>)` and keeps its first-word contract. |

## Out of Scope

- Hardware or VM isolation, kernel-escape and malicious-administrator threats, key custody outside the operator (spec delivery note; roadmap 013).
- Heartbeats and short activity timeouts (roadmap 007); WORM evidence storage (010); migration of the legacy checks (012); own semgrep ruleset (005).
- Publishing the scanner image to a registry, reproducible image builds (014, 027).
- A Temporal Web UI with authentication; multi-identity authorization (one client identity suffices per spec assumption).
- CI that proves kernel containment (needs a Woodpecker agent with the local backend; backlog).

## Decisions Recorded in This Plan (2026-10-04)

The product owner's earlier decisions (container per audit, rootless podman preferred, docker fallback, trunk-based, no new runtime dependency without justification) are taken as given. Decisions made here, each with alternatives in research.md:

1. Boundary: fetch and scanners in containers; Tessera's own data readers stay on the host with no-follow reads (R1).
2. Runner: decorator behind `ProcessRunner`, create/inspect/start/rm, no unisolated path (R2).
3. Limits for memory and processes are read from per-step cgroup slices, not from the runtime's flags (R5); slice names `tessera-<run32>-<stepSlug>a<attempt>.slice` without `-` in the slug, path via `systemctl show` (spike S1).
4. Image pinned by image ID; inputs pinned; not bit-reproducible, stated (R6).
5. npm advisories by record, host fetch and replay; semgrep packs in the image with a staleness threshold (R7). Stated limit (spike S1): packuments are 404 in replay, remediation reads "update to latest" without a version.
6. Levels `none`, `partial`, `contained`; mandatory restrictions block a step, resource restrictions lower the level; rootful docker is `partial` (R9).
7. Source size bounded by cloning into the fetch container's tmpfs (R10).
8. Temporal: mTLS, stock server in rootless podman publishing only the loopback frontend, Node-native PKI, no UI (R12).
9. `docker-compose.yml` and `Dockerfile` are removed (needs confirmation, row 19).

Open questions: none left unresolved in the technical context. Spike S1 or S2 can force a re-plan (stated in Phase 0).

## Project Structure

### Documentation (this feature)

```text
specs/005-isolated-execution/
  spec.md
  plan.md              # this file
  research.md          # decisions R1–R20, measurements, alternatives
  data-model.md        # entities, validation, state transitions
  quickstart.md        # test scenarios per user story
  contracts/
    isolation-runner.ts
    isolation-record.ts
    advisory-data.ts
    temporal-access.ts
    worker-registry.ts
    scanner-image.md
    verify-isolation.md
  tasks.md             # /iikit-05-tasks (not produced by this phase)
```

### Source Code (repository root)

```text
config/
  scanners/                     # unchanged, copied into the image and hash-checked
  isolation/
    Containerfile
    bin/advisory-proxy.js  bin/bounded-fetch.js  bin/selftest.js
    npm/userconfig  npm/globalconfig
src/
  isolation/
    profiles.ts  path-map.ts  container-args.ts   # pure
    observe.ts  level.ts                           # pure
    isolated-runner.ts  runtime.ts  check.ts  teardown.ts  image-manifest.ts
  temporal/
    access.ts  pki.ts
  scan/
    process-runner.ts  run-tool.ts  tool-types.ts  status.ts  lifecycle.ts  source-probe.ts   # additive changes
    activities.ts                                  # wiring, checkIsolation, teardown
    tools/gitleaks.ts  tools/semgrep.ts  tools/npm-audit.ts  tools/npm-advisories.ts
  evidence/
    types.ts  manifest.ts  verify.ts               # isolation block and statement
  activities/
    index.ts                                       # factory deps: isolated runner; legacy exports untouched
    registry.ts                                    # workflowActivities
  report/outcome-block.ts
  cli/
    verify-evidence.ts  isolation-build.ts  temporal-pki.ts  temporal-local.ts
  workflows/index.ts
  worker.ts  client.ts
demo/
  run-demo.js                                      # isolated, mTLS, mirror
  attack/build-fixtures.js  attack/EXPECTED.md
scripts/
  dogfood.js                                       # isolated, mTLS
tests/
  unit/isolation/  unit/temporal/  unit/worker/
  integration/workflow-isolation.test.ts
  isolation/                                       # real runtime, own vitest config
  fixtures/isolation/                              # recorded inspect, info, cgroup counters
```

**Structure Decision**: existing single project. Isolation and Temporal access get their own directories (`src/isolation/`, `src/temporal/`) instead of growing `src/scan/` or the `src/activities/index.ts` monolith; `src/scan/` changes stay additive so 004's Tier C logic keeps its tests.

## Complexity Tracking

No constitution violations; not applicable.

## Amendments after spikes S1 and S2

Source: the addenda at the end of `research.md` (R12 for S2; R3, R5, R6, R7 for S1). Each change is marked `(spike S1)` or `(spike S2)` in the file named. No decision changes and no re-plan; details only.

| # | Where | Old | New | Reason |
|---|-------|-----|-----|--------|
| 1 | `contracts/isolation-runner.ts` argv | podman: `--userns keep-id` | podman: `--userns keep-id --user <uid>:<gid>` (docker unchanged); image ends with `USER 65534:65534`; mutation list adds "drop `--user` on podman" | the image `USER` overrides keep-id (ran as root with `USER root`) |
| 2 | `contracts/isolation-runner.ts` argv | `--tmpfs /scratch:...,mode=1700,...` | podman `mode=0700,...,U`; docker `mode=0700,uid=,gid=` (verify in S3) | `mode=1700` is root-owned, unusable by uid 1000; podman rejects `uid=`/`gid=` |
| 3 | `contracts/isolation-runner.ts` (`MountTable`, `ContainerSpec.envNames/envValues`), `plan.md` FR-009, `scanner-image.md` | `<WORK>/home` to `/scratch/home`, `<WORK>/tmp` to `/scratch/tmp`; env passed by name | both aliases map to `/scratch`; `HOME`, `TMPDIR`, `NPM_CONFIG_*` passed by value (`--env NAME=value`); by-name passing of runtime-steering names refused; entrypoint/helpers create the directories tools expect | semgrep failed without existing dirs; `HOME` by name breaks podman itself |
| 4 | `contracts/isolation-runner.ts` `cgroupParent`, `data-model.md` StepContainer, `plan.md` decision 3 | `tessera-<run32>-<stepSlug>.slice` | `tessera-<run32>-<stepSlug>a<attempt>.slice`, no `-` in the slug, path via `systemctl --user show -p ControlGroup --value` | systemd reads `-` as nesting; counters are cumulative per slice, so retries must not share one |
| 5a | `contracts/scanner-image.md`, `plan.md` Technical Context | Node 22; npm via distribution; catatonit in image; semgrep `/usr/local/bin/semgrep`; base digest open; no `CMD` statement | Node 24.18.1; npm 10.9.8 tarball with sha256; no catatonit; `/usr/bin/semgrep` (also `TOOL_ENTRYPOINTS`); base digest recorded; `CMD []`; manifest `node: 24.x` | Alpine 3.23 has no Node 22; distribution npm is 11.x; podman supplies the init |
| 5b | `contracts/advisory-data.ts` | stdin path assumed | stdin via `create --interactive` plus `start --attach --interactive`; empty snapshot exits 4 (stated once) | measured |
| 5c | `contracts/advisory-data.ts`, `data-model.md`, `plan.md` decision 5 | packument fallout unstated | packuments 404: empty `range`, remediation "update to latest" without version; stated limit shown in the report | measured; findings, severities and titles still reproduce |
| 5d | `contracts/isolation-runner.ts` runner steps and precedence, `data-model.md`, `plan.md` FR-005 | timeout and OOM implied by runtime message or inspect | `--timeout` kill is ExitCode -1, rc 255, no message (classify by host timer or ExitCode, not message); OOM read from `memory.events` `oom_kill`, since inspect says `OOMKilled=false` | measured |
| 6 | `contracts/temporal-access.ts` launcher, `plan.md` row 18 | frontend bind and runtime flags unstated; `systemWorker or internode` open; HTTP/metrics not published | frontend `bindOnIP 0.0.0.0` in the container (host publish stays `127.0.0.1`); `--userns=keep-id`; `global.tls.systemWorker` with fifth leaf `temporal-system-worker` (`PkiPaths` gains `systemWorkerCert`/`systemWorkerKey`); `TEMPORAL_ALLOW_NO_AUTH=true`; register `default` at every start; `stop()` uses `rm -f -t`; no Web UI in the image | `bindOnLocalHost` resets every connection under pasta; key files 0600 need keep-id; system worker loops without its certificate |
| 6b | `contracts/temporal-access.ts`, `plan.md` row 18 | SQLite in memory, implicit | stated limit: all state, including `default`, is lost on restart | measured with `podman restart` |
| 7 | `contracts/temporal-access.ts` serial rule, `plan.md` row 16 | "16 random bytes, first bit cleared" | positive minimal DER INTEGER: `serial[0] = (serial[0] & 0x7f) | 0x40`; encoder strips redundant leading zeros and prefixes `0x00` when the high bit is set; unit test with leading zero byte | non-minimal or negative serial (about 1 in 256) is rejected by Go DER parsing |
