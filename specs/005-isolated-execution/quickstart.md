# Quickstart: Isolated Execution

**Feature**: 005-isolated-execution | **Date**: 2026-10-04
Test scenarios per user story, traceable to FR and SC. Test file names are proposals; final test IDs come from `/iikit-04-testify`. Hermetic = fake inner `ProcessRunner` with recorded runtime output and cgroup counters, temporary evidence root, no runtime or network needed. Gate = needs rootless podman (or docker) and the scanner image; part of `npm run release:gate`.

## Preparation

```bash
npm ci
npm run verify                                   # build, hermetic tests with coverage, lint (also CI)

# one-time, needs network: scanner image and Temporal PKI
npm run isolation:build                          # writes ~/.config/tessera/isolation.json (image ID)
npm run isolation:check                          # runtime, image, self-test; prints the restriction table
npm run temporal:pki                             # ~/.config/tessera/temporal-pki (0700)

# local gates
npm run test:isolation                           # attack fixtures, containment (environment and audit layers)
npm run demo                                     # isolated, mTLS; recall, VERIFIED, isolation level
npm run dogfood                                  # Tessera audits itself isolated
npm run release:gate                             # all of the above; a skipped isolation test fails it
```

Run a single audit by hand:

```bash
npm run temporal:local                           # stock server in rootless podman, 127.0.0.1:7233, mTLS
npm start                                        # worker; logs registered activities and the isolation check
npm run workflow -- https://github.com/<owner>/<repo>
npm run evidence:verify -- <bundle> --pubkey <key.pub> --report <report.md>
```

## US1: Hostile source cannot escape (P1)

| # | Scenario | Level | FR / SC |
|---|----------|-------|---------|
| 1.1 | Argv for the scan profile contains `--network none`, `--read-only`, `--cap-drop all`, `no-new-privileges`, limits, one `:ro` source mount, image by ID; never `--privileged`, `--cap-add`, extra `-v` | hermetic `tests/unit/isolation/container-args.test.ts` | FR-002..005, FR-009 |
| 1.2 | Path translation maps source, home, tmp, config; an argument or env value with any other absolute host path is refused with `EISOLATION` | hermetic `path-map.test.ts` | FR-007 |
| 1.3 | Inspect fixture with `Privileged: true` or an extra bind → mandatory restriction not applied → container removed, never started, step `failed/isolation-unavailable` | hermetic `isolated-runner.test.ts` | FR-002, FR-011 |
| 1.4 | Host timeout or stdout overflow → `rm --force --time 0` is called before the outcome returns | hermetic | FR-005 |
| 1.5 | Counter fixtures `oom_kill 1` → `failed/limit-memory`; `pids max 3` with otherwise valid output → `partial/limit-pids` | hermetic `observe.test.ts`, `run-tool-isolation.test.ts` | FR-005 |
| 1.6 | Probe records `link-outside-source` for `a -> /etc/shadow` and `b -> ../../..`; `detectTechStack` ignores a linked `package.json` | hermetic | FR-006 |
| 1.7 | A01 to A06 environment payloads (fork flood, memory hog, 200 MB stdout, TCP/DNS to host listener and public address, writes to `/src`, `/`, `/etc`, scratch overflow, read of a sibling audit path) end with the expected status and cause; host canary tree hash unchanged; listener saw 0 connections; sibling audit unchanged | gate `tests/isolation/environment.test.ts` | SC-001 |
| 1.8 | Audit-layer fixtures: links to a host canary (incl. `package.json` and lockfile), oversized gitleaks output, 200 000 files, hostile `.npmrc` and lifecycle scripts, size bomb (`source-too-large`), hooks and attribute filters in the repository: defined outcome, canary secret nowhere in evidence, report, findings, worker log | gate `tests/isolation/audit.test.ts` | SC-001, FR-006 |
| 1.9 | After complete, incomplete, failed, cancelled audits and after a worker killed mid-scan: no container with the run label, no audit slice, no work directory | gate (with Temporal) | FR-001, FR-021, SC-008 |
| 1.10 | 10 distinct concurrent pairs (20 audits, staggered starts): no cross-read, separate labels, slices, work directories, bundles; hermetic: 200 concurrent allocations with forced equal starting pairs give pairwise distinct SELinux labels | gate + hermetic | FR-008, SC-009 |

## US2: Same results when isolated (P1)

| # | Scenario | Level | FR / SC |
|---|----------|-------|---------|
| 2.1 | Advisory request validation matrix (too large, too many names, invalid name, invalid version → dropped and counted, empty) | hermetic `npm-advisories.test.ts` | FR-020 |
| 2.2 | Fetch failures (network, timeout, HTTP 500, not JSON, oversize) → `unavailable/advisory-data-missing`; replay is never started | hermetic | FR-020, constitution VII |
| 2.3 | `advisory-proxy.js` record captures a gzip bulk body and prints only it; replay refuses an empty snapshot; replay serves 404 for packuments | hermetic (fake npm script) `tests/unit/isolation/advisory-proxy.test.ts` | FR-004 |
| 2.4 | Rules older than `TESSERA_RULES_MAX_AGE_DAYS` → `semgrep partial/rules-stale` | hermetic | FR-020 |
| 2.5 | Demo isolated: strict recall ≥ 8 of 18, D05, D06, D07 found, clean-app `complete`, planted secrets nowhere, overhead within budget | `npm run demo` | FR-019, SC-002 |
| 2.6 | Every demo and dogfood bundle: `VERIFIED` with the run's public key, no modified, missing or extra record | `npm run demo`, `npm run dogfood` | SC-003 |
| 2.7 | Dogfood isolated: outcome COMPLETE, all five scanners completed | `npm run dogfood` | SC-002 |

## US3: Orchestration reachable only locally and authenticated (P1)

| # | Scenario | Level | FR / SC |
|---|----------|-------|---------|
| 3.1 | PKI: CA, server and client certificates parse with `X509Certificate`, chain verifies, SAN and EKU correct; key files 0600 in a 0700 dir; dir inside the repository or evidence root refused | hermetic `tests/unit/temporal/pki.test.ts` | FR-013 |
| 3.2 | `node:tls` server with `requestCert` and `rejectUnauthorized`: handshake succeeds with the client certificate, fails without one, fails with an expired one, fails after `--rotate` with the old one | hermetic | FR-013, SC-006 |
| 3.3 | `resolveTemporalAccess`: missing certificate → `no-credentials`; key mode 0644 → `insecure-key-file`; `10.0.0.5:7233` → `non-loopback`; with `TESSERA_TEMPORAL_REMOTE=1` and certificates → allowed | hermetic | FR-012, FR-013 |
| 3.4 | `temporal:local` config generation: `requireClientAuth: true`, only the frontend published on the bind address; bind `0.0.0.0` without `--expose` refused | hermetic | FR-012, FR-013 |
| 3.5 | No committed configuration publishes Temporal beyond loopback (scan of repository config files) | hermetic | FR-012 |
| 3.6 | Real server: Temporal CLI without certificate refused; with client certificate works; worker and audit run (demo); connect via the host's LAN address refused; expired client certificate refused | local gate (spike S2 checks as tests) | SC-006 |

Note: "another machine" is tested as a connection to the host's non-loopback address from the same host; the published port exists only on 127.0.0.1.

## US4: Never silently unisolated (P1)

| # | Scenario | Level | FR / SC |
|---|----------|-------|---------|
| 4.1 | Workflow with `checkIsolation` failing (no runtime, image missing, image ID mismatch, image outdated, mandatory restriction missing, self-test failed): `fetchSource` never called, outcome INCOMPLETE, cause `isolation-unavailable` with detail, every required scanner `unavailable`, report has no "no findings" line | hermetic workflow integration `workflow-isolation.test.ts` | FR-010, SC-005 |
| 4.2 | Isolation lost after gitleaks completed: semgrep and npm `failed/isolation-unavailable`, review `skipped`, gitleaks record kept and sealed, outcome INCOMPLETE | hermetic workflow integration | FR-010 |
| 4.3 | A `ProcessRequest` without isolation hint is refused; the activity factory in production wiring holds the isolated runner; no module under `src/scan/` imports `defaultProcessRunner` except the wiring | hermetic architecture test | FR-011 |
| 4.4 | There is no env value that selects an unisolated runner (`TESSERA_ISOLATION_RUNTIME=none` → configuration error) | hermetic | FR-011 |
| 4.5 | Real host: runtime made unavailable (`TESSERA_ISOLATION_RUNTIME=podman` with podman hidden from `PATH`, and with a wrong image ID): INCOMPLETE, the source was never cloned | gate | SC-005 |

## US5: Legacy command-text checks unreachable (P2)

| # | Scenario | Level | FR / SC |
|---|----------|-------|---------|
| 5.1 | `Object.keys(workflowActivities)` equals `WORKFLOW_ACTIVITY_NAMES`; no `LEGACY_ACTIVITY_NAMES` member present; object frozen | hermetic `tests/unit/worker/registry.test.ts` | FR-014, SC-007 |
| 5.2 | `buildWorkerOptions().activities === workflowActivities` (identity, not a namespace import) | hermetic | FR-014 |
| 5.3 | Workflow proxy typed with `WorkflowActivities` (type test: calling a legacy name does not compile) | hermetic (tsc in verify) | FR-014 |
| 5.4 | Real worker: start log lists 16 activities; starting a workflow named `runLighthouse` runs nothing (no work directory, no container) and its workflow task fails as unknown | local gate | SC-007 |

## US6: Report states the isolation actually used (P2)

| # | Scenario | Level | FR / SC |
|---|----------|-------|---------|
| 6.1 | `computeIsolationLevel` table: all applied → `contained`; one resource not applied → `partial` naming it; a tool-run without block → `none`; violated limit → level unchanged; order of records irrelevant | hermetic `level.test.ts` | FR-016, FR-018 |
| 6.2 | Every `tool-run` record of an isolated audit has an isolation block with all restrictions and the image ID; `environment.check` and `environment.teardown` records present | hermetic integration, gate | FR-015, SC-004 |
| 6.3 | Report outcome block: level, runtime, image ID, restricted list, limits; `partial` names each missing restriction; `none` says no area was scanned | hermetic `report-isolation.test.ts` | FR-016, FR-018 |
| 6.4 | Verify tamper matrix (`contracts/verify-isolation.md`): mismatch, missing statement, invalid block, `--report` mismatch, pre-005 bundle | hermetic | FR-017, SC-004 |
| 6.5 | Docker run on this host: level `partial` with `rootless-runtime` and `limit-observation` named | gate (spike S3 then test) | FR-018 |
| 6.6 | Demo and dogfood: verify recomputes the same level as stated in every bundle | `npm run demo`, `npm run dogfood` | SC-004 |

## Expected numbers for the release gate

- Attack fixtures: 100 % contained (SC-001); environment gone after 100 % of exits (SC-008); 10 of 10 distinct concurrent pairs clean (SC-009).
- Demo: strict recall ≥ 8/18 with D05–D07; dogfood COMPLETE, 5 of 5 scanners completed (SC-002); 100 % bundles VERIFIED (SC-003).
- Isolation level: `contained` with rootless podman on the development host; recomputed equal in every bundle (SC-004).
- Isolation unavailable: 100 % INCOMPLETE with cause, 0 scanned (SC-005). Temporal: 100 % of unauthenticated or non-loopback attempts refused (SC-006). Legacy: 0 of the legacy names startable (SC-007).
