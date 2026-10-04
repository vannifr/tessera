# Research: Isolated Execution

**Feature**: 005-isolated-execution | **Date**: 2026-10-04
**Sources**: `spec.md`, `CONSTITUTION.md` v2.1.0, `docs/assurance-roadmap.md` (items 006, 008, 012), `docs/review-report.md` (#1, #3, #6, #8, #16, #21), `docs/dogfood/2026-10-04-triage.md`, `specs/004-reliable-scan-core/research.md` (R1-R19 and addenda), code on `main` (`3fe3e84`).

Empirical checks were run on 2026-10-04 on the development host (Fedora, kernel 7.2, SELinux enforcing, cgroup v2 with `cpu io memory pids` delegated to the user) in the session scratchpad: podman 5.8.7 (rootless, crun, netavark, pasta), Docker 29.8.2 (rootful, systemd cgroup driver, builtin seccomp), bubblewrap 0.12.0, Temporal CLI 1.9.1 (server 1.32.0), npm 10.9.8. Only images already present locally were used (`alpine:3`, `node:22-alpine`); nothing was pulled. Results hold for these versions; the versions actually used are recorded per evidence record.

---

## R1 The isolation boundary: what runs where

**Decision**: every external program that opens audited content runs in a throwaway container; the framework's own memory-safe code that reads audited files as data stays on the host, behind the 004 no-follow readers.

| Runs in an isolated container | Runs on the host (trusted zone) |
|-------------------------------|----------------------------------|
| `git clone` and `git rev-parse` (fetch profile, R3) | Temporal worker, workflow, activity orchestration |
| `gitleaks dir` | `runTool`: policy, parse, classify, sanitize, redact of bounded scanner output |
| `semgrep` | evidence store, manifest, signing key, signature, report |
| `npm audit` (record and replay passes, R7) | isolated runner (drives the container CLI) |
| tool version probes (`--version` of the in-image tool) | source probe and neutralization (`source-probe.ts`, renames steering files) |
| environment self-test (R8) | license check from the lockfile (in-process JSON, 004 R14) |
| | tech-stack detection and the heuristic code review (in-process, no-follow reads) |
| | advisory fetch from the npm registry with a validated package list (R7) |

**Rationale**: the review (#1, #6) and the dogfood run showed the actual attack surface: third-party programs whose behaviour the audited source can steer or whose parsers process hostile bytes (git: hooks, config, attributes, submodules and pack parsing; npm: `.npmrc`, lifecycle scripts; semgrep and gitleaks: config and ignore files). These are the programs constitution VIII and FR-002 target. Git has a history of clone-time vulnerabilities (submodule and symlink handling, config injection), so the fetch is isolated too, not only the scanners. The host-side readers are Tessera's own TypeScript, execute nothing, parse only JSON or match regexes, and already read with `lstat` plus `O_NOFOLLOW` and size budgets (004 R5, R14, `safe-walk.ts`). Moving them into the container would put framework code into the image (a rebuild for every probe change, two copies of the same logic in flight), add a second result channel from the container, and rewrite five Tier C modules for no gain against execution.

**Alternatives**:
- *A. Scanners only in the container, clone on the host*: smallest change, keeps the demo's local `insteadOf` mapping working, but leaves git's handling of a hostile remote in the trust zone. Rejected for an assurance level 2 claim.
- *B. Everything that reads the source in the container, host never opens an audited file*: strongest boundary, but requires framework code in the image, a named volume per audit the host cannot read, and moving tech-stack detection, review, probe and license check. Rejected now; it is the natural next step if a host-side parser ever gets a vulnerability, and the runner interface (R2) does not block it.

**Gap found while checking the host-side readers**: `detectTechStack` (`src/activities/index.ts:114`) uses `existsSync` and `readFileSync` on `package.json`, `requirements.txt` and `docker-compose.yml`, which follow a symbolic link. A source with `package.json -> /home/<user>/.npmrc` makes the host read a host file. It is fixed in this feature (R11).

## R2 One isolated runner behind the existing `ProcessRunner` interface

**Decision**: a new `createIsolatedRunner(deps): ProcessRunner` decorates the existing `defaultProcessRunner` (which stays the only module importing `child_process`). `runTool`, the tool policies, classification, redaction and evidence writing keep their logic. Additive changes only:
- `ToolInvocation.isolation` (an `IsolationHint`: profile, source directory and access, optional helper mode) is copied by `runTool` into `ProcessRequest.isolation`, also for the version probe.
- `ProcessRequest.stdin?: Buffer` (advisory snapshot, R7) and `ProcessOutcome.isolation?: IsolationObservation`, which `runTool` copies into the record as `record.isolation`.
- `runTool.override()` gains three mappings in its precedence list: `isolation-unavailable`, `limit-memory`, `limit-pids` (R5).

Per request the runner does: build the argument vector (pure, R3/R4) → `<rt> create` → `<rt> inspect` (restrictions as the runtime accepted them) → `<rt> start --attach [--interactive]` through the inner runner with the host timeout and output limit → read the per-step cgroup counters (R5) → `<rt> rm --force`. Every call to the container CLI is itself an `execFile` array through `defaultProcessRunner`.

**No unisolated path (FR-011)**: the activity factory in `src/activities/index.ts` is wired with the isolated runner only. A `ProcessRequest` without `isolation` is refused by the isolated runner with `spawnErrorCode: 'EISOLATION'` (fail closed); there is no configuration value that selects the plain runner for audit steps. An architecture test asserts the wiring and that no scan module imports `defaultProcessRunner` (extends `tests/unit/architecture-exec-ratchet.test.ts`).

**Runtime selection**: `TESSERA_ISOLATION_RUNTIME=podman|docker`; unset means podman when it is usable rootless, else docker. Unset and neither usable means isolation unavailable (R8). There is no `none`.

**Why create/inspect/start instead of `run --rm`**: the inspect between create and start yields the configuration the runtime actually applied (FR-015, "applied, not requested"); `run` gives no such point. Cost: two extra CLI calls per step (R17).

**Alternatives**: bubblewrap (present, smaller, but the product owner chose a container per audit and bwrap lacks image pinning and cgroup limits without systemd-run); a long-lived container per audit with `exec` per step (network and mount settings cannot differ between the fetch step and scan steps, and one compromised step would share a process namespace with the next); Podman's REST API socket (a second protocol and a socket to protect; the CLI is enough).

## R3 Container profiles and the smoke test on this host

**Decision**: two profiles, both with these restrictions: `--read-only` root filesystem with `--read-only-tmpfs=false` and an explicit `--tmpfs /tmp:size=64m,noexec,nosuid,nodev`; `--cap-drop all`; `--security-opt no-new-privileges`; default seccomp profile; non-root user equal to the host worker uid (`--userns keep-id` on podman, `--user <uid>:<gid>` on docker, see R4); `--init`; `--pids-limit`; `--memory` with `--memory-swap` equal to it (no swap); `--cpus`; `--tmpfs /scratch:size=<n>,mode=1700,noexec,nosuid,nodev` as the private scratch (FR-009), `HOME=/scratch/home`, `TMPDIR=/scratch/tmp`; `--pull=never`; image by ID (R6); absolute entrypoint per tool from a fixed table (`git`, `gitleaks`, `semgrep`, `npm`, `node`), unknown tool refused; `--label tessera.run=<run>`, `--label tessera.step=<step>`; `--name tessera-<run>-<step>-a<n>`; `--log-driver none` (output only through attach, never into a runtime log file); `--cgroup-parent` per step (R5); podman `--timeout` slightly above the host timeout.

| Profile | Used by | Source mount | Network | Defaults (bounded, env-tunable) |
|---------|---------|--------------|---------|-----------------------------------|
| `fetch` | `git clone` (bounded fetch helper, R10) | source directory read-write | egress (pasta default) | memory 2048 MiB, pids 256, cpus 2, scratch = source limit 1024 MiB, time 300 s |
| `scan` | `git rev-parse`, gitleaks, semgrep, npm audit (both passes), version probes, self-test | source directory read-only | `none` (loopback only) | memory 2048 MiB, pids 512, cpus 2, scratch 512 MiB, time = existing per-tool timeouts (gitleaks 300 s, semgrep 180 s, npm 120 s) |

**Fetch hardening (review fix)**: the fetch container runs git with `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null` and the clone argv carries `-c core.fsmonitor=false -c protocol.file.allow=never` (lifted only for the development mirror path). A hostile `.gitattributes` filter, hook or fsmonitor in the audited repository cannot run during fetch; a hermetic test proves it with a fake git runner (argv and env assertions) and the gate fixture with a `.gitattributes` filter that would write a marker.

Bounds: memory 512 to 16384 MiB, pids 64 to 4096, scratch 64 to 4096 MiB. A value outside the bounds stops the worker at start; no value can switch a limit off.

**Measured on this host (rootless podman 5.8.7, `alpine:3`, `--network none --read-only --cap-drop all --security-opt no-new-privileges --pids-limit 64 --memory 256m --userns keep-id -v src:/src:ro,Z --tmpfs /scratch:size=16m`)**:

| Check | Result |
|-------|--------|
| identity | `uid=1000` (host uid via keep-id), `CapEff: 0000000000000000`, `NoNewPrivs: 1`, `Seccomp: 2` |
| cgroup limits visible inside | `memory.max = 268435456`, `pids.max = 64` |
| network | only `lo`; `wget http://1.1.1.1` → "Network unreachable"; DNS lookup fails |
| write to `/src` and `/etc` | "Read-only file system" for both |
| link `evil -> /etc/shadow` in the source | resolves to the image's own `/etc/shadow` (permission denied), never the host file |
| link `ssh -> /home/vannifr/.ssh` | "No such file or directory" inside the container |
| scratch size | `dd` of 20 MB stops at 16 MB (16777216 bytes) |
| process flood (100 background `sleep` with pids 32) | "can't fork: Resource temporarily unavailable"; container exit code 0 |
| memory hog (`sort` of 300 MB with 64m) | `Killed`, exit 137, `State.OOMKilled=false` (not reported by the runtime) |
| inspect after create | `ReadonlyRootfs=true`, `NetworkMode=none`, `PidsLimit=32`, `Memory=67108864`, all default caps in `CapDrop`, `SecurityOpt=[no-new-privileges]`, `User=1000:1000` |
| start-up time | 0.69 s wall for one container |
| Docker 29.8.2 fallback, same flags with `--user 1000:1000`, `node:22-alpine` | uid 1000, `CapEff 0`, source readable, write "Read-only file system", `net.connect` → `ENETUNREACH` |

Two findings shape the design: a process flood does not show in the exit code, and the runtime does not report OOM kills reliably. Both are therefore read from the kernel (R5). A third: `/proc/self/mountinfo` inside the container shows the host path of the source mount (the private work directory name). This reveals the run id and the temp root, nothing else; accepted and listed as a limit.

## R4 Mounts, path translation and user mapping

**Decision**: exactly one host directory is mounted per container: the request's declared source directory (`IsolationHint.sourceDir`, which must lie inside the run's private work directory, already enforced by `runTool`'s precheck). Everything else the tools need is inside the image or in the per-container tmpfs. A pure `translateRequest()` maps host paths to container paths with a fixed table:

| Host path | Container path |
|-----------|----------------|
| `hint.sourceDir` (clone target, `repo/`, or `npm-audit/`) | `/src` |
| `<WORK>/home`, `<WORK>/tmp` | `/scratch/home`, `/scratch/tmp` |
| framework `config/scanners/` | `/opt/tessera/config/` (inside the image, verified by hash, R6) |
| `<WORK>` as cwd | `/scratch` |

Arguments and environment values are translated when they equal a mapped path or start with it followed by `/` (also after `=` in `--opt=value` form). Any other absolute host path in an argument or environment value makes the runner refuse the request (`EISOLATION`, cause detail names the argument index, path tokenized). The container environment is built from the request's environment minus `PATH`, `PYTHONUSERBASE` and the proxy variables (fetch keeps the proxy variables); it is passed by name (`--env NAME` with the value in the CLI's own environment), so values never appear in the host process list.

**User mapping**: the container user is the host worker uid (podman `--userns keep-id`; docker `--user uid:gid`). Reason: the fetch container writes the clone into a host directory that `cleanupRun` must remove, and the scan containers must read the 0700 work directory. With rootless podman a container escape lands as the host user in either mapping, so keep-id costs nothing extra there. With rootful docker the daemon is root-equivalent; that is why docker lowers the isolation level (R9).

**SELinux**: the source mount gets `:Z` with a per-audit MCS level (`--security-opt label=level:s0:cX,cY`, the pair allocated per audit: sha256(runId) gives the starting pair, a host-wide registry of active labels under a lock picks the first free pair from there and releases it at teardown, because hashing 20 bits cannot guarantee distinct labels for concurrent audits (birthday collisions); see data-model), so the parallel scan containers of one audit share a label and another audit's containers do not. Defense in depth only; separation of audits rests on the mount namespace (each container sees only its own run's source). Recorded as restriction `selinux-label`.

**Alternatives**: a named volume per audit (host cannot read it without `podman unshare`, breaks the host-side readers of R1); passing configs as extra read-only mounts (a third mount type to verify; baking them into the image and checking their hash is simpler); string replacement over the whole argument line (would translate substrings; prefix match on whole arguments is exact).

## R5 Limits and how a reached limit is observed

**Decision**:
- **Time**: the existing host timeout in `runTool` plus podman `--timeout` (conmon-enforced, independent of the worker). After any timeout or output overflow the runner runs `<rt> rm --force --time 0 <name>`, because killing the `podman start --attach` client process does not stop the container. Status unchanged from 004: `failed/timeout`.
- **Output**: the existing `maxBuffer` (64 MiB stdout, 1 MiB stderr) plus the forced removal. Status unchanged: `partial/output-truncated`.
- **Memory and processes**: each step gets its own cgroup parent `tessera-<run32>-<step>.slice` (nested under `tessera-<run32>.slice`, run id without hyphens). After the container exits, the runner reads `memory.events` (`oom_kill`) and `pids.events` (`max`) of that slice, then stops the audit slice at teardown. Mapping: `oom_kill > 0` → `failed/limit-memory`; `pids max > 0` → `partial/limit-pids` when the tool otherwise completed, `failed/limit-pids` otherwise. These come from the kernel, not from tool output the source can influence.
- **Scratch**: tmpfs size; a full scratch is an `ENOSPC` inside the tool and surfaces as the tool's own failure.

**Measured on this host**: with `--cgroup-parent=tessera-smoke.slice`, after the container exited, `pids.events` of the slice read `max 1` (fork refused 1 time) and, in a second run, `memory.events` read `oom 1, oom_kill 1` while the runtime reported `OOMKilled=false`. The slices persist until `systemctl --user stop`, which removed them.

**Docker**: with the rootful daemon the slices belong to root's systemd; the worker cannot stop them and their placement is not verified. On docker the runner falls back to exit-code classification (137 without host timeout → `failed/limit-memory` suspected, labeled heuristic) and records restriction `limit-observation: not-applied`, which lowers the level (R9).

**Alternatives**: the runtime's `OOMKilled` flag (measured unreliable); an in-container wrapper that reports cgroup counters on stderr (the audited workload shares the uid and could forge the trailer); `podman events` (no reliable OOM event rootless).

## R6 The scanner image

**Decision**: one image, `config/isolation/Containerfile`, built locally by `npm run isolation:build` and pinned by **image ID** (`sha256:<64 hex>`, the content address of the image config and its layer diff ids).
- **Base**: `semgrep/semgrep:1.178.0` pinned by digest (same semgrep version as the 004 measurements, so recall is comparable). Added: `nodejs` and `npm` from the base distribution at pinned package versions, npm set to 10.9.8 (the version measured in 004), `git`, gitleaks 8.30.1 as the release tarball with a pinned sha256, `catatonit` for `--init`.
- **Framework files** under `/opt/tessera/`: `config/` (copy of `config/scanners/`, empty npm user and global config files), `rules/` (semgrep packs, R7), `bin/advisory-proxy.js`, `bin/bounded-fetch.js`, `bin/selftest.js` (small Node scripts, no dependencies), `manifest.json`.
- **`manifest.json`**: base image digest, tool versions as installed, sha256 of every file under `/opt/tessera/`, semgrep pack fetch time, build time, git revision of the framework the image was built from.
- **Pinning in use**: `TESSERA_ISOLATION_IMAGE=sha256:…` or the value that `isolation:build` writes to `~/.config/tessera/isolation.json` (0600). The worker refuses a tag or name reference. `checkIsolation` verifies that the image exists with that ID, that its manifest parses, and that the sha256 of every host `config/scanners/*` file and helper script equals the manifest entry; a difference is `isolation-unavailable` with detail `image-outdated`.
- **Recorded per step**: image ID, manifest sha256, runtime name and version, and the tool version from the in-container `--version` probe (kept from 004; a pin is not a measurement).

**Reproducibility, stated plainly**: inputs are pinned (base digest, package versions, tarball hash), but the build is not bit-for-bit reproducible: pip, apk and the rule download write timestamps, and the semgrep packs are whatever the registry serves at build time (their hash is recorded, not pinned in advance). Two builds give different IDs. That is acceptable for level 2 (each audit names the exact image it used); a reproducible, signed, published image belongs to roadmap items 014 and 027. Publishing to a registry is an outward action and is not part of this feature.

**Alternatives**: three upstream images (semgrep, gitleaks, node) pinned by digest without a build (no place for offline rules and the helper scripts; three digests per audit); building FROM a slim Node image and `pip install semgrep` with hashes (larger risk of a different semgrep build than the one measured).

## R7 Data scanners need while offline (FR-020)

**gitleaks**: rules are built into the binary; nothing to prepare. Version recorded.

**semgrep**: the packs `p/javascript` and `p/nodejs` (004 R6) are downloaded at image build time to `/opt/tessera/rules/*.yaml`; semgrep runs with `--config /opt/tessera/rules/<pack>.yaml --metrics=off --disable-version-check`. Freshness: `manifest.rules[].fetchedAt`. When the packs are older than `TESSERA_RULES_MAX_AGE_DAYS` (default 90), semgrep is `partial/rules-stale` (required scanner, so the audit is INCOMPLETE) until the image is rebuilt. Licence note: Semgrep Registry rules are licensed for internal use; baking them into a locally built image that is not redistributed fits that; the own versioned ruleset (roadmap 005) removes the question.

**npm audit**: npm has no offline mode; it posts the dependency tree to `<registry>/-/npm/v1/security/advisories/bulk`. Decision: **record, fetch on the host, replay**:
1. *Record* (scan profile, no network): `node /opt/tessera/bin/advisory-proxy.js record -- npm audit --json …` starts a loopback HTTP listener inside the container, points npm at it with `--registry=http://127.0.0.1:<port>/` as last argument, captures the gzip body of the bulk request, answers 503, and prints only the captured body (bounded, JSON) to stdout. npm's own tree building decides the package list, so nothing is reimplemented.
2. *Fetch* (host, in-process, record `npm-audit.advisories`): the body is validated (JSON object, at most 20 000 package names matching the npm name grammar, at most 1 000 versions per name, each at most 256 characters of `[0-9A-Za-z.+_-]`, body at most 5 MiB; invalid entries are dropped and counted, which makes npm-audit `partial/advisory-request-filtered`), gzip-posted with Node's built-in `fetch` to the fixed URL `https://registry.npmjs.org/-/npm/v1/security/advisories/bulk` (never a registry from the source), timeout 60 s, response at most 32 MiB and validated as an object of arrays. Recorded: URL, `fetchedAt`, request sha256, number of names and versions, HTTP status, response sha256 (the response is stored as an artifact).
3. *Replay* (scan profile, no network): the same `npm audit --json` under `advisory-proxy.js replay`, the snapshot delivered on stdin; the listener serves it for the bulk endpoint and returns 404 for everything else. The existing npm-audit policy parses and classifies the output unchanged.

**Both request orderings (review fix)**: the proxy must handle npm sending the bulk request first and the quick-audit request first (and only the quick one). Hermetic tests with a fake npm cover bulk-first and quick-first. A capture that contains only a quick-audit request (no bulk body) ends the record step with exit 3 and the step as `advisory-data-missing` with the diagnostic "npm sent no bulk advisory request (quick audit only)"; it is never replayed and never reported as zero vulnerabilities.

**Notes**: the advisory results reflect what the lockfile claims (names and versions as written in it, not what is installed); the report says so, and the request sha256 and the lockfile sha256 are recorded together in the `npm-audit.advisories` record so the two can be tied.

If the fetch fails, npm-audit is `unavailable/advisory-data-missing` and the replay never runs: an empty snapshot would yield "0 vulnerabilities", which is exactly the false comfort constitution VII forbids. The proxy also refuses to start replay with an empty or invalid snapshot. Freshness: the snapshot is fetched in the same audit; its age is reported, there is no cross-audit cache.

**Measured on this host (npm 10.9.8, demo `package.json` and lockfile, no network for npm)**: in record mode npm sent `POST /-/npm/v1/security/advisories/bulk` (gzip, 1138 bytes JSON of name to versions), then fell back to `POST /-/npm/v1/security/audits/quick`, and exited 1. The host posted the captured body to the public registry: HTTP 200, 6680 bytes. In replay mode npm reported `{"low":3,"high":5,"critical":1,"total":9}` for `body-parser, cookie, express, lodash, minimist, path-to-regexp, qs, send, serve-static`: the same 9 vulnerable packages (1 critical, 5 high) that 004 measured with live npm audit, so D05 to D07 are covered. During replay npm also requested 18 packuments (`GET /<name>`) to compute fix information; they got 404. Expected effect: `fixAvailable` details may be missing or differ; findings do not change. To be confirmed by the demo gate with the full parser.

**Information leaving the host**: the package names and versions of the audited lockfile go to the npm registry, as they already did in 004. Recorded in the evidence and in the report's limits.

**Known limit**: Node's built-in `fetch` does not honour `HTTPS_PROXY` on Node 22. A worker behind a mandatory proxy gets `advisory-data-missing` (visible, not silent) until a proxy-aware fetch is added.

**Alternatives**: npm audit with network in a container that holds only the lockfile (violates FR-004 as written: scanners have no network while scanning); osv-scanner with an offline OSV database (new tool, different matching, recall unmeasured, would change D05 to D07 behaviour); reimplementing npm's advisory matching on the host (semver ranges and the dependency graph: large, error-prone, new dependency).

## R8 Checking isolation and failing closed (FR-010, FR-011)

**Decision**: a new activity `checkIsolation(run)` runs after `initAuditRun` and before `fetchSource`. It determines the runtime (R2), its version, rootless or not, cgroup v2 with `memory` and `pids` controllers, the image (R6), and runs `/opt/tessera/bin/selftest.js` in the scan profile against an empty test source. The self-test reports, from inside: uid not 0, `CapEff` zero, `NoNewPrivs` 1, seccomp mode 2, `memory.max` and `pids.max` equal to the configured values, only `lo` present, a write to `/src` and `/` fails with `EROFS`, a TCP connect to a public address fails, the scratch size equals the configured value, and the mount list contains only the expected mount points. The result is an `environment.check` record (kind `lifecycle`) with the restriction states.

Outcomes:
- runtime missing, unusable, image missing, wrong ID, outdated, or any **mandatory** restriction (R9) not confirmed → `IsolationUnavailableError` (non-retryable). The workflow seals the check record, marks the outcome INCOMPLETE with cause `isolation-unavailable` and detail, never calls `fetchSource`, and every required scanner is listed as `unavailable/isolation-unavailable` (no area shows "no findings").
- only **resource** restrictions not confirmed (for example limits ignored on a cgroup v1 host) → the audit continues at level `partial` with the restriction named.

**Between steps (US4 scenario 2)**: the isolated runner fails each request closed. When a scan step returns `isolation-unavailable`, the workflow does not start further source-touching steps (the heuristic review becomes `skipped/isolation-unavailable`), finishes teardown and seals what exists; completed steps keep their records.

## R9 Isolation record, restriction set and the isolation level (FR-015 to FR-018)

**Decision**: every `tool-run` record gets an `isolation` block (contract `contracts/isolation-record.ts`): runtime and version, rootless flag, image ID and manifest sha256, container name, profile, the translated container argument vector, and the restriction list. Each restriction has a class and a state:

| Restriction | Class | Source of the state |
|-------------|-------|---------------------|
| `source-mount-only`, `source-read-only` (scan) or `source-private-write` (fetch), `network-none` (scan) or `network-egress` (fetch), `rootfs-read-only`, `non-root-user`, `capabilities-dropped`, `no-new-privileges`, `image-pinned`, `time-limit`, `output-limit` | mandatory | inspect after create; host-enforced for time and output |
| `memory-limit`, `pids-limit`, `cpu-limit`, `scratch-size-limit`, `seccomp-default`, `selinux-label`, `rootless-runtime`, `limit-observation` | resource | inspect, self-test, runtime info, slice readability |

States: `applied`, `not-applied`, `violated` (the limit was reached and enforced: `memory-limit` on an OOM kill, `pids-limit` on refused forks). A mandatory restriction that is `not-applied` after inspect means the runner does not start the container and the step is `failed/isolation-unavailable`.

`blockedAttempts` lists what was refused and observed: limit events from the kernel (R5), and, labeled `heuristic`, network and write refusals recognized in stderr (`ENETUNREACH`, `EAI_AGAIN`, `EROFS`, `Read-only file system`). Escaping links are recorded by the host-side probe (R11). A payload that swallows its own errors leaves no observed attempt; containment does not depend on observation, and the report says that attempts are recorded when observable.

**Levels** (ordered): `none` < `partial` < `contained`, computed by the pure function `computeIsolationLevel(records)`:
- `none`: no `tool-run` step ran isolated, or any `tool-run` record lacks an `isolation` block (only possible for a pre-005 bundle or a tampered one), or isolation was unavailable.
- `partial`: every `tool-run` record is isolated with all mandatory restrictions applied, and at least one resource restriction is `not-applied` in some record or in the `environment.check` record. Rootful docker always lands here (`rootless-runtime` and `limit-observation` not applied).
- `contained`: every `tool-run` record isolated with every restriction applied or violated-and-enforced, and the environment check passed.
`violated` does not lower the level: it shows the limit worked; it makes the step partial or failed (FR-005). In-process records (probe, license check, tech stack, review, advisory fetch) are host-side by design and are named in the limits; they do not change the level.

**Where the level is stated**: `sealEvidence` computes it from the records it seals and writes `manifest.isolation = { level, computedFrom: [recordIds], restrictionsNotApplied: [...], limits: [...] }`. The manifest is covered by the Ed25519 signature (004 R19), so the statement is bound to the key. The report prints the same object; `AuditResult.isolation` carries it into the history. `evidence:verify` recomputes the level from the records and fails with `isolation-level-mismatch` when it differs from the manifest; with `--report <file>` it also compares the level line in the report (FR-017). A pre-005 bundle has no `isolation` field and no isolation blocks: verify reports `isolation: not stated (pre-005 bundle)` without failing; a bundle with isolation blocks but no statement fails.

**Relation to the assurance level**: the assurance level (004 FR-020: 0 or 1) is unchanged by this feature. Level 2 needs all of roadmap items 005 to 012; isolation is one exit criterion. The report shows both lines.

**Alternatives**: a numeric score (false precision); one level per step (the reader needs one statement per audit; the per-step detail is in the records); trusting the requested flags (FR-015 and constitution XII require what actually applied).

## R10 Environment lifetime, teardown and residue (FR-001, FR-021, SC-008)

**Decision**: the per-audit environment is: the private work directory (004), the per-step containers labeled `tessera.run=<run>`, and the audit slice `tessera-<run32>.slice`. `teardownEnvironment(run)` (replaces `cleanupRun`, same path guards) removes containers by label (`rm --force --time 0`), stops the audit slice, removes the work directory, then lists what still exists and writes an `environment.teardown` record: `removed`, `leftovers[]`, `residue: none | present`.

Order: on the success path teardown already precedes sealing (the workflow removes the work directory before `seal`); on the failure paths the workflow changes from "seal, then clean in `finally`" to "teardown, then seal best-effort", so the teardown record is sealed on every path that seals. The `finally` still calls teardown (idempotent). If sealing happened before an unexpected crash, residue is `unknown` in the report.

Crash and cancel: a worker crash leaves the container running until its podman `--timeout`; the retried activity uses a new container name (`a<attempt>`); the workflow's teardown removes all by label. Cancellation reaches the `finally` block; running activities are not heartbeated (roadmap 007), so their containers are force-removed by label. A terminated workflow runs no `finally`: `npm run isolation:sweep` and a sweep at worker start remove Tessera-labeled containers, slices and `tessera-*` work directories older than the maximum audit duration, and log each removal.

**Notes (no design change)**: the 30 s added to the podman `--timeout` is a fixed margin, not a tunable, so the host timeout stays the sole enforcer and the runtime timeout is only a backstop. The fetch container exits right after the copy (`bounded-fetch.js` is the only process, started with `--init`), so no background process survives the step.

**Source size (zip-bomb guard)**: the fetch container clones into its own size-limited `/scratch` tmpfs (`TESSERA_MAX_SOURCE_MB`, default 1024) through `bounded-fetch.js`, and copies the tree (links kept as links) to the host source directory only when the clone succeeded within the limit. A pack that expands beyond the limit fails with `ENOSPC` inside the container: `source-unavailable` with detail `source-too-large`, host disk untouched. The tmpfs counts against the container's memory, which is why the fetch profile has 2048 MiB.

**Alternatives**: post-clone size check on the host (the disk is already filled); `git clone --filter=blob:limit=` (changes what the scanners see); a quota-backed volume (needs XFS project quotas, not available on default rootless storage).

## R11 Links and the host-side readers (FR-006)

**Decision**:
- Inside containers, a link to an absolute path resolves in the container's mount namespace (image files, measured in R3) and never reaches the host; gitleaks and semgrep do not follow links by default.
- The host-side probe already walks with `lstat` and never follows links. It now also records every link whose target is absolute or escapes the source root after normalization as `blockedAttempts: { kind: 'link-outside-source', path, count }` in the `source.probe` record (target paths are not stored: they can contain user names; they are counted and tokenized).
- `detectTechStack` moves to `readSourceFile` (`O_NOFOLLOW`, size cap); a linked manifest is ignored and recorded as an attempt.
- The license check and npm-audit preparation already refuse links via `lstat` (004 R14); a test proves it for `package.json` and the lockfile.

## R12 Orchestration access: local-only and authenticated (FR-012, FR-013)

**Findings**:
- `temporal server start-dev` (CLI 1.9.1, server 1.32.0) has `--ip`, `--port`, `--ui-port`, `--headless`, `--http-port`, `--metrics-port`, `--dynamic-config-value`, but **no TLS, client authentication or authorizer flags** (help text read on this host). It also opens an HTTP API and a metrics port on random free ports. It can be bound to loopback (the demo and dogfood scripts already pass `--ip 127.0.0.1`), but every local user can connect to a loopback port. It cannot meet FR-013.
- The stock server (`temporal-server` from release v1.32.0, 100 MB tarball, or the `temporalio/server` image) supports `global.tls.frontend` with `requireClientAuth` and client CA files, `global.tls.internode`, and `global.authorization` with the default JWT claim mapper and a `file://` JWKS key source (`config/development-jwt.yaml` in the v1.32.0 repository). `development-sqlite.yaml` runs with in-memory SQLite, no external database.
- The TypeScript SDK 1.24.0 supports `tls: { serverRootCACertificate, clientCertPair, serverNameOverride }` on both `Connection` (client) and `NativeConnection` (worker), and `apiKey` (sent as `Authorization: Bearer`; TLS is switched on by default when an API key is set unless `tls: false` is given).
- Unix domain sockets: the server frontend listens on TCP only, and the worker's native connection does not accept a `unix:` target; not an option.
- `openssl` is not installed on this host; `certtool` and Python `cryptography` are, but neither is a project prerequisite.

| Option | Authenticates | Protects internal ports | Works with the CLI dev server | Extra parts |
|--------|---------------|-------------------------|-------------------------------|-------------|
| Loopback binding only | no | no | yes | none |
| JWT via default authorizer, file JWKS | bearer token, replayable | no (history and matching ports have no authorizer) | no | token minting, JWKS file, plus internode protection anyway |
| Custom authorizer with API keys | yes | no | no | custom Go server build |
| **mTLS on the frontend, server in a rootless container that publishes only the frontend** | yes, both directions | yes (internal ports never leave the container network namespace) | no | local CA and certificates, pinned server image |

**Decision**: mutual TLS.
- **Server for development, demo and dogfood**: `npm run temporal:local` starts the stock server image `temporalio/server:1.32.0` pinned by digest in rootless podman with a generated config (in-memory SQLite, `global.tls.frontend.server.requireClientAuth: true`, client CA = the local CA, system worker client certificate, pprof and metrics off), and publishes **only** `-p 127.0.0.1:7233:7233`. The HTTP API, membership and internal gRPC ports are not published, so they are reachable only inside the container's network namespace. No Web UI (it has no authentication of its own); operators use the Temporal CLI with `--tls-cert-path`, `--tls-key-path`, `--tls-ca-path`. The launcher refuses any bind address other than `127.0.0.1` or `::1` unless `--expose <ip>` is given explicitly; mTLS cannot be switched off, so any exposure is authenticated (FR-013).
- **PKI**: `npm run temporal:pki` creates, with Node's `crypto` only, an ECDSA P-256 CA (validity 365 days), a server certificate (SAN `localhost`, `127.0.0.1`, `::1`; 90 days), and client certificates `tessera-worker` and `tessera-client` (EKU clientAuth; 90 days) in `~/.config/tessera/temporal-pki/` (directory 0700, keys 0600, outside the repository and outside any evidence root). The DER encoding of the three certificate profiles is a small, fixed template (~150 lines). The demo and dogfood scripts generate a throwaway PKI in their private run directory. Expired certificates are refused by the TLS handshake. There is no revocation list: "revoked" means rotating the CA with `temporal:pki --rotate`, after which every old certificate is refused. Stated as a limit.
- **Clients and worker**: one helper `connectTemporal(identity)` used by `src/worker.ts`, `src/client.ts`, `demo/run-demo.js` and `scripts/dogfood.js`: address from `TESSERA_TEMPORAL_ADDRESS` (default `127.0.0.1:7233`), certificates from `TESSERA_TEMPORAL_TLS_DIR`. It refuses to connect without certificate material (there is no plaintext mode) and refuses a non-loopback address unless `TESSERA_TEMPORAL_REMOTE=1`. This also fixes review #21 (the worker ignored `TEMPORAL_ADDRESS`).
- **`docker-compose.yml` and `Dockerfile`**: they publish Temporal and its UI on all interfaces without authentication (review #3), and their worker container cannot run the nested isolation this feature requires (R16). Decision: remove both and document the supported topology (worker on a host with rootless podman; Temporal via `temporal:local` or an operator-run cluster with frontend mTLS and client authentication). Removing tracked files is listed for the orchestrator's confirmation in the plan.

**Why not write the certificates with `openssl`**: not installed on this host and absent from the CI image; a dependency like `node-forge` needs a justification the Node-native path removes. The cost is a small custom DER encoder, so it is Tier C: tests parse every certificate with `crypto.X509Certificate`, verify the chain, and run real mTLS handshakes with `node:tls` (OpenSSL) in the hermetic suite; the Go server handshake is proven in the local gate.

**Not verified on this host (needs the spike, plan Phase 0)**: the pinned server image with the generated TLS config (no image pulled during planning); whether the system worker needs `global.tls.systemWorker` or internode settings in single-binary mode; pasta port forwarding to the in-container frontend. Fallback if the containerized server fails: the release binary on the host with frontend and internode mTLS, accepting that the unauthenticated membership ports on loopback allow a local denial of service (never data access, because every gRPC port then requires a client certificate).

## R13 Legacy command-text checks unreachable (FR-014)

**Decision**: `src/activities/registry.ts` exports `workflowActivities`, an object with exactly the activities the workflow proxies: `initAuditRun`, `checkIsolation`, `fetchSource`, `detectTechStack`, `generateScopeDocument`, `runNpmAudit`, `runGitleaks`, `runSemgrep`, `runLicenseCheck`, `reviewCriticalPaths`, `mapToCompliance`, `crossValidate`, `generateReport`, `teardownEnvironment`, `sealEvidence`, `signEvidence`. The workflow types its proxy as `proxyActivities<WorkflowActivities>` (compile-time: the workflow can only call registered names). `src/worker.ts` builds its options in an exported pure function `buildWorkerOptions()` with `activities: workflowActivities` instead of `import * as activities`. The 30-odd legacy functions in `src/activities/index.ts` stay in the code (their tests import them directly; migration is roadmap 012) but no worker can run them.

Tests: the registry's key set equals the fixed list; none of the legacy names (`runLighthouse`, `runAxeAccessibility`, `runSqlInjectionCheck`, `checkReliability`, `checkObservability`, `checkCicd`, `checkCodeQuality`, `checkDocumentation`, `checkPrivacy`, `checkFunctionalRequirements`, `checkBlindSpots`, `measureThroughput`, `assess*`, `waitForHumanApproval`, `checkToolRequirements`, …) is present; `buildWorkerOptions().activities` is the registry object. Local gate with a real server: the worker logs its registered activity names at start, and a workflow started under a legacy name never runs anything (no process spawned, no work directory created) and fails its workflow task as unknown.

Limit, stated plainly: Temporal clients start workflows, not activities, so "a client requests a legacy check by name" is tested as (a) starting a workflow of that name and (b) the worker's activity map; there is no client API that schedules a bare activity.

## R14 Attack fixtures and how containment is asserted (FR-022, SC-001, SC-009)

**Decision**: fixtures are **generated**, not committed as hostile trees: `demo/attack/build-fixtures.js` builds git repositories in a private temp directory (committed links to `/etc/shadow` in our own repository would be followed by tools that scan this repository). Expected outcomes live in `demo/attack/EXPECTED.md`, next to `demo/EXPECTED.md`.

Two layers, both in `npm run test:isolation` (own vitest config, needs a runtime and the image):

1. **Environment layer**: payloads from a fixture source are executed deliberately inside the scan profile via the isolated runner (`/bin/sh /src/payload.sh`), because the scanners themselves do not execute audited code; this proves what any scanner bug or future scanner would be confined by. Payloads: fork flood, memory hog, 200 MB to stdout, TCP and DNS to a host listener and a public address, writes to `/src`, `/`, `/etc`, scratch overflow, reading `/proc/1/environ`, reading another audit's known work path, creating a setuid file in scratch.
2. **Audit layer**: full audits through the workflow functions against repositories that attack the scanners and the host-side readers: links to a host canary file (absolute and `../` chains, including `package.json` and the lockfile as links), a 64 MiB-plus gitleaks result set (oversized output), 200 000 files in deep nesting (time and probe budget), lifecycle scripts and a hostile `.npmrc` pointing at a host listener, a pack that expands beyond the source limit, a `.gitattributes` filter and a hook in the repository.

Assertions per fixture:
- **Host unchanged**: a canary directory with a unique secret string outside the work directory; sha256 tree hash before and after; the secret appears nowhere in evidence, report, findings or worker log; host listeners received zero connections.
- **Other audits unchanged**: a sibling audit's work directory hash before and after (SC-009: 10 distinct concurrent pairs (20 audits, labels allocated from the active-label registry) with staggered starts at environment level, not one pair repeated; one concurrent pair at workflow level in the demo).
- **Evidence unchanged**: the sealed bundle of an earlier audit still verifies.
- **Defined outcome**: the expected status and cause from `demo/attack/EXPECTED.md` (for example `failed/limit-pids` or `partial/limit-pids`, `failed/limit-memory`, `partial/output-truncated`, `source-unavailable/source-too-large`), and the expected restriction states and blocked attempts in the record.
- **Environment gone** (SC-008): no container with the run's label, no audit slice, no work directory; also after a cancelled audit and after a worker killed mid-scan (local gate with Temporal).

The release gate (`npm run release:gate`) runs `test:isolation`, `npm run demo`, `npm run dogfood`; a skipped isolation test fails the gate (unlike `test:tools`, where a missing tool is a recorded skip).

## R15 Demo and dogfood under isolation (FR-019, SC-002, SC-003)

**Decision**:
- The demo maps `https://github.com/<owner>/<app>` to local fixture repositories via `GIT_CONFIG_*` `insteadOf` (`demo/run-demo.js:26-29`). The fetch container cannot see host paths. New, development only: `TESSERA_SOURCE_MIRROR=<dir>` mounts that directory read-only at `/mirror` in the fetch container, and the demo's `insteadOf` values point to `file:///mirror/<app>`. The mirror is the source, read-only, so the "only the source and scratch" rule holds; the fetch record states `inputs.mirror = true`. The worker refuses the variable when `NODE_ENV=production`.
- Dogfood clones from GitHub through the fetch profile's egress network; no change beyond the Temporal connection.
- Both scripts: preflight for podman (or docker) and the pinned image, `temporal:local` instead of `temporal server start-dev`, throwaway PKI, `connectTemporal`, and the isolation level printed next to recall.
- Pass criteria unchanged and extended: demo strict recall at least 8 of 18 with D05, D06, D07; clean-app `complete`; every bundle `VERIFIED` with the run's public key; the planted secrets nowhere; isolation level `contained` on podman; dogfood COMPLETE with all five scanners completed and `VERIFIED`.

**Risks to recall**: semgrep packs fetched at a different date than the 004 baseline (same risk as live fetching; the hash is now recorded); npm replay without packuments (R7: fix information only); semgrep inside a container with 2048 MiB (demo and dogfood are small; measured during the spike).

## R16 CI impact: what Woodpecker can and cannot prove

**Measured**: in a Docker 29.8.2 container with the default seccomp profile (`node:22-alpine`, the CI image family) `unshare -Ur id` fails with "Operation not permitted"; inside rootless podman it succeeds. Woodpecker's Docker backend runs steps as unprivileged Docker containers, so rootless podman (and bubblewrap, which needs the same user namespaces) cannot run inside a CI step. Making the step privileged would give the CI step root on the CI host and still test a nested setup that differs from production. Not done.

**What CI proves (hermetic, in `npm run verify`)**: argument construction and path translation for both profiles and both runtimes, refusal of unmapped paths and requests without a hint, restriction observation from recorded `inspect` and cgroup fixtures, level computation and its verify recomputation, status and outcome mapping of every new cause, the advisory request validation and the proxy's record and replay logic (with a fake npm), registry contents and worker options, the Temporal connection guards, the PKI (parse, chain, expiry, real `node:tls` mTLS handshakes with and without a client certificate), and a static check that no committed configuration binds Temporal beyond loopback.

**What CI does not prove**: that the kernel enforces the restrictions, the attack fixtures, the image build, the Go server's mTLS handshake, recall under isolation. These run in the local release gate (R14). This extends an existing, documented class of local gates (`test:tools`, `demo`); `npm run verify` and CI stay equivalent, so no new local-versus-CI gap arises. The README's "Known deviations" gets the statement in plain words. **Visible limit in every CI run**: until a CI backend that can run containers exists, every CI run prints one line in its summary: `Containment: local release gate only, not proven in CI`. A green CI is therefore never read as proof of containment.

A Woodpecker agent with the `local` backend on a dedicated host user would run `test:isolation` with real rootless podman; that is infrastructure outside this feature and goes to the backlog.

## R17 Performance and overhead

Measured: one container start 0.69 s. Per isolated step: create, inspect, start, rm (estimate 1.0 to 1.5 s). Steps per audit: fetch (1 plus version probe), rev-parse (2), gitleaks (2), semgrep (2), npm record (2), npm replay (2), self-test (1): about 12 container runs, mostly in parallel for the scans. Budget: isolation overhead at most 20 s per demo audit and at most 25 % of the audit's wall time, measured by the demo from the per-step durations in the records. Memory: up to 4 parallel steps at 2048 MiB each (worker setting `maxConcurrentActivityTaskExecutions: 4`), so a worker host needs about 8 GiB free for audits. Revisit by caching the version probes per image ID if the budget is missed.

## R18 Tier C additions and the mutation loop

New Tier C files (added to `docs/agile/working-agreement.md` in this feature): `src/isolation/*`, `config/isolation/bin/*` (runs on hostile data inside the sandbox; its output is parsed by the host), `src/scan/tools/npm-advisories.ts` (host network call with a body derived from the source), `src/temporal/*` (access guard and PKI), `src/activities/registry.ts` and `src/worker.ts` (what is reachable), `src/cli/temporal-local.ts` (binding and exposure). Existing Tier C files touched: `run-tool.ts`, `process-runner.ts`, `status.ts`, `lifecycle.ts`, `source-probe.ts`, `src/evidence/*` (types, manifest, verify), `src/workflows/index.ts`, `src/scan/activities.ts`, `src/report/outcome-block.ts`, `src/cli/verify-evidence.ts`. The mutation loop applies to every task that changes one of these files (plan, migration table). The security review checkpoint covers the isolated runner, path translation, advisory fetch, Temporal access and PKI.

## R19 Tessl tiles

Searched the registry for podman and Temporal TypeScript on 2026-10-04: no relevant tile (results were unrelated integrations). Nothing installed. No new npm dependency in this feature: Node built-ins (`crypto`, `fetch`, `zlib`, `http`, `tls`) and the existing Temporal SDK. New host prerequisites: podman (or docker) and, for local development, the pinned Temporal server image instead of the Temporal CLI dev server.

## R20 Risks and what could not be verified here

| Risk or unverified item | Effect | Mitigation |
|-------------------------|--------|------------|
| Temporal server image with generated mTLS config not run on this host | US3 depends on it | Spike first (plan Phase 0) with acceptance checks; host-binary fallback (R12) |
| Image build not done (needs network and pulls) | semgrep, gitleaks, npm versions and rule fetch unverified in the image | Spike builds the image and re-runs the R3 smoke test and the R7 record and replay inside it |
| `--log-driver none` with `start --attach`, per-audit SELinux level with `:Z` in parallel containers, `--timeout` behaviour | runner details | Spike items with a fallback each (`k8s-file` with size cap; `:z`; host kill only) |
| Docker cgroup slice placement and counters | docker level is `partial` anyway | documented; no claim of observation on docker |
| Missing packuments during npm replay | fix information may differ | demo gate compares findings, not fix fields |
| Kernel escape, malicious administrator, local signing key | out of scope (spec delivery note) | stated in every report's limits |
| Host path of the work directory visible in `mountinfo` | reveals run id and temp root | accepted, listed |
| Host-side readers parse hostile data (JSON, regex) | a parser bug in our own code | budgets, no-follow, Tier C tests; option B of R1 if this ever bites |
| Ringpop membership ports in the host-binary fallback | local denial of service only | containerized server is the primary path |
| `HTTPS_PROXY` not used by Node 22 `fetch` | advisory fetch fails behind a proxy | visible as `advisory-data-missing` |
| Concurrency memory (4 × 2048 MiB) | host pressure under parallel audits | documented sizing; limits are per container, so one audit cannot starve the host |


## Addendum R12 (spike S2, 2026-10-04): mutual TLS on the stock Temporal server

### R12 addendum: spike S2 result (T001, 2026-10-04)

**Decision: delivered.** Mutual TLS on the stock `temporalio/server:1.32.0` image, rootless in podman, publishing only `127.0.0.1:7233`, works with certificates made by Node `crypto` alone. The Go server, the Go `temporal` CLI, the TypeScript client (`@temporalio/client` 1.24.0, grpc-js/OpenSSL) and the worker (`NativeConnection`, Rust core/rustls) all accept the Node-made chain. No re-plan trigger fired; the openssl fallback is not needed. Six configuration facts below are new and must flow into the `temporal:local` launcher and PKI tasks (no change of decision, only of detail).

**Host and versions**: Fedora 44, kernel 7.2.4, rootless podman 5.8.7 with pasta networking (netavark backend), `temporal` CLI 1.9.1, Node 22.23.1, SDK 1.24.0. Image `docker.io/temporalio/server:1.32.0`, digest `sha256:ca47d4de249b9cc28137628dba77ae5e75e8b313ebb5c801c64615c1c99cbb09`; image user `temporal` (uid 1000), entrypoint `exec temporal-server start`, no config files in the image (`render-config` fails: "no config files found"), so the config is mounted and selected with `TEMPORAL_SERVER_CONFIG_FILE_PATH`.

**Configuration used** (`scripts/spikes/s2-mtls/config.template.yaml`):
- persistence: upstream `development-sqlite.yaml` datastores, `mode: memory`, `cache: private`, one history shard.
- `global.tls.frontend.server`: `certFile`, `keyFile`, `requireClientAuth: true`, `clientCaFiles: [ca.pem]`; `global.tls.frontend.client`: `serverName: localhost`, `rootCaFiles: [ca.pem]`.
- `global.tls.systemWorker`: own client certificate `temporal-system-worker`, `client.serverName: localhost`, `client.rootCaFiles: [ca.pem]`. No `internode` TLS.
- `global.pprof.port: 0`, no `global.metrics` block, no archival, no dynamic config file.
- frontend `rpc.bindOnIP: "0.0.0.0"` (grpc 7233, http 7243, membership 6933); history, matching, worker `bindOnLocalHost: true`; `membership.broadcastAddress: 127.0.0.1`.
- run: `podman run -d --name tessera-spike-s2-server --userns=keep-id -p 127.0.0.1:7233:7233 -v <cfg>:/etc/temporal/config:ro,Z -v <pki>:/etc/temporal/pki:ro,Z -e TEMPORAL_SERVER_CONFIG_FILE_PATH=/etc/temporal/config/config.yaml -e TEMPORAL_ALLOW_NO_AUTH=true <image>`.
- PKI (`scripts/spikes/s2-mtls/pki.mts`, ~200 lines): ECDSA P-256, SHA-256, the profiles of `contracts/temporal-access.ts` (CA: basicConstraints CA critical, keyUsage keyCertSign+cRLSign critical, SKI; leaf: basicConstraints CA:false, keyUsage digitalSignature critical, EKU serverAuth or clientAuth, SKI, AKI; server SAN `localhost`, `127.0.0.1`, `::1`). Keys PKCS#8 PEM; dir 0700, files 0600. Self-check with `X509Certificate.verify/checkIssued/checkHost/checkIP` all ok; `certtool --certificate-info` parses every certificate as expected.

**Measured results per exit criterion** (`run.sh` output, trimmed; every line was also run by hand):

| Criterion | Result | Evidence |
|-----------|--------|----------|
| CLI without certificate refused | PASS | plaintext: rc=1 `the server requires TLS but the CLI is connecting without it`; TLS without client cert: rc=1 `TLS handshake failed: server requires client certificate (mTLS)` |
| With certificate `operator namespace list` works | PASS | rc=0, lists `temporal-system` and `default` (after the launcher step below registered `default`) |
| TS client and worker connect | PASS | `connect.mts`: worker (`NativeConnection` + `Worker.create`, cert `tessera-worker`) and client (`Connection`, cert `tessera-client`) run a workflow with one activity: result `"echo:mtls"`. Client refusals for plaintext, no cert, expired, other CA: `Failed to connect before the deadline`; worker refusals: `transport error ... received fatal alert: CertificateRequired` / `ConnectionReset` / `BrokenPipe` |
| `podman port` shows only 127.0.0.1:7233 | PASS | `7233/tcp -> 127.0.0.1:7233` (also `podman port -a`); host `ss -ltn` shows only `127.0.0.1:7233` from this container |
| Connection via host LAN address refused | PASS | `--address 192.168.1.132:7233`: rc=1 `connection refused`; also refused on the VPN address 10.134.0.230, on the docker bridge 10.200.0.1 and on `[::1]:7233`. Raw TCP probes of 7234, 7235, 7239, 7243, 6933, 7936 on 127.0.0.1, LAN and bridge: all `ECONNREFUSED` |
| Expired client certificate refused | PASS | CLI rc=1 `remote error: tls: expired certificate` (TLS 1.3: the CLI prints "TLS handshake succeeded" first because the server checks the client certificate after the client's Finished; the server alert follows); HTTP API: `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED`; worker: fatal alert |
| (extra) certificate from another CA refused | PASS | CLI rc=1 (the Go client does not even offer a certificate whose issuer is not in the server's CertificateRequest list); TS client refused |

**Other recorded items**:
- **SQLite mode**: in-memory. Schema is created automatically, but only `temporal-system` exists at start; `default` must be registered (`temporal operator namespace create --namespace default`) after `operator cluster health` succeeds. All state, including `default`, is lost on container restart (measured with `podman restart`: only `temporal-system` listed afterwards). Acceptable for dev, demo and dogfood (each run is self-contained); file mode was not tested.
- **System worker TLS**: `global.tls.systemWorker` is required and sufficient. Measured without it: the worker service loops on `error creating sdk client ... client auth required, but no certificate provided`. With it, the delete-namespace system workflows (`temporal-sys-delete-namespace-workflow`, `temporal-sys-reclaim-namespace-resources-workflow`) complete. Internode TLS is not needed because history, matching and worker ports never leave the container network namespace. This settles the open point in `contracts/temporal-access.ts` ("systemWorker or internode").
- **Web UI and other ports**: the image contains no Web UI and nothing listens for one. Listeners inside the container: 7233, 7243 (HTTP API) and 6933 on `0.0.0.0` (consequence of the frontend `bindOnIP`), 7234, 7235, 7239, 6934, 6935, 6939 on `127.0.0.1`; no pprof (port 0) and no metrics listener. None of these is published. The HTTP API also enforces mTLS (measured in a throwaway variant that published `127.0.0.1:17243:7243`: no cert `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED`, expired cert refused, client cert 200), so even an accidental publish stays authenticated. Port 8000 on the host belongs to `woodpecker-server` (docker), unrelated.
- **Authorizer**: without an authorizer the server logs `Not using any authorizer and flag --allow-no-auth not detected. Future versions will require using the flag`. `TEMPORAL_ALLOW_NO_AUTH=true` silences it (server log empty at level warn). Consequence, unchanged from R12: any certificate signed by the local CA has full access to every namespace; authentication, not authorization.

**New facts the launcher and PKI tasks must adopt** (amend `contracts/temporal-access.ts` comments and the Phase 5 rows; no decision changes):
1. **Frontend bind**: the frontend must bind a non-loopback address inside the container (`rpc.bindOnIP: "0.0.0.0"`). With `bindOnLocalHost: true` the published port accepts TCP but every connection is reset: pasta forwards to the container's interface address, not to its loopback (measured: `connection reset by peer` for plaintext, TLS and mTLS alike). Other services stay on loopback.
2. **`--userns=keep-id`** is required with 0600 key files owned by the host user: without it the container user `temporal` maps to a subordinate uid and the server exits at start with `open /etc/temporal/pki/system-worker.pem: permission denied`. The docker fallback (`runtime: 'docker'` in the contract) was not measured; it would need `--user $(id -u):$(id -g)` or a copied key set, and belongs to S3/US3 follow-up.
3. **System worker certificate**: the PKI gets a fifth leaf, `temporal-system-worker` (clientAuth), mounted only into the server; `PkiPaths` gains `systemWorkerCert`/`systemWorkerKey`.
4. **Namespace bootstrap**: the launcher waits for `operator cluster health` and registers `default` on every start.
5. **`TEMPORAL_ALLOW_NO_AUTH=true`** is passed by the launcher, so a future image bump cannot silently refuse to start or change behavior unnoticed.
6. **Serial encoding**: the contract says "16 random bytes, first bit cleared". If the first byte then happens to be `0x00`, and the second byte's top bit is clear, a naive encoder produces a non-minimal DER INTEGER (about 1 in 256 certificates), which Go's strict DER parsing rejects (`integer not minimally-encoded`; known Go behavior, not provoked in this spike). The spike sets `serial[0] = (serial[0] & 0x7f) | 0x40` (always 16 bytes, positive, minimal); the encoder must also strip redundant leading zeros in general. A PKI unit test should cover a serial with a leading zero byte.

**Risks and limits**:
- `:Z` on the PKI bind mount relabels the host directory with the container's private SELinux label on every start; for `~/.config/tessera/temporal-pki` prefer mounting a per-run copy of only the server files (ca.pem, server, system-worker), which also keeps the client keys out of the container.
- Stop: a server stuck in its start-up retry loop ignored SIGTERM for the default 10 s (`resorting to SIGKILL`); the launcher's `stop()` should use `podman rm -f -t <short>`.
- grpc-js reports every refusal as the generic `Failed to connect before the deadline`; `connectTemporal` cannot map refusal causes from the client error text (the native worker error does name the TLS alert).
- No revocation (unchanged): a leaked client key works until CA rotation.
- Not measured: SQLite file mode, docker runtime, IPv6 bind (`::1`) of the launcher, image digest stability over time.

**How to reproduce**: see `scripts/spikes/s2-mtls/README.md`. In short: `podman pull docker.io/temporalio/server:1.32.0`, ensure 7233/8233 are free, then `bash scripts/spikes/s2-mtls/run.sh <work-dir-outside-repo> <lan-ip>`; expected last line `RESULT: all checks passed`; the script removes its container on exit (`podman ps -a --filter name=tessera-spike-s2-` empty, no volumes created).


## Addendum R3, R6, R7 (spike S1, 2026-10-04): scanner image, offline packs, npm replay

### Spike S1 addenda for research.md (R3, R6, R7), measured 2026-10-04

Scratch files: `scripts/spikes/s1-image/` (Containerfile, build.sh, write-manifest.js, advisory-proxy.js,
fetch-advisories.js, profile.sh, run-checks.sh, README.md with the reproduce steps). Raw outputs for T004:
`<scratchpad>/s1/fixtures/` (podman-version.json, podman-info.json, image-inspect.json, inspect-*.json,
memhog/forkbomb memory.events and pids.events, start-*.stdout/stderr, advisory snapshot and metadata).
Host: Fedora 44, kernel 7.2.4, rootless podman 5.8.7, crun 1.28, conmon 2.2.1, cgroup v2 (systemd manager,
controllers cpu io memory pids), SELinux Enforcing, netavark/pasta.

## Exit criteria (T002)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| image ID recorded | PASS | `sha256:d5f6ca15a82d3e80bbcffa71fec6fd1ea26c33d982de245fda48d0948b54f2cc` (tag `localhost/tessera-spike-s1-scanner:latest`, 1 213 455 897 bytes) |
| demo npm replay yields the 9 packages | PASS | replay: `{"low":3,"high":5,"critical":1,"total":9}` for body-parser, cookie, express, lodash, minimist, path-to-regexp, qs, send, serve-static; identical package set, severities and 22 advisory sources as a live `npm audit` (npm 10.9.8) on the host the same day |
| semgrep packs present and hashed | PASS | `p/javascript` 74 rules sha256 `e65e8449…cf4e`, `p/nodejs` 36 rules sha256 `eed00ab9…a78f`, fetchedAt 2026-10-04T19:32Z, in `/opt/tessera/manifest.json`; hashes re-verified inside the container |
| semgrep and gitleaks run offline on the demo in the scan profile | PASS (after two profile corrections, below) | gitleaks: 1 leak `generic-api-key src/config.js:4` (D18), exit 1, 0.51 s, same as host gitleaks 8.30.1. semgrep `--network none --metrics=off` with the baked packs: 4 results (raw-html-format :15, direct-response-write :15 and :19, code-string-concat :19), 0 errors, exit 0, 4.4 s; identical to host semgrep 1.178.0 with registry packs |
| `--log-driver none` with `start --attach` streams output | PASS | lines arrive live (t=0.08, 1.07, 2.08 s for a 1 s cadence); stdout and stderr stay separate; 100 MiB stdout passes intact (104 857 604 bytes); the container's exit code (7) is the exit code of `start --attach`; `podman logs` refuses ("using the 'none' log driver") |
| parallel containers with a shared SELinux level work with `:Z` | PASS | 4 concurrent containers, `label=level:s0:c101,c202`, `-v src:/src:ro,Z`: 50/50 reads each, process label `container_t:s0:c101,c202`; host dir relabelled `container_file_t:s0:c101,c202`; a container at `s0:c303,c404` on the same dir without relabel: `Permission denied` |
| podman `--timeout` kills a sleeping container | PASS | `--timeout 5`, `sleep 120`: `start --attach` returned after 5.36 s with rc 255, inspect `State.Status=exited`, `ExitCode=-1`, `OOMKilled=false`, `State.Error` empty, no stderr |

Additional (R5 counters, requested by T002):

| Payload | Profile | Exit / inspect | Slice counters |
|---------|---------|----------------|----------------|
| memory hog (node allocating 16 MiB buffers) | memory 512m, swap = memory | rc 137, `OOMKilled=false` | `memory.events`: `max 36, oom 1, oom_kill 1`; `pids.events`: `max 0` |
| fork bomb (busybox sh, 200 background sleeps) | pids 64 | rc 2 after 0.21 s (busybox sh treats fork failure as fatal), `OOMKilled=false` | `pids.events`: `max 1`; `memory.events` all 0 |

R5 holds: the runtime does not report the OOM kill; the kernel counters do.

## R3 addendum: scan profile rerun with the scanner image

Same checks as the R3 table, now with the built image and the full scan profile (`profile.sh`):
`uid=1000 gid=1000`, `CapEff 0000000000000000`, `NoNewPrivs 1`, `Seccomp 2`, `memory.max 2147483648`,
`memory.swap.max 0`, `pids.max 512`, `cpu.max 200000 100000`, interfaces `lo` only, TCP `ENETUNREACH`, DNS
`EAI_AGAIN`, writes to `/src`, `/etc`, `/opt/tessera` → "Read-only file system", executing a copied binary from
`/scratch` → "Permission denied" (noexec), scratch fill stops at 512 MiB, 0 setuid/setgid files on the root
filesystem, PID 1 `/run/podman-init`, `git rev-parse HEAD` on the read-only source works, start-up 0.29 s.
Inspect after create: `ReadonlyRootfs=true`, `NetworkMode=none`, `PidsLimit=512`, `Memory=MemorySwap=2147483648`,
11 caps in `CapDrop`, `CapAdd=[]`, `SecurityOpt=[no-new-privileges, label=level:s0:c101,c202]`, `User=1000:1000`,
`LogConfig.Type=none`, `Init=true`, `NanoCpus=2000000000`, `CgroupParent=<slice>`, `Config.Timeout=<s>`.

**Contradicts the plan (must change before T009/T010):**
1. **`--userns keep-id` alone does not set the user.** The draft image (`USER root` during the build) ran as
   `uid=0` with keep-id; with `USER 65534` it ran as 65534. An image `USER` overrides the keep-id default. Decision:
   the podman argv also carries `--user <uid>:<gid>` (as docker does), and the Containerfile ends with
   `USER 65534:65534` so a forgotten `--user` fails closed (cannot read the 0700 work dir) instead of running as
   root. `buildContainerArgs` mutation list should add "drop `--user` on podman". Contract `isolation-runner.ts`
   argv comment: `--userns keep-id --user <uid>:<gid>` (podman).
2. **Scratch tmpfs ownership.** `--tmpfs /scratch:…,mode=1700` is root-owned and unusable by uid 1000 (`mkdir`
   denied). Podman: `--tmpfs /scratch:size=<n>m,mode=0700,noexec,nosuid,nodev,U` (measured: `drwx------ 1000 1000`,
   mount options `uid=1000,gid=1000`). Podman rejects `uid=`/`gid=` options; docker needs `uid=<uid>,gid=<gid>`
   instead of `U` (to verify in S3).
3. **HOME and TMPDIR.** `/scratch/home` and `/scratch/tmp` do not exist on a fresh tmpfs, and the runner cannot
   create them (the entrypoint is the tool). semgrep then fails with exit 2, `"Failed to obtain target files from
   semgrep-core"`. Decision: `HOME=/scratch`, `TMPDIR=/scratch` (gitleaks, semgrep, npm and node all worked). R4's
   path table maps `<WORK>/home` and `<WORK>/tmp` both to `/scratch`; arguments naming them translate to `/scratch`.
4. **Environment by name.** `env HOME=/scratch/home podman create --env HOME …` fails with
   `cannot resolve /scratch/home: lstat /scratch: no such file or directory`: the value-by-name trick sets the
   variable for podman itself. Decision: fixed framework values (`HOME`, `TMPDIR`, `NPM_CONFIG_*`) are passed by
   value (`--env NAME=value`, not secret); request-derived values stay by name, and the runner refuses by-name
   passing of names that steer the runtime CLI (`HOME`, `TMPDIR`, `XDG_*`, `PATH`, `CONTAINERS_*`,
   `REGISTRY_AUTH_FILE`, `DOCKER_*`, `CONTAINER_HOST`).
5. `/proc/self/mountinfo` still shows the host source path (R3 limit confirmed, unchanged).

## R5 note from S1 (cgroup slices)

- systemd treats `-` in a slice name as hierarchy: `--cgroup-parent tessera-spike-s1-memhog.slice` landed at
  `…/user@1000.service/tessera.slice/tessera-spike.slice/tessera-spike-s1.slice/tessera-spike-s1-memhog.slice`.
  So `tessera-<run32>-<step>.slice` nests under `tessera-<run32>.slice` as planned, but a step slug containing `-`
  (`npm-audit`) adds a level (`tessera-<run32>-npm.slice`). Decision: step slugs in slice names have no `-`
  (e.g. `npmaudit`, `npmauditrecord`), and the reader resolves the path with
  `systemctl --user show -p ControlGroup --value <slice>`, never by string building.
- Counters are cumulative per slice: a retry in the same slice adds to the earlier attempt's counts. Decision:
  the attempt is part of the slice name (`tessera-<run32>-<step>a<n>.slice`).
- `systemctl --user stop tessera-<run32>.slice` removes the run's slices; the empty parent `tessera.slice` stays
  (harmless, not residue of a run). Stopping `tessera.slice` removed everything.
- podman `--timeout` produces exit code -1 (attach rc 255) with no message and `OOMKilled=false`; the runner can
  only map it as `failed/timeout` via its own host timer (which fires first by design) or via inspect `ExitCode=-1`.

## R6 addendum: the scanner image

**Containerfile used** (`scripts/spikes/s1-image/Containerfile`, built with `build.sh`, minimal context):
base `docker.io/semgrep/semgrep:1.178.0@sha256:fbba1f23d2ef94630c828e8692758f8bc6353a8089841a396a5c041451966ffb`
(Alpine 3.23.6, local image ID `490afa6660c6`); `apk add --no-cache nodejs=24.18.1-r0 git=2.52.0-r0`; npm 10.9.8 from
`https://registry.npmjs.org/npm/-/npm-10.9.8.tgz`, sha256 `3e68f9b5…f780` checked, unpacked to
`/usr/lib/node_modules/npm`, `/usr/bin/npm` linked to `npm-cli.js`; gitleaks 8.30.1 `linux_x64` tarball sha256
`551f6fc8…70eb` checked; `p/javascript` and `p/nodejs` from `https://semgrep.dev/c/p/<pack>` to
`/opt/tessera/rules/p-<pack>.yaml`; empty npm user and global config; `gitleaks.toml` and `advisory-proxy.js` copied;
`manifest.json` written by `write-manifest.js`; `/opt/tessera` root-owned, dirs 0555, files 0444; `USER 65534:65534`.
Manifest tools as installed: git 2.52.0, node v24.18.1, npm 10.9.8, semgrep 1.178.0, gitleaks 8.30.1.
File hashes match the host sources (`gitleaks.toml b575f648…05e4`, `advisory-proxy.js f5fb716a…c1bc`).
Build: about 10 to 15 s with the base already pulled. Size 1.21 GB (base 1.11 GB).

**Contradicts the plan / contract `scanner-image.md`:**
1. **Node 22 is not available** in Alpine 3.23 (only `nodejs` 24.18.1 and `nodejs-current` 24.15.0). Decision:
   Node 24.18.1 from the distribution; npm stays 10.9.8 (supports Node ≥ 22.9). Manifest `tools.node` is `24.x`.
   Alternative considered: copy Node 22 from a digest-pinned `node:22-alpine` stage (second base digest, binary
   outside the distribution's update path); rejected for the spike, can be revisited if a Node 24 difference shows.
2. **npm pin**: the distribution `npm` is 11.11.0, and `npm install -g npm@10.9.8` installs to `/usr/local` while
   `/usr/bin/npm` stays 11.11.0 (measured: manifest showed npm 11.11.0). Decision: no distribution `npm`; npm is a
   sha256-checked registry tarball, like gitleaks.
3. **semgrep entrypoint** is `/usr/bin/semgrep` (Python wrapper) in this base; `/usr/local/bin` is empty.
   `TOOL_ENTRYPOINTS.semgrep` changes to `/usr/bin/semgrep`.
4. **catatonit is not needed in the image**: podman bind-mounts the host's catatonit as `/run/podman-init`
   (PID 1 measured). Docker uses its own `docker-init`. Drop catatonit from the contract inputs.
5. The base sets `Cmd=["semgrep","--help"]` and env `SEMGREP_IN_DOCKER=1`, `DD_SERVICE`, `PYTHONUNBUFFERED`,
   `DOCKER_OTEL_RESOURCE_ATTRIBUTES`; harmless because the runner always sets the entrypoint and arguments, but the
   production Containerfile should set `CMD []` and the manifest should list the inherited env.
6. `ARG BASE` must be redeclared after `FROM` to be visible to `RUN` (first build wrote an empty base digest).
7. Reproducibility as stated in R6: three builds gave three IDs (`82ba711b…`, `32b51362…`, `d5f6ca15…`, each also
   with a Containerfile change); rule packs are whatever the registry served (hash recorded, not pinned).

## R7 addendum: offline data

- **gitleaks**: built-in rules; works offline. Version 8.30.1.
- **semgrep**: baked packs with `--config /opt/tessera/rules/<pack>.yaml --metrics=off --disable-version-check`
  under `--network none` give the same 4 results as host semgrep with registry packs (`p/javascript` 74 rules,
  `p/nodejs` 36 rules).
- **npm record/replay** (scan profile, `--network none`, source mount `npm-audit/` read-only):
  - record: npm 10.9.8 sent `POST /-/npm/v1/security/advisories/bulk` first, then `POST /-/npm/v1/security/audits/quick`
    (bulk-first ordering); captured body 1138 bytes, 51 names, 52 versions, sha256 `d2f6d415…ed4c` (equals the
    canonical request hash); exit 0, 0.53 s.
  - host fetch (`fetch-advisories.js`, Node 22 `fetch`, gzip POST to the fixed URL): HTTP 200, 6680 bytes, sha256
    `38fef8d3…1031`, object of arrays, 9 package keys.
  - replay with the snapshot on stdin: works through `podman create --interactive` + `podman start --attach
    --interactive` (the stdin path of R2 is viable). npm exit 1 (vulnerabilities found), 0.59 s, 9 packages as above.
    npm then requested 18 packuments (`GET /<name>`, each of the 9 names twice), answered 404.
  - empty stdin: proxy exits 4, npm never started, stdout empty.
- **Effect of the 404 packuments (confirmed)**: `fixAvailable` becomes `true`/`false` instead of
  `{name, version, isSemVerMajor}`, and `range` is `""` for every package. The 004 parser therefore builds the same
  9 findings with the same severities and advisory titles, but the evidence content has an empty range and the
  remediation reads "Update <pkg> to latest" instead of a concrete version. Demo scoring (D05 to D07 match on
  package name, category and severity) is unaffected. Options for later: also fetch the packuments of the vulnerable
  names on the host and serve them in replay (more data leaves the host, larger snapshot), or state the limit in
  the report. Not a re-plan trigger: the findings reproduce.

## Decision

S1 passes every exit criterion. R6 and R7 stand as designed, with the corrections above: podman argv adds
`--user`, scratch tmpfs gets `mode=0700,U`, `HOME=TMPDIR=/scratch`, framework env by value with a deny-list for
by-name runtime-steering names, slice names without `-` in the step slug and with the attempt, slice path via
`systemctl show`, Node 24 instead of 22, npm and gitleaks as hash-checked tarballs, semgrep entrypoint
`/usr/bin/semgrep`, no catatonit, `CMD []`. These are amendments to `contracts/isolation-runner.ts`,
`contracts/scanner-image.md`, R3, R4, R5 and R6 (semantic diff), not a re-plan. Open for the product owner: whether
the missing fix versions in replayed npm findings are acceptable as a stated limit.

## Limits of this spike

- Only rootless podman on this host; docker (`--user`, `uid=`/`gid=` tmpfs, observable restrictions) is S3.
- The mount-label collision payload (a second audit relabelling the same directory with `:Z` at another level) was
  not run, to avoid relabelling a shared directory; R14 keeps it for the gate.
- The fork bomb used busybox sh, which stops at the first refused fork (pids.events `max 1`); a tool that keeps
  running after a refused fork (exit 0, `partial/limit-pids`) was measured in R3, not again here.
- Raw fixtures contain host paths (`/home/vannifr/...`, the scratch path) and the hostname; T004 must scrub them.


## Addendum S3 (docker fallback, 2026-10-04) and spike decisions

## S3 addendum: docker fallback (T003, T004)

**Setup**: image of S1 loaded with `podman save | docker load` (15 s); docker 29.8.2, daemon is rootful (dockerd, containerd
run as root; `SecurityOptions` has only `seccomp` and `cgroupns`, no `rootless`, no userns); the user reaches it through the
`docker` group, no sudo needed. Profile: `--read-only`, `--tmpfs /tmp` and `/scratch` (`mode=0700,uid=1000,gid=1000`),
`--cap-drop ALL`, `no-new-privileges`, `--init`, `--pids-limit`, `--memory`/`--memory-swap`, `--cpus 2`, `--log-driver none`,
`--user 1000:1000`, `--network none`, `-v <src>:/src:ro`, `--cgroup-parent`, labels.

**Result**: the profile runs under docker with `--user` and gives the same scanner results as podman (gitleaks exit 1 with
1 finding, semgrep 4 results, npm replay exit 1 with 9 packages). Attach works with `--log-driver none`
(`docker start -a`, `-a -i` for stdin); `docker logs` is refused ("does not support reading"), which is the wanted effect.
Fixtures: `tests/fixtures/isolation/docker/`.

**Observable by the unprivileged user** (docker group): in `docker inspect` `HostConfig`: ReadonlyRootfs, Tmpfs (with uid/gid
and size), CapDrop/CapAdd, SecurityOpt `no-new-privileges`, PidsLimit, Memory, MemorySwap, NanoCpus, NetworkMode `none`,
LogConfig `none`, Init, Binds with `:ro`, Privileged, CgroupParent; `Config.User`, labels; `State.OOMKilled` (true for the
memory hog, exit 137) and `ExitCode`. `docker info`: no `rootless`, no userns, cgroup driver and version.
Cgroup counters ARE readable here: `/sys/fs/cgroup` is world-readable on this host, `/proc/<State.Pid>/status` shows
CapEff 0, NoNewPrivs 1, Seccomp 2 and `/proc/<pid>/cgroup` names the scope while it runs. While the container runs the
scope has `pids.max`, `memory.max`, `memory.swap.max`, `cpu.max`, `memory.events`, `pids.events`; after exit the scope is
gone, but the parent slice keeps the counters (`oom_kill 1`, `pids.events max 1`). This is a property of this host's cgroup
permissions, not of docker: it needs the systemd cgroup driver, a readable cgroup tree, and the runner deriving the path
(a `-` in a slice name is nesting: `tessera-spike-s3.slice` became `tessera.slice/tessera-spike.slice/tessera-spike-s3.slice`
in the system manager). Docker reports no cgroup path in inspect.
**Not observable or not trustworthy**: that the daemon is the real boundary (rootful, root-equivalent for any `docker` group
member, which the runner cannot restrict); the effective limits after exit (the scope is gone, only inspect `HostConfig`,
which is the requested value, remains); SELinux label per container (no MCS level was set here; mount relabel `:Z` would
relabel the host directory as root); `State.OOMKilled` is true here but podman reports false for the same event, so
counters, not the flag, stay the evidence; docker has no `--timeout` (host timer only).

**New findings**: (1) a rootful docker `--cgroup-parent` creates system slices that the unprivileged runner cannot stop
(`systemctl stop` needs interactive auth, `rmdir` is denied); three empty slices (`tessera.slice`,
`tessera-spike.slice`, `tessera-spike-s3.slice`) remain until reboot or a root `systemctl stop tessera.slice`. The docker
profile should therefore not pass a slice name (use the default `system.slice/docker-<id>.scope`, removed with the
container) or accept the residue as stated. (2) tmpfs needs `uid=`/`gid=` for docker (podman uses `U`).

**Decision**: docker stays `partial` and is never `contained`: the daemon is rootful and the runner cannot observe or
prove it as the boundary, whatever the restrictions look like. The profile and the observation of the restrictions through
`inspect` still apply, so a docker run can name which restrictions are applied; no change to the level function (rule
"rootful docker is partial" already there). No re-plan.

**Open**: whether to read cgroup counters for docker at all (works on this host, depends on a readable cgroup tree; safe
default: report limit events as `not observable` for docker unless the scope or slice is readable); the slice residue
decision for the docker profile (no `--cgroup-parent` versus accepted residue); rootless docker and docker with userns
remap were not tried; containerd/Podman-as-docker-socket not tried.
**Leftover**: three empty system slices (see above), root needed to remove.

**T004**: 46 sanitized files in `tests/fixtures/isolation/` (`podman/` 25 from S1, `docker/` 21 from S3), with `README.md`
(origin, what each proves, sanitization rules); grep for `vannifr`, the host name and `/home/vannifr` finds nothing.

### Decisions after the spikes (autonomous, 2026-10-04)
- **npm replay limit accepted**: the advisory replay reproduces packages, severities and advisories but not fix versions (packuments are not replayed), so remediation reads "update to latest". The report states this limit; recall on D05 to D07 is unaffected. Revisit when level 3 adds attested advisory data.
- **Docker profile passes no cgroup-parent slice**: under the rootful daemon it creates system slices the unprivileged runner cannot remove (three empty slices from this spike remain until reboot or a root `systemctl stop tessera.slice`; harmless). Docker counters are read only as an observation, never as a reason to claim `contained`.
- **Docker scratch option**: the equivalent of the podman `mode=0700,U` option is handled by `--user` plus a tmpfs `uid=,gid=`; checked in S3, recorded in the fixtures README.
- **No re-plan triggered**: S1, S2 and S3 passed their exit criteria; the contracts were amended (plan.md, "Amendments after spikes S1 and S2").
