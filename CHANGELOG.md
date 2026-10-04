# Changelog

## Unreleased

- Dogfooding: `npm run dogfood` lets Tessera audit its own repository (signed evidence verified). It found and led to fixes for: audits refused for repositories without a web framework, inline import types that semgrep could not parse (correctly reported as INCOMPLETE), and 11 dev-dependency advisories (now 0). See `docs/dogfood/2026-10-04-triage.md`.
- Renamed the project to Tessera (package, repository, Sonar key, CI).
- SonarQube quality gate is blocking again: 125 new violations fixed without behavior change (differential test on 174k inputs, 40 of 42 mutations killed, 2 equivalent); one accepted issue, see README. The 2026-11-01 deviation is closed.
- `tests/unit/security.test.ts` is parameterized (same 21 cases); skipped tests carry cause and owner; the k6 throughput check uses a private temp directory.

## v0.2.0 (2026-10-03): scan core with an honest outcome, evidence and signing (Tessera, feature 004)

Assurance level 1 for the scan core. Not production ready; see `docs/review-report.md`, `docs/assurance-roadmap.md`
and the limits in the README.

### Added
- Audit outcome `COMPLETE` or `INCOMPLETE` with a status per scanner; a missing, failed, partial or skipped required
  scanner makes the audit incomplete and the report names it; "No findings" only when every required scanner completed.
- One tool runner for all scanners: no shell, argument arrays, environment allow-list, timeouts, output caps, exit-code
  policy per tool (a tool that reports issues is not a tool that failed).
- Evidence record for every executed step; one sealed evidence bundle per run with manifest, hash chain, `SHA256SUMS`
  and a root hash; `npm run evidence:verify` detects modified, missing and extra files, a broken chain, a foreign run and a forged root.
- Signing of the manifest with an Ed25519 key held outside the evidence folder (`npm run evidence:keygen`);
  verification reports valid, invalid, unsigned or unknown-key; the report shows what was signed, the key and a computed
  assurance level (0 or 1). `TESSERA_REQUIRE_SIGNATURE=1` makes a missing signature an incomplete audit.
- Neutralization of scanner steering from the audited source (ignore files, scanner configs, inline markers) with every
  attempt recorded; secrets are redacted before they reach evidence, results, reports or logs.
- License check from the lockfile as data (replaces `npx license-checker`, which executed code from the audited repo).
- BDD scenarios of all six user stories running on the real code (45 scenarios) and a demo release gate (`npm run demo`).

### Changed
- npm audit runs in an isolated directory and exit code 1 with valid JSON is "issues found", not an error.
- Semgrep runs with metrics off and fixed packs (no `--config auto`).
- Workflow errors end the workflow (non-retryable failures); model review corrections are advisory only.
- Report starts with the outcome block; the title is configurable (`TESSERA_PRODUCT_NAME`).
- Coverage floors are enforced for real and ratcheted (global 84/74/90/87); `src/scan` and `src/evidence` have their own floors.
- CI and local verification share scripts; images are pinned by digest.

### Fixed
- The coverage threshold key was invalid, so the gate could never fail.
- `npm run test:bdd` ran 0 scenarios (config file name never loaded).
- `npm audit` errors, a crashing scanner or a missing tool no longer turn into "no findings".
- Shell and path injection through the workflow id and repo path on the workflow path; code execution from the audited
  repository through `npx` is gone.
- Status documents with wrong figures were replaced by pointers to measured sources.

### Measured on the demo
Strict recall 8 of 18 (6 before), correct severity 5 of 18 (3 before), false positives on the clean app 0 (1 before).

### Known limits
Signing key on the worker host (level 1, not independent); signing time not attested; code review is a heuristic;
semgrep skips `tests/` by default; SonarQube gate failing (non-blocking deviation until 2026-11-01); remaining
`exec` calls outside the workflow path (tasks T042 to T045); sandboxing, authentication of Temporal and worker-crash
recovery are on the roadmap (items 006 to 008).
