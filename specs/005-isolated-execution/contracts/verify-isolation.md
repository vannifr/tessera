# Contract: verification of the isolation statement (FR-016, FR-017, SC-004)

Target modules: `src/evidence/verify.ts` (library), `src/cli/verify-evidence.ts` (CLI). Extends the 004 contract (`specs/004-reliable-scan-core/contracts/verify-contract.md`); existing behaviour, exit codes and the first-word contract are unchanged.

## Library

```ts
export interface VerifyOptions {
  expectRootHash?: string;
  reportPath?: string;            // new: compare the level line in a report file
}

export interface IsolationVerification {
  stated: IsolationLevel | 'not-stated';
  recomputed: IsolationLevel;
  match: boolean;
  reportStated?: IsolationLevel | 'missing';
}

// VerifyReport gains: isolation: IsolationVerification
// New VerifyIssue codes:
//   'isolation-level-mismatch'       stated level ≠ recomputed level
//   'isolation-statement-missing'    records carry isolation blocks but the manifest has no statement
//   'isolation-record-invalid'       an isolation block fails validation (unknown restriction id, bad image id,
//                                    mandatory restriction not applied in a record that claims the step ran; also: a tool-run record has an isolation block but `environment.check` is absent)
//   'isolation-report-mismatch'      --report given and its level differs from the manifest statement
//   'isolation-report-missing'       --report given and it contains no isolation line
```

Recomputation uses the same pure `computeIsolationLevel` the worker uses at seal time, on the records listed in the manifest (after their hashes were checked). It never reads the report to decide the level.

## Cases

| Bundle | Result |
|--------|--------|
| 005 bundle, statement equals recomputation | `isolation: contained (recomputed: contained)`, no issue |
| statement edited (`partial` → `contained`) | signature invalid (manifest bytes changed) and `isolation-level-mismatch` |
| statement edited and manifest re-signed with another key | `unknown-key` (004) and `isolation-level-mismatch` |
| an `isolation` block removed from a record | record hash mismatch (004) and recomputed `none` → `isolation-level-mismatch` |
| any tool-run record carries an isolation block but the `environment.check` record is absent from the manifest | `isolation-record-invalid` (in addition to recomputed `none`) |
| statement removed, blocks present | `isolation-statement-missing` |
| pre-005 bundle (no statement, no blocks) | `isolation: not stated (pre-005 bundle)`, no issue, exit unchanged |
| `--report` with a different level line | `isolation-report-mismatch` |

## CLI

```
npm run evidence:verify -- <bundle-dir> [--expect-root <sha256>] [--pubkey <file|dir>]... [--report <file>] [--json] [--trace <recordId>]
```

Human output adds one line after the signature line: `isolation: <stated> (recomputed: <recomputed>)` or `isolation: not stated (pre-005 bundle)`. Any new issue makes the first word `FAILED` and the exit code 1. `--json` adds the `isolation` object.

## Report line (outcome block)

```
Isolation: contained (podman 5.8.7, rootless, image sha256:1a2b…, 12 isolated steps)
Restricted: source read-only, no network while scanning, memory 2048 MiB, 512 processes, 2 CPUs, scratch 512 MiB, time and output limits, non-root, no capabilities, read-only root
Limits: <one line per LIMIT_TEXTS entry that applies>
```

For `partial`: `Isolation: partial: memory-limit not applied (environment.check), rootless-runtime not applied (docker)`. For `none`: `Isolation: none (isolation unavailable: <detail>); no area was scanned`. The verify `--report` comparison reads only the first word after `Isolation:`.
