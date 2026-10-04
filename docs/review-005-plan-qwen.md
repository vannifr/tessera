# Review of the plan for feature 005 by Qwen (qwen3.7-plus), triage

Date 2026-10-04, read-only run through opencode (about 3 minutes). Builder family: Claude (Opus designed, Sonnet applied fixes). Every claim was checked against the plan artifacts and the code; the raw report is not kept as truth. Basis: the autonomous-approval rule in `docs/agile/working-agreement.md`.

| # | Claim (Qwen) | Severity | Verdict | Action |
|---|--------------|----------|---------|--------|
| 1 | legacy `exec` calls reachable by any client | high | valid, already the plan's target | plan row 15 (explicit registry); architecture test added (item 8 below) |
| 2 | `detectTechStack` follows symlinks | high | valid, already found by the planner | plan row 8 |
| 3 | worker registers every export | high | valid, already the plan's target | plan row 15; test that `import *` cannot return |
| 4 | compose file publishes Temporal on 0.0.0.0 without auth, unpinned image | high | valid, already the plan's target | plan row 19 removes it; no deviation needed because nothing in CI uses it |
| 5 | mTLS server not run on this host yet | high | known risk, covered by spike S2 | re-plan trigger written: if S2 fails, US3 is not delivered and the report and README say so; never an unauthenticated claim |
| 6 | git config and filter drivers could run during fetch with egress | high | valid, cheap to close | `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` set to /dev/null, fsmonitor off, file protocol denied, hermetic test |
| 7 | advisory proxy depends on request order | medium | valid | tests for both orderings; quick-only ends as `advisory-data-missing` |
| 8 | isolation level could be lowered by a missing worker record | medium | valid | verifier rule `isolation-record-invalid` |
| 9 | SELinux label derivation unspecified | medium | valid | first fix (hash of the run id) was itself wrong: 20 bits collide for concurrent audits (birthday); replaced by allocation from a host-wide registry of active labels under a lock, tested with forced equal starting pairs |
| 10 | lockfile-derived advisory request can mislead | medium | valid, limit | report states results reflect the lockfile's claims; request and lockfile hashes recorded together |
| 11 | docker cannot observe cgroup counters | medium | known, handled | level `partial` with `limit-observation: not-applied`, asserted for docker in a hermetic test |
| 12 | custom DER encoder may produce certificates the server rejects | medium | valid | S2 runs with Node-generated certificates first; fallback openssl in the image |
| 13 | teardown-before-seal ordering can lose evidence | medium | valid | test: teardown succeeds, seal throws, audit INCOMPLETE with loss reported |
| 14 | attack-fixture gate could pass vacuously | medium | valid | static coverage test per FR-022 threat; build script exits non-zero on any failed fixture |
| 15 | spikes lack re-plan triggers | low | valid | triggers written |
| 16 | 30 s timeout padding arbitrary | low | minor | note: fixed margin, host timeout is the sole enforcer |
| 17 | window between clone and copy | low | minor | fetch container exits right after the copy; noted |
| 18 | SC-009 repeats one pair | low | valid | 10 distinct pairs, staggered |
| 19 | architecture test might miss production wiring | low | valid | test asserts the factory wiring in the activity factory |
| 20 | CI green may be read as proof of containment | low | valid | one summary line in every CI run |

Clean areas named by Qwen: FR and SC traceability, level computation purity, Tier C coverage, demo and dogfood recall, verifier first-word contract, task order, constitution check. These were not independently re-proven by this review.

Approval decision: no high finding remains open without a recorded plan change; the five high items are existing defects the feature removes or a risk with a spike and a fallback. Plan approved by independent review (Qwen), with the fixes above. Tasks and tests may proceed; the first Tier C task is gated on spikes S1 to S3.

Yield: 20 items, 15 valid and actioned, 5 known or minor.
