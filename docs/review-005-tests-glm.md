# Review of the feature 005 scenarios by GLM (glm-5), triage

Date 2026-10-04, read-only run through opencode (about 2.5 minutes). Builder family: Claude (Sonnet wrote and corrected the scenarios). The claims were checked against the feature files and contracts; the raw report is not kept as truth. Basis: the autonomous-approval rule in `docs/agile/working-agreement.md`.

| # | Claim (GLM) | Verdict | Action |
|---|-------------|---------|--------|
| 1 | TS-081 asserts only that fields exist | valid | concrete patterns and configured values added |
| 2 | TS-001 asserts only a negative | valid | positive assertion: blocked by relative path only, no host content read |
| 3 | TS-067 reports values without comparing them | valid | values compared with the configured limits |
| 4 | TS-009 lacks the FR-022 tag | valid | tag added |
| 5 | exit code 4 is not in any contract | valid | documented in contracts/advisory-data.ts |
| 6 | TS-062 is a one-time migration check | valid | reworded as a repeatable static check |
| 7 | gaming the level by removing environment.check is not a scenario | valid | two rows added to the TS-089 examples |
| 8 | crash residue has no scenario | false | residue scenarios exist in hostile-source-containment (partial with cause residue, report shows residue) |
| 9 | no workflow-level concurrency scenario | minor | SC-009 is an environment-level gate by design; the demo runs one concurrent pair at workflow level; kept |
| 10 | no scenario that docker can never be contained | false | "A rootful docker run is partial and never contained" exists |
| 11 | no scenario for a worker without certificates | false | exists in orchestration-access |
| 12 | no regression scenario for `import *` | valid | TS-096 added |
| 13 | TS-087 could be hermetic | minor | the hermetic variant already exists; TS-087 is the real-host check and stays tagged |
| 14 | TS-038 Given wording may mislead | valid | wording clarified |
| 15 | TS-034 compares against a file only | valid | status and cause per fixture in the examples, file kept as a pointer |
| 16 | TS-089 outline is tautological | not applicable | each example row names a different tampering and a different issue |
| 17 | TS-053 checks only the code | valid | exact messages asserted (contract comment lists them) |
| 18 | TS-045 does not assert capture in both orderings | valid | assertion and the advisory-data-missing end added |

Yield: 18 items, 12 valid and actioned, 6 false, minor or not applicable. The scenario set is now 96 scenarios (TS-001 to TS-096), every FR and SC tagged, zero Gherkin parse errors.

Approval decision: no open high finding; the scenarios are approved by independent review (GLM) and locked.
