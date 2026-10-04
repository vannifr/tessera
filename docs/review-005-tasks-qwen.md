# Review of the feature 005 task list by Qwen (qwen3.7-plus), triage

Date 2026-10-04, read-only run through opencode (about 2 minutes). Builder family: Claude (Sonnet wrote and corrected the list). Claims were checked against tasks.md, plan and contracts; the raw report is not kept as truth. Basis: the autonomous-approval rule in `docs/agile/working-agreement.md`.

| # | Claim (Qwen) | Severity | Verdict | Action |
|---|--------------|----------|---------|--------|
| 1 | PKI work wrongly waits for the coverage gate | high | valid | T043 and T044 no longer depend on T021; T045 depends on T044 |
| 2 | T020 references TS-067 which T052 owns | high | valid | reference removed |
| 3 | scanner hint files are Tier B but decide what runs on the source | high | valid | T029 is Tier C with a mutation requirement; Tier C lists extended |
| 4 | no task performs the worker drain before workflow-code commits | high | valid | explicit step in T035 and T042, checklist line in T066 |
| 5 | T050 deletes tracked files but is Tier A | medium | valid | Tier B; commit body states reason, reversibility and the plan-review approval |
| 6 | T052 mixes environment and audit layer | medium | valid | split, new T068 audit-layer test |
| 7 | T015 misses release, stale reclaim, same-start-pair tests | medium | valid | cases added |
| 8 | the task that proves the gate clean also activates it | medium | valid | dry run then activation (new T067) |
| 9 | T043 overlap contradicts the critical path | medium | valid | contradiction removed |
| 10 | gate owner hardcoded | low | valid | env variable with default |
| 11 | dashboard regeneration command unnamed | low | valid | command named from the rules file |
| 12 | US3 deferral not marked in tasks | low | valid | deferred notes on the US3 tasks |
| 13 | TS-094 asserted in the demo task and a unit task | low | valid | clarified: via demo output; unit tests in the verifier tasks |
| 14 | new coverage thresholds may be vacuous | low | partly valid | measured value recorded and used; temporal thresholds set in T048 because that code does not exist at T021 |
| 15 | spike script not preserved | low | valid | scripts/spikes/s2-mtls/ committed with the R12 addendum |

Clean areas named by Qwen: plan rows 1 to 20, spikes and triggers, research R1 to R20, contracts, feature files, FR and SC traceability, security gate checkpoints, 004 style. Not independently re-proven.

Yield: 15 items, 15 valid (one partly). The list is now 68 tasks (T001 to T068); every TS-001 to TS-096 and FR-001 to FR-022 is still referenced.

Approval decision: no open high finding; the task list is approved by independent review (Qwen) and implementation starts with spikes S1 to S3.
