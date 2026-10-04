# Working agreement (Project Tessera)

Minimal agility on top of IIKit: Kanban for flow, XP for technical practice, a weekly review and retro,
and a time budget per slice. IIKit stays the source for spec, plan, tests and tasks.

## Flow

- Board columns: Backlog, Ready, Doing, CI/Review, Done (GitHub Project on the backlog issues).
- **WIP limit**: one feature and one user story in Doing. No new story while the pipeline on `main` is red.
- Work lands on `main` in small, atomic, green commits. Unfinished work stays dark behind a toggle.

## Definition of Ready

- Approved spec and locked scenarios (`/iikit-04-testify`), a task with tier label, files and interfaces.
- An appetite (time budget) for the slice.

## Definition of Done

- Code on `main`, pipeline verified green after the push (not assumed).
- BDD scenarios and unit tests green; no test skipped, emptied or weakened.
- The demo was run and recall and false positives are recorded; claims in docs match measurements.
- Non-functional aspects weighed: performance, security, accessibility, logging, error handling.
- A retro note exists for the slice.

## Timebox and circuit breaker

We do not estimate. The product owner sets a timebox for each slice before it starts: how much time we are willing to
spend, not a prediction. Current timebox: MVP slice of feature 004 (User Story 1, release v0.2.0), one working day,
started 2026-10-03. When the timebox is spent, stop, say so, and re-slice or amend plan and tasks with a semantic diff.
Do not extend silently. Cut scope, not quality: the first things to go are later stories and polish.

## Agent runs and resources

- Every opencode run gets a hard timeout (`timeout 600`) so a runaway cannot burn the quota; an agent run that exceeds it is
  killed and its task is re-cut. After a 429 do not retry in a loop: fall back to a Claude subagent or a free Zen model.
- Quota and tokens are a budget: note exhaustion as an incident and take the next task that does not need that resource.

## Review by another model family

- Builder and reviewer come from different families for Tier B and C work (for example Claude builds and Qwen, GLM or Kimi
  reviews the diff read-only, or the other way round). Tier C also gets a second opinion for the highest-stakes files.
- The commit body names who built, who reviewed and what the review found. Model review never replaces mutation tests,
  property tests or the product owner's judgment on Tier C commits.
- Only the framework's own code goes to external models; client code never, without explicit permission.

## End of every phase (fixed ritual)

A phase is an IIKit phase (spec, plan, tests, tasks, implementation) or a delivered slice. It is not closed until all four are done:
1. **Retro note**: `docs/retro/NNN-<phase>.md` from `TEMPLATE.md`, with numbers and actions; running observations go to `docs/retro/NNN-agentic-notes.md`.
2. **Independent model review**: a different family than the builder reviews the framework's own artifacts read-only through
   `opencode-orchestratie` (default GLM; Qwen or Kimi as second opinion), Alibaba runs serial under `flock` and `timeout`.
   The raw report is never trusted: every claim is checked against the code and triaged in `docs/review-NNN-<model>.md` with
   an action per item (valid, minor, not applicable, false).
3. **Actions land**: valid findings become fixes or backlog issues in the same phase, with the review named in the commit body.
4. **Dogfood run**: `npm run dogfood` on the pushed commit must end COMPLETE with a verified signature; what it exposes becomes a fix or a backlog issue.
5. **Long-term goal check**: re-read the product goal and levels in `docs/assurance-roadmap.md`; note whether the phase moved a
   level criterion and update the roadmap in the same commit.

## Tier C files and the security gate

Tier C (never delegated blind, diff read in full, mutation loop required, second opinion by another model family):
`src/scan/run-tool.ts`, `process-runner.ts`, `env.ts`, `status.ts`, `lifecycle.ts`, `source-probe.ts`, `safe-walk.ts`,
`src/evidence/*`, `src/workflows/index.ts`, `src/scan/activities.ts`, `src/report/outcome-block.ts`, `src/cli/verify-evidence.ts`.
A feature that adds or changes process execution, the network boundary or anything under `src/scan/` or `src/evidence/` has a
security review checkpoint in its tasks, executed before the feature counts as done.

## Stop the line

A red pipeline on `main` stops all new work until it is green again. Security fixes from the review (class of service
"expedite") may go first.

## Cadence (weekly, 30 minutes)

- **Review**: run `npm run demo` and `npm run dogfood` (Tessera audits itself), show the report and the computed assurance level; triage the dogfood findings in `docs/dogfood/`.
- **Retro**: what worked, what broke, numbers, actions. Notes in `docs/retro/NNN.md` from `TEMPLATE.md`.
- **Planning**: pull the next story from Ready, set its appetite.

## Numbers per slice

Demo recall and false positives, hours the pipeline on `main` was red, lead time per story, open deviations.

## Roles

Product owner: vannifr (priority by risk times client value). Execution: Claude (Opus for Tier C, Sonnet for Tier B)
and opencode (Qwen, GLM, Kimi; serial) for Tier A and suitable B work. Executors never commit; the orchestrator commits as vannifr.

## When to stop and ask

A new architecture or security decision outside the plan, a destructive or outward-facing action, a gate that cannot be made green,
or a change to the constitution.

## Customer feedback

One design partner reviews the demo and the report. Feedback becomes issues with the label `feedback`.
