# Feature Specification: Isolated Execution

**Feature Branch**: `005-isolated-execution`
**Created**: 2026-10-04
**Status**: Draft
**Input**: User description: "Isolated execution of every audit so that hostile audited source cannot touch the host, other audits, or the evidence; local-only authenticated orchestration; honest isolation reporting"
**Project**: Tessera (internal codename)

## User Stories *(mandatory)*

### User Story 1 - Hostile source cannot escape (Priority: P1)

An operator audits a repository they do not trust. The repository may contain paths that point
outside itself, links to host files, code that spawns processes without end, output of absurd
size, code that calls out to the network while being scanned, and attempts to write outside its
own working area. Every audit runs in its own throwaway isolated execution environment that is
discarded after the audit. Inside it the audited source is read-only, scanners have no network
access while scanning, and time, memory, process count, and output size are limited. The host
framework never executes audited code.

**Why this priority**: The independent review confirmed that a scan can execute code from the
audited repository. Until this is closed the framework cannot be pointed at any source it does not
already trust, which blocks assurance level 2.

**Independent Test**: Run an audit against each attack fixture (path traversal, symbolic links
to host files, process flood, huge output, network call at scan time, writes outside the
workspace). In every case the host, other audits, and the evidence are unchanged, and the audit
ends with a defined outcome.

**Acceptance Scenarios**:

1. **Given** a repository whose paths or links point outside itself, **When** an audit runs,
   **Then** no host file is read, written, or reported, and the attempt is recorded in the evidence.
2. **Given** a repository that tries to write outside its workspace or to modify the audited
   source, **When** an audit runs, **Then** the write fails, nothing outside the environment
   changes, and the attempt is recorded.
3. **Given** a repository that floods the system with processes or produces output beyond the
   limit, **When** the audit runs, **Then** the step ends at its limit, is reported as failed or
   partial with the cause, and the host and other audits keep working normally.
4. **Given** a repository that attempts a network call while being scanned, **When** the audit
   runs, **Then** the call does not leave the environment and the attempt is recorded.
5. **Given** any audit that has ended, whether complete, incomplete, or crashed, **When** the end
   state is inspected, **Then** its isolated environment and working area no longer exist.

---

### User Story 2 - Same results when isolated (Priority: P1)

A consultant wants isolation without losing audit quality. Run isolated, an audit finds the same
planted defects as before and still produces an evidence bundle that verifies with a valid
signature.

**Why this priority**: Isolation that degrades results or breaks the evidence chain is not
usable; the levels reached so far must not be lowered (constitution XII).

**Independent Test**: Run the demo release gate and the dogfood run in isolated mode. Recall on
the demo ground truth is not lower than 8 of 18, the dependency defects D05 to D07 are still
found, and verification reports a valid signature.

**Acceptance Scenarios**:

1. **Given** the demo vulnerable source, **When** it is audited isolated, **Then** recall is at
   least 8 of 18 and D05, D06, D07 are reported.
2. **Given** a completed isolated audit, **When** verification runs with the trusted public key,
   **Then** it reports a valid signature and no modified, missing, or extra record.
3. **Given** the framework's own repository, **When** the dogfood run completes isolated, **Then**
   all scanners are completed and the outcome is complete.

---

### User Story 3 - Orchestration reachable only locally and authenticated (Priority: P1)

An operator runs the framework on a shared or networked machine. The orchestration service that
starts and controls audits accepts connections only from the same machine, and only from clients
that authenticate. An unauthenticated client, or a client from another machine, is refused.

**Why this priority**: The review found the service open to every network interface without
authentication, so anyone who could reach it could start, read, or steer audits.

**Independent Test**: From the same machine without credentials, from the same machine with
valid credentials, and from another machine, attempt to start and query an audit.

**Acceptance Scenarios**:

1. **Given** a running framework, **When** a client without credentials connects locally,
   **Then** it is refused and cannot start or read any audit.
2. **Given** a running framework, **When** a client on another machine tries to connect, **Then**
   the connection is refused whatever credentials it presents.
3. **Given** a local client with valid credentials, **When** it starts an audit, **Then** the
   audit runs normally.
4. **Given** the framework is configured to listen beyond the local machine, **When** it
   starts, **Then** it refuses to start unless the exposure is explicit and authenticated.

---

### User Story 4 - Never silently unisolated (Priority: P1)

An operator starts an audit on a machine where isolation cannot be provided. The audit is
reported INCOMPLETE and says why. The framework never falls back to running the audited source
without isolation (constitution VII).

**Why this priority**: A silent fallback would reproduce the original defect while looking safe.

**Independent Test**: Make the isolation capability unavailable and start an audit. The audit
ends INCOMPLETE with the cause, no scanner has touched the audited source, and no clean result
is shown for any area.

**Acceptance Scenarios**:

1. **Given** the isolation capability is missing or unusable, **When** an audit starts, **Then**
   no audited content is scanned, the outcome is INCOMPLETE, and the report names the cause.
2. **Given** isolation became unavailable between two steps of one audit, **When** the next step
   would run, **Then** the audit stops, is INCOMPLETE, and the completed steps keep their evidence.
3. **Given** isolation is unavailable, **When** the report is read, **Then** it never states
   "no findings" for areas that were not scanned.

---

### User Story 5 - Legacy command-text checks unreachable (Priority: P2)

Older checks assemble commands as text and run them with interpretation. They are not part of
the verified scan path. They are no longer registered with the worker and cannot be started by
any client.

**Why this priority**: They are the injection surface named in the review. Removing their
reachability closes it now; their migration is separate work.

**Independent Test**: Ask the worker for the list of runnable activities and attempt to start each
legacy check by name. None is available; the verified scan path still runs.

**Acceptance Scenarios**:

1. **Given** a running worker, **When** its registered activities are listed, **Then** none of the
   legacy command-text checks is present.
2. **Given** a client that requests a legacy check by name, **When** the request is made, **Then**
   it fails as unknown and nothing is executed.
3. **Given** the verified scan path, **When** an audit runs, **Then** it is unaffected.

---

### User Story 6 - Report states the isolation actually used (Priority: P2)

A consultant or client reading the report needs to know how isolated the audit was and what that
does not cover. The report states the isolation level used, derived from what actually happened
in that audit, and lists its limits. Each isolated step has its own evidence record.

**Why this priority**: Constitution XII forbids hand-entered assurance; a claim of isolation must
come from recorded facts.

**Independent Test**: Complete one isolated audit and one audit where isolation was unavailable.
The first report states the isolation used with limits and every step has an isolation record;
the second states that no isolation was applied.

**Acceptance Scenarios**:

1. **Given** a completed isolated audit, **When** the report is read, **Then** it states the
   isolation level reached, what was restricted (access to the source, network, resources), and
   the known limits.
2. **Given** a completed isolated audit, **When** the evidence is listed, **Then** each isolated
   step has a record showing the environment used and the restrictions that applied.
3. **Given** an audit where a restriction could not be applied, **When** the report is read,
   **Then** the stated level is lowered accordingly and the missing restriction is named.
4. **Given** verification of the evidence, **When** it runs, **Then** the stated isolation level
   is recomputed from the records and a mismatch is reported.

---

### Edge Cases

- The isolation capability is not installed on the machine. The audit is INCOMPLETE with the cause
  "isolation unavailable"; no unisolated attempt is made.
- The isolated environment crashes mid-audit. The step is failed with cause, the audit is
  INCOMPLETE, the environment is discarded, and evidence of completed steps stays valid.
- The disk is full when creating the environment or writing output. The step fails with cause,
  the audit is INCOMPLETE, and partial working data is removed.
- A scanner needs a writable temporary area. It gets a private, size-limited one inside the
  environment; the audited source stays read-only.
- Two audits run at the same time. Each has its own environment; neither can see the other's
  source, working data, or evidence.
- A scanner that needs the network (for example to fetch advisory data) cannot be run with network
  access during scanning. Required data is prepared before the scan, outside the audited source's
  reach; if it is stale or missing the scanner is reported as partial or unavailable.
- The audited source contains a very large number of files or very deep nesting. The step ends at
  its limit and is reported as partial.
- The audit is cancelled by an operator. The environment is discarded the same way as after a
  normal end.
- The environment cannot be discarded. The audit is reported with the cause, the leftover is
  flagged for removal, and the evidence set is not marked as clean of residue.
- A client presents credentials that are expired or revoked. It is refused as an unauthenticated
  client.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST run every audit in its own isolated execution environment, created
  for that audit and discarded after it ends on every exit path (complete, incomplete, failed,
  cancelled, crashed).
- **FR-002**: The system MUST NOT execute audited code, configuration, or repository metadata
  outside the isolated execution environment.
- **FR-003**: The audited source MUST be read-only inside the environment; any write to it MUST
  fail and be recorded.
- **FR-004**: Scanners MUST have no network access while scanning; any attempt MUST fail and be
  recorded.
- **FR-005**: The system MUST enforce limits on run time, memory, number of processes, and output
  size for every isolated step, and MUST report a step that reached a limit as failed or partial
  with the limit named.
- **FR-006**: Paths and links in the audited source that resolve outside the audited source MUST
  NOT be followed, and each attempt MUST be recorded.
- **FR-007**: Nothing created inside an environment MUST be visible to, or able to modify, the
  host, other audits, or any evidence set, except the evidence the framework itself collects.
- **FR-008**: Concurrent audits MUST use separate environments and MUST NOT share source copies,
  working data, or evidence.
- **FR-009**: The system MUST provide scanners with a private, size-limited temporary area inside
  the environment, discarded with it.
- **FR-010**: When isolation is unavailable at the start of an audit or before any step, the
  system MUST NOT scan the audited source, MUST mark the audit INCOMPLETE, and MUST state the cause.
- **FR-011**: The system MUST NOT run any step unisolated as a fallback, by default or by
  configuration.
- **FR-012**: The orchestration service MUST accept connections only from the local machine.
- **FR-013**: The orchestration service MUST refuse every client that does not present valid
  credentials, and MUST refuse to start if configured to accept non-local clients without
  explicit, authenticated exposure.
- **FR-014**: The system MUST NOT register the legacy command-text checks with the worker, and a
  request for any of them MUST fail as unknown without executing anything.
- **FR-015**: Every isolated step MUST produce an evidence record stating the environment used,
  the restrictions applied (source access, network, resource limits), and any restriction that
  could not be applied or was violated.
- **FR-016**: The report MUST state the isolation level used for the audit and its known limits,
  computed from the evidence records of that audit and never entered by hand.
- **FR-017**: Verification MUST recompute the isolation level from the evidence and report a
  mismatch with the level stated in the report.
- **FR-018**: A restriction that could not be applied MUST lower the stated isolation level and
  MUST be named in the report.
- **FR-019**: The system MUST produce the same findings and a verifiable signed evidence bundle
  when run isolated as before this feature, for the demo source and for the framework's own
  repository.
- **FR-020**: Data that scanners need from outside the audited source (such as advisory data)
  MUST be prepared outside the audited source's reach, and its freshness or absence MUST be
  reflected in the scanner status.
- **FR-021**: The system MUST remove all working data of an audit on every exit path, and MUST
  report any leftover that could not be removed.
- **FR-022**: The system MUST provide attack fixtures for path traversal, links to host files,
  process flood, oversized output, network call at scan time, and writes outside the workspace,
  and the release gate MUST run them.

**Delivery note (decided 2026-10-04)**: This feature delivers software isolation on a shared
host. There is no hardware-level isolation, the host kernel is shared with the isolated
environment, and the signing key is still held locally by the operator. A kernel-level escape or
a malicious administrator is therefore out of scope. Key custody outside the operator's control,
independent time attestation, and external anchoring belong to level 3, and independent
verification to level 4 (see `docs/assurance-roadmap.md`, items 006 and 008). Evidence storage
that even an administrator cannot alter is item 010. Migration of the legacy checks to the
verified scan path is item 012; this feature only makes them unreachable. Reports state these
limits.

**Assumptions**:

- The attack fixtures are written for this feature and live with the ground-truth material.
- The isolation level in reports is a small ordered set whose exact names are fixed in planning.
- Enterprise multi-tenant authentication (accounts, roles) is out of scope; one authenticated
  local client identity suffices for this version.
- Level 2 items 007 (recovery) and 010 (evidence storage) are separate features.

### Key Entities

- **Isolated Environment**: A throwaway execution context created for one audit with its
  restrictions, discarded afterwards.
- **Isolation Restriction**: One applied limit or denial (read-only source, no network, time,
  memory, process count, output size), recorded as applied, not applied, or violated.
- **Isolation Record**: The evidence record of one isolated step: environment, restrictions,
  attempts that were blocked.
- **Isolation Level**: The computed statement of how isolated an audit was, derived from its
  Isolation Records.
- **Client Credential**: Proof presented by a client of the orchestration service.
- **Attack Fixture**: A hostile source used to demonstrate containment.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of attack fixtures are contained: after each, the host, other audits, and
  evidence are unchanged, and the environment is gone.
- **SC-002**: Against the demo ground truth run isolated, recall is not lower than 8 of 18 and
  D05, D06, D07 are found; the dogfood run completes with all scanners completed.
- **SC-003**: 100% of isolated audits produce evidence that verifies with a valid signature.
- **SC-004**: 100% of audits state the isolation level used, and verification recomputes the same
  level in every tested case.
- **SC-005**: In 100% of tests with isolation made unavailable, the audit is INCOMPLETE with the
  cause named and no audited content scanned.
- **SC-006**: Unauthenticated or non-local access to the orchestration service is refused in
  100% of tests.
- **SC-007**: None of the legacy command-text checks is startable in 100% of tests.
- **SC-008**: After 100% of audit exits (complete, failed, cancelled, crashed), no environment or
  working data remains.
- **SC-009**: Two concurrent audits never mix source, working data, or evidence in a test of at
  least 10 repeated runs.
