# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-001
Feature: Hostile source cannot escape
  Every audit runs in its own throwaway isolated environment. Hostile audited source cannot touch the host, other audits or the evidence, and the environment is gone after every exit. Scenarios tagged @isolation need a real container runtime and the scanner image; all others are hermetic.

  Background:
    Given an audit of a repository the operator does not trust

  @TS-001 @FR-006 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario: Links and paths pointing outside the source are not followed
    Given the attack fixture "link-to-host-file" with an absolute link to a host canary file, a "../" chain, and package.json and the lockfile as links
    When the audit runs
    Then the host canary file is unchanged and its secret string appears in no evidence record, report, finding or worker log
    And the source probe record reports each escaping link as blocked, by its relative path only and with no absolute target
    And no tool execution read host content through any of those links
    And no link target is stored in any record
    And the audit ends with a defined outcome

  @TS-002 @FR-006 @P1 @validation
  Scenario: The source probe records escaping links and tech-stack detection ignores linked manifests
    Given a source containing the link "a" to "/etc/shadow", the link "b" to "../../.." and a package.json that is a link
    When the source probe and the tech-stack detection run on the host
    Then the probe records a "link-outside-source" attempt for "a" and for "b"
    And the tech-stack detection reports no package.json content
    And no file outside the source was opened

  @TS-003 @FR-003 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario: Writes outside the workspace and to the audited source fail
    Given the attack fixture "write-outside-workspace" whose payload writes to "/src", "/" and "/etc"
    When the payload runs in the scan environment
    Then every write fails with a read-only file system error
    And the host canary tree hash is unchanged
    And the isolation record shows restriction "source-read-only" as "applied"
    And the record lists a blocked attempt of kind "write" observed by "stderr-pattern", reported as heuristic

  @TS-004 @FR-005 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario: A process flood ends at the process limit
    Given the attack fixture "process-flood" that forks without end
    When the step runs
    Then the step ends with status "failed" or "partial" and cause "limit-pids"
    And the isolation record reports limitEvents.pidsMax greater than 0
    And a sibling audit running at the same time completes normally
    And the host stays responsive

  @TS-005 @FR-005 @SC-001 @P1 @isolation @acceptance
  Scenario: A memory hog ends at the memory limit
    Given the attack fixture "memory-hog" that allocates beyond 2048 MiB
    When the step runs
    Then the step ends with status "failed" and cause "limit-memory"
    And the isolation record reports limitEvents.oomKill of at least 1
    And the restriction "memory-limit" is recorded as "violated"
    And the isolation level of the audit is not lowered by the violation

  @TS-006 @FR-005 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario: Oversized output ends at the output limit
    Given the attack fixture "oversized-output" that writes 200 MB to standard output
    When the step runs
    Then the step ends with status "partial" and cause "output-truncated"
    And the container was force-removed before the outcome was returned
    And the findings of the step are capped at 2000

  @TS-007 @FR-004 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario: A network call at scan time does not leave the environment
    Given the attack fixture "network-at-scan-time" that connects by TCP and DNS to a host listener and to a public address
    When the payload runs in the scan environment
    Then the host listener received 0 connections
    And the isolation record shows restriction "network-none" as "applied"
    And the record lists a blocked attempt of kind "network"

  @TS-008 @FR-002 @FR-004 @SC-001 @P1 @isolation @acceptance
  Scenario: A hostile npm configuration and lifecycle scripts reach nothing
    Given the attack fixture "hostile-npmrc" with an .npmrc pointing at a host listener and lifecycle scripts that write a marker file
    When the audit runs
    Then the host listener received 0 connections
    And no marker file exists on the host
    And the npm-audit step ends with a defined status

  @TS-009 @FR-002 @FR-006 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario: A repository hook and an attribute filter do not run during fetch
    Given the attack fixture "hook-and-filter" with a git hook and a .gitattributes filter that write a marker file
    When the audit fetches and scans the repository
    Then no marker file exists on the host or in the source copy
    And the audit ends with a defined outcome

  @TS-010 @FR-002 @P1 @contract
  Scenario: The fetch step is configured so that repository configuration cannot execute
    Given a fetch step is prepared for a repository
    When the container command is built
    Then the clone arguments start with "-c core.fsmonitor=false -c protocol.file.allow=never"
    And the environment sets GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM to "/dev/null"
    And "protocol.file.allow=never" is lifted only for the development mirror path

  @TS-011 @FR-005 @SC-001 @P1 @isolation @acceptance
  Scenario: A source that expands beyond the size limit stops the fetch
    Given the attack fixture "size-bomb" whose clone expands beyond 1024 MiB
    When the audit runs
    Then the source step fails with cause "source-too-large"
    And the host disk holds no part of the clone
    And no scanner ran
    And the outcome is INCOMPLETE

  @TS-012 @FR-005 @P2 @isolation @acceptance
  Scenario: A very large or deeply nested source ends at its limit as partial
    Given a source of 200000 files in deep nesting
    When the audit runs
    Then the affected step ends with status "partial" and names the limit that was reached
    And the outcome is INCOMPLETE

  @TS-013 @FR-007 @SC-001 @P1 @isolation @acceptance
  Scenario: Nothing created inside an environment is visible outside it
    Given an environment payload that creates a setuid file in scratch, reads "/proc/1/environ" and reads the work path of a sibling audit
    When the payload runs
    Then the sibling audit's work directory hash is unchanged
    And the setuid file does not exist after the step
    And the sibling's source and evidence are not readable from the environment
    And a sealed bundle of an earlier audit still verifies

  @TS-014 @FR-002 @FR-003 @FR-004 @FR-005 @FR-009 @P1 @contract
  Scenario: The scan container is built with every restriction and none of the forbidden options
    Given a scan step is prepared for the scan profile
    When the container command is built
    Then it contains "--network none", "--read-only", "--cap-drop all", "no-new-privileges", "--init", "--pids-limit 512", "--memory 2048m", "--cpus 2" and "--log-driver none"
    And it contains one source mount with access "ro" and a scratch area of 512m with "noexec,nosuid,nodev"
    And the image is given by ID matching "sha256:" followed by 64 hex digits
    And it never contains "--privileged", "--cap-add", "--device", "--pid host", "--network host", "--ipc host" or "label=disable"
    And it contains no mount other than the source and, in development only, the read-only mirror

  @TS-015 @FR-002 @P1 @validation
  Scenario Outline: An image reference that is not an image ID is refused
    Given a step with image reference "<reference>"
    When the container command is built
    Then the request is refused with code "EISOLATION"

    Examples:
      | reference                  |
      | scanner:latest             |
      | scanner@sha256:0123        |
      | sha256:ABCDEF              |

  @TS-016 @FR-002 @FR-011 @P1 @validation
  Scenario: A process request without an isolation hint is refused
    Given a process request that carries no isolation hint
    When the isolated runner receives it
    Then the outcome carries code "EISOLATION"
    And no process was started

  @TS-017 @FR-007 @P1 @validation
  Scenario Outline: A host path that is not mapped is refused
    Given a request whose <where> contains the host path "<path>"
    When the paths are translated for the container
    Then the request is refused with code "EISOLATION" naming the <where>

    Examples:
      | where       | path                    |
      | argument    | /etc/passwd             |
      | environment | /home/operator/.ssh     |
      | working dir | /tmp/tessera-other-run  |

  @TS-018 @FR-007 @P1 @validation
  Scenario: Path translation respects the directory boundary
    Given the mapped source directory "/tmp/tessera-run1/source"
    When the argument "/tmp/tessera-run1/source-evil/file" is translated
    Then the request is refused with code "EISOLATION"
    And the argument "/tmp/tessera-run1/source/file" is translated to "/src/file"

  @TS-019 @FR-002 @FR-011 @P1 @validation
  Scenario Outline: A mandatory restriction that is not applied prevents the container from starting
    Given the runtime reports "<inspect fact>" for the created container
    When the isolated runner checks the container
    Then the container is removed and never started
    And the step ends with status "failed" and cause "isolation-unavailable"
    And the detail names "mandatory-restriction-missing:<restriction>"

    Examples:
      | inspect fact                       | restriction          |
      | Privileged true                    | capabilities-dropped |
      | an extra bind mount                | source-mount-only    |
      | a network other than the profile's | network-none         |
      | a writable root filesystem         | rootfs-read-only     |

  @TS-020 @FR-005 @P1 @validation
  Scenario Outline: A step that reaches its time or output limit is force-removed first
    Given a step whose "<limit>" is reached
    When the isolated runner returns the outcome
    Then a forced removal with zero grace time was issued before the outcome returned
    And the status is "<status>" with cause "<cause>"

    Examples:
      | limit   | status  | cause            |
      | time    | failed  | timeout          |
      | output  | partial | output-truncated |

  @TS-021 @FR-005 @P1 @validation
  Scenario Outline: Kernel counters decide the limit status
    Given the cgroup counters of the step show "<counters>" and the tool result is "<tool result>"
    When the outcome is classified
    Then the status is "<status>" with cause "<cause>"

    Examples:
      | counters      | tool result | status  | cause       |
      | oom_kill 1    | usable      | failed  | limit-memory |
      | pids max 3    | usable      | partial | limit-pids  |
      | pids max 3    | unusable    | failed  | limit-pids  |

  @TS-022 @FR-009 @P1 @acceptance
  Scenario: A scanner gets a private size-limited temporary area while the source stays read-only
    Given a scanner that needs a writable temporary area
    When the step runs in the scan environment
    Then HOME and TMPDIR point inside a private scratch area of 512 MiB
    And writing beyond 512 MiB fails inside the tool with a no-space error
    And the audited source stays read-only
    And the scratch area no longer exists after the step

  @TS-023 @FR-007 @FR-008 @P1 @contract
  Scenario: The fetch step writes the source only after a complete bounded clone
    Given a fetch step with a size limit of 1024 MiB
    When the clone completes within the limit
    Then the tree is copied to the audit's own source directory with links kept as links and without setuid or setgid bits
    And nothing was written to the source directory before the clone completed
    And a clone that runs out of space exits with the single line "tessera: source-too-large"

  @TS-024 @FR-008 @SC-009 @P1 @validation
  Scenario: Concurrent audits never share an SELinux label
    Given 200 audits allocate an SELinux label at the same time and all run ids hash to the same starting pair
    When the labels are allocated
    Then the 200 labels are pairwise distinct
    And each label has two different categories between 0 and 1023
    And a released label can be allocated again

  @TS-025 @FR-008 @FR-007 @SC-009 @P1 @isolation @acceptance
  Scenario: Ten repeated runs of two concurrent audits never mix source, working data or evidence
    Given 20 audits started with staggered starts as 10 concurrent pairs
    When all audits finish
    Then each audit used its own environment label, cgroup slice, work directory and evidence bundle
    And no audit read the source, working data or evidence of its pair
    And each of the 10 pairs held two distinct SELinux label pairs while running

  @TS-026 @FR-001 @FR-021 @SC-008 @P1 @isolation @acceptance
  Scenario Outline: No environment or working data remains after any exit
    Given an audit that ends by "<exit>"
    When the end state is inspected
    Then no container carrying the run label exists
    And the audit's cgroup slice no longer exists
    And its work directory no longer exists

    Examples:
      | exit                                  |
      | completing                            |
      | being incomplete                      |
      | failing in a step                     |
      | being cancelled by an operator        |
      | a worker killed in the middle of a scan |

  @TS-027 @FR-001 @FR-021 @P1 @validation
  Scenario: Teardown removes everything and records the result
    Given an audit with two step containers, an audit slice and a work directory
    When the environment is torn down
    Then the teardown record states containersRemoved 2, slicesRemoved 1 and workDirRemoved true
    And the teardown record states residue "none" with status "completed"

  @TS-028 @FR-021 @P1 @validation
  Scenario: A leftover that cannot be removed is reported
    Given the runtime refuses to remove one container
    When the environment is torn down
    Then the teardown record has status "partial" with cause "residue" and lists the container tokenized
    And the leftover is flagged for removal by the sweeper
    And the report shows the residue and the evidence set is not marked clean of residue

  @TS-029 @FR-021 @FR-001 @P1 @validation
  Scenario: A terminated audit is swept
    Given a Tessera-labeled container, slice and work directory older than the maximum audit duration whose workflow was terminated
    When the sweeper runs at worker start
    Then they are removed and each removal is logged

  @TS-030 @FR-001 @FR-021 @P1 @validation
  Scenario: A crashing environment ends the step with cause and keeps earlier evidence
    Given the isolated environment crashes during the third step of an audit
    When the audit proceeds
    Then that step is failed with its cause and the outcome is INCOMPLETE
    And the environment and partial working data are removed
    And the evidence records of the two completed steps still verify

  @TS-031 @FR-021 @FR-001 @P1 @validation
  Scenario: A full disk fails the step and removes partial data
    Given the disk is full while the environment is created or output is written
    When the audit proceeds
    Then the step is failed with its cause and the outcome is INCOMPLETE
    And partial working data is removed

  @TS-032 @FR-021 @FR-001 @SC-008 @P1 @validation
  Scenario: Teardown succeeds but sealing throws
    Given teardown completed with residue "none"
    And sealing the evidence throws an error
    When the workflow finishes
    Then the outcome is INCOMPLETE
    And no sealed bundle exists
    And the report states the evidence loss and the error cause
    And the loss is never silent

  @TS-033 @FR-022 @SC-001 @P1 @contract
  Scenario: The attack fixtures cover every named threat and the release gate runs them
    Given the file "demo/attack/EXPECTED.md" and the fixture build script
    When the static check runs
    Then the file lists at least one fixture each for path traversal, links to host files, process flood, oversized output, network call at scan time and writes outside the workspace
    And the fixture build script exits non-zero when any fixture cannot be created
    And "npm run release:gate" runs "test:isolation"
    And a skipped isolation test fails the release gate

  @TS-034 @FR-022 @SC-001 @P1 @isolation @acceptance
  Scenario Outline: Every attack fixture is contained
    Given the attack fixture "<fixture>"
    When an audit runs against it
    Then the host canary tree hash is unchanged
    And the sibling audit and an earlier sealed bundle are unchanged
    And the step ends with status "<status>" and cause "<cause>"
    And <observation>
    And the status and cause match those given for "<fixture>" in "demo/attack/EXPECTED.md"
    And the environment no longer exists

    Examples:
      | fixture                 | status             | cause              | observation                                                       |
      | link-to-host-file       | completed          | none               | each escaping link is a blocked attempt of kind "link-outside-source" |
      | write-outside-workspace | completed          | none               | the blocked write attempts are recorded and host files are unchanged |
      | process-flood           | partial            | limit-pids         | the pids-limit restriction has state "violated"                   |
      | memory-hog              | failed             | limit-memory       | the memory-limit restriction has state "violated" and oomKill is greater than 0 |
      | oversized-output        | partial            | output-truncated   | the output is marked truncated and the host never held more than the output limit |
      | network-at-scan-time    | completed          | none               | the blocked attempt of kind "network" is shown and no host listener saw a connection |
      | hostile-npmrc           | completed          | none               | the host listener received zero connections                       |
      | hook-and-filter         | completed          | none               | no marker file exists on the host or in the source copy           |
      | size-bomb               | source-unavailable | source-too-large   | no scan step ran on the oversized source                          |
