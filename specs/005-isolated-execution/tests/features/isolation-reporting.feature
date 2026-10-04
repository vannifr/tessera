# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-006
Feature: Report states the isolation actually used
  The report states the isolation level reached, computed from the evidence records, with its limits. Verification recomputes it. Scenarios tagged @isolation need a real container runtime and the scanner image; all others are hermetic.

  Background:
    Given a completed audit with isolation records

  @TS-078 @FR-016 @FR-018 @P1 @validation
  Scenario Outline: The isolation level is computed from the records
    Given the records show <records>
    When the isolation level is computed
    Then the level is "<level>"

    Examples:
      | records                                                                 | level     |
      | every restriction applied and the environment check passed              | contained |
      | memory-limit not applied in one record                                  | partial   |
      | a mandatory restriction not applied in one record                       | none      |
      | one tool-run record without an isolation block                          | none      |
      | no tool-run record at all                                               | none      |
      | the environment check failed with isolation-unavailable                 | none      |
      | memory-limit violated and enforced in one record                        | contained |

  @TS-079 @FR-016 @P1 @validation
  Scenario: The level does not depend on the order of the records
    Given a set of records that yields "partial"
    When the records are computed in every order tested
    Then the level is "partial" and restrictionsNotApplied is the same each time

  @TS-080 @FR-015 @SC-004 @P1 @validation
  Scenario: Every isolated step has its own isolation record
    Given an isolated audit with 12 tool-run steps
    When the evidence is listed
    Then every tool-run record has an isolation block with all restrictions and the image ID
    And an "environment.check" record and an "environment.teardown" record are present

  @TS-081 @FR-015 @P1 @contract
  Scenario: An isolation record carries what an auditor needs
    When a reviewer opens the isolation block of a tool-run record
    Then it has the schema "tessera.isolation/v1", the profile, the runtime name, version and rootless flag
    And the runtime name is "podman" or "docker"
    And the image ID matches "^sha256:[0-9a-f]{64}$" and the image manifest hash is present
    And the numeric limits equal the configured values
    And the container name and slice and the container-side argument vector, redacted
    And the mounts with their access
    And each restriction with id, class, state, expected value, observed value and source
    And limitEvents with oomKill and pidsMax, or null when not observable
    And the blocked attempts with kind, count and observedBy

  @TS-082 @FR-015 @P1 @validation
  Scenario: A restriction that could not be applied or was violated is recorded
    Given a step where "cpu-limit" could not be applied and "pids-limit" was reached
    When the record is built
    Then "cpu-limit" has state "not-applied" and "pids-limit" has state "violated"
    And only the limits memory, pids, time, output and scratch size can have state "violated"

  @TS-083 @FR-016 @SC-004 @P1 @contract
  Scenario: The report states the contained level, what was restricted and the limits
    Given an audit whose level is "contained" on rootless podman 5.8.7 with 12 isolated steps
    When the report is read
    Then the outcome block has a line starting "Isolation: contained (podman 5.8.7, rootless, image sha256:"
    And a "Restricted:" line naming source read-only, no network while scanning, memory 2048 MiB, 512 processes, 2 CPUs, scratch 512 MiB, time and output limits, non-root, no capabilities and read-only root
    And a "Limits:" line for shared kernel, local signing key, host-side readers, fetch egress, advisory egress and attempts recorded when observable

  @TS-084 @FR-018 @FR-016 @P1 @contract
  Scenario: A restriction that could not be applied lowers the level and is named
    Given an audit where memory-limit and rootless-runtime could not be applied
    When the report is read
    Then it states "Isolation: partial: memory-limit not applied (environment.check), rootless-runtime not applied (docker)"
    And the manifest statement lists both under restrictionsNotApplied with their record ids

  @TS-085 @FR-016 @P2 @contract
  Scenario: The statement is computed at sealing and cannot be entered by hand
    Given the sealing step
    When it writes the manifest
    Then manifest.isolation holds the level, computedFrom, restrictionsNotApplied, limits, runtime and imageId
    And the statement is inside the signed manifest bytes
    And no input exists through which the level can be set

  @TS-086 @FR-018 @P1 @validation
  Scenario: A rootful docker run is partial and never contained
    Given every restriction is applied except that the runtime is docker with a root daemon
    When the isolation level is computed
    Then the level is "partial"
    And "rootless-runtime" and "limit-observation" are named as not applied
    And the limits include the rootful-runtime text

  @TS-087 @FR-018 @P2 @isolation @acceptance
  Scenario: An audit run through docker on a real host is partial
    Given a host where the docker fallback is used with the same image
    When an audit completes
    Then its report states level "partial" naming "rootless-runtime" and "limit-observation"

  @TS-088 @FR-017 @SC-004 @P1 @validation
  Scenario: Verification recomputes the same level
    Given a bundle whose statement equals the recomputation
    When the evidence is verified
    Then the output has the line "isolation: contained (recomputed: contained)"
    And no isolation issue is reported

  @TS-089 @FR-017 @SC-004 @P1 @validation
  Scenario Outline: Verification reports a tampered isolation statement
    Given a bundle where <tampering>
    When the evidence is verified with its public key
    Then the first word of the output is "FAILED" and the exit code is 1
    And the issues include <issues>

    Examples:
      | tampering                                                                 | issues                                                          |
      | the statement was edited from partial to contained                        | an invalid signature and "isolation-level-mismatch"             |
      | the statement was edited and the manifest re-signed with another key      | "unknown-key" and "isolation-level-mismatch"                    |
      | an isolation block was removed from one record                            | a record hash mismatch and "isolation-level-mismatch"           |
      | the statement was removed while isolation blocks remain                   | "isolation-statement-missing"                                   |
      | a record has an unknown restriction id                                    | "isolation-record-invalid"                                      |
      | a record has an image ID that is not sha256 followed by 64 hex digits     | "isolation-record-invalid"                                      |
      | a mandatory restriction is not applied in a record that claims the step ran | "isolation-record-invalid"                                    |
      | the environment.check record was removed while tool-run records still carry an isolation block | "isolation-record-invalid"          |
      | a forged isolation block was added to a bundle that has no environment.check | "isolation-record-invalid"                           |

  @TS-090 @FR-017 @P1 @validation
  Scenario: Isolation blocks without an environment check record are invalid
    Given a bundle whose tool-run records carry isolation blocks but whose manifest lists no "environment.check" record
    When the evidence is verified
    Then the issues include "isolation-record-invalid"
    And the recomputed level is "none"

  @TS-091 @FR-017 @P1 @validation
  Scenario: A bundle from before this feature verifies without an isolation statement
    Given a bundle with no isolation statement and no isolation blocks
    When the evidence is verified
    Then the output has the line "isolation: not stated (pre-005 bundle)"
    And no issue is reported and the exit code is unchanged

  @TS-092 @FR-017 @P1 @validation
  Scenario Outline: Verification compares the level line of a report file
    Given a bundle with level "contained" and a report file where <report>
    When the evidence is verified with the report file
    Then the issues include <issue>

    Examples:
      | report                                  | issue                       |
      | the line reads "Isolation: partial: …"  | "isolation-report-mismatch" |
      | no Isolation line exists                | "isolation-report-missing"  |
      | the line reads "Isolation: contained …" | no issue                    |

  @TS-093 @FR-016 @FR-017 @SC-004 @P1 @validation
  Scenario: Every audit outcome states its isolation level and verification agrees
    Given audits that end complete, incomplete, failed and with isolation unavailable
    When each report is read and each bundle verified
    Then every report has an "Isolation:" line
    And verification recomputes the same level as stated in every case

  @TS-094 @FR-017 @SC-004 @P1 @isolation @acceptance
  Scenario: Demo and dogfood bundles recompute to the stated level
    Given the isolated demo and dogfood bundles
    When each is verified
    Then each reports "isolation: contained (recomputed: contained)"

  @TS-095 @FR-016 @P2 @contract
  Scenario: The report states the limits of this delivery
    Given the delivery decision of 2026-10-04
    When the report limits are read
    Then they state shared host kernel with no hardware isolation and a signing key held locally by the operator
    And they state that blocked attempts are recorded when observable
