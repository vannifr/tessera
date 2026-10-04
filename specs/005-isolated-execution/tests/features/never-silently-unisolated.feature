# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-004
Feature: Never silently unisolated
  When isolation cannot be provided the audit is INCOMPLETE and says why. The framework never falls back to scanning the audited source without isolation. Scenarios tagged @isolation need a real container runtime and the scanner image; all others are hermetic.

  Background:
    Given an audit is started

  @TS-063 @FR-010 @SC-005 @P1 @validation
  Scenario Outline: Isolation unavailable at the start scans nothing
    Given the isolation check fails with detail "<detail>"
    When the audit proceeds
    Then the source is never fetched and no audited content is scanned
    And the outcome is INCOMPLETE with cause "isolation-unavailable" and detail "<detail>"
    And every required scanner is listed as "unavailable" with cause "isolation-unavailable"
    And the check record is sealed with status "failed"
    And the isolation unavailable error is not retried

    Examples:
      | detail                                  |
      | no-runtime                              |
      | runtime-unusable                        |
      | image-missing                           |
      | image-id-mismatch                       |
      | image-outdated                          |
      | mandatory-restriction-missing:network-none |
      | selftest-failed:write-src               |

  @TS-064 @FR-010 @SC-005 @P1 @isolation @acceptance
  Scenario Outline: On a real host without usable isolation the source is never cloned
    Given the host condition "<condition>"
    When an audit starts
    Then the outcome is INCOMPLETE with the cause named
    And the source was never cloned
    And no area is reported as having no findings

    Examples:
      | condition                                   |
      | the container runtime hidden from the path  |
      | an image ID that does not exist             |

  @TS-065 @FR-010 @P1 @validation
  Scenario: Isolation lost between two steps stops the audit
    Given gitleaks completed and isolation then became unavailable
    When the next step would run
    Then semgrep and npm-audit are "failed" with cause "isolation-unavailable"
    And the heuristic review is "skipped" with cause "isolation-unavailable"
    And the gitleaks record is kept and sealed
    And the outcome is INCOMPLETE
    And teardown still runs

  @TS-066 @FR-010 @SC-005 @P1 @validation
  Scenario: The report never says no findings for areas that were not scanned
    Given an audit ended because isolation was unavailable
    When the report is read
    Then it contains no "no findings" statement for any area
    And the outcome block reads "Isolation: none (isolation unavailable: no-runtime); no area was scanned"

  @TS-067 @FR-010 @FR-015 @P1 @isolation @contract
  Scenario: The isolation check confirms each restriction from inside a test environment
    Given an empty test source in the scan environment
    When the self-test runs
    Then it reports a non-root user, no effective capabilities, no-new-privileges 1 and seccomp mode 2
    And it reports the memory limit equal to the configured memoryMiB times 1048576 and the process limit equal to the configured pids limit
    And the network mode is "none" and the source is mounted read-only
    And only the loopback interface is present
    And a write to "/src" and to "/" fails with a read-only error
    And a TCP connection to a public address fails as unreachable
    And the scratch size equals the configured value and no setuid file exists under "/opt/tessera"

  @TS-068 @FR-010 @FR-018 @P2 @validation
  Scenario: Only resource restrictions missing continues at a lower level
    Given the host uses cgroup v1 so memory and process limits cannot be confirmed
    When the isolation check runs
    Then the check record has status "partial" and names the restrictions not applied
    And the audit continues at isolation level "partial"

  @TS-069 @FR-011 @SC-005 @P1 @validation
  Scenario Outline: No configuration value selects unisolated execution
    Given the setting "<setting>"
    When the framework starts
    Then it stops with a configuration error
    And no step runs

    Examples:
      | setting                           |
      | TESSERA_ISOLATION_RUNTIME=none    |
      | TESSERA_ISOLATION_MEMORY_MB=0     |
      | TESSERA_ISOLATION_PIDS=unlimited  |
      | TESSERA_ISOLATION_CPUS=abc        |
      | TESSERA_ISOLATION_MEMORY_MB=100   |

  @TS-070 @FR-011 @FR-002 @P1 @contract
  Scenario: The production wiring only holds the isolated runner
    Given the source of the framework
    When the architecture check runs
    Then the activity factory used by the worker is built with the isolated runner
    And no module under the scan directory imports the default process runner except the wiring
    And the worker cannot import the activities as a module namespace

  @TS-071 @FR-010 @FR-011 @SC-005 @P1 @validation
  Scenario: Each way isolation can be missing yields INCOMPLETE with no audited content scanned
    Given isolation is made unavailable by each of: no runtime, image missing, image outdated, mandatory restriction not applied, lost between steps
    When an audit runs for each case
    Then every audit is INCOMPLETE with the cause named
    And in the first four cases no step touched the audited source
    And in the fifth case no step after the loss touched it
