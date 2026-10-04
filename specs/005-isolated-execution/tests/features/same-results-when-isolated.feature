# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-002
Feature: Same results when isolated
  Run isolated, an audit finds the same planted defects as before and still produces an evidence bundle that verifies. Scenarios tagged @isolation need a real container runtime and the scanner image; all others are hermetic.

  Background:
    Given the framework runs every audit isolated

  @TS-035 @FR-019 @SC-002 @P1 @isolation @acceptance
  Scenario: The demo source keeps its recall under isolation
    Given the demo vulnerable source with 18 planted defects
    When it is audited isolated
    Then strict recall is at least 8 of 18
    And defects D05, D06 and D07 are reported
    And the clean demo application ends with outcome "complete"
    And the planted secrets appear nowhere in evidence, report or logs

  @TS-036 @FR-019 @SC-003 @P1 @isolation @acceptance
  Scenario: A completed isolated audit verifies with a valid signature
    Given a completed isolated audit of the demo source
    When verification runs with the trusted public key
    Then the first word of the output is "VERIFIED"
    And the signature is valid
    And no record is reported as modified, missing or extra

  @TS-037 @FR-019 @SC-002 @P1 @isolation @acceptance
  Scenario: The framework's own repository completes isolated
    Given the framework's own repository
    When the dogfood run completes isolated
    Then the outcome is "complete"
    And all 5 scanners have status "completed"
    And the bundle is "VERIFIED"

  @TS-038 @FR-019 @SC-003 @P1 @validation
  Scenario: Every isolated audit produces evidence that verifies
    Given isolated audits through a hermetic fake runner that returns fixture outcomes, ending complete, incomplete and failed
    When each sealed bundle is verified with the run's public key
    Then every bundle verifies with a valid signature

  @TS-039 @FR-019 @P2 @isolation @acceptance
  Scenario: Isolation overhead stays within its budget on the demo
    Given the isolated demo audit
    When the durations of the isolation records are summed
    Then the overhead is at most 20 seconds
    And at most 25 percent of the audit's wall time

  @TS-040 @FR-020 @P1 @validation
  Scenario Outline: The advisory request is validated before it leaves the host
    Given a captured advisory request containing <case>
    When the request is validated
    Then the result is <result>

    Examples:
      | case                                         | result                                       |
      | a body larger than 5 MiB                     | the error "too-large"                        |
      | more than 20000 package names                | the error "too-many-names"                   |
      | an empty package list                        | the error "empty"                            |
      | text that is not JSON                        | the error "not-json"                         |
      | a JSON array instead of an object            | the error "not-object"                       |
      | one name "../evil" among valid names         | the entry dropped and droppedEntries 1       |
      | one version "1.0.0;rm" among valid versions  | the entry dropped and droppedEntries 1       |

  @TS-041 @FR-020 @P1 @validation
  Scenario: Dropped advisory entries make npm-audit partial
    Given a validated advisory request with droppedEntries 1
    When the npm-audit step completes
    Then its status is "partial" with cause "advisory-request-filtered"
    And the outcome is INCOMPLETE

  @TS-042 @FR-020 @FR-004 @P1 @validation
  Scenario Outline: A failed advisory fetch is never an empty clean result
    Given the advisory fetch fails with "<failure>"
    When the npm-audit step runs
    Then its status is "unavailable" with cause "advisory-data-missing"
    And the replay pass is never started
    And the report does not state zero vulnerabilities for npm-audit

    Examples:
      | failure              |
      | network              |
      | timeout              |
      | http-status          |
      | too-large            |
      | not-json             |
      | not-object-of-arrays |

  @TS-043 @FR-020 @FR-004 @P1 @validation
  Scenario: A capture holding only a quick-audit request is advisory data missing
    Given the record pass captured only a quick-audit request and no bulk advisory body
    When the npm-audit step runs
    Then the record pass exits with code 3 and prints nothing
    And the step is "unavailable" with cause "advisory-data-missing"
    And the diagnostic reads "npm sent no bulk advisory request (quick audit only)"
    And the replay pass never runs and the result is never zero vulnerabilities

  @TS-044 @FR-004 @FR-020 @P1 @validation
  Scenario: Replay refuses an empty snapshot
    Given an empty snapshot on standard input
    When the replay pass starts
    Then it exits with code 4 and does not start npm

  @TS-045 @FR-004 @FR-019 @P1 @validation
  Scenario Outline: The advisory proxy captures and replays in either request ordering
    Given a fake npm that sends the bulk request <ordering>
    When the record pass and then the replay pass run
    Then the record pass prints only the captured bulk body
    And the record pass captured the bulk request in both orderings
    And the quick-only ordering ends as "advisory-data-missing"
    And the replay answers the bulk request with status 200 and every other request with status 404
    And the replay exits with the exit code of npm

    Examples:
      | ordering                         |
      | first                            |
      | after a quick-audit request      |

  @TS-046 @FR-020 @FR-015 @P1 @contract
  Scenario: The advisory snapshot is recorded with its freshness
    Given the host fetched advisories for 9 packages
    When the npm-audit steps are recorded
    Then an in-process record "npm-audit.advisories" has the registry URL, requestSha256, fetchedAt, httpStatus, responseSha256 and responseBytes
    And it carries the response as artifact "advisories.json"
    And the replay record names advisorySnapshotSha256 and advisoryFetchedAt in its inputs

  @TS-047 @FR-020 @P1 @validation
  Scenario Outline: Stale semgrep rules make the scanner partial and keep findings
    Given the oldest rule pack was fetched <age> days before the scan and the limit is <limit> days
    When semgrep completes
    Then its status is "<status>"
    And its findings are kept

    Examples:
      | age | limit | status                      |
      | 91  | 90    | partial with cause rules-stale |
      | 90  | 90    | completed                   |
      | 10  | 90    | completed                   |
