# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-005
Feature: Legacy command-text checks unreachable
  The legacy checks that assemble commands as text are not registered with the worker and cannot be started by any client. Scenarios tagged @isolation need a real container runtime and the local orchestration server; all others are hermetic.

  Background:
    Given the worker's activity registry

  @TS-072 @FR-014 @SC-007 @P2 @validation
  Scenario: The registry holds exactly the sixteen verified activities
    When the registry keys are listed
    Then they equal: initAuditRun, checkIsolation, fetchSource, detectTechStack, generateScopeDocument, runNpmAudit, runGitleaks, runSemgrep, runLicenseCheck, reviewCriticalPaths, mapToCompliance, crossValidate, generateReport, teardownEnvironment, sealEvidence, signEvidence
    And the registry object is frozen

  @TS-073 @FR-014 @SC-007 @P2 @validation
  Scenario Outline: A legacy check is not registered
    When the registry is asked for "<name>"
    Then the name is not a key of the registry

    Examples:
      | name                        |
      | checkToolRequirements       |
      | runLighthouse               |
      | runAxeAccessibility         |
      | runSqlInjectionCheck        |
      | checkReliability            |
      | checkObservability          |
      | checkCicd                   |
      | waitForHumanApproval        |
      | checkCodeQuality            |
      | checkDocumentation          |
      | checkPrivacy                |
      | checkFunctionalRequirements |
      | checkBlindSpots             |
      | measureThroughput           |
      | assessDurability            |
      | assessStability             |
      | assessRobustness            |
      | cleanupRun                  |

  @TS-074 @FR-014 @P2 @contract
  Scenario: The worker passes the registry itself, not a module namespace
    When the worker options are built
    Then the activities are the registry object itself
    And the task queue is "audit"
    And at most 4 activity tasks and 10 workflow tasks run concurrently

  @TS-075 @FR-014 @P2 @contract
  Scenario: The workflow can only call registered names
    Given the workflow's activity proxy typed with the registry
    When the source calls the activity "runLighthouse" through the proxy
    Then the compilation fails

  @TS-076 @FR-014 @SC-007 @P2 @isolation @acceptance
  Scenario: A real worker lists its activities and runs nothing for a legacy workflow name
    Given a running worker connected with its certificate
    When its start log is read
    Then it lists 16 registered activities and the isolation check summary
    And a workflow started under the name "runLighthouse" fails as unknown
    And no process is spawned, no work directory is created and no container exists

  @TS-077 @FR-014 @P2 @validation
  Scenario: The verified scan path is unaffected
    Given an audit through the workflow with fake activities taken from the registry
    When it runs from start to report
    Then every activity it called is a registry key
    And the audit completes with its report and signed evidence

  @TS-096 @FR-014 @SC-007 @P2 @contract
  Scenario: The worker source never imports the activities module as a namespace
    When the worker source is scanned
    Then it contains no namespace import of the activities module, neither "import * as activities" nor any "import *" from it
    And it builds its options from the explicit registry
