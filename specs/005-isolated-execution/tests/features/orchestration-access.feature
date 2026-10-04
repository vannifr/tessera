# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-003
Feature: Orchestration reachable only locally and authenticated
  The orchestration service accepts only local, authenticated clients. Scenarios tagged @isolation need a real container runtime and the local orchestration server; all others are hermetic.

  Background:
    Given the framework's orchestration service

  @TS-048 @FR-013 @SC-006 @P1 @isolation @acceptance
  Scenario: A local client without credentials is refused
    Given the service is running on the local machine
    When a local client connects without a certificate
    Then the connection is refused
    And it cannot start or read any audit

  @TS-049 @FR-012 @SC-006 @P1 @isolation @acceptance
  Scenario: A client addressing the machine's network address is refused
    Given the service is running
    When a client connects to the host's non-loopback address with valid credentials
    Then the connection is refused
    And the published port exists only on "127.0.0.1"

  @TS-050 @FR-013 @P1 @isolation @acceptance
  Scenario: A local client with valid credentials starts an audit
    Given a local client with a valid client certificate
    When it starts an audit
    Then the audit runs normally
    And the worker, started with its own certificate, executes it

  @TS-051 @FR-013 @SC-006 @P2 @isolation @acceptance
  Scenario: An expired or rotated credential is refused as unauthenticated
    Given a client certificate that has expired and one issued before a rotation
    When each connects
    Then both connections are refused

  @TS-052 @FR-013 @SC-006 @P1 @validation
  Scenario Outline: A mutual TLS handshake accepts only a valid client certificate
    Given a TLS server that requires a client certificate signed by the local CA
    When a client connects <presenting>
    Then the handshake <result>

    Examples:
      | presenting                                  | result       |
      | with a valid client certificate             | succeeds     |
      | without a client certificate                | is refused   |
      | with an expired client certificate          | is refused   |
      | with a certificate from before a rotation   | is refused   |
      | with a certificate from another CA          | is refused   |

  @TS-053 @FR-012 @FR-013 @SC-006 @P1 @validation
  Scenario Outline: The connection helper refuses unsafe configuration
    Given the connection settings <settings>
    When the connection is resolved
    Then it fails with code "<code>"
    And the error message reads "<message>"

    Examples:
      | settings                                        | code              | message                                                                 |
      | a missing client certificate file               | no-credentials    | client certificate or key file missing or unreadable                    |
      | a key file with mode 0644                       | insecure-key-file | key file mode is wider than 0600 or not owned by the current user       |
      | the address "10.0.0.5:7233" without the remote flag | non-loopback  | non-loopback address requires TESSERA_TEMPORAL_REMOTE=1                 |
      | the address "not an address"                    | invalid-address   | address is not a valid host:port                                        |

  @TS-054 @FR-012 @FR-013 @P1 @validation
  Scenario: A non-loopback address is allowed only explicitly and still needs certificates
    Given the address "10.0.0.5:7233", the remote flag set to "1" and valid certificates
    When the connection is resolved
    Then it resolves with mutual TLS settings
    And resolving without certificates still fails with "no-credentials"

  @TS-055 @FR-013 @P1 @validation
  Scenario: There is no plaintext mode and no way to skip the client certificate
    Given every connection setting the framework offers
    When they are inspected
    Then none selects plaintext
    And none omits the client certificate
    And a worker without certificates exits non-zero and a client without certificates prints the code

  @TS-056 @FR-012 @FR-013 @P1 @validation
  Scenario Outline: The local server refuses to start with unsafe exposure
    Given the server is configured with bind address "<bind>" and expose "<expose>"
    When it starts
    Then <result>

    Examples:
      | bind      | expose    | result                                                              |
      | 0.0.0.0   | none      | it exits with code 2 naming the exposure rule                       |
      | 127.0.0.1 | none      | it starts publishing only the frontend on 127.0.0.1                 |
      | 10.0.0.5  | 10.0.0.5  | it starts and client certificates are still required                |

  @TS-057 @FR-013 @P1 @validation
  Scenario: The local server refuses to start without certificates
    Given the PKI directory does not exist
    When the local server is started
    Then it exits with code 2 naming the missing PKI

  @TS-058 @FR-012 @P1 @validation
  Scenario: The server image must be pinned by digest
    Given the server image "temporalio/server:1.32.0" without a digest
    When the local server is started
    Then it exits with code 2 naming the pinning rule

  @TS-059 @FR-012 @FR-013 @P1 @contract
  Scenario: The generated server configuration requires client certificates and exposes only the frontend
    Given the generated server configuration
    When it is inspected
    Then frontend TLS has requireClientAuth true and the local CA as client CA
    And pprof is disabled and metrics and the HTTP API are not published
    And only one port mapping of the form "bind:port:7233" exists

  @TS-060 @FR-013 @P1 @contract
  Scenario: The local certificate authority issues correct certificates
    Given a freshly generated PKI
    When the certificates are parsed
    Then the CA has CA true and key usage keyCertSign with a 365 day validity
    And the server certificate has the names "localhost", "127.0.0.1" and "::1", usage serverAuth and a 90 day validity
    And the worker and client certificates have usage clientAuth and a 90 day validity
    And every certificate chains to the CA

  @TS-061 @FR-013 @P1 @validation
  Scenario Outline: PKI files are written safely
    Given the PKI directory is <directory>
    When the PKI is generated
    Then <result>

    Examples:
      | directory                               | result                                                |
      | a new directory in the home area        | the directory has mode 0700 and every file mode 0600  |
      | inside the repository                   | generation is refused                                 |
      | inside the evidence root                | generation is refused                                 |
      | a link                                  | generation is refused                                 |

  @TS-062 @FR-012 @SC-006 @P1 @validation
  Scenario: No committed configuration binds the orchestration service beyond loopback
    Given the repository
    When scanned for orchestration exposure
    Then no committed configuration publishes the orchestration port on a non-loopback address
    And no unauthenticated orchestration container definition exists
    And the previous compose file and worker Dockerfile are removed
