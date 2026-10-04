# Spike S2: mTLS on a rootless Temporal server (scratch, not production code)

Task T001 of `specs/005-isolated-execution/tasks.md`; results in the R12 addendum of `research.md`.
Nothing here is imported by `src/` or `tests/`; `tsc`, `eslint` and vitest do not include this directory.

## Files

| File | Role |
|------|------|
| `pki.mts` | ECDSA P-256 certificate generator with Node `crypto` only (hand-written DER for the CA, server and client profiles of `contracts/temporal-access.ts`); writes `ca`, `server`, `worker`, `client`, `system-worker`, `client-expired` (valid 10 to 9 days ago) and `client-rogue` (signed by a second CA) into a 0700 directory, keys 0600, and self-checks with `X509Certificate` |
| `config.template.yaml` | server config: in-memory SQLite, frontend mTLS (`requireClientAuth`, client CA = local CA), `global.tls.systemWorker`, pprof off, no metrics; `__FRONTEND_BIND__` is replaced by `run.sh` |
| `workflows.ts` | one workflow that calls one activity |
| `connect.mts` | `@temporalio/client` and `@temporalio/worker` probes: refusals (plaintext, no client cert, expired, other CA) and a full worker plus client round trip |
| `run.sh` | end-to-end reproduction of every exit criterion; removes its container on exit |

## Prerequisites

Rootless podman 5 (pasta networking), the `temporal` CLI (1.9.1 measured), Node 22 (runs `.mts` with built-in type stripping), `npm ci` done in the repo. No openssl.

```sh
podman pull docker.io/temporalio/server:1.32.0
# measured digest: sha256:ca47d4de249b9cc28137628dba77ae5e75e8b313ebb5c801c64615c1c99cbb09
```

Ports 7233 and 8233 must be free (`ss -ltn`); the script refuses to start otherwise.

## Run

```sh
bash scripts/spikes/s2-mtls/run.sh <work-dir-outside-the-repo> <host-lan-ip>
# example: bash scripts/spikes/s2-mtls/run.sh "$XDG_RUNTIME_DIR/s2" 192.168.1.132
```

Without the second argument the LAN address is taken from the default route (`ip route get 1.1.1.1`), which is the VPN address when a VPN is up. `S2_KEEP_LOG=<file>` saves the server log. Expected last line: `RESULT: all checks passed`.

What it does, in order:

1. `node --no-warnings pki.mts <work>/pki`
2. render `config.yaml` with `bindOnIP: "0.0.0.0"` for the frontend (all other services `bindOnLocalHost: true`)
3. `podman run -d --name tessera-spike-s2-server --userns=keep-id -p 127.0.0.1:7233:7233 -v <cfg>:/etc/temporal/config:ro,Z -v <pki>:/etc/temporal/pki:ro,Z -e TEMPORAL_SERVER_CONFIG_FILE_PATH=/etc/temporal/config/config.yaml -e TEMPORAL_ALLOW_NO_AUTH=true docker.io/temporalio/server:1.32.0`
4. wait for `temporal operator cluster health`, then register namespace `default` (in-memory SQLite starts with `temporal-system` only)
5. CLI checks, `podman port`, LAN and `[::1]` probes, `connect.mts`, a delete-namespace system workflow, in-container listener list
6. `podman rm -f` on exit

## Manual CLI use against the spike server

```sh
temporal operator namespace list --address 127.0.0.1:7233 \
  --tls-ca-path <work>/pki/ca.pem --tls-cert-path <work>/pki/client.pem --tls-key-path <work>/pki/client-key.pem
```

## Cleanup check

```sh
podman ps -a --filter name=tessera-spike-s2-   # empty
podman volume ls                               # no new volume (the spike uses bind mounts only)
```
