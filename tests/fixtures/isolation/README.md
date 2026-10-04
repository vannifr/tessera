# Isolation fixtures (spikes S1 and S3)

Raw outputs recorded on one Linux host (Fedora 44, kernel 7.2.4, cgroup v2, SELinux enforcing) during spike S1
(rootless podman 5.8.7, task T002) and spike S3 (docker 29.8.2, rootful daemon reached through the `docker` group,
task T003). They are the input for the pure observation and level tests (T011, T012) and must not be edited to turn a
test green; re-record instead. Scanner image: the S1 image (semgrep 1.178.0 base, gitleaks 8.30.1, npm 10.9.8, Node 24).
Source scanned: `demo/vulnerable-app`.

All files are sanitized: the original home directory is `/home/user`, the user name is `user`, the host name is `host`
(this also turns the Fedora edition word into `host`), the scratch directory is `/work/scratch`, container ids are the
fixed fake ids `c0ffee01...` to `c0ffee11...` (full, 12 and 8 character forms), the docker network id is all zeros and
the uptime is fixed. Image ids, layer hashes and content hashes are not host-specific and are kept. No MAC addresses,
host IP addresses, machine ids or boot ids were present in the recorded output.

## podman/ (rootless podman, S1)

| File | Source | Proves |
|------|--------|--------|
| `podman-version.json`, `podman-info.json` | `podman version`/`podman info --format json` | rootless, cgroup v2, SELinux, security capabilities, version for the runtime probe |
| `inspect-scan-created.json`, `inspect-scan-exited.json` | `podman inspect` of the smoke container (scan profile) before and after the run | restriction fields (ReadonlyRootfs, CapDrop, SecurityOpt, PidsLimit, Memory, NetworkMode none, User, Tmpfs, Mounts ro, LogDriver none) |
| `inspect-tessera-spike-s1-{gitleaks,semgrep,npm-replay}.json` | `podman inspect` of the real scan steps | same fields for the three scanner invocations |
| `inspect-memhog-exited.json`, `memhog.{txt,memory.events,pids.events}` | memory hog at 512 MiB | exit 137, `OOMKilled=false` in podman inspect, slice `memory.events` `oom_kill 1` is the only reliable signal |
| `forkbomb.{txt,memory.events,pids.events}` | fork bomb at pids 64 | exit 2, slice `pids.events` `max 1` |
| `inspect-timeout-exited.json`, `timeout.txt` | podman `--timeout 5` | exit code -1, attach rc 255, no OOM |
| `attach-streaming.txt` | attach streaming under `--log-driver none` | stdout streamed through `start --attach` |
| `start-gitleaks.*`, `start-semgrep.stdout`, `start-npm-replay*.std*` | stdout/stderr of the three scanners and the npm replay (also the empty-stdin failure) | scanner outputs under `--network none`: 1 gitleaks finding, 4 semgrep results, 9 npm packages |
| `advisory-fetch-meta.json`, `image-manifest-and-hashes.txt` | host advisory fetch, image manifest | snapshot metadata and image tool versions |

## docker/ (rootful docker fallback, S3)

| File | Source | Proves |
|------|--------|--------|
| `docker-version.json`, `docker-info.json` | `docker version`/`docker info` (subset) | daemon runs as root (no `rootless` in SecurityOptions, no userns), cgroup driver systemd, cgroup v2 |
| `inspect-{gitleaks,semgrep,npm-replay}-created.json`, `inspect-{gitleaks,semgrep,npm-replay}-exited.json` | `docker inspect` before and after each scan | the profile is observable in `HostConfig` (ReadonlyRootfs, CapDrop ALL, no-new-privileges, PidsLimit, Memory, MemorySwap, NanoCpus, NetworkMode none, LogConfig none, Init, Tmpfs, Binds `:ro`, `Config.User`) |
| `inspect-memhog-exited.json` | memory hog at 256 MiB | docker reports `OOMKilled=true`, exit 137 |
| `inspect-forkbomb-exited.json`, `start-forkbomb.stderr` | fork bomb at pids 64 | exit 2, `can't fork`, `OOMKilled=false` |
| `cgroup-sleep-readable.txt` | cgroup files of a running container read as the unprivileged user | counters and limits readable while the scope exists (`pids.max 64`, `memory.max`, `memory.events`) |
| `slice-after-memhog.txt`, `slice-after-forkbomb.txt` | parent slice counters after the container is gone | `oom_kill 1` and `pids.events max 1` survive on the parent slice |
| `start-*.stdout/stderr` | scanner outputs under docker | same results as podman (1 gitleaks, 4 semgrep, 9 npm packages) |
