# Spike S1: scanner image (scratch, not production code)

Task T002 of `specs/005-isolated-execution/tasks.md`. Results are recorded as R3, R6 and R7 addenda in
`research.md` (by T002/T004); this directory only holds what is needed to reproduce the measurements.
The production versions are `config/isolation/Containerfile` and `config/isolation/bin/*` (T018).

| File | Purpose |
|------|---------|
| `Containerfile` | image draft: semgrep 1.178.0 base by digest, Alpine `nodejs` 24 and `git`, npm 10.9.8 and gitleaks 8.30.1 as sha256-checked tarballs, `p/javascript` and `p/nodejs` baked into `/opt/tessera/rules`, `manifest.json`, ends with `USER 65534:65534` |
| `build.sh` | assembles a minimal build context in `$TMPDIR` (never the repository root) and builds; prints the image ID |
| `write-manifest.js` | build-time manifest writer (tool versions, rule pack sha256 and fetch time, file hashes) |
| `advisory-proxy.js` | scratch record/replay proxy for `npm audit` (contract `advisory-data.ts`) |
| `fetch-advisories.js` | host step: posts the captured bulk request to the npm registry, writes snapshot and metadata |
| `profile.sh` | the scan profile of R3 as a bash function `s1_create` (corrected by S1, see below) |
| `run-checks.sh` | attach streaming, shared SELinux level with `:Z`, podman `--timeout`, memory hog and fork bomb with slice counters |

## Reproduce (bash, rootless podman with SELinux and cgroup v2)

`profile.sh` must be sourced from **bash** (zsh does not word-split `S1_ENV`).

```bash
export TMPDIR=<scratch dir>; OUT=$TMPDIR/s1/fixtures; W=$TMPDIR/s1/work/tessera-spike-s1-run
podman pull docker.io/semgrep/semgrep:1.178.0
IMG=$(scripts/spikes/s1-image/build.sh | tail -1)
mkdir -p $W/repo $W/npm-audit $OUT && chmod 700 $W
cp -r demo/vulnerable-app/. $W/repo/ && cp $W/repo/package{,-lock}.json $W/npm-audit/
bash -c "source scripts/spikes/s1-image/profile.sh
  s1_create tessera-spike-s1-gitleaks $IMG $W/repo s0:c101,c202 tessera-spike-s1-gitleaks.slice 330 2048 512 -- \
    /usr/local/bin/gitleaks dir --no-banner --redact=100 --exit-code 1 --report-format json --report-path - \
    --config /opt/tessera/config/gitleaks.toml --ignore-gitleaks-allow .
  s1_create tessera-spike-s1-semgrep $IMG $W/repo s0:c101,c202 tessera-spike-s1-semgrep.slice 210 2048 512 -- \
    /usr/bin/semgrep --metrics=off --config /opt/tessera/rules/p-javascript.yaml \
    --config /opt/tessera/rules/p-nodejs.yaml --disable-nosem --disable-version-check --json --quiet .
  export S1_ENV='NPM_CONFIG_USERCONFIG=/opt/tessera/config/npm/userconfig NPM_CONFIG_GLOBALCONFIG=/opt/tessera/config/npm/globalconfig NPM_CONFIG_UPDATE_NOTIFIER=false'
  s1_create tessera-spike-s1-npm-record $IMG $W/npm-audit s0:c101,c202 tessera-spike-s1-npm.slice 150 2048 512 -- \
    /usr/bin/node /opt/tessera/bin/advisory-proxy.js record -- /usr/bin/npm audit --json
  s1_create tessera-spike-s1-npm-replay $IMG $W/npm-audit s0:c101,c202 tessera-spike-s1-npm.slice 150 2048 512 --interactive -- \
    /usr/bin/node /opt/tessera/bin/advisory-proxy.js replay -- /usr/bin/npm audit --json"
podman start --attach tessera-spike-s1-gitleaks > $OUT/start-gitleaks.stdout
podman start --attach tessera-spike-s1-semgrep  > $OUT/start-semgrep.stdout
podman start --attach tessera-spike-s1-npm-record > $OUT/request.json
node scripts/spikes/s1-image/fetch-advisories.js $OUT/request.json $OUT/advisory-snapshot.json $OUT/advisory-fetch-meta.json
podman start --attach --interactive tessera-spike-s1-npm-replay < $OUT/advisory-snapshot.json > $OUT/start-npm-replay.stdout
jq -c '.metadata.vulnerabilities, (.vulnerabilities|keys)' $OUT/start-npm-replay.stdout
scripts/spikes/s1-image/run-checks.sh $IMG $W $OUT
```

Cleanup: `podman rm -f $(podman ps -a --filter name=tessera-spike-s1 -q)`, `systemctl --user stop tessera.slice`,
`rm -rf $W`. Keep or remove the image `localhost/tessera-spike-s1-scanner` as needed.

## Corrections S1 made to the R3 profile (reflected in `profile.sh`)

- podman also needs `--user <uid>:<gid>`: an image `USER` overrides the `--userns keep-id` default user.
- scratch tmpfs: `mode=0700,U` (podman); a root-owned `mode=1700` tmpfs is unusable for the container user.
- `HOME=TMPDIR=/scratch`: `/scratch/home` and `/scratch/tmp` do not exist on a fresh tmpfs (semgrep fails).
- `HOME`/`TMPDIR` passed by value: passing them by name sets podman's own `HOME` and breaks podman.
- slice paths are resolved with `systemctl --user show -p ControlGroup --value <slice>` (`-` means nesting).
