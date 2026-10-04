# Contract: scanner image (FR-002, FR-019, FR-020)

Source: `config/isolation/Containerfile`. Build: `npm run isolation:build` (`src/cli/isolation-build.ts`, runs the runtime's `build` through `defaultProcessRunner` with an argument array). Research: R6, R7.

## Inputs (all pinned)

| Input | Pin |
|-------|-----|
| Base | `semgrep/semgrep:1.178.0@sha256:<digest>` (digest fixed in spike S1) |
| Node.js, npm, git, catatonit | distribution packages at fixed versions; npm forced to 10.9.8 |
| gitleaks | release 8.30.1 `linux_x64` tarball, sha256 checked in the build before extraction |
| semgrep packs | `p/javascript`, `p/nodejs` downloaded at build time; sha256 and fetch time recorded (not pinned in advance) |
| Framework files | `config/scanners/*`, `config/isolation/bin/*`, `config/isolation/npm/*` copied from the repository |

## Layout

| Path | Content | Mode |
|------|---------|------|
| `/usr/bin/git`, `/usr/bin/node`, `/usr/bin/npm`, `/usr/local/bin/semgrep`, `/usr/local/bin/gitleaks` | tools (entrypoints table in `isolation-runner.ts`) | 0755 root |
| `/opt/tessera/config/` | scanner configs, `npm/userconfig`, `npm/globalconfig` (empty) | 0444 root |
| `/opt/tessera/rules/<pack>.yaml` | semgrep packs | 0444 root |
| `/opt/tessera/bin/advisory-proxy.js`, `bounded-fetch.js`, `selftest.js` | helpers, Node built-ins only | 0444 root |
| `/opt/tessera/manifest.json` | see below | 0444 root |

No `ENTRYPOINT`, no `CMD` used (the runner always sets `--entrypoint`). No `USER` reliance (the runner sets the user). No setuid or setgid files under `/opt/tessera` (checked by `selftest.js`).

## `manifest.json`

```json
{
  "schema": "tessera.scanner-image/v1",
  "builtAt": "2026-10-05T10:00:00Z",
  "frameworkRevision": "<git sha of the repository at build>",
  "base": { "ref": "semgrep/semgrep:1.178.0", "digest": "sha256:…" },
  "tools": { "git": "2.x", "node": "22.x", "npm": "10.9.8", "semgrep": "1.178.0", "gitleaks": "8.30.1" },
  "rules": [ { "name": "p/javascript", "path": "/opt/tessera/rules/p-javascript.yaml", "sha256": "…", "fetchedAt": "…" } ],
  "files": { "/opt/tessera/config/gitleaks.toml": "<sha256>", "/opt/tessera/bin/advisory-proxy.js": "<sha256>" }
}
```

## Pinning in use

- `TESSERA_ISOLATION_IMAGE=sha256:<64 hex>` (image ID) or `~/.config/tessera/isolation.json` `{ "imageId": "sha256:…", "builtAt": "…", "containerfileSha256": "…" }` (0600), written by `isolation:build`. A name or tag is refused.
- `checkIsolation` verifies: the image exists with that ID; `manifest.json` parses (`selftest.js` prints it from inside the scan profile; the host never mounts or extracts the image); every entry under `files` whose source exists in the repository has the same sha256 on the host; otherwise `isolation-unavailable` / `image-outdated`.
- Every `tool-run` record carries `isolation.image.id` and `isolation.image.manifestSha256`; the `environment.check` record carries the full manifest as an artifact.

## `selftest.js` (runs in the scan profile with an empty source)

Prints one JSON object: `uid`, `gid`, `capEff`, `noNewPrivs`, `seccomp`, `memoryMax`, `pidsMax`, `interfaces`, `writeSrc` (`EROFS` expected), `writeRoot` (`EROFS` expected), `tcpConnect` (`ENETUNREACH` or `EHOSTUNREACH` expected), `scratchBytes`, `mounts` (mount points only), `setuidUnderOptTessera` (0 expected), `manifest` (the parsed manifest). `checkIsolation` compares each value with the profile; mismatches become restriction states.

## `bounded-fetch.js` (fetch profile)

`node /opt/tessera/bin/bounded-fetch.js -- /usr/bin/git <clone args ending in /scratch/clone>`: runs git with the given arguments (array), on success copies `/scratch/clone` to `/src` keeping links as links and modes without setuid/setgid bits, then exits 0. `ENOSPC` during clone or copy → exit 5 and a single stderr line `tessera: source-too-large`. Nothing is written to `/src` before the clone completed.
