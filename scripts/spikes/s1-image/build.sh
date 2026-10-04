#!/usr/bin/env bash
# Spike S1 scratch build. Assembles a minimal build context (never the repository root) and builds
# the scanner image with rootless podman. Prints the image ID on the last line. Not production code.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
ctx="$(mktemp -d "${TMPDIR:-/tmp}/tessera-spike-s1-ctx.XXXXXX")"
trap 'rm -rf "$ctx"' EXIT
cp "$here/Containerfile" "$here/advisory-proxy.js" "$here/write-manifest.js" "$ctx/"
cp "$repo/config/scanners/gitleaks.toml" "$ctx/"
podman build \
  --pull=missing \
  --iidfile "$ctx/iid" \
  --build-arg BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg FRAMEWORK_REVISION="$(git -C "$repo" rev-parse HEAD)" \
  -t localhost/tessera-spike-s1-scanner:latest \
  -f "$ctx/Containerfile" "$ctx" >&2
cat "$ctx/iid"
echo
