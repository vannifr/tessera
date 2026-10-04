#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
OWNER="${TESSERA_GATE_OWNER:-vannifr}"
STRICT="${TESSERA_GATE_STRICT:-0}"
OUT="${TMPDIR:-/tmp}/tessera-isolation-$$.json"
trap 'rm -f "$OUT"' EXIT

if [ -z "$(find tests/isolation -name '*.test.ts' 2>/dev/null | head -n 1)" ]; then
  if [ "$STRICT" = "1" ]; then
    echo "release gate FAILED: the isolation suite is empty or skipped (no tests in tests/isolation); owner: $OWNER" >&2
    exit 1
  fi
  echo "no isolation tests yet (tests/isolation is empty); owner: $OWNER"
else
  npx vitest run --config vitest.isolation.config.ts --reporter=default --reporter=json --outputFile.json="$OUT"
  if [ "$STRICT" = "1" ]; then
    node -e '
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
const skipped = r.numPendingTests + (r.numTodoTests || 0);
if (r.numTotalTests === 0 || skipped > 0) {
  console.error("release gate FAILED: the isolation suite is empty or skipped (" + r.numTotalTests + " total, " + skipped + " skipped); owner: " + (process.env.TESSERA_GATE_OWNER || "vannifr"));
  process.exit(1);
}' "$OUT"
  fi
fi

if find specs/005-isolated-execution/tests/step_definitions -name '*.ts' 2>/dev/null | grep -q .; then
  npm run test:bdd:005:isolation
else
  echo "no isolation step definitions yet; @isolation scenarios not run"
  [ "$STRICT" = "1" ] && { echo "release gate FAILED: the isolation suite is empty or skipped (no @isolation step definitions)" >&2; exit 1; }
fi
exit 0
