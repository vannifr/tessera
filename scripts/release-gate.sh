#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
TESSERA_GATE_STRICT=1 npm run test:isolation
npm run demo
npm run dogfood
