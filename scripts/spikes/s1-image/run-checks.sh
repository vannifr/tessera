#!/usr/bin/env bash
# Spike S1 scratch: attach streaming, SELinux shared level, --timeout, memory hog and fork bomb with slice counters.
# Usage: run-checks.sh <imageId> <workDir with repo/> <outDir>. Not production code.
set -uo pipefail
export LC_ALL=C
IMG="$1"; W="$2"; OUT="$3"
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/profile.sh"
mkdir -p "$OUT"
now() { date +%s.%N; }
since() { echo "$(now) - $1" | bc; }
slicepath() { echo "/sys/fs/cgroup$(systemctl --user show -p ControlGroup --value "$1")"; }

echo "## attach streaming with --log-driver none"
s1_create tessera-spike-s1-stream "$IMG" "$W/repo" s0:c101,c202 tessera-spike-s1-stream.slice 60 2048 512 -- \
  /bin/sh -c 'for i in 1 2 3; do echo "out $i"; echo "err $i" >&2; sleep 1; done; exit 7' >/dev/null
t0=$(now)
: >"$OUT/start-stream.timeline"
podman start --attach tessera-spike-s1-stream 2>"$OUT/start-stream.stderr" | while IFS= read -r line; do
  printf '%s t=%.2f\n' "$line" "$(since "$t0")" >>"$OUT/start-stream.timeline"
done
s1_create tessera-spike-s1-stream2 "$IMG" "$W/repo" s0:c101,c202 tessera-spike-s1-stream.slice 60 2048 512 -- \
  /bin/sh -c 'echo out; echo err >&2; head -c 104857600 /dev/zero | tr "\0" "a"; exit 7' >/dev/null
podman start --attach tessera-spike-s1-stream2 >"$OUT/stream2.stdout" 2>"$OUT/start-stream2.stderr"; rc=$?
{
  echo "timeline (stdout lines as they arrived):"; cat "$OUT/start-stream.timeline"
  echo "stderr of first:"; cat "$OUT/start-stream.stderr"
  echo "second: rc=$rc stdout_bytes=$(wc -c <"$OUT/stream2.stdout") stderr=$(cat "$OUT/start-stream2.stderr")"
  echo "inspect exit code: $(podman inspect tessera-spike-s1-stream2 --format '{{.State.ExitCode}}')"
  echo "podman logs: $(podman logs tessera-spike-s1-stream2 2>&1 | head -c 300)"
  echo "LogPath: $(podman inspect tessera-spike-s1-stream2 --format '{{.HostConfig.LogConfig.Type}} path={{.LogPath}}')"
} | tee "$OUT/attach-streaming.txt"
rm -f "$OUT/stream2.stdout"
podman rm -f tessera-spike-s1-stream tessera-spike-s1-stream2 >/dev/null

echo "## parallel containers, shared SELinux level, :Z"
for n in a b c d; do
  s1_create "tessera-spike-s1-par-$n" "$IMG" "$W/repo" s0:c101,c202 tessera-spike-s1-par.slice 60 2048 512 -- \
    /bin/sh -c 'ok=0; for i in $(seq 1 50); do cat /src/src/server.js >/dev/null && ok=$((ok+1)); sleep 0.05; done; echo "reads_ok=$ok/50 label=$(cat /proc/self/attr/current)"' >/dev/null
done
t0=$(now)
for n in a b c d; do podman start --attach "tessera-spike-s1-par-$n" >"$OUT/start-par-$n.stdout" 2>&1 & done
wait
{
  echo "4 parallel, level s0:c101,c202, :Z, wall=$(since "$t0")"
  for n in a b c d; do echo "$n: $(cat "$OUT/start-par-$n.stdout")"; done
  echo "host label of source: $(ls -dZ "$W/repo" | awk '{print $1}')"
} | tee "$OUT/selinux-parallel.txt"
podman rm -f tessera-spike-s1-par-a tessera-spike-s1-par-b tessera-spike-s1-par-c tessera-spike-s1-par-d >/dev/null
podman run --rm --name tessera-spike-s1-otherlevel --pull=never --read-only --userns keep-id --user "$(id -u):$(id -g)" \
  --network none --cap-drop all --security-opt no-new-privileges --security-opt label=level:s0:c303,c404 \
  -v "$W/repo:/src:ro" --entrypoint /bin/sh "$IMG" -c 'cat /src/src/server.js >/dev/null && echo read-ok || echo read-denied' \
  2>&1 | sed 's/^/other level, no relabel: /' | tee -a "$OUT/selinux-parallel.txt"

echo "## podman --timeout"
s1_create tessera-spike-s1-timeout "$IMG" "$W/repo" s0:c101,c202 tessera-spike-s1-timeout.slice 5 2048 512 -- /bin/sleep 120 >/dev/null
t0=$(now)
podman start --attach tessera-spike-s1-timeout >"$OUT/start-timeout.stdout" 2>"$OUT/start-timeout.stderr"; rc=$?
{
  echo "--timeout 5, sleep 120: start rc=$rc wall=$(since "$t0")"
  echo "stderr: $(cat "$OUT/start-timeout.stderr")"
  podman inspect tessera-spike-s1-timeout --format 'state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}'
} | tee "$OUT/timeout.txt"
podman inspect tessera-spike-s1-timeout >"$OUT/inspect-timeout-exited.json"
podman rm -f tessera-spike-s1-timeout >/dev/null

echo "## memory hog"
s1_create tessera-spike-s1-memhog "$IMG" "$W/repo" s0:c101,c202 tessera-spike-s1-memhog.slice 60 512 512 -- \
  /usr/bin/node -e 'const a=[]; for(;;){a.push(Buffer.alloc(16*1024*1024,1));}' >/dev/null
podman start --attach tessera-spike-s1-memhog >"$OUT/start-memhog.stdout" 2>"$OUT/start-memhog.stderr"; rc=$?
p="$(slicepath tessera-spike-s1-memhog.slice)"
cp "$p/memory.events" "$OUT/memhog.memory.events"; cp "$p/pids.events" "$OUT/memhog.pids.events"
{
  echo "memory 512m node allocation loop: start rc=$rc"
  echo "slice: $p"
  echo "memory.events:"; cat "$OUT/memhog.memory.events"
  echo "pids.events:"; cat "$OUT/memhog.pids.events"
  podman inspect tessera-spike-s1-memhog --format 'inspect: exit={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}'
  echo "stderr tail: $(tail -c 300 "$OUT/start-memhog.stderr")"
} | tee "$OUT/memhog.txt"
podman inspect tessera-spike-s1-memhog >"$OUT/inspect-memhog-exited.json"
podman rm -f tessera-spike-s1-memhog >/dev/null

echo "## fork bomb"
s1_create tessera-spike-s1-forkbomb "$IMG" "$W/repo" s0:c101,c202 tessera-spike-s1-forkbomb.slice 60 2048 64 -- \
  /bin/sh -c 'i=0; while [ $i -lt 200 ]; do sleep 30 & i=$((i+1)); done 2>/dev/null; echo "spawned loop done"; exit 0' >/dev/null
t0=$(now)
podman start --attach tessera-spike-s1-forkbomb >"$OUT/start-forkbomb.stdout" 2>"$OUT/start-forkbomb.stderr"; rc=$?
p="$(slicepath tessera-spike-s1-forkbomb.slice)"
cp "$p/memory.events" "$OUT/forkbomb.memory.events"; cp "$p/pids.events" "$OUT/forkbomb.pids.events"
{
  echo "pids 64, 200 background sleeps: start rc=$rc wall=$(since "$t0")"
  echo "stdout: $(cat "$OUT/start-forkbomb.stdout") stderr: $(head -c 200 "$OUT/start-forkbomb.stderr")"
  echo "pids.events:"; cat "$OUT/forkbomb.pids.events"
  echo "memory.events:"; cat "$OUT/forkbomb.memory.events"
  podman inspect tessera-spike-s1-forkbomb --format 'inspect: exit={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}'
} | tee "$OUT/forkbomb.txt"
podman rm -f tessera-spike-s1-forkbomb >/dev/null

echo "## slices present before stop"
systemctl --user list-units --all --no-legend 'tessera-spike-s1*' | tee "$OUT/slices-before-stop.txt"
