# Spike S1 scratch: the scan profile of research R3 as a bash function. Source this file. Not production code.
# s1_create <name> <imageId> <srcHostDir> <selinuxLevel|-> <cgroupParent> <timeoutS> <memMiB> <pids> [--interactive] -- <entrypoint> [args...]
# HOME and TMPDIR are passed by value: passing them by name would set podman's own HOME (measured: breaks podman).
# HOME=TMPDIR=/scratch: /scratch/home and /scratch/tmp do not exist on a fresh tmpfs (measured: semgrep fails).
# Extra non-secret env: S1_ENV="NAME=VALUE NAME2=VALUE2".
s1_create() {
  local name="$1" image="$2" src="$3" level="$4" slice="$5" timeout="$6" mem="$7" pids="$8"
  shift 8
  local interactive=()
  if [ "${1:-}" = "--interactive" ]; then interactive=(--interactive); shift; fi
  [ "$1" = "--" ] || { echo "s1_create: missing --" >&2; return 2; }
  shift
  local entry="$1"
  shift
  local label=()
  [ "$level" != "-" ] && label=(--security-opt "label=level:$level")
  local z=""
  local extra=()
  local kv
  for kv in ${S1_ENV:-}; do extra+=(--env "$kv"); done
  [ "$level" != "-" ] && z=",Z"
  podman create \
    --pull=never --read-only --read-only-tmpfs=false \
    --tmpfs /tmp:size=64m,noexec,nosuid,nodev \
    --tmpfs /scratch:size=512m,mode=0700,noexec,nosuid,nodev,U \
    --cap-drop all --security-opt no-new-privileges --init \
    --pids-limit "$pids" --memory "${mem}m" --memory-swap "${mem}m" --cpus 2 \
    --log-driver none --userns keep-id --user "$(id -u):$(id -g)" --hostname tessera --network none \
    "${label[@]}" --cgroup-parent "$slice" --timeout "$timeout" \
    --label tessera.run=tessera-spike-s1 --label "tessera.step=$name" \
    --env "HOME=${S1_HOME:-/scratch}" --env "TMPDIR=${S1_TMPDIR:-/scratch}" "${extra[@]}" \
    --name "$name" --workdir /src --entrypoint "$entry" \
    -v "$src:/src:ro$z" "${interactive[@]}" \
    "$image" "$@"
}
