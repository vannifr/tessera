#!/usr/bin/env bash
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
WORK="${1:?usage: run.sh <work-dir outside the repo> [lan-ip]}"
LAN_IP="${2:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')}"
IMAGE="${S2_IMAGE:-docker.io/temporalio/server:1.32.0}"
NAME="tessera-spike-s2-server"
PKI="$WORK/pki"
CFG="$WORK/cfg"
FAIL=0

cleanup() { podman rm -f -t 2 "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

check() {
  local label="$1" expect="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if { [ "$expect" = ok ] && [ $rc -eq 0 ]; } || { [ "$expect" = refused ] && [ $rc -ne 0 ]; }; then
    echo "PASS $label (rc=$rc)"
  else
    echo "FAIL $label (rc=$rc)"; FAIL=1
  fi
  printf '%s\n' "$out" | grep -E 'Error:|NamespaceInfo.Name|registered' | head -3 | sed 's/^/     /'
}

for p in 7233 8233; do
  if ss -ltn | awk '{print $4}' | grep -qE "[:.]$p\$"; then echo "port $p already in use; stop that listener first"; exit 2; fi
done

rm -rf "$PKI" "$CFG"; mkdir -p "$CFG"
node --no-warnings "$HERE/pki.mts" "$PKI" || exit 1
sed 's/__FRONTEND_BIND__/bindOnIP: "0.0.0.0"/' "$HERE/config.template.yaml" > "$CFG/config.yaml"

podman run -d --name "$NAME" --userns=keep-id \
  -p 127.0.0.1:7233:7233 \
  -v "$CFG:/etc/temporal/config:ro,Z" -v "$PKI:/etc/temporal/pki:ro,Z" \
  -e TEMPORAL_SERVER_CONFIG_FILE_PATH=/etc/temporal/config/config.yaml \
  -e TEMPORAL_ALLOW_NO_AUTH=true \
  "$IMAGE" >/dev/null || exit 1
[ -n "${S2_KEEP_LOG:-}" ] && (sleep 20; podman logs "$NAME" > "$S2_KEEP_LOG" 2>&1) &

T=(--address 127.0.0.1:7233 --tls-ca-path "$PKI/ca.pem")
C=(--tls-cert-path "$PKI/client.pem" --tls-key-path "$PKI/client-key.pem")
for _ in $(seq 1 30); do
  temporal operator cluster health "${T[@]}" "${C[@]}" >/dev/null 2>&1 && break
  sleep 1
done
temporal operator namespace create --namespace default "${T[@]}" "${C[@]}" >/dev/null 2>&1
sleep 2

echo "== exit criteria"
check "CLI plaintext refused" refused temporal operator namespace list --address 127.0.0.1:7233
check "CLI TLS without client certificate refused" refused temporal operator namespace list "${T[@]}"
check "CLI with client certificate: namespace list" ok temporal operator namespace list "${T[@]}" "${C[@]}"
check "CLI expired client certificate refused" refused temporal operator namespace list "${T[@]}" --tls-cert-path "$PKI/client-expired.pem" --tls-key-path "$PKI/client-expired-key.pem"
check "CLI certificate from another CA refused" refused temporal operator namespace list "${T[@]}" --tls-cert-path "$PKI/client-rogue.pem" --tls-key-path "$PKI/client-rogue-key.pem"
check "CLI via LAN address $LAN_IP refused" refused temporal operator namespace list --address "$LAN_IP:7233" --tls-ca-path "$PKI/ca.pem" --tls-server-name localhost "${C[@]}"
check "CLI via [::1]:7233 refused" refused temporal operator namespace list --address "[::1]:7233" --tls-ca-path "$PKI/ca.pem" --tls-server-name localhost "${C[@]}"

echo "== podman port"
ports="$(podman port "$NAME")"; echo "     $ports"
if [ "$ports" = "7233/tcp -> 127.0.0.1:7233" ]; then echo "PASS only 127.0.0.1:7233 published"; else echo "FAIL unexpected publish"; FAIL=1; fi

echo "== TS client and worker"
(cd "$REPO" && node --no-warnings "$HERE/connect.mts" "$PKI" 2>&1 | grep -E '^(PASS|FAIL)') || FAIL=1

echo "== system worker (delete-namespace system workflow)"
temporal operator namespace create --namespace s2-tmp "${T[@]}" "${C[@]}" >/dev/null 2>&1; sleep 2
temporal operator namespace delete --namespace s2-tmp --yes "${T[@]}" "${C[@]}" >/dev/null 2>&1; sleep 8
if temporal workflow list --namespace temporal-system "${T[@]}" "${C[@]}" 2>&1 | grep -q 'Completed.*temporal-sys-delete-namespace-workflow/s2-tmp'; then
  echo "PASS system worker ran delete-namespace workflow over mTLS"; else echo "FAIL system worker"; FAIL=1; fi

echo "== listeners inside the container (hex port)"
podman exec "$NAME" sh -c 'cat /proc/net/tcp /proc/net/tcp6 | awk "\$4==\"0A\"{print \"     \" \$2}"'

[ $FAIL -eq 0 ] && echo "RESULT: all checks passed" || echo "RESULT: failures"
exit $FAIL
