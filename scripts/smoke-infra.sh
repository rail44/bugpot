#!/bin/sh
# Step 1 smoke test: bring up bugpot with no apps and verify the
# infrastructure layer (bridge, nft, DNS listener, HTTP router) is healthy.
#
# Usage:
#   sudo bash scripts/smoke-infra.sh
#
# This script:
#   1. Points bugpot at an empty apps directory (so no image pulls / no
#      container starts happen).
#   2. Launches bugpot in the background.
#   3. Probes bridge / nftables / port bindings.
#   4. Sends SIGINT to bugpot and waits for clean exit.
#   5. Tears down bugpot0 + the nft table so the host is left as it was.

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (try: sudo bash scripts/smoke-infra.sh)" >&2
    exit 1
fi

BIN="$WORKDIR/target/debug/bugpotd"
if [ ! -x "$BIN" ]; then
    echo "binary not built. run: cargo build -p bugpotd" >&2
    exit 1
fi

EMPTY_APPS=$(mktemp -d)
LOGFILE=$(mktemp)
cleanup() {
    rc=$?
    # Stop bugpot if still running.
    if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
        kill -INT "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    # Tear down the infrastructure so the host returns to its previous state.
    nft delete table inet bugpot 2>/dev/null || true
    ip link delete bugpot0 2>/dev/null || true
    rm -rf "$EMPTY_APPS"
    echo
    echo "(script exit=$rc; log=$LOGFILE)"
}
trap cleanup EXIT INT TERM

echo "=== preflight ==="
echo "bugpot binary : $BIN"
echo "empty apps    : $EMPTY_APPS"
echo "log           : $LOGFILE"
echo

echo "=== launching bugpot ==="
BUGPOT_APPS_DIR="$EMPTY_APPS" \
RUST_LOG="bugpot=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
    "$BIN" >"$LOGFILE" 2>&1 &
PID=$!
echo "pid=$PID"

# Wait until "bugpot up" is logged, or fail after a timeout.
ok=0
for _ in $(seq 1 40); do
    if grep -q "bugpot up" "$LOGFILE" 2>/dev/null; then
        ok=1
        break
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        break
    fi
    sleep 0.25
done

echo
echo "=== startup log ==="
cat "$LOGFILE"

if [ "$ok" -ne 1 ]; then
    echo "(bugpot did not reach 'bugpot up' state)"
    exit 1
fi

echo
echo "=== bridge ==="
ip -brief link show bugpot0 || true
ip -brief addr show bugpot0 || true

echo
echo "=== nft ruleset (inet bugpot) ==="
nft list table inet bugpot || true

echo
echo "=== listeners (DNS on 172.20.0.1, router on 127.0.0.1:8080) ==="
ss -tulnp "src = 172.20.0.1" || true
ss -tlnp "( sport = :8080 )" || true

echo
echo "=== shutting down ==="
kill -INT "$PID"
wait "$PID" 2>/dev/null || true
echo "bugpot exited"

echo
echo "=== tail of log ==="
tail -10 "$LOGFILE"
