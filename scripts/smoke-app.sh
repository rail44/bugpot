#!/bin/sh
# Step 2 smoke test: launch bugpot with a single 12-factor app spec, verify
# the image is pulled, the container starts inside a per-app netns, the
# router proxies HTTP to the container, then tear everything down.
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-app.sh

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

APP_NAME=hello
DOMAIN="${APP_NAME}.bugpot.ts.net"
LISTEN=127.0.0.1:8080
IMAGE="gcr.io/google-samples/hello-app:1.0"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (try: sudo $0)" >&2
    exit 1
fi

BIN="$WORKDIR/target/debug/bugpot"
if [ ! -x "$BIN" ]; then
    echo "binary not built. run: cargo build -p bugpot" >&2
    exit 1
fi

APPS_DIR=$(mktemp -d)
STATE_DIR=$(mktemp -d)
LOG=$(mktemp)
RESP=$(mktemp)

PID=""
cleanup() {
    rc=$?
    set +e
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -INT "$PID"
        # bugpot has no shutdown reconcile yet, so wait briefly only
        for _ in $(seq 1 20); do
            kill -0 "$PID" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$PID" 2>/dev/null
        wait "$PID" 2>/dev/null
    fi
    # Best-effort container / netns cleanup. The agent's netns naming is
    # observed at runtime; we delete anything that looks ours.
    ip -all netns list 2>/dev/null | awk '{print $1}' | while read -r ns; do
        case "$ns" in
            bugpot-*) ip netns del "$ns" 2>/dev/null ;;
        esac
    done
    nft delete table inet bugpot 2>/dev/null
    ip link delete bugpot0 2>/dev/null
    rm -rf "$APPS_DIR" "$STATE_DIR"
    echo
    echo "(script exit=$rc; bugpot log=$LOG resp=$RESP kept for inspection)"
    return $rc
}
trap cleanup EXIT INT TERM

cat >"$APPS_DIR/$APP_NAME.toml" <<EOF
image = "$IMAGE"
port = 8080
EOF

echo "=== preflight ==="
echo "bin       : $BIN"
echo "apps_dir  : $APPS_DIR"
echo "state_dir : $STATE_DIR"
echo "image     : $IMAGE"
echo "log       : $LOG"
echo

echo "=== launching bugpot (image pull may take 30s) ==="
BUGPOT_APPS_DIR="$APPS_DIR" \
BUGPOT_STATE_DIR="$STATE_DIR" \
BUGPOT_LISTEN="$LISTEN" \
RUST_LOG="bugpot=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
    "$BIN" >"$LOG" 2>&1 &
PID=$!
echo "pid=$PID"

# Wait for "bugpot up" (or early failure).
ok=0
for _ in $(seq 1 240); do
    if grep -q "bugpot up" "$LOG" 2>/dev/null; then
        ok=1
        break
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

echo
echo "=== startup log ==="
cat "$LOG"

if [ "$ok" -ne 1 ]; then
    echo "(bugpot did not reach 'bugpot up' state)"
    exit 1
fi

echo
echo "=== environment after bring-up ==="
ip -brief link show bugpot0 || true
ip -brief addr show bugpot0 || true
echo "  netns:"
ip -all netns list | head -10 || true
echo "  veth-ish links:"
ip -brief link show | awk '/veth|bugpot/' | head -10 || true

echo
echo "=== HTTP smoke test ==="
status=$(curl -sS -o "$RESP" -w "%{http_code}" -m 10 -H "Host: $DOMAIN" "http://$LISTEN/" || echo "curl-failed")
echo "HTTP status : $status"
echo "Body:"
sed 's/^/    /' "$RESP" | head -20

echo
echo "=== allow set after request ==="
nft list set inet bugpot allow4 2>/dev/null | head -10 || true

echo
echo "=== shutting down ==="
kill -INT "$PID"
wait "$PID" 2>/dev/null || true
echo
echo "=== tail of log ==="
tail -20 "$LOG"

# Result assertions (after the success-or-skip path).
if [ "$status" != "200" ]; then
    echo
    echo "FAIL: expected HTTP 200, got $status"
    exit 1
fi
if ! grep -q "Hello" "$RESP"; then
    echo
    echo "FAIL: response did not contain 'Hello'"
    exit 1
fi
echo
echo "OK"
