#!/bin/sh
# Multi-app smoke test: deploy two apps that point at the same upstream
# image but get different subdomains/container IPs, and verify that the
# router dispatches by Host header to the correct container.
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-multi.sh

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

LISTEN=127.0.0.1:8080
IMAGE_REPO="gcr.io/google-samples/hello-app"
IMAGE_TAG="1.0"

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
        for _ in $(seq 1 20); do
            kill -0 "$PID" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$PID" 2>/dev/null
        wait "$PID" 2>/dev/null
    fi
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

for name in alpha beta; do
    cat >"$APPS_DIR/$name.toml" <<EOF
repo = "$IMAGE_REPO"
port = 8080
[rollout]
tag = "$IMAGE_TAG"
created_at = "1970-01-01T00:00:00Z"
EOF
done

echo "=== preflight ==="
echo "apps_dir  : $APPS_DIR"
ls -1 "$APPS_DIR"
echo

echo "=== launching bugpot ==="
BUGPOT_APPS_DIR="$APPS_DIR" \
BUGPOT_STATE_DIR="$STATE_DIR" \
BUGPOT_LISTEN="$LISTEN" \
RUST_LOG="bugpot=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
    "$BIN" >"$LOG" 2>&1 &
PID=$!
echo "pid=$PID"

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

if [ "$ok" -ne 1 ]; then
    echo "=== startup log (bugpot did not reach 'up') ==="
    cat "$LOG"
    exit 1
fi

echo
echo "=== environment after bring-up ==="
ip -brief addr show bugpot0
ip -all netns list | head -10
nft list set inet bugpot allow4 2>/dev/null | head -5

# Helper: fetch and check.
fetch_and_assert() {
    domain=$1
    expected_hostname=$2
    echo
    echo "=== fetch http://$LISTEN/ Host=$domain ==="
    status=$(curl -sS -o "$RESP" -w "%{http_code}" -m 10 -H "Host: $domain" "http://$LISTEN/" || echo "curl-failed")
    echo "HTTP $status"
    cat "$RESP"
    if [ "$status" != "200" ]; then
        echo "FAIL: expected 200 for $domain, got $status"
        exit 1
    fi
    if ! grep -q "Hostname: $expected_hostname" "$RESP"; then
        echo "FAIL: response for $domain did not contain 'Hostname: $expected_hostname'"
        exit 1
    fi
}

fetch_and_assert "alpha.bugpot.example" "alpha"
fetch_and_assert "beta.bugpot.example"  "beta"

# Round-trip a few more times to confirm each subdomain is sticky.
echo
echo "=== sanity: 3x alpha + 3x beta ==="
for _ in 1 2 3; do
    fetch_and_assert "alpha.bugpot.example" "alpha"
done
for _ in 1 2 3; do
    fetch_and_assert "beta.bugpot.example" "beta"
done

echo
echo "=== shutdown ==="
kill -INT "$PID"
wait "$PID" 2>/dev/null || true
echo
echo "=== tail of log ==="
tail -25 "$LOG"

echo
echo "OK: 2-app routing verified."
