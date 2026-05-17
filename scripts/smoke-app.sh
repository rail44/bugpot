#!/bin/sh
# Step 2 smoke test: launch bugpot, register a single 12-factor app via
# the admin API, verify the image is pulled, the container starts inside
# a per-app netns, the router proxies HTTP to the container, then tear
# everything down.
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-app.sh

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

APP_NAME=hello
DOMAIN="${APP_NAME}.bugpot.example"
LISTEN=127.0.0.1:8080
ADMIN_LISTEN=127.0.0.1:8081
ADMIN_TOKEN="smoke-only-do-not-deploy"
IMAGE_REPO="gcr.io/google-samples/hello-app"
IMAGE_TAG="1.0"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (try: sudo $0)" >&2
    exit 1
fi

BIN="$WORKDIR/target/debug/bugpotd"
if [ ! -x "$BIN" ]; then
    echo "binary not built. run: cargo build -p bugpotd" >&2
    exit 1
fi

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
    rm -rf "$STATE_DIR"
    echo
    echo "(script exit=$rc; bugpot log=$LOG resp=$RESP kept for inspection)"
    return $rc
}
trap cleanup EXIT INT TERM

# Register an app by posting its TOML body. Mirrors what an ops repo's
# apply.yml workflow does: spec mutations are admin-token-authenticated.
register_app() {
    body=$1
    curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/toml" \
        --data-binary "$body" \
        "http://$ADMIN_LISTEN/apps" >/dev/null
}

# Mint a per-app deploy key (admin-scoped one-shot), then use it to push
# a rollout. The two-step is the production shape — rollouts use a
# narrower token than spec management. The mint endpoint returns a JSON
# `{"token": "bp1.<hex>"}` body.
push_rollout() {
    name=$1
    tag=$2
    deploy_token=$(curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$ADMIN_LISTEN/apps/$name/deploy-keys" \
        | sed 's/.*"token":[ ]*"\([^"]*\)".*/\1/')
    curl -fsS -X POST \
        -H "Authorization: Bearer $deploy_token" \
        -H "Content-Type: application/json" \
        -d "{\"tag\":\"$tag\"}" \
        "http://$ADMIN_LISTEN/apps/$name/rollouts" >/dev/null
}

echo "=== preflight ==="
echo "bin       : $BIN"
echo "state_dir : $STATE_DIR"
echo "image     : $IMAGE_REPO:$IMAGE_TAG"
echo "log       : $LOG"
echo

echo "=== launching bugpot ==="
BUGPOT_STATE_DIR="$STATE_DIR" \
BUGPOT_LISTEN="$LISTEN" \
BUGPOT_ADMIN_LISTEN="$ADMIN_LISTEN" \
BUGPOT_ADMIN_TOKEN="$ADMIN_TOKEN" \
BUGPOT_DEPLOY_SECRET="smoke-only-deploy-secret" \
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

echo
echo "=== startup log ==="
cat "$LOG"

if [ "$ok" -ne 1 ]; then
    echo "(bugpot did not reach 'bugpot up' state)"
    exit 1
fi

echo
echo "=== registering app + rollout via admin API ==="
register_app "$(cat <<EOF
name = "$APP_NAME"
repo = "$IMAGE_REPO"
port = 8080
EOF
)"
push_rollout "$APP_NAME" "$IMAGE_TAG"
echo "registered + rolled out (image pull may take ~30s on the request below)"

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
status=$(curl -sS -o "$RESP" -w "%{http_code}" -m 60 -H "Host: $DOMAIN" "http://$LISTEN/" || echo "curl-failed")
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
