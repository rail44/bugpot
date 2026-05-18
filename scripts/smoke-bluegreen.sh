#!/bin/sh
# Blue-green rollout smoke test: launch bugpot, register an app, push
# successive rollouts of `gcr.io/google-samples/hello-app` at different
# tags, and assert:
#
#   1. The initial rollout creates `<app>-a` on disk (slot A).
#   2. A second rollout starts `<app>-b` *before* tearing down `<app>-a`
#      (blue-green; verified by a high-rate curl loop that must see zero
#      failed requests across the switch).
#   3. The to-slot start precedes the from-slot stop (= the version body
#      changes from 1.0 to 2.0 in the loop log without a FAIL gap).
#   4. A third rollout alternates the slot back from B → A.
#   5. `PATCH /apps/<name>` (spec change, not rollout) rides the same
#      blue-green pipeline — no curl gap, slot flip.
#   6. A bad-tag rollout (image-pull failure) auto-rolls-back: 4xx/5xx
#      from the admin API, from-side still serves, slot does *not* flip.
#
# Sized to exercise the user-facing contract; matches the manual
# verification scenarios documented on PR #149.
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-bluegreen.sh

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

APP_NAME=bluegreen
DOMAIN="${APP_NAME}.bugpot.example"
LISTEN=127.0.0.1:8080
ADMIN_LISTEN=127.0.0.1:8081
ADMIN_TOKEN="smoke-only-do-not-deploy"
IMAGE_REPO="gcr.io/google-samples/hello-app"

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
CURL_LOG=$(mktemp)

PID=""
CURL_PID=""

fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }
ok()   { printf "ok:   %s\n" "$*"; }
note() { printf "\n=== %s ===\n" "$*"; }

cleanup() {
    rc=$?
    set +e
    if [ -n "$CURL_PID" ] && kill -0 "$CURL_PID" 2>/dev/null; then
        kill "$CURL_PID" 2>/dev/null
        wait "$CURL_PID" 2>/dev/null
    fi
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
    echo
    echo "(script exit=$rc; bugpot log=$LOG curl log=$CURL_LOG state=$STATE_DIR kept for inspection)"
    return $rc
}
trap cleanup EXIT INT TERM

register_app() {
    body=$1
    curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/toml" \
        --data-binary "$body" \
        "http://$ADMIN_LISTEN/apps" >/dev/null
}

mint_deploy_key() {
    name=$1
    curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$ADMIN_LISTEN/apps/$name/deploy-keys" \
        | sed 's/.*"token":[ ]*"\([^"]*\)".*/\1/'
}

push_rollout() {
    name=$1
    tag=$2
    deploy_token=$3
    curl -fsS -X POST \
        -H "Authorization: Bearer $deploy_token" \
        -H "Content-Type: application/json" \
        -d "{\"tag\":\"$tag\"}" \
        "http://$ADMIN_LISTEN/apps/$name/rollouts" >/dev/null
}

# Returns the HTTP status code of a rollout POST (used for the bad-tag
# case where we expect 4xx/5xx but don't want curl to exit non-zero).
push_rollout_status() {
    name=$1
    tag=$2
    deploy_token=$3
    curl -sS -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $deploy_token" \
        -H "Content-Type: application/json" \
        -d "{\"tag\":\"$tag\"}" \
        "http://$ADMIN_LISTEN/apps/$name/rollouts"
}

# High-rate curl loop in the background. Each tick logs `<ts> OK <Version>`
# or `<ts> FAIL <error>` — the OK/FAIL split is what we count.
start_curl_loop() {
    (
        while :; do
            ts=$(date +%H:%M:%S.%3N)
            out=$(curl -fsS --max-time 2 -H "Host: $DOMAIN" "http://$LISTEN/" 2>&1) \
                && echo "$ts OK $(echo "$out" | grep Version)" \
                || echo "$ts FAIL $out"
            sleep 0.1
        done
    ) >>"$CURL_LOG" 2>&1 &
    CURL_PID=$!
}
stop_curl_loop() {
    kill "$CURL_PID" 2>/dev/null || true
    wait "$CURL_PID" 2>/dev/null || true
    CURL_PID=""
}

note "preflight"
echo "bin       : $BIN"
echo "state_dir : $STATE_DIR"
echo "image     : $IMAGE_REPO"
echo "log       : $LOG"

note "launching bugpot"
BUGPOT_STATE_DIR="$STATE_DIR" \
BUGPOT_LISTEN="$LISTEN" \
BUGPOT_ADMIN_LISTEN="$ADMIN_LISTEN" \
BUGPOT_ADMIN_TOKEN="$ADMIN_TOKEN" \
BUGPOT_DEPLOY_SECRET="smoke-only-deploy-secret" \
RUST_LOG="bugpot=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
    "$BIN" >"$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 240); do
    grep -q "bugpot up" "$LOG" 2>/dev/null && break
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.5
done
grep -q "bugpot up" "$LOG" 2>/dev/null || fail "bugpotd did not reach 'bugpot up'"
ok "bugpotd up (pid=$PID)"

note "registering app + initial rollout 1.0"
register_app "$(cat <<EOF
name = "$APP_NAME"
repo = "$IMAGE_REPO"
port = 8080
[scaling]
idle_timeout = "0"
EOF
)"
DEPLOY_KEY=$(mint_deploy_key "$APP_NAME")
push_rollout "$APP_NAME" "1.0" "$DEPLOY_KEY"

# Sanity-check serving + slot layout.
body=$(curl -fsS -m 30 -H "Host: $DOMAIN" "http://$LISTEN/")
case "$body" in
    *"Version: 1.0.0"*) ok "serving 1.0.0";;
    *) fail "unexpected initial response: $body";;
esac
[ -d "$STATE_DIR/containers/$APP_NAME-a" ] || fail "expected slot A on disk"
[ ! -d "$STATE_DIR/containers/$APP_NAME-b" ] || fail "slot B should not exist yet"
ok "slot A present, B absent"

note "rollout 2.0 (blue-green; expect zero-gap switch + slot flip)"
start_curl_loop
sleep 1
push_rollout "$APP_NAME" "2.0" "$DEPLOY_KEY"
ok "rollout 2.0 returned"
sleep 2
stop_curl_loop

total=$(wc -l <"$CURL_LOG")
fails=$(grep -c '^.* FAIL' "$CURL_LOG" || true)
v1=$(grep -c 'Version: 1.0.0' "$CURL_LOG" || true)
v2=$(grep -c 'Version: 2.0.0' "$CURL_LOG" || true)
echo "  total=$total fails=$fails v1=$v1 v2=$v2"
[ "$fails" -eq 0 ] || fail "rollover dropped $fails requests"
[ "$v1" -gt 0 ] || fail "no v1 responses captured"
[ "$v2" -gt 0 ] || fail "no v2 responses captured"
ok "no-gap rollover"

[ -d "$STATE_DIR/containers/$APP_NAME-b" ] || fail "expected slot B after rollover"
[ ! -d "$STATE_DIR/containers/$APP_NAME-a" ] || fail "slot A should be torn down"
ok "slot flipped a → b"

note "rollout 1.0 again (alternation b → a)"
push_rollout "$APP_NAME" "1.0" "$DEPLOY_KEY"
[ -d "$STATE_DIR/containers/$APP_NAME-a" ] || fail "expected slot A after alternation"
[ ! -d "$STATE_DIR/containers/$APP_NAME-b" ] || fail "slot B should be gone"
ok "slot flipped b → a"

note "PATCH /apps/$APP_NAME (env change → blue-green)"
PATCH_START=$(wc -l <"$CURL_LOG")
start_curl_loop
sleep 1
curl -fsS -X PATCH \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/toml" \
    --data-binary "$(cat <<EOF
name = "$APP_NAME"
repo = "$IMAGE_REPO"
port = 8080
[scaling]
idle_timeout = "0"
[env]
BUGPOT_SMOKE = "1"
EOF
)" "http://$ADMIN_LISTEN/apps/$APP_NAME" >/dev/null
ok "PATCH returned"
sleep 2
stop_curl_loop

patch_fails=$(tail -n +$((PATCH_START + 1)) "$CURL_LOG" | grep -c '^.* FAIL' || true)
[ "$patch_fails" -eq 0 ] || fail "PATCH dropped $patch_fails requests"
ok "PATCH zero-gap"
[ -d "$STATE_DIR/containers/$APP_NAME-b" ] || fail "expected slot B after PATCH"
[ ! -d "$STATE_DIR/containers/$APP_NAME-a" ] || fail "slot A should be torn down after PATCH"
ok "PATCH flipped a → b"

note "bad-tag rollout (expect failure + rollback; from-side keeps serving)"
http_code=$(push_rollout_status "$APP_NAME" "does-not-exist-9999" "$DEPLOY_KEY")
case "$http_code" in
    4*|5*) ok "bad tag rejected ($http_code)";;
    *) fail "expected 4xx/5xx for bad tag, got $http_code";;
esac
[ -d "$STATE_DIR/containers/$APP_NAME-b" ] || fail "from-side should still be present after rollback"
body=$(curl -fsS -m 10 -H "Host: $DOMAIN" "http://$LISTEN/")
case "$body" in
    *"Version: 1.0.0"*) ok "from-side serving 1.0.0 after rollback";;
    *) fail "unexpected response after rollback: $body";;
esac

echo
echo "OK — all blue-green scenarios passed"
