#!/bin/sh
# Freezer-based scale-to-zero smoke test.
#
# Verifies the three invariants of PR #92:
#   1. `idle_timeout` elapsed → `state` becomes `frozen` (not `stopped`)
#   2. next HTTP request resumes the frozen app, state returns to `running`
#   3. across a bugpotd restart, `reattach_running` recognises the paused
#      container and restores the handle to `Frozen`
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-freeze.sh
#
# Wall-clock ≈ 2 min: the controller's sweep loop ticks every 30 s
# (`SWEEP_INTERVAL` in cmd/bugpotd/src/main.rs), so each freeze
# transition needs ~`idle_timeout + 30 s` to fire.

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

APP_NAME=freeze-demo
SUBDOMAIN=freeze
LISTEN=127.0.0.1:8080
ADMIN_LISTEN=127.0.0.1:8081
IMAGE_REPO="gcr.io/google-samples/hello-app"
IMAGE_TAG="1.0"
ADMIN_TOKEN="smoke-only-do-not-deploy"
IDLE_TIMEOUT="5s"
# Idle timeout (5s) + sweep tick (30s) + slop.
FREEZE_WAIT_SECS=40

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (try: sudo $0)" >&2
    exit 1
fi

BIN="$WORKDIR/target/debug/bugpotd"
if [ ! -x "$BIN" ]; then
    echo "binary not built. run: cargo build -p bugpotd" >&2
    exit 1
fi

# A single state dir survives across the bugpotd restart in step 4 —
# that's the whole point of the reattach assertion. Specs + rollouts
# persist there; we register the app once on the first launch and
# expect it to come back on its own.
STATE_DIR=$(mktemp -d)
LOG=$(mktemp)
RESP=$(mktemp)
LOG_OFFSET=0
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
    echo "(script exit=$rc; bugpotd log=$LOG resp=$RESP kept for inspection)"
    return $rc
}
trap cleanup EXIT INT TERM

launch_bugpot() {
    LOG_OFFSET=$(wc -l <"$LOG" 2>/dev/null | awk '{print $1}')
    BUGPOT_STATE_DIR="$STATE_DIR" \
    BUGPOT_LISTEN="$LISTEN" \
    BUGPOT_ADMIN_LISTEN="$ADMIN_LISTEN" \
    BUGPOT_ADMIN_TOKEN="$ADMIN_TOKEN" \
    BUGPOT_DEPLOY_SECRET="smoke-only-deploy-secret" \
    RUST_LOG="bugpot=info,bugpot_core=debug,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
        "$BIN" >>"$LOG" 2>&1 &
    PID=$!
}

wait_for_up() {
    for _ in $(seq 1 240); do
        if tail -n "+$((LOG_OFFSET + 1))" "$LOG" | grep -q "bugpot up"; then
            return 0
        fi
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "bugpotd exited before becoming ready" >&2
            tail -30 "$LOG" >&2
            return 1
        fi
        sleep 0.5
    done
    echo "bugpotd did not reach 'bugpot up' within 120 s" >&2
    return 1
}

register_app() {
    body=$1
    curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/toml" \
        --data-binary "$body" \
        "http://$ADMIN_LISTEN/apps" >/dev/null
}

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

state_of() {
    curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$ADMIN_LISTEN/apps/$APP_NAME" \
        | grep -o '"state"[ ]*:[ ]*"[^"]*"' \
        | sed 's/.*"state"[ ]*:[ ]*"\([^"]*\)"/\1/'
}

hit_app() {
    curl -sS -o "$RESP" -w "%{http_code} %{time_total}\n" -m 60 \
        -H "Host: $SUBDOMAIN.bugpot.example" "http://$LISTEN/"
}

assert_state() {
    expected=$1
    label=$2
    got=$(state_of)
    if [ "$got" != "$expected" ]; then
        echo "FAIL [$label]: expected state=$expected, got '$got'"
        echo
        echo "=== tail of log ==="
        tail -40 "$LOG"
        exit 1
    fi
    echo "  state=$got [$label]"
}

assert_http_200() {
    label=$1
    line=$2
    status=$(echo "$line" | awk '{print $1}')
    if [ "$status" != "200" ]; then
        echo "FAIL [$label]: expected HTTP 200, got '$status'"
        exit 1
    fi
}

echo "=== preflight ==="
echo "bin       : $BIN"
echo "state_dir : $STATE_DIR"
echo "idle      : $IDLE_TIMEOUT"
echo "log       : $LOG"
echo

echo "=== launching bugpotd + registering app ==="
launch_bugpot
wait_for_up || exit 1
echo "pid=$PID"

register_app "$(cat <<EOF
name = "$APP_NAME"
repo = "$IMAGE_REPO"
port = 8080
subdomain = "$SUBDOMAIN"
[scaling]
idle_timeout = "$IDLE_TIMEOUT"
EOF
)"
push_rollout "$APP_NAME" "$IMAGE_TAG"

echo
echo "=== 1. cold start (first hit) ==="
result=$(hit_app)
echo "  http result: $result"
assert_http_200 "cold-start" "$result"
assert_state "running" "after first hit"

echo
echo "=== 2. waiting ${FREEZE_WAIT_SECS}s for idle freeze ==="
sleep "$FREEZE_WAIT_SECS"
assert_state "frozen" "after idle timeout"

echo
echo "=== 3. resume (second hit; should be sub-ms) ==="
result=$(hit_app)
echo "  http result: $result"
assert_http_200 "resume" "$result"
assert_state "running" "after resume"
latency=$(echo "$result" | awk '{print $2}')
case "$latency" in
    0.0*|0.1*) echo "  OK resume latency ${latency}s (under 200 ms)" ;;
    *) echo "  WARN resume latency ${latency}s — investigate (typical < 0.05s)" ;;
esac

echo
echo "=== 4. wait ${FREEZE_WAIT_SECS}s for second freeze, then restart bugpotd ==="
sleep "$FREEZE_WAIT_SECS"
assert_state "frozen" "before restart"

kill -INT "$PID"
wait "$PID" 2>/dev/null || true
PID=""
echo "  bugpotd stopped"

# Reuse the same STATE_DIR — the spec + rollout are persisted there
# and rehydrate at boot. No re-register needed; that's the whole
# reattach guarantee.
launch_bugpot
wait_for_up || exit 1
echo "  pid=$PID (restarted)"

assert_state "frozen" "after reattach"

echo
echo "=== 5. resume after reattach ==="
result=$(hit_app)
echo "  http result: $result"
assert_http_200 "post-reattach-resume" "$result"
assert_state "running" "after post-reattach resume"

echo
echo "=== shutdown ==="
kill -INT "$PID"
wait "$PID" 2>/dev/null || true
PID=""
echo
echo "OK: freezer scale-to-zero verified end-to-end"
echo "  - freeze after idle      OK"
echo "  - resume from frozen     OK"
echo "  - reattach across restart  OK"
