#!/bin/sh
# Persistent-volume bind-mount smoke test.
#
# Verifies the four invariants of PR #94 (`[[volumes]]` support):
#   1. `<state>/volumes/<app>/<name>/` is materialised on first start
#   2. the bind mount appears in the container's `/proc/<pid>/mountinfo`
#      pointing at that host directory
#   3. files dropped into the host directory survive a freeze → resume
#      cycle (the container is paused, not stopped, so the bind mount
#      and everything beneath it must be untouched)
#   4. `DELETE /apps/<name>` removes the host directory cleanly
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-volume.sh
#
# Wall-clock ≈ 1 min: a single freeze cycle needs `idle_timeout` +
# the controller's 30 s sweep tick.

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

APP_NAME=vol-demo
SUBDOMAIN=vol
LISTEN=127.0.0.1:8080
ADMIN_LISTEN=127.0.0.1:8081
IMAGE_REPO="gcr.io/google-samples/hello-app"
IMAGE_TAG="1.0"
ADMIN_TOKEN="smoke-only-do-not-deploy"
VOLUME_NAME=data
VOLUME_PATH=/data
IDLE_TIMEOUT="5s"
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

state_of() {
    curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$ADMIN_LISTEN/apps/$APP_NAME" \
        | grep -o '"state"[ ]*:[ ]*"[^"]*"' \
        | sed 's/.*"state"[ ]*:[ ]*"\([^"]*\)"/\1/'
}

hit_app() {
    # 60s timeout absorbs the first-time image pull on the cold-start
    # request — subsequent resumes are sub-second.
    curl -sS -o "$RESP" -w "%{http_code}\n" -m 60 \
        -H "Host: $SUBDOMAIN.bugpot.example" "http://$LISTEN/"
}

# Resolve the container PID by reading libcontainer's on-disk state.
# `state.json` is updated on every container lifecycle transition, so
# its `init_process_pid` field is the authoritative PID once the
# container is Running.
container_pid() {
    state_file="$STATE_DIR/containers/$APP_NAME/state.json"
    [ -f "$state_file" ] || return 1
    # `init_process_pid` is the libcontainer field name; older fields
    # like `pid` may also appear. Try both.
    pid=$(grep -o '"init_process_pid"[ ]*:[ ]*[0-9]\+' "$state_file" \
        | grep -o '[0-9]\+$' | head -1)
    if [ -z "$pid" ]; then
        pid=$(grep -o '"pid"[ ]*:[ ]*[0-9]\+' "$state_file" \
            | grep -o '[0-9]\+$' | head -1)
    fi
    [ -n "$pid" ] || return 1
    echo "$pid"
}

assert_volume_mounted_in_container() {
    pid=$(container_pid) || {
        echo "FAIL: could not resolve container PID"
        exit 1
    }
    mi="/proc/$pid/mountinfo"
    if [ ! -r "$mi" ]; then
        echo "FAIL: $mi unreadable (container not running yet?)"
        exit 1
    fi
    # mountinfo column 5 is the mount point in the *container*. column
    # 4 (root inside source fs) plus column 10+ (source) tell us where
    # the bind came from. Just confirm the container path appears.
    if ! awk '{print $5}' "$mi" | grep -Fxq "$VOLUME_PATH"; then
        echo "FAIL: $VOLUME_PATH not in container mountinfo"
        echo "  mountinfo:"
        sed 's/^/    /' "$mi" | head -20
        exit 1
    fi
    echo "  OK $VOLUME_PATH visible in container's /proc/$pid/mountinfo"
}

assert_state() {
    expected=$1
    label=$2
    got=$(state_of)
    if [ "$got" != "$expected" ]; then
        echo "FAIL [$label]: expected state=$expected, got '$got'"
        tail -40 "$LOG"
        exit 1
    fi
    echo "  state=$got [$label]"
}

echo "=== preflight ==="
echo "bin       : $BIN"
echo "state_dir : $STATE_DIR"
echo "log       : $LOG"
echo

echo "=== launching bugpotd + registering app ==="
launch_bugpot
wait_for_up || exit 1
echo "pid=$PID"

# UID 0 keeps the host dir owned by root, matching hello-app's
# container user (also root). For real apps (Linkding uid=33,
# Vaultwarden uid=1000) operators set `user = N` explicitly.
register_app "$(cat <<EOF
name = "$APP_NAME"
repo = "$IMAGE_REPO"
port = 8080
subdomain = "$SUBDOMAIN"
[scaling]
idle_timeout = "$IDLE_TIMEOUT"
[[volumes]]
name = "$VOLUME_NAME"
path = "$VOLUME_PATH"
EOF
)"
push_rollout "$APP_NAME" "$IMAGE_TAG"

echo
echo "=== 1. cold start ==="
result=$(hit_app)
echo "  http: $result"
[ "$(echo "$result" | awk '{print $1}')" = "200" ] || {
    echo "FAIL: expected 200, got $result"
    exit 1
}
assert_state "running" "after first hit"

echo
echo "=== 2. volume host dir created ==="
host_vol="$STATE_DIR/volumes/$APP_NAME/$VOLUME_NAME"
if [ ! -d "$host_vol" ]; then
    echo "FAIL: $host_vol missing"
    exit 1
fi
echo "  OK $host_vol exists"

echo
echo "=== 3. volume mount visible inside container ==="
assert_volume_mounted_in_container

echo
echo "=== 4. drop sentinel file in volume ==="
echo "smoke" >"$host_vol/sentinel.txt"
echo "  wrote $host_vol/sentinel.txt"

echo
echo "=== 5. wait ${FREEZE_WAIT_SECS}s for freeze cycle ==="
sleep "$FREEZE_WAIT_SECS"
assert_state "frozen" "after idle"
# Sentinel must be present while frozen — freeze pauses processes,
# it does not unmount the bind.
if [ ! -f "$host_vol/sentinel.txt" ]; then
    echo "FAIL: sentinel disappeared during freeze"
    exit 1
fi
echo "  OK sentinel survives freeze"

echo
echo "=== 6. resume ==="
result=$(hit_app)
echo "  http: $result"
[ "$(echo "$result" | awk '{print $1}')" = "200" ] || {
    echo "FAIL: resume hit failed: $result"
    exit 1
}
assert_state "running" "after resume"
if [ ! -f "$host_vol/sentinel.txt" ]; then
    echo "FAIL: sentinel disappeared during resume"
    exit 1
fi
echo "  OK sentinel persisted across freeze→resume"

echo
echo "=== 7. DELETE removes the volume dir ==="
delete_status=$(curl -sS -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
    -w "%{http_code}\n" -o /dev/null "http://$ADMIN_LISTEN/apps/$APP_NAME")
echo "  DELETE: HTTP $delete_status"
if [ "$delete_status" != "204" ] && [ "$delete_status" != "200" ]; then
    echo "FAIL: expected 2xx on DELETE, got $delete_status"
    exit 1
fi
if [ -d "$host_vol" ]; then
    echo "FAIL: $host_vol still exists after DELETE"
    ls -la "$host_vol"
    exit 1
fi
echo "  OK volume dir removed"

echo
echo "=== shutdown ==="
kill -INT "$PID"
wait "$PID" 2>/dev/null || true
PID=""
echo
echo "OK: volume bind-mount + lifecycle verified end-to-end"
echo "  - host dir created           OK"
echo "  - mount visible in container OK"
echo "  - sentinel persists freeze   OK"
echo "  - sentinel persists resume   OK"
echo "  - DELETE removes host dir    OK"
