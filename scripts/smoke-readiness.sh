#!/bin/sh
# HTTP-readiness smoke test.
#
# Verifies the contract of PR #95 (`[readiness] path`): when a path is
# set, the cold-start path holds until the upstream returns a 2xx, and
# bails (without serving the first request) if the upstream answers
# anything else.
#
# Drives two apps in parallel against the same hello-app image:
#   * `good`: `path = "/"`         → 200 → cold start succeeds, request 200s
#   * `bad`:  `path = "/no-such"`  → 404 → cold start fails, request 502s
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/smoke-readiness.sh
#
# Wall-clock < 30s — no freeze cycle needed.

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

LISTEN=127.0.0.1:8080
ADMIN_LISTEN=127.0.0.1:8081
# nginx (not the gcr.io hello-app) is the right test fixture here:
# hello-app responds 200 to *every* path, so a bogus `/no-such-path`
# probe path would silently pass and the failure-mode half of this
# test would be unable to fire. nginx returns 404 for unknown paths
# out of the box, which lets us prove the non-2xx → unready path.
IMAGE_REPO="docker.io/library/nginx"
IMAGE_TAG="alpine"
ADMIN_TOKEN="smoke-only-do-not-deploy"
READINESS_TIMEOUT="5s"

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
    RUST_LOG="bugpot=info,bugpot_controller=debug,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
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
    app=$1
    curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$ADMIN_LISTEN/apps/$app" \
        | grep -o '"state"[ ]*:[ ]*"[^"]*"' \
        | sed 's/.*"state"[ ]*:[ ]*"\([^"]*\)"/\1/'
}

hit_app() {
    subdomain=$1
    curl -sS -o "$RESP" -w "%{http_code}\n" -m 30 \
        -H "Host: $subdomain.bugpot.example" "http://$LISTEN/"
}

echo "=== preflight ==="
echo "bin       : $BIN"
echo "state_dir : $STATE_DIR"
echo "log       : $LOG"
echo

echo "=== launching bugpotd + registering apps ==="
launch_bugpot
wait_for_up || exit 1
echo "pid=$PID"

for spec in \
    "good /" \
    "bad /no-such-path"; do
    name=$(echo "$spec" | awk '{print $1}')
    path=$(echo "$spec" | awk '{print $2}')
    register_app "$(cat <<EOF
name = "$name"
repo = "$IMAGE_REPO"
port = 80
subdomain = "$name"
[readiness]
path = "$path"
timeout = "$READINESS_TIMEOUT"
EOF
)"
    push_rollout "$name" "$IMAGE_TAG" || true
done
# push_rollout for `bad` may surface a server-side error (the
# readiness probe deliberately fails). The pull / start ran, so the
# subsequent HTTP test is what actually exercises the failure path.

echo
echo "=== 1. 'good' app (readiness path = / → 200) ==="
result=$(hit_app good)
echo "  http: $result"
status=$(echo "$result" | awk '{print $1}')
if [ "$status" != "200" ]; then
    echo "FAIL: expected 200 for good app, got $status"
    echo
    echo "=== tail of log ==="
    tail -40 "$LOG"
    exit 1
fi
good_state=$(state_of good)
if [ "$good_state" != "running" ]; then
    echo "FAIL: expected state=running for good app, got '$good_state'"
    exit 1
fi
echo "  OK good app: HTTP 200, state=running"

echo
echo "=== 2. 'bad' app (readiness path = /no-such-path → 404 ⇒ cold-start fails) ==="
result=$(hit_app bad)
echo "  http: $result"
status=$(echo "$result" | awk '{print $1}')
# Current behaviour: the router's `UpstreamResolver::resolve` returns
# `Option<Upstream>`, so a cold-start failure (ensure_running → Err)
# collapses to the same `None` the router uses for "no such
# subdomain", which it surfaces as HTTP 404. The user-visible signal
# is therefore the same for "you never deployed Linkding" and "Linkding
# is registered but broken", which is operationally confusing.
#
# 502 would be a clearer "the app exists but its upstream is sick"
# signal, but distinguishing the two cases requires widening the
# resolver to `Result<Upstream, ResolveError>` — out of scope for
# this smoke test. Filed as a follow-up; for now we lock in the
# observable behaviour.
if [ "$status" != "404" ]; then
    echo "FAIL: expected 404 for bad app (cold-start failure → resolver None → router 404), got $status"
    echo
    echo "=== tail of log ==="
    tail -40 "$LOG"
    exit 1
fi
bad_state=$(state_of bad)
if [ "$bad_state" != "stopped" ]; then
    echo "FAIL: expected state=stopped for bad app after readiness failure, got '$bad_state'"
    exit 1
fi
echo "  OK bad app: HTTP 404, state=stopped"

# Spot-check the log so a future regression that silently swallows the
# readiness error doesn't pass this test on counts alone.
if ! grep -q "readiness probe failed" "$LOG"; then
    echo "FAIL: 'readiness probe failed' not in log; was the path probe even attempted?"
    echo
    echo "=== relevant log lines ==="
    grep -i "readiness\|404\|HTTP " "$LOG" | tail -20
    exit 1
fi
echo "  OK log contains 'readiness probe failed' for the bad app"

echo
echo "=== shutdown ==="
kill -INT "$PID"
wait "$PID" 2>/dev/null || true
PID=""
echo
echo "OK: HTTP readiness verified end-to-end"
echo "  - 2xx path → cold start succeeds, HTTP 200"
echo "  - non-2xx path → cold start fails, HTTP 404, state=stopped"
