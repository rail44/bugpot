#!/bin/sh
# Long-running bugpot for browser interaction.
#
# Spins up two demo apps (alpha, beta) with a short idle_timeout so you can
# watch scale-to-zero in action. Press Ctrl+C to shut down cleanly.
#
# Usage:
#   sudo /home/satoshi/src/github.com/rail44/bugpot/scripts/run-local.sh
#
# Prereqs (one-time):
#   1) /etc/sudoers.d/bugpot-dev has a NOPASSWD entry for this script.
#
# After it's up, point your browser at:
#   http://alpha.localhost:8080/
#   http://beta.localhost:8080/
# (the `*.localhost` wildcard resolves to 127.0.0.1 on modern OSes; no
# /etc/hosts edits required)

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

LISTEN=127.0.0.1:8080
ADMIN_LISTEN=127.0.0.1:8081
ADMIN_TOKEN="dev-only-do-not-deploy"
IMAGE_REPO="gcr.io/google-samples/hello-app"
IMAGE_TAG="1.0"
IDLE="30s"

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
PID=""

cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -INT "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$STATE_DIR" "$LOG"
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

cat <<EOF

== bugpot will listen on $LISTEN ==

In your browser:
   http://alpha.localhost:8080/
   http://beta.localhost:8080/

   First load ≈ 5s (image pull + container start).
   After ${IDLE} idle, the controller freezes the container; next
   request resumes it in sub-ms.

   Watch the terminal: you'll see freeze / resume lines from the
   controller as each app idles and wakes back up.

Press Ctrl+C to shut down.

EOF

BUGPOT_STATE_DIR="$STATE_DIR" \
BUGPOT_LISTEN="$LISTEN" \
BUGPOT_ADMIN_LISTEN="$ADMIN_LISTEN" \
BUGPOT_ADMIN_TOKEN="$ADMIN_TOKEN" \
BUGPOT_DEPLOY_SECRET="dev-only-deploy-secret" \
RUST_LOG="bugpot=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
    "$BIN" 2>&1 | tee "$LOG" &
PID=$!

# Wait for the daemon to surface its admin listener before the curls
# below try to land on it.
for _ in $(seq 1 120); do
    if grep -q "bugpot up" "$LOG" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

for name in alpha beta; do
    register_app "$(cat <<EOF
name = "$name"
repo = "$IMAGE_REPO"
port = 8080
[scaling]
idle_timeout = "$IDLE"
EOF
)"
    push_rollout "$name" "$IMAGE_TAG"
    echo "registered $name"
done

# Block on the daemon. cleanup() handles SIGINT.
wait "$PID"
