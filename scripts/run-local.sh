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
#
# Each cold start runs `oci-client` pull + libcontainer start (~3-5s the
# first time, ~0.5-1s after the image is cached). After ~30s of no traffic
# for a given app, the idle sweeper stops its container; the next request
# restarts it.

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

LISTEN=127.0.0.1:8080
IMAGE_REPO="gcr.io/google-samples/hello-app"
IMAGE_TAG="1.0"
IDLE="30s"

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

cleanup() {
    rm -rf "$APPS_DIR" "$STATE_DIR"
}
trap cleanup EXIT INT TERM

for name in alpha beta; do
    cat >"$APPS_DIR/$name.toml" <<EOF
repo = "$IMAGE_REPO"
port = 8080

[scaling]
idle_timeout = "$IDLE"

[rollout]
tag = "$IMAGE_TAG"
created_at = "1970-01-01T00:00:00Z"
EOF
done

cat <<EOF

== bugpot will listen on $LISTEN ==

In your browser:
   http://alpha.localhost:8080/
   http://beta.localhost:8080/

   First load ≈ 5s (image pull + container start).
   After ${IDLE} idle, the container auto-stops; next request restarts it.

   Watch the terminal: you'll see 'starting' / 'stopping' lines from the
   controller as each app spins up and down.

Press Ctrl+C to shut down.

EOF

# `exec` replaces this shell with bugpot so Ctrl+C delivers SIGINT
# directly to bugpot. `env` cleanly sets the override variables.
exec env \
    BUGPOT_APPS_DIR="$APPS_DIR" \
    BUGPOT_STATE_DIR="$STATE_DIR" \
    BUGPOT_LISTEN="$LISTEN" \
    RUST_LOG="bugpot=info,bugpot_router=info,bugpot_runtime=info,bugpot_egress=info" \
    "$BIN"
