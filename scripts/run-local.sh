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
#   2) /etc/hosts has entries for the demo subdomains:
#        127.0.0.1  alpha.bugpot.ts.net  beta.bugpot.ts.net
#      (any subdomain of bugpot.ts.net is fine — just add it to /etc/hosts
#       and bugpot will route it as long as a matching app spec exists.)
#
# After it's up, point your browser at:
#   http://alpha.bugpot.ts.net:8080/
#   http://beta.bugpot.ts.net:8080/
#
# Each cold start runs `oci-client` pull + libcontainer start (~3-5s the
# first time, ~0.5-1s after the image is cached). After ~30s of no traffic
# for a given app, the idle sweeper stops its container; the next request
# restarts it.

set -eu

cd "$(dirname "$0")/.."
WORKDIR=$(pwd)

LISTEN=127.0.0.1:8080
IMAGE="gcr.io/google-samples/hello-app:1.0"
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
image = "$IMAGE"
port = 8080

[scaling]
idle_timeout = "$IDLE"
EOF
done

cat <<EOF

== bugpot will listen on $LISTEN ==

If you haven't already, add this to /etc/hosts:
   127.0.0.1  alpha.bugpot.ts.net  beta.bugpot.ts.net

Then in your browser:
   http://alpha.bugpot.ts.net:8080/
   http://beta.bugpot.ts.net:8080/

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
