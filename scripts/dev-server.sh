#!/bin/sh
# Background bugpot for iterative dev. Runs INSIDE the bugpot Lima VM
# (needs root). The Mac-side entry points are `just start` / `just stop` /
# `just logs`, which limactl-shell into the VM and run this script.
#
# Defaults to two eager-started demo apps (`alpha`, `beta`) on
# gcr.io/google-samples/hello-app:1.0. From the host:
#
#   curl -i http://alpha.localhost:8080/
#   curl -i http://beta.localhost:8080/
#
# Lifecycle is managed via a transient systemd unit `bugpot-dev.service`,
# so it never touches an unrelated bugpot the user may have running in the
# same VM. Logs go through journalctl. Shared infra (bugpot0 bridge,
# `nft inet bugpot` table) is NOT torn down on stop — bugpot's setup is
# idempotent and another instance may still need them.

set -eu

cd "$(dirname "$0")/.."

UNIT=bugpot-dev.service
APPS_LINK=/tmp/bugpot-dev.apps-dir
STATE_DIR=/var/lib/bugpot-dev
LISTEN=127.0.0.1:8080
IMAGE_REPO=${BUGPOT_DEV_REPO:-gcr.io/google-samples/hello-app}
IMAGE_TAG=${BUGPOT_DEV_TAG:-1.0}
BIN="$(pwd)/target/debug/bugpot"

is_active() {
    sudo systemctl is-active --quiet "$UNIT" 2>/dev/null
}

start() {
    if is_active; then
        echo "$UNIT already running" >&2
        return 1
    fi
    if [ ! -x "$BIN" ]; then
        echo "binary not built ($BIN). run: just build" >&2
        return 1
    fi

    # App names are dev-prefixed so the resulting netns (`bugpot-dev-*`) and
    # container ids are unambiguously owned by this dev-server. The
    # subdomain is kept short (`alpha` / `beta`) so `just hit alpha` works.
    APPS=$(mktemp -d)
    for sub in alpha beta; do
        cat >"$APPS/dev-$sub.toml" <<EOF
repo = "$IMAGE_REPO"
port = 8080
name = "dev-$sub"
subdomain = "$sub"
[scaling]
idle_timeout = "0"
[rollout]
tag = "$IMAGE_TAG"
created_at = "1970-01-01T00:00:00Z"
EOF
    done
    echo "$APPS" >"$APPS_LINK"
    sudo mkdir -p "$STATE_DIR"

    # Scope readiness journal lookups to logs after this point so we don't
    # match "bugpot up" from a prior run of the same unit name.
    since_ts=$(date '+%Y-%m-%d %H:%M:%S')

    # Admin auth is mandatory; dev gets a fixed throwaway token via
    # env-var. Production deployments must use BUGPOT_ADMIN_TOKEN_FILE
    # (chmod 600) instead.
    sudo systemd-run \
        --unit="$UNIT" \
        --description="bugpot dev server (managed by scripts/dev-server.sh)" \
        --collect \
        --property=KillSignal=SIGINT \
        --setenv=BUGPOT_APPS_DIR="$APPS" \
        --setenv=BUGPOT_STATE_DIR="$STATE_DIR" \
        --setenv=BUGPOT_LISTEN="$LISTEN" \
        --setenv=BUGPOT_ADMIN_TOKEN="dev-only-do-not-deploy" \
        --setenv=BUGPOT_DEPLOY_SECRET="dev-only-deploy-secret" \
        --setenv=BUGPOT_METRICS_LISTEN=127.0.0.1:9090 \
        "$BIN" >/dev/null

    for _ in $(seq 1 60); do
        if sudo journalctl --unit="$UNIT" --no-pager --since="$since_ts" 2>/dev/null \
            | grep -q "bugpot up"
        then
            echo "ready. try:"
            echo "  curl -i http://alpha.localhost:8080/"
            echo "  curl -i http://beta.localhost:8080/"
            return 0
        fi
        if ! is_active; then
            echo "$UNIT exited before becoming ready:" >&2
            sudo journalctl --unit="$UNIT" --no-pager --since="$since_ts" 2>/dev/null \
                | tail -20 >&2
            return 1
        fi
        sleep 0.5
    done
    echo "did not become ready within 30s (try: just logs)" >&2
    return 1
}

stop() {
    if is_active; then
        sudo systemctl stop "$UNIT" 2>/dev/null || true
    fi
    if [ -f "$APPS_LINK" ]; then
        rm -rf "$(cat "$APPS_LINK")" && rm -f "$APPS_LINK"
    fi
    echo "stopped"
}

logs() {
    sudo journalctl --unit="$UNIT" --no-pager "$@"
}

cmd=${1:-}
shift 2>/dev/null || true
case "$cmd" in
    start) start ;;
    stop) stop ;;
    logs) logs "$@" ;;
    *) echo "usage: $0 {start|stop|logs}" >&2; exit 1 ;;
esac
