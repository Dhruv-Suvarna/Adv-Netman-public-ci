#!/usr/bin/env bash
set -euo pipefail

readonly DEPLOYMENT_ROOT="/home/student/Scripts/clab_dualstack_lab-deploy"
readonly DEPLOYMENT_ROOT_TOKEN="@@DEPLOYMENT_ROOT@@"
SCRIPT_BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SERVICE_TEMPLATE="$SCRIPT_BASE_DIR/monitoring/config/nmas-credential-rotation.service.in"

usage() {
    printf 'Usage: %s [--check-root PATH | --render-only OUTPUT]\n' "$0" >&2
}

check_root() {
    local candidate
    candidate="$(realpath -m -- "$1")"
    if [[ "$candidate" != "$DEPLOYMENT_ROOT" ]]; then
        printf 'Refusing timer installation from non-canonical checkout: %s\n' "$candidate" >&2
        printf 'Run the installer from the dedicated deployment checkout: %s\n' "$DEPLOYMENT_ROOT" >&2
        return 1
    fi
}

render_service() {
    local output="$1"
    sed "s|$DEPLOYMENT_ROOT_TOKEN|$DEPLOYMENT_ROOT|g" "$SERVICE_TEMPLATE" > "$output"
    if grep -Fq "$DEPLOYMENT_ROOT_TOKEN" "$output"; then
        printf 'Credential-rotation unit still contains an unresolved deployment-root token.\n' >&2
        return 1
    fi
}

case "${1:-}" in
    --check-root)
        [[ $# -eq 2 ]] || { usage; exit 2; }
        check_root "$2"
        exit
        ;;
    --render-only)
        [[ $# -eq 2 ]] || { usage; exit 2; }
        render_service "$2"
        exit
        ;;
    "")
        ;;
    *)
        usage
        exit 2
        ;;
esac

# Installation is valid only from the physical, dedicated deployment checkout.
# The read-only modes above exist for CI and pre-deployment validation; neither
# creates the runtime environment nor invokes sudo/systemctl.
check_root "$SCRIPT_BASE_DIR"

BASE_DIR="$DEPLOYMENT_ROOT"
CONFIG_DIR="$BASE_DIR/monitoring/config"
ENV_FILE="$BASE_DIR/monitoring/runtime/credential-rotation.env"
PYTHON="${NMAS_PYTHON:-/home/student/Scripts/.venv/bin/python}"
RENDERED_SERVICE="$(mktemp --tmpdir nmas-credential-rotation.service.XXXXXX)"
trap 'rm -f -- "$RENDERED_SERVICE"' EXIT

render_service "$RENDERED_SERVICE"

# The oneshot runs Django with DEBUG off, which requires DJANGO_SECRET_KEY.
# Generate a dedicated runtime-only value once (mode 600, git-ignored);
# re-running the installer never rotates or prints it.
if [[ ! -s "$ENV_FILE" ]]; then
    umask 077
    printf 'DJANGO_SECRET_KEY=%s\n' "$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(50))')" > "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

sudo -n install -m 0644 "$RENDERED_SERVICE" /etc/systemd/system/nmas-credential-rotation.service
sudo -n install -m 0644 "$CONFIG_DIR/nmas-credential-rotation.timer" /etc/systemd/system/nmas-credential-rotation.timer
sudo -n systemd-analyze verify /etc/systemd/system/nmas-credential-rotation.service /etc/systemd/system/nmas-credential-rotation.timer
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now nmas-credential-rotation.timer
