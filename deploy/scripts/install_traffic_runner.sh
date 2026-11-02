#!/usr/bin/env bash
# Install / refresh the NMAS traffic runner (V2 Phase 5B): tools image, root-owned runner code + configuration, socket + service units.
#
#   sudo deploy/scripts/install_traffic_runner.sh --deploy-root /home/student/Scripts/clab_dualstack_lab-deploy
#   deploy/scripts/install_traffic_runner.sh --deploy-root <checkout> --render-only <dir>     # no root, installs nothing
#
# Run it ONLY after the deployment checkout has been promoted to the merged code.  It does not touch nmas-web.service: the website
# keeps NoNewPrivileges and gains no privilege -- it only connects to the runner's socket (root:<website group> 0660).
# Idempotent.  Prints no secret (the runner has none).
# Steps: check the checkout -> build the pinned tools image -> install runner code (root-owned copy) -> render + install the endpoint
#        catalogue -> render units -> systemd-analyze verify -> daemon-reload -> enable + start the SOCKET (the service starts on demand).
set -euo pipefail

DEPLOY_ROOT=""
RUN_USER="${SUDO_USER:-student}"
VENV="/home/student/Scripts/.venv"
RENDER_ONLY=""
LIB_DIR="/usr/local/lib/nmas-traffic-runner"
CONFIG="/etc/nmas/traffic-runner.json"
IMAGE_TAG="nmas-traffic-tools:1"

usage() { sed -n '2,11p' "$0"; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deploy-root) DEPLOY_ROOT="$2"; shift 2 ;;
    --run-user) RUN_USER="$2"; shift 2 ;;
    --venv) VENV="$2"; shift 2 ;;
    --render-only) RENDER_ONLY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[[ -n "$DEPLOY_ROOT" && -f "$DEPLOY_ROOT/web/manage.py" ]] || { echo "--deploy-root must contain web/manage.py" >&2; exit 1; }
RUNNER_SRC="$DEPLOY_ROOT/web/core/services/traffic/runner"
[[ -f "$RUNNER_SRC/__main__.py" && -f "$DEPLOY_ROOT/deploy/traffic-tools/Dockerfile" ]] || { echo "--deploy-root has no traffic runner" >&2; exit 1; }
RUN_GROUP="$(id -gn "$RUN_USER")"
RUN_UID="$(id -u "$RUN_USER")"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
UNITS=(nmas-traffic-runner.socket nmas-traffic-runner.service)

render_to() {  # render_to <template> <dest>
  sed -e "s#@DEPLOY_ROOT@#${DEPLOY_ROOT}#g" -e "s#@RUN_GROUP@#${RUN_GROUP}#g" "$1" > "$2"
}

if [[ -n "$RENDER_ONLY" ]]; then
  mkdir -p "$RENDER_ONLY"
  for unit in "${UNITS[@]}"; do render_to "$SRC/systemd/$unit" "$RENDER_ONLY/$unit"; done
  echo "rendered ${UNITS[*]} into $RENDER_ONLY (nothing installed)"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "run with sudo (or use --render-only)" >&2; exit 1; }
[[ -x "$VENV/bin/python" ]] || { echo "$VENV/bin/python missing" >&2; exit 1; }

# 1. The tools image, then its immutable ID: the runner starts the image by ID, never by this tag.
docker build --quiet --tag "$IMAGE_TAG" "$DEPLOY_ROOT/deploy/traffic-tools" >/dev/null
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG")"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "could not determine the tools image ID" >&2; exit 1; }

# 2. The runner code: a root-owned copy outside the checkout, so the website's account cannot change it.
install -d -m 0755 -o root -g root "$LIB_DIR" "$LIB_DIR/nmas_traffic_runner.new"
install -m 0644 -o root -g root "$RUNNER_SRC"/*.py "$LIB_DIR/nmas_traffic_runner.new/"
rm -rf "$LIB_DIR/nmas_traffic_runner.old"
[[ -d "$LIB_DIR/nmas_traffic_runner" ]] && mv "$LIB_DIR/nmas_traffic_runner" "$LIB_DIR/nmas_traffic_runner.old"
mv "$LIB_DIR/nmas_traffic_runner.new" "$LIB_DIR/nmas_traffic_runner"
rm -rf "$LIB_DIR/nmas_traffic_runner.old"

# 3. The endpoint catalogue, rendered from the tracked inventory by the website's own code and installed root-owned (no secret in it).
install -d -m 0755 -o root -g root /etc/nmas
sudo -u "$RUN_USER" bash -c "set -a; . /etc/nmas/nmas-web.env; set +a; cd '$DEPLOY_ROOT/web' && '$VENV/bin/python' manage.py traffic_runner_config --tools-image '$IMAGE_ID' --peer-uid '$RUN_UID'" > "$CONFIG.tmp"
install -m 0644 -o root -g root "$CONFIG.tmp" "$CONFIG"; rm -f "$CONFIG.tmp"

# 4. Units.
for unit in "${UNITS[@]}"; do
  render_to "$SRC/systemd/$unit" "/etc/systemd/system/$unit.tmp"
  install -m 0644 -o root -g root "/etc/systemd/system/$unit.tmp" "/etc/systemd/system/$unit"; rm -f "/etc/systemd/system/$unit.tmp"
done
systemd-analyze verify "/etc/systemd/system/nmas-traffic-runner.socket" "/etc/systemd/system/nmas-traffic-runner.service"
systemctl daemon-reload
systemctl enable --now nmas-traffic-runner.socket >/dev/null
systemctl try-restart nmas-traffic-runner.service      # pick up new code / configuration if it was already running
systemctl --no-pager --lines=0 status nmas-traffic-runner.socket | head -5
echo "traffic runner installed: image $IMAGE_ID, socket /run/nmas-traffic-runner/runner.sock (root:$RUN_GROUP 0660)"
