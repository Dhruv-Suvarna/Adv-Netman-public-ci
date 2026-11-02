#!/usr/bin/env bash
# Install / refresh the NMAS probation soak collector timer (V2 Phase 5C).
#
#   sudo deploy/scripts/install_soak_timer.sh --deploy-root /home/student/Scripts/clab_dualstack_lab-deploy
#   deploy/scripts/install_soak_timer.sh --deploy-root <checkout> --render-only <dir>     # no root, installs nothing
#
# Run it ONLY after the deployment checkout has been promoted to the merged code and its database migrated: the timer runs
# `manage.py probation_soak_tick` in --deploy-root, so that checkout must already contain the command and the schema.
# Idempotent.  Prints no secret (the unit reads the website's protected /etc/nmas/nmas-web.env).
# Steps: check the checkout -> render units -> systemd-analyze verify -> daemon-reload -> enable + start the timer -> one dry-run tick.
set -euo pipefail

DEPLOY_ROOT=""
RUN_USER="${SUDO_USER:-student}"
VENV="/home/student/Scripts/.venv"
RENDER_ONLY=""

usage() { sed -n '2,10p' "$0"; exit 2; }
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
[[ -f "$DEPLOY_ROOT/web/core/management/commands/probation_soak_tick.py" ]] || { echo "--deploy-root has no probation_soak_tick command" >&2; exit 1; }
[[ -x "$VENV/bin/python" ]] || { echo "$VENV/bin/python missing" >&2; exit 1; }
RUN_GROUP="$(id -gn "$RUN_USER")"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
UNITS=(nmas-probation-soak-tick.service nmas-probation-soak-tick.timer)

render_to() {  # render_to <template> <dest>
  sed -e "s#@DEPLOY_ROOT@#${DEPLOY_ROOT}#g" -e "s#@RUN_USER@#${RUN_USER}#g" -e "s#@RUN_GROUP@#${RUN_GROUP}#g" -e "s#@VENV@#${VENV}#g" "$1" > "$2"
}

if [[ -n "$RENDER_ONLY" ]]; then
  mkdir -p "$RENDER_ONLY"
  for unit in "${UNITS[@]}"; do render_to "$SRC/systemd/$unit" "$RENDER_ONLY/$unit"; done
  echo "rendered ${UNITS[*]} into $RENDER_ONLY (nothing installed)"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "run with sudo (or use --render-only)" >&2; exit 1; }
# The checkout must be the promoted, migrated deployment: refuse to schedule a collector against a schema that is behind the code.
sudo -u "$RUN_USER" bash -c "set -a; . /etc/nmas/nmas-web.env; set +a; cd '$DEPLOY_ROOT/web' && '$VENV/bin/python' manage.py migrate --check" >/dev/null \
  || { echo "the deployment database has unapplied migrations; promote and migrate first" >&2; exit 1; }
for unit in "${UNITS[@]}"; do
  render_to "$SRC/systemd/$unit" "/etc/systemd/system/$unit.tmp"
  install -m 0644 -o root -g root "/etc/systemd/system/$unit.tmp" "/etc/systemd/system/$unit"; rm -f "/etc/systemd/system/$unit.tmp"
done
systemd-analyze verify "/etc/systemd/system/nmas-probation-soak-tick.timer"
systemctl daemon-reload
systemctl enable --now nmas-probation-soak-tick.timer >/dev/null
# One read-only dry run as the service user proves the command starts in the deployment environment (it samples nothing).
sudo -u "$RUN_USER" bash -c "set -a; . /etc/nmas/nmas-web.env; set +a; cd '$DEPLOY_ROOT/web' && '$VENV/bin/python' manage.py probation_soak_tick --dry-run"
systemctl --no-pager list-timers nmas-probation-soak-tick.timer | head -3
