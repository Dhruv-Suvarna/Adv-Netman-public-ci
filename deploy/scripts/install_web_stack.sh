#!/usr/bin/env bash
# Install / refresh the persistent NMAS website stack: Apache (reverse proxy) + Gunicorn (systemd) (V2 Phase 1).
#
#   sudo deploy/scripts/install_web_stack.sh --deploy-root /home/student/Scripts/clab_dualstack_lab-deploy
#
# Idempotent.  It never prints a secret: the protected env file is created once with a generated SECRET_KEY and
# afterwards left untouched (edit it by hand).  It does not stop any existing `runserver`; cut over deliberately.
# Steps: apt install apache2 -> enable proxy modules -> render units/vhosts -> collectstatic -> configtest ->
#        enable + (re)start nmas-web -> reload Apache -> local health checks.
set -euo pipefail

DEPLOY_ROOT=""
RUN_USER="${SUDO_USER:-student}"
VENV="/home/student/Scripts/.venv"
LOCAL_LISTEN="127.0.0.1:80"
SKIP_APT=0

usage() { sed -n '2,9p' "$0"; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deploy-root) DEPLOY_ROOT="$2"; shift 2 ;;
    --run-user) RUN_USER="$2"; shift 2 ;;
    --venv) VENV="$2"; shift 2 ;;
    --local-listen) LOCAL_LISTEN="$2"; shift 2 ;;
    --skip-apt) SKIP_APT=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -n "$DEPLOY_ROOT" && -f "$DEPLOY_ROOT/web/manage.py" ]] || { echo "--deploy-root must contain web/manage.py" >&2; exit 1; }
[[ "$LOCAL_LISTEN" =~ ^[0-9.]+:[0-9]+$ ]] || { echo "--local-listen must be ADDR:PORT" >&2; exit 1; }
[[ -x "$VENV/bin/gunicorn" ]] || { echo "$VENV/bin/gunicorn missing (pip install -r web/requirements.txt)" >&2; exit 1; }
RUN_GROUP="$(id -gn "$RUN_USER")"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

render() {  # render <template> <dest> <mode>
  sed -e "s#@DEPLOY_ROOT@#${DEPLOY_ROOT}#g" -e "s#@RUN_USER@#${RUN_USER}#g" -e "s#@RUN_GROUP@#${RUN_GROUP}#g" \
      -e "s#@VENV@#${VENV}#g" -e "s#@LOCAL_LISTEN@#${LOCAL_LISTEN}#g" "$1" > "$2.tmp"
  install -m "$3" -o root -g root "$2.tmp" "$2"; rm -f "$2.tmp"
}

if [[ $SKIP_APT -eq 0 ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 >/dev/null
fi
a2enmod -q proxy proxy_http headers >/dev/null
# Ubuntu's default site listens on *:80; NMAS owns the HTTP listeners instead (no default site, no ports.conf Listen).
a2dissite -q 000-default >/dev/null 2>&1 || true
sed -i 's/^Listen 80$/# Listen 80  (disabled: NMAS vhost owns the listener)/' /etc/apache2/ports.conf

# Protected runtime environment (created once; never printed; never in Git).
install -d -m 0750 -o root -g "$RUN_GROUP" /etc/nmas
if [[ ! -f /etc/nmas/nmas-web.env ]]; then
  umask 027
  SECRET="$("$VENV/bin/python" -c 'import secrets; print(secrets.token_urlsafe(64))')"
  sed -e "s#^DJANGO_SECRET_KEY=.*#DJANGO_SECRET_KEY=${SECRET}#" "$SRC/env/nmas-web.env.example" | grep -v '^#' > /etc/nmas/nmas-web.env
  unset SECRET
  chown root:"$RUN_GROUP" /etc/nmas/nmas-web.env; chmod 0640 /etc/nmas/nmas-web.env
  echo "created /etc/nmas/nmas-web.env (0640 root:$RUN_GROUP; secret not shown)"
fi

grep -q '^DJANGO_STATIC_ROOT=' /etc/nmas/nmas-web.env || echo 'DJANGO_STATIC_ROOT=/var/lib/nmas/static' >> /etc/nmas/nmas-web.env

install -m 0644 -o root -g root "$SRC/gunicorn/gunicorn.conf.py" /etc/nmas/gunicorn.conf.py
render "$SRC/systemd/nmas-web.service" /etc/systemd/system/nmas-web.service 0644
render "$SRC/apache/nmas-common.conf" /etc/apache2/nmas-common.conf 0644
render "$SRC/apache/nmas.conf" /etc/apache2/sites-available/nmas.conf 0644
a2ensite -q nmas >/dev/null

# Static files for Apache (DEBUG=false never serves them from Django), outside the home directory so no home
# permission is widened.  Owned by the run user, world-readable (public CSS/JS/artwork only).
install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" /var/lib/nmas /var/lib/nmas/static
sudo -u "$RUN_USER" bash -c "set -a; . /etc/nmas/nmas-web.env; set +a; cd '$DEPLOY_ROOT/web' && '$VENV/bin/python' manage.py collectstatic --noinput -v0"
# A deploy root older than V2 Phase 1 ignores DJANGO_STATIC_ROOT and collects into web/staticfiles: mirror it.
if [[ -z "$(ls -A /var/lib/nmas/static)" && -d "$DEPLOY_ROOT/web/staticfiles" ]]; then
  cp -a "$DEPLOY_ROOT/web/staticfiles/." /var/lib/nmas/static/
  chown -R "$RUN_USER:$RUN_GROUP" /var/lib/nmas/static
fi

apache2ctl configtest
systemctl daemon-reload
systemctl enable nmas-web.service >/dev/null
systemctl restart nmas-web.service
systemctl enable apache2 >/dev/null
systemctl reload-or-restart apache2

for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:8002/healthz" && break; sleep 1
done
curl -fsS "http://${LOCAL_LISTEN}/healthz" >/dev/null && echo "local vhost OK: http://${LOCAL_LISTEN}/"
curl -fsS "http://127.0.0.1:8081/healthz" >/dev/null && echo "tunnel vhost OK: http://127.0.0.1:8081/ (loopback only)"
systemctl --no-pager --lines=0 status nmas-web.service | head -3
