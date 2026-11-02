#!/usr/bin/env bash
# Install cloudflared and the NMAS website tunnel unit (V2 Phase 1).  Website-only; no device integration.
#
#   sudo deploy/scripts/install_cloudflared.sh                # install package + unit (does not start it)
#
# Cloudflare ACCOUNT authorization is an explicit, interactive operator step this script never fakes:
#   1. cloudflared tunnel login                               (browser; writes ~/.cloudflared/cert.pem)
#   2. cloudflared tunnel create nmas                         (writes ~/.cloudflared/<UUID>.json -- a secret)
#   3. sudo install -d -m 0700 /etc/cloudflared && sudo install -m 0600 ~/.cloudflared/<UUID>.json /etc/cloudflared/
#   4. render deploy/cloudflared/config.yml.example to /etc/cloudflared/config.yml (UUID + hostname)
#   5. cloudflared tunnel route dns nmas <hostname>
#   6. sudo systemctl enable --now cloudflared-nmas.service
#   7. add https://<hostname> to DJANGO_CSRF_TRUSTED_ORIGINS / DJANGO_ALLOWED_HOSTS in /etc/nmas/nmas-web.env;
#      sudo systemctl restart nmas-web
#   8. (recommended) Cloudflare Zero Trust -> Access application for <hostname> (email OTP / IdP policy).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(dpkg --print-architecture)"
if ! command -v cloudflared >/dev/null; then
  TMP="$(mktemp -d)"
  curl -fsSL -o "$TMP/cloudflared.deb" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
  dpkg -i "$TMP/cloudflared.deb" >/dev/null
  rm -rf "$TMP"
fi
cloudflared --version
install -m 0644 -o root -g root "$SRC/cloudflared/cloudflared-nmas.service" /etc/systemd/system/cloudflared-nmas.service
install -d -m 0700 -o root -g root /etc/cloudflared
systemctl daemon-reload
if [[ -f /etc/cloudflared/config.yml ]]; then
  cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate
else
  echo "No /etc/cloudflared/config.yml yet: complete the account authorization steps in this script's header."
fi
