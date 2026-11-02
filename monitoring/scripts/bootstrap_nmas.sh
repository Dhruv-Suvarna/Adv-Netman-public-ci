#!/usr/bin/env bash
set -euo pipefail
# Supported bootstrap target: Ubuntu 24.04 with systemd and sudo privileges.
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo "Supported NMAS host: Ubuntu 24.04" >&2; exit 1; }
sudo -n true || { echo "Run sudo -v before provisioning (or configure noninteractive sudo)." >&2; exit 1; }
missing=()
for package in python3-venv snmp snmptrapd rsyslog logrotate curl openssl iproute2 ca-certificates; do
    [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) == 'install ok installed' ]] || missing+=("$package")
done
if ! command -v docker >/dev/null; then
    missing+=(docker.io docker-compose-v2)
elif ! docker compose version >/dev/null 2>&1; then
    # Respect an existing Docker CE installation instead of replacing its engine.
    if dpkg-query -W -f='${Status}' docker-ce 2>/dev/null | grep -q 'install ok installed'; then
        missing+=(docker-compose-plugin)
    else
        missing+=(docker-compose-v2)
    fi
fi
if ((${#missing[@]})); then
    sudo -n apt-get update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
fi
sudo -n systemctl enable docker.service logrotate.timer
sudo -n systemctl start docker.service logrotate.timer
sudo -n docker info >/dev/null
sudo -n docker compose version
