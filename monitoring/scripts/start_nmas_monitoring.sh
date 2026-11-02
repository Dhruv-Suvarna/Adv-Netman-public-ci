#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$REPO_DIR"
bash "$BASE_DIR/scripts/install_python_dependencies.sh"
"$PYTHON" -c 'from modules.nmas import validate_runtime; validate_runtime()'

RUNTIME_DIR="$BASE_DIR/runtime"
ENV_FILE="$RUNTIME_DIR/monitoring.env"
mkdir -p "$RUNTIME_DIR/influxdb2" "$RUNTIME_DIR/influxdb2-engine"
# UID/GID of the pinned Grafana image; retain the existing bind-mounted data.
sudo install -d -o 472 -g 0 -m 0750 "$RUNTIME_DIR/grafana"

if [[ ! -s "$ENV_FILE" ]]; then
    umask 077
    influx_token=$(openssl rand -hex 32)
    influx_password=$(openssl rand -hex 24)
    grafana_password=$(openssl rand -hex 24)
    cat > "$ENV_FILE" <<EOF
INFLUXDB_ADMIN_USER=nmas-admin
INFLUXDB_ADMIN_PASSWORD=$influx_password
INFLUXDB_ORG=csci5840
INFLUXDB_BUCKET=network-monitoring
INFLUXDB_TOKEN=$influx_token
GRAFANA_ADMIN_USER=nmas-admin
GRAFANA_ADMIN_PASSWORD=$grafana_password
EOF
    chmod 600 "$ENV_FILE"
fi

cd "$BASE_DIR"
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d --wait --wait-timeout 120
"$PYTHON" "$BASE_DIR/scripts/influxdb_retention.py" --apply
