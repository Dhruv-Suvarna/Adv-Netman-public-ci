#!/usr/bin/env bash
# NMAS V2 Phase 8 -- a DISPOSABLE InfluxDB 2 + Grafana pair for the dynamic-telemetry live proof, inside the fixture's NMAS
# network namespace only (``--network container:nmas-mgmt-p4-nmas``): both listen on that namespace's loopback, so the
# fixture's NMAS process reaches them at 127.0.0.1 and nothing else can.  No host port is published; the production
# monitoring stack (monitoring-influxdb-1 / monitoring-grafana-1) is never touched.
#
# Grafana provisions the REPOSITORY's dashboards read-only (monitoring/grafana/provisioning/dashboards) and a fixture
# datasource with the production uid ``nmas-influxdb`` pointing at 127.0.0.1:8086.  The bucket is named like production's
# (``network-monitoring``) because the provisioned dashboards query it by name.  Credentials are random, generated into
# runtime/tsdb/ (git-ignored) and destroyed by ``down``.
#
# Usage: tsdb.sh up | down | env        (env prints NMAS_P8_INFLUX_* / NMAS_P8_GRAFANA_* assignments for the harness)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUNTIME="${NMAS_MGMT_FX_RUNTIME:-$HERE/runtime}/tsdb"
NS="nmas-mgmt-p4-nmas"
INFLUX="nmas-p8-influx"; GRAFANA="nmas-p8-grafana"
ORG="nmas-p8"; BUCKET="network-monitoring"

up() {
  docker inspect "$NS" >/dev/null 2>&1 || { echo "fixture namespace $NS is not running (fixture.sh up first)" >&2; exit 1; }
  mkdir -p "$RUNTIME/datasources"; chmod 700 "$RUNTIME"
  [ -f "$RUNTIME/token" ] || openssl rand -hex 32 > "$RUNTIME/token"
  [ -f "$RUNTIME/admin" ] || openssl rand -hex 16 > "$RUNTIME/admin"
  chmod 600 "$RUNTIME/token" "$RUNTIME/admin"
  cat > "$RUNTIME/datasources/influxdb.yml" <<EOF
apiVersion: 1
datasources:
  - name: NMAS InfluxDB
    uid: nmas-influxdb
    type: influxdb
    access: proxy
    url: http://127.0.0.1:8086
    isDefault: true
    editable: false
    jsonData:
      version: Flux
      organization: $ORG
      defaultBucket: $BUCKET
    secureJsonData:
      token: \$__env{INFLUXDB_TOKEN}
EOF
  chmod 644 "$RUNTIME/datasources/influxdb.yml"
  docker run -d --name "$INFLUX" --network "container:$NS" \
    -e DOCKER_INFLUXDB_INIT_MODE=setup -e DOCKER_INFLUXDB_INIT_USERNAME=p8admin \
    -e DOCKER_INFLUXDB_INIT_PASSWORD="$(cat "$RUNTIME/admin")" -e DOCKER_INFLUXDB_INIT_ORG="$ORG" \
    -e DOCKER_INFLUXDB_INIT_BUCKET="$BUCKET" -e DOCKER_INFLUXDB_INIT_ADMIN_TOKEN="$(cat "$RUNTIME/token")" \
    influxdb:2.7.11 >/dev/null
  docker run -d --name "$GRAFANA" --network "container:$NS" \
    -e GF_SERVER_HTTP_ADDR=127.0.0.1 -e GF_SERVER_HTTP_PORT=3000 -e GF_SECURITY_ADMIN_USER=p8admin \
    -e GF_SECURITY_ADMIN_PASSWORD="$(cat "$RUNTIME/admin")" -e INFLUXDB_TOKEN="$(cat "$RUNTIME/token")" \
    -e GF_ANALYTICS_REPORTING_ENABLED=false -e GF_ANALYTICS_CHECK_FOR_UPDATES=false \
    -v "$REPO/monitoring/grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards:ro" \
    -v "$RUNTIME/datasources:/etc/grafana/provisioning/datasources:ro" \
    grafana/grafana:11.5.2 >/dev/null
  echo "tsdb up: $INFLUX / $GRAFANA in $NS (127.0.0.1:8086, 127.0.0.1:3000)"
}

down() {
  docker rm -f "$INFLUX" "$GRAFANA" >/dev/null 2>&1 || true
  rm -rf "$RUNTIME"
  echo "tsdb down"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  env) printf 'NMAS_P8_INFLUX_URL=http://127.0.0.1:8086\nNMAS_P8_INFLUX_ORG=%s\nNMAS_P8_INFLUX_BUCKET=%s\nNMAS_P8_TSDB_RUNTIME=%s\n' "$ORG" "$BUCKET" "$RUNTIME" ;;
  *) echo "usage: $0 up|down|env" >&2; exit 2 ;;
esac
