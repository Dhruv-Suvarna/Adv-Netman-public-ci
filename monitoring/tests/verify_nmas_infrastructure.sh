#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="$BASE_DIR/runtime/monitoring.env"
PASS=0
FAIL=0

check() {
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        printf 'PASS: %s\n' "$label"
        PASS=$((PASS + 1))
    else
        printf 'FAIL: %s\n' "$label"
        FAIL=$((FAIL + 1))
    fi
}

source "$BASE_DIR/scripts/common.sh"

bound_only() {
    local protocol=$1 port=$2 endpoints
    endpoints=$(ss -H -ln"$protocol" | awk -v port="$port" '$4 ~ (":" port "$") {print $4}' | sort -u)
    [[ "$endpoints" == "192.168.200.100:$port" ]]
}

http_health() {
    "$PYTHON" - "$ENV_FILE" "$1" <<'PYTHON'
import sys
from pathlib import Path
import requests
session = requests.Session()
session.trust_env = False
kind = sys.argv[2]
if kind == "influxdb":
    url = "http://127.0.0.1:8086/health"
else:
    url = "http://127.0.0.1:3000/api/health"
if kind == "datasource":
    env = dict(line.split("=", 1) for line in Path(sys.argv[1]).read_text().splitlines() if "=" in line)
    session.auth = (env["GRAFANA_ADMIN_USER"], env["GRAFANA_ADMIN_PASSWORD"])
    url = "http://127.0.0.1:3000/api/datasources/uid/nmas-influxdb/health"
response = session.get(url, timeout=10)
response.raise_for_status()
data = response.json()
print(data)
ok = data.get("status") == "pass" if kind == "influxdb" else data.get("status") == "OK" if kind == "datasource" else data.get("database") == "ok"
raise SystemExit(0 if ok else 1)
PYTHON
}

container_healthy() {
    local id
    id=$(docker compose --env-file "$ENV_FILE" -f "$BASE_DIR/docker-compose.yml" ps -q "$1") || return
    [[ -n "$id" ]] || return 1
    [[ $(docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' "$id") == 'running healthy' ]]
}

check "rsyslog active" systemctl is-active --quiet rsyslog
check "Syslog UDP 514 bound only to 192.168.200.100" bound_only u 514
check "Syslog TCP 514 bound only to 192.168.200.100" bound_only t 514
check "snmptrapd active" systemctl is-active --quiet snmptrapd
check "SNMP trap UDP 162 bound only to 192.168.200.100" bound_only u 162
check "SNMP client tools" bash -c 'command -v snmpget && command -v snmpwalk && command -v snmptranslate'
check "Python dependency health" "$PYTHON" -m pip check
check "ncclient / NETCONF client" "$PYTHON" -c 'import ncclient; from ncclient import manager; print(ncclient.__version__)'
check "gNMI/gRPC client tooling" "$PYTHON" -c 'from pygnmi.client import gNMIclient; import grpc'
check "InfluxDB container healthy" container_healthy influxdb
check "InfluxDB HTTP health" http_health influxdb
check "InfluxDB 30-day retention" "$PYTHON" "$BASE_DIR/scripts/influxdb_retention.py"
check "Grafana running and healthy" container_healthy grafana
check "Grafana HTTP health" http_health grafana
check "Grafana InfluxDB datasource health" http_health datasource
logrotate_valid() {
    local output
    output=$(sudo -n logrotate -d /etc/logrotate.d/lab-monitoring 2>&1) || return
    # Some ignored-file errors are printed even when logrotate returns zero.
    ! grep -q '^error:' <<< "$output" && grep -q 'Handling 1 logs' <<< "$output"
}
check "Logrotate configuration valid" logrotate_valid
check "Installed logrotate policy matches repository" cmp "$BASE_DIR/config/lab-monitoring-logrotate" /etc/logrotate.d/lab-monitoring
check "Daily logrotate timer active" systemctl is-active --quiet logrotate.timer

if [[ -s "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    run_id="$(date +%s%N)"
    line="nmas_test,source=local,run_id=$run_id phase=\"infrastructure\",value=1i"
    check "InfluxDB synthetic write" curl --max-time 10 -fsS -XPOST "http://127.0.0.1:8086/api/v2/write?org=$INFLUXDB_ORG&bucket=$INFLUXDB_BUCKET&precision=s" -H "Authorization: Token $INFLUXDB_TOKEN" --data-raw "$line"
    query_synthetic() {
        local result
        result=$(curl --max-time 10 -fsS -XPOST "http://127.0.0.1:8086/api/v2/query?org=$INFLUXDB_ORG" -H "Authorization: Token $INFLUXDB_TOKEN" -H 'Content-Type: application/vnd.flux' --data "from(bucket: \"$INFLUXDB_BUCKET\") |> range(start: -5m) |> filter(fn: (r) => r._measurement == \"nmas_test\" and r.run_id == \"$run_id\" and r._field == \"value\" and r._value == 1)") || return
        grep -q "$run_id" <<< "$result"
    }
    check "InfluxDB synthetic query (same run, value=1)" query_synthetic
else
    printf 'FAIL: missing monitoring environment file\n'
    FAIL=$((FAIL + 1))
fi

printf 'SUMMARY: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
