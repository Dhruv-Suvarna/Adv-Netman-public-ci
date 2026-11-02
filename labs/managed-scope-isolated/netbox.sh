#!/usr/bin/env bash
# PR #69 live acceptance -- a DISPOSABLE NetBox (same pinned images as netbox/docker-compose.yml) for the managed-scope proof.
#
# Nothing here touches the production NetBox stack ("netbox" Compose project, 127.0.0.1:8000, its volumes or network):
#   * own container names (nmas-p69-nb-*), own bridge network (nmas-p69-nb), no named volumes (state dies with `down`);
#   * the API is published on 127.0.0.1:18069 only, for the host-side seeding;
#   * `link <netns-pid>` adds one point-to-point veth from the NetBox container into a fixture namespace
#     (10.254.69.1/30 fixture side, 10.254.69.2/30 NetBox side) -- the only path the live harness has to it;
#   * secrets and the API token are generated into runtime/ (git-ignored, mode 600) and destroyed by `down`.
#
# The model is seeded with the repository's own netbox/scripts/populate_netbox.py --apply against THIS instance, so the
# managed-scope authority (ownership tag, `managed` / `unmanaged` tags, the `iac_managed` custom field, device types and roles)
# is exactly what production NetBox carries -- nothing is hand-made for the test.
#
# Usage: netbox.sh up | finish (resume: wait, token, seed) | down | status | env | link <netns-pid> | prefixes
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUNTIME="${NMAS_P69_RUNTIME:-$HERE/runtime}"
PY="${NMAS_PYTHON:-/home/student/Scripts/.venv-ci/bin/python}"
P="nmas-p69-nb"
NET="$P"
HOST_PORT=18069
IMAGE_NETBOX="docker.io/netboxcommunity/netbox:v4.7-5.1.1"
IMAGE_PG="docker.io/postgres:18-alpine"
IMAGE_KV="docker.io/valkey/valkey:9.1-alpine"
FX_LOCAL=10.254.69.1; FX_NETBOX=10.254.69.2

secrets() {
  [ -f "$RUNTIME/netbox.env" ] && return 0
  mkdir -p "$RUNTIME"; umask 077
  local pg kv kvc key pepper admin
  pg=$(openssl rand -hex 24); kv=$(openssl rand -hex 24); kvc=$(openssl rand -hex 24)
  key=$(openssl rand -hex 32); pepper=$(openssl rand -hex 32); admin=$(openssl rand -hex 16)
  cat > "$RUNTIME/netbox.env" <<EOF
POSTGRES_DB=netbox
POSTGRES_USER=netbox
POSTGRES_PASSWORD=$pg
DB_NAME=netbox
DB_USER=netbox
DB_PASSWORD=$pg
DB_HOST=$P-postgres
REDIS_HOST=$P-redis
REDIS_PASSWORD=$kv
REDIS_CACHE_HOST=$P-redis-cache
REDIS_CACHE_PASSWORD=$kvc
SECRET_KEY=$key
API_TOKEN_PEPPER_1=$pepper
SKIP_SUPERUSER=false
SUPERUSER_NAME=nmas-p69-admin
SUPERUSER_EMAIL=nmas-p69-admin@example.invalid
SUPERUSER_PASSWORD=$admin
EOF
  chmod 600 "$RUNTIME/netbox.env"
}

envval() { sed -n "s/^$1=//p" "$RUNTIME/netbox.env"; }

wait_healthy() {
  local i
  for i in $(seq 1 300); do   # a fresh NetBox applies its whole migration history on first start (10+ minutes)
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$P-netbox" 2>/dev/null)" = healthy ] && return 0
    sleep 4
  done
  echo "NetBox did not become healthy" >&2; return 1
}

token() {
  [ -f "$RUNTIME/client.env" ] && return 0
  local user out value
  user=$(envval SUPERUSER_NAME)
  out=$(docker exec "$P-netbox" /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell -c "
import json
from django.contrib.auth import get_user_model
from users.models import Token
user = get_user_model().objects.get(username='$user')
token = Token.objects.create(user=user)
print('P69_TOKEN ' + (f'nbt_{token.key}.{token.token}' if token.v2 else token.token))
")
  value=$(printf '%s\n' "$out" | sed -n 's/^P69_TOKEN //p')
  [ -n "$value" ] || { echo "token creation failed" >&2; return 1; }
  umask 077
  printf 'NETBOX_URL=http://127.0.0.1:%s\nNETBOX_TOKEN=%s\nNETBOX_TIMEOUT=15\nNETBOX_VERIFY_SSL=true\n' "$HOST_PORT" "$value" > "$RUNTIME/client.env"
  printf 'NETBOX_URL=http://%s:8080\nNETBOX_TOKEN=%s\nNETBOX_TIMEOUT=15\nNETBOX_VERIFY_SSL=true\n' "$FX_NETBOX" "$value" > "$RUNTIME/fixture-client.env"
  chmod 600 "$RUNTIME/client.env" "$RUNTIME/fixture-client.env"
}

seed() {  # the repository's own NetBox model, applied to THIS instance only (the URL is set explicitly; netbox/.env is never read)
  set -a; . "$RUNTIME/client.env"; set +a
  case "$NETBOX_URL" in "http://127.0.0.1:$HOST_PORT") ;; *) echo "refusing to seed $NETBOX_URL" >&2; exit 1 ;; esac
  (cd "$REPO" && "$PY" netbox/scripts/populate_netbox.py --apply) > "$RUNTIME/seed.log" 2>&1 \
    || { tail -20 "$RUNTIME/seed.log" >&2; return 1; }
  tail -3 "$RUNTIME/seed.log"
  prefixes
}

prefixes() {  # the fixture's own networks, as the operator's IPAM records them (a non-disposable reservation requires its prefix)
  set -a; . "$RUNTIME/client.env"; set +a
  case "$NETBOX_URL" in "http://127.0.0.1:$HOST_PORT") ;; *) echo "refusing $NETBOX_URL" >&2; exit 1 ;; esac
  (cd "$REPO" && "$PY" -c '
import sys
from modules import netbox_ipam as nb
client = nb.build_client()
for prefix in sys.argv[1:]:
    if not list(client.ipam.prefixes.filter(prefix=prefix)):
        client.ipam.prefixes.create(prefix=prefix, status="active", description="PR #69 isolated fixture network")
    print("prefix", prefix)
' 10.254.60.0/24 10.254.64.0/24 10.254.255.0/24)
}

up() {
  secrets
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  local kv kvc
  kv=$(envval REDIS_PASSWORD); kvc=$(envval REDIS_CACHE_PASSWORD)
  docker run -d --name "$P-postgres" --network "$NET" --env-file "$RUNTIME/netbox.env" \
    --health-cmd 'pg_isready -q -t 2 -d netbox -U netbox' --health-interval 5s "$IMAGE_PG" >/dev/null
  docker run -d --name "$P-redis" --network "$NET" -e REDIS_PASSWORD="$kv" "$IMAGE_KV" \
    sh -c 'valkey-server --requirepass "$REDIS_PASSWORD"' >/dev/null
  docker run -d --name "$P-redis-cache" --network "$NET" -e REDIS_PASSWORD="$kvc" "$IMAGE_KV" \
    sh -c 'valkey-server --requirepass "$REDIS_PASSWORD"' >/dev/null
  local i
  for i in $(seq 1 30); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$P-postgres")" = healthy ] && break; sleep 2
  done
  docker run -d --name "$P-netbox" --network "$NET" --env-file "$RUNTIME/netbox.env" -p "127.0.0.1:$HOST_PORT:8080" \
    -v "$REPO/netbox/configuration:/etc/netbox/config:ro" \
    --health-cmd /opt/netbox/health.sh --health-interval 10s --health-start-period 90s "$IMAGE_NETBOX" >/dev/null
  wait_healthy
  token
  seed
  echo "disposable NetBox up: http://127.0.0.1:$HOST_PORT (host), http://$FX_NETBOX:8080 after \`link\`"
}

link() {  # link <netns-pid>: one veth from the NetBox container into a fixture namespace
  local target="$1" nbpid
  nbpid=$(docker inspect -f '{{.State.Pid}}' "$P-netbox")
  sudo -n nsenter -t "$target" -n ip link show nbx0 >/dev/null 2>&1 && { echo "already linked"; return 0; }
  sudo -n ip link add p69nbA type veth peer name p69nbB
  sudo -n ip link set p69nbA netns "$target"; sudo -n ip link set p69nbB netns "$nbpid"
  sudo -n nsenter -t "$target" -n ip link set p69nbA name nbx0
  sudo -n nsenter -t "$nbpid" -n ip link set p69nbB name nbx0
  sudo -n nsenter -t "$target" -n ip addr add "$FX_LOCAL/30" dev nbx0
  sudo -n nsenter -t "$nbpid" -n ip addr add "$FX_NETBOX/30" dev nbx0
  sudo -n nsenter -t "$target" -n ip link set nbx0 up; sudo -n nsenter -t "$nbpid" -n ip link set nbx0 up
  echo "linked: fixture $FX_LOCAL <-> NetBox $FX_NETBOX"
}

down() {
  for c in netbox redis-cache redis postgres; do docker rm -f "$P-$c" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$RUNTIME"
  echo "disposable NetBox removed"
}

status() { docker ps -a --filter "name=$P-" --format '{{.Names}} {{.Status}}'; }

case "${1:-}" in
  up) up ;; down) down ;; status) status ;;
  env) cat "$RUNTIME/client.env" | sed 's/^NETBOX_TOKEN=.*/NETBOX_TOKEN=<set>/' ;;
  link) link "${2:?netns pid}" ;;
  finish) wait_healthy; token; seed ;;
  prefixes) prefixes ;;
  *) echo "usage: $0 up|down|status|env|link <netns-pid>" >&2; exit 2 ;;
esac
