#!/usr/bin/env bash
# NMAS V2 Phase 9 -- disposable, isolated DHCP relay option 82 fixture (cEOS relay -> ISC dhcpd, alpine DHCP client).
#
#   [CLIENT alpine]                 [RELAY cEOS 4.36.2F]                      [SVC nmas-ztp-svc:p3: ISC dhcpd]
#   eth1 (udhcpc) ============ Et1 10.254.90.1/24  ip helper 10.254.91.2
#                                   Et2 10.254.91.1/30 ===================== eth1 10.254.91.2/30
#
# Every container uses Docker's "none" network (no Containerlab bridge, no docker0, no route to the production lab, VLAN 200 or
# the host).  Links are point-to-point veth pairs created here; every name starts with nmas-p9-.  The relay starts WITHOUT
# option 82: NMAS renders, applies, reads back and compensates it.  `down` removes everything.
#
# Usage: fixture.sh up | down | status | cli <command> | client <cmd...> | svc <cmd...>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${NMAS_P9_FX_RUNTIME:-$HERE/runtime}"
CEOS_IMAGE="${NMAS_P9_FX_CEOS_IMAGE:-ceos:4.36.2F}"
SVC_IMAGE="${NMAS_P9_FX_SVC_IMAGE:-nmas-ztp-svc:p3}"
P="nmas-p9"
CEOS_ENV=(-e CEOS=1 -e EOS_PLATFORM=ceoslab -e container=docker -e INTFTYPE=eth -e ETBA=1
          -e SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 -e MAPETH0=0)
CEOS_INIT=(/sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1
           systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab systemd.setenv=container=docker systemd.setenv=MAPETH0=0)

pid_of() { docker inspect -f '{{.State.Pid}}' "$1"; }
ns() { local pid; pid=$(pid_of "$1"); shift; sudo -n nsenter -t "$pid" -n "$@"; }

veth() {  # veth <tag> <containerA> <ifA> <containerB> <ifB>
  local a b; a=$(pid_of "$2"); b=$(pid_of "$4")
  local ta="$P-$1a" tb="$P-$1b"
  sudo -n ip link add "$ta" type veth peer name "$tb"
  sudo -n ip link set "$ta" netns "$a"; sudo -n ip link set "$tb" netns "$b"
  sudo -n nsenter -t "$a" -n ip link set "$ta" name "$3"; sudo -n nsenter -t "$b" -n ip link set "$tb" name "$5"
  sudo -n nsenter -t "$a" -n ip link set "$3" up; sudo -n nsenter -t "$b" -n ip link set "$5" up
  sudo -n nsenter -t "$a" -n ethtool -K "$3" tx off >/dev/null; sudo -n nsenter -t "$b" -n ethtool -K "$5" tx off >/dev/null
}

up() {
  mkdir -p "$RUNTIME/relay-flash" "$RUNTIME/dhcp"
  cat > "$RUNTIME/relay-flash/startup-config" <<'CFG'
! NMAS V2 Phase 9 isolated option-82 fixture -- relay (fixture infrastructure)
hostname P9RELAY
!
ip routing
!
interface Ethernet1
   description downstream bootstrap port (client side)
   no switchport
   ip address 10.254.90.1/24
   ip helper-address 10.254.91.2
!
interface Ethernet2
   description NMAS bootstrap service
   no switchport
   ip address 10.254.91.1/30
!
end
CFG
  printf 'DISABLE=True\n' > "$RUNTIME/relay-flash/zerotouch-config"
  printf 'SERIALNUMBER=P9RELAY01\nSYSTEMMACADDR=02:5a:79:00:00:01\n' > "$RUNTIME/relay-flash/ceos-config"
  docker run -d --name "$P-relay-ns" --network none alpine:latest sleep infinity >/dev/null
  docker run -d --name "$P-client" --network none alpine:latest sleep infinity >/dev/null
  docker run -d --name "$P-svc" --network none -v "$RUNTIME/dhcp:/srv/dhcp" "$SVC_IMAGE" >/dev/null
  veth 1 "$P-client" eth1 "$P-relay-ns" eth1
  veth 2 "$P-relay-ns" eth2 "$P-svc" eth1
  ns "$P-svc" ip addr add 10.254.91.2/30 dev eth1
  ns "$P-svc" ip route add 10.254.90.0/24 via 10.254.91.1
  ns "$P-client" ip link set eth1 address 02:5a:79:00:00:99
  docker run -d --name "$P-relay" --privileged --network "container:$P-relay-ns" "${CEOS_ENV[@]}" \
    -v "$RUNTIME/relay-flash:/mnt/flash" "$CEOS_IMAGE" "${CEOS_INIT[@]}" >/dev/null
  echo "fixture up: $P-relay (cEOS), $P-svc (10.254.91.2), $P-client"
}

down() {
  for c in "$P-relay" "$P-client" "$P-svc" "$P-relay-ns"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for l in $(ip -o link | awk -F': ' '{print $2}' | cut -d@ -f1 | grep "^$P-" || true); do sudo -n ip link del "$l" || true; done
  sudo -n rm -rf "$RUNTIME"
  echo "fixture down"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) docker ps -a --filter "name=$P-" --format '{{.Names}} {{.Status}}' ;;
  cli) shift; docker exec "$P-relay" Cli -p 15 -c "$*" ;;
  client) shift; docker exec "$P-client" "$@" ;;
  svc) shift; docker exec "$P-svc" "$@" ;;
  *) echo "usage: $0 up|down|status|cli|client|svc" >&2; exit 2 ;;
esac
