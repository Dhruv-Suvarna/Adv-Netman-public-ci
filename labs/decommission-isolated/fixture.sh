#!/usr/bin/env bash
# NMAS V2 Phase 7 (+8) -- disposable, isolated decommission / restoration fixture.  Never touches the production lab.
#
#   [HA alpine]                 [E1 cEOS]                [T1 cEOS: preferred transit]               [E2 cEOS]               [HB alpine]
#   eth1 10.254.80.10/24 ---- Et1 10.254.80.1/24  Et2 10.254.81.0/31 ---- Et1  Et2 10.254.83.0/31 ---- Et2 10.254.83.1/31
#        2001:db8:254:80::10                     Et3 10.254.82.0/31 ---- [T2 cEOS: alternate, cost 100] ---- Et3 10.254.84.1/31
#                                                                                                          Et1 10.254.85.1/24 ---- eth1 10.254.85.10/24
#                                                                                                          Et4 10.254.86.0/31 ---- Et1 [STUB cEOS]
#
# OSPFv2 + OSPFv3 area 0 everywhere; T2's links cost 100, so the production flow HA <-> HB takes T1 and T2 is the existing,
# verified alternate (no new drain mechanism is introduced; the transition is OSPF's own stub-router function).  STUB carries no
# production traffic and has no redundancy (the quiescent case).  E2 is HB's only gateway (the active, non-redundant case).
#
# Management: every router's Ethernet5 sits on a private bridge inside the NMAS namespace ($P-nmas, 10.254.70.100/24); the
# harness runs in that namespace.  Every container uses Docker's "none" network: no Containerlab bridge, no docker0, no route to
# the production lab, its VLAN 200 or the host.  Keys are generated into runtime/ (git-ignored) and destroyed by `down`.
#
# Usage: fixture.sh up | down | status | nmas-pid | cli <node> <command> | host <ha|hb> <cmd...> | hostkey <node>
#                   | mgmt <node> up|down     (the router's management link on NMAS's bridge: a real management-path outage)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${NMAS_P7_FX_RUNTIME:-$HERE/runtime}"
CEOS_IMAGE="${NMAS_P7_FX_CEOS_IMAGE:-ceos:4.36.2F}"
P="nmas-p7"
NODES="e1 t1 t2 e2 stub"
CEOS_ENV=(-e CEOS=1 -e EOS_PLATFORM=ceoslab -e container=docker -e INTFTYPE=eth -e ETBA=1
          -e SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 -e MAPETH0=0)
CEOS_INIT=(/sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1
           systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab systemd.setenv=container=docker systemd.setenv=MAPETH0=0)

pid_of() { docker inspect -f '{{.State.Pid}}' "$1"; }
ns() { local pid; pid=$(pid_of "$1"); shift; sudo -n nsenter -t "$pid" -n "$@"; }

veth() {  # veth <containerA> <ifA> <containerB> <ifB>
  local a b; a=$(pid_of "$1"); b=$(pid_of "$3")
  local ta="p7${RANDOM}a" tb="p7${RANDOM}b"
  sudo -n ip link add "$ta" type veth peer name "$tb"
  sudo -n ip link set "$ta" netns "$a"; sudo -n ip link set "$tb" netns "$b"
  sudo -n nsenter -t "$a" -n ip link set "$ta" name "$2"; sudo -n nsenter -t "$b" -n ip link set "$tb" name "$4"
  sudo -n nsenter -t "$a" -n ip link set "$2" up; sudo -n nsenter -t "$b" -n ip link set "$4" up
  # cEOS (ETBA) forwards in software and does not complete partial checksums
  sudo -n nsenter -t "$a" -n ethtool -K "$2" tx off >/dev/null; sudo -n nsenter -t "$b" -n ethtool -K "$4" tx off >/dev/null
}

holder() { docker run -d --name "$1" --network none --restart unless-stopped alpine:latest sleep infinity >/dev/null; }

users_block() {  # fixture-admin: setup / out-of-band console stand-in only; nmas-svc: NMAS's machine identity (key only)
  local hash; hash=$(openssl passwd -6 "$(openssl rand -hex 24)")
  cat <<EOF
aaa authorization exec default local
!
username fixture-admin privilege 15 role network-admin secret sha512 $hash
username fixture-admin ssh-key $(cut -d' ' -f1-2 "$RUNTIME/keys/fixture-admin.pub") fixture-admin
username nmas-svc privilege 15 role network-admin secret sha512 $hash
username nmas-svc ssh-key $(cut -d' ' -f1-2 "$RUNTIME/keys/nmas-svc.pub") nmas-svc
!
EOF
}

router_body() {  # router_body <loopback octet> <mgmt octet> <ospf cost lines...>: the common part
  cat <<EOF
ip routing
ipv6 unicast-routing
!
interface Ethernet5
   description NMAS management (fixture)
   no switchport
   ip address 10.254.70.$2/24
!
interface Loopback0
   ip address 10.254.255.$1/32
   ipv6 address 2001:db8:254:255::$1/128
   ipv6 ospf 1 area 0.0.0.0
!
EOF
}

p2p() {  # p2p <ifname> <v4/31> <v6 suffix> <description> [cost]
  printf 'interface %s\n   description %s\n   no switchport\n   ip address %s\n   ipv6 address %s\n   ipv6 ospf 1 area 0.0.0.0\n' "$1" "$4" "$2" "$3"
  if [ -n "${5:-}" ]; then printf '   ip ospf cost %s\n   ipv6 ospf cost %s\n' "$5" "$5"; fi
  printf '!\n'
}

ospf() {  # ospf <router-id> <networks...>
  local rid=$1; shift
  printf 'router ospf 1\n   router-id %s\n' "$rid"
  for n in "$@"; do printf '   network %s area 0.0.0.0\n' "$n"; done
  printf '!\nipv6 router ospf 1\n   router-id %s\n!\n' "$rid"
}

startup() {  # startup <node> <hostname> <body file>
  mkdir -p "$RUNTIME/$1-flash"
  { printf '! NMAS V2 Phase 7 isolated fixture -- %s\nhostname %s\n!\n' "$2" "$2"
    cat "$3"; users_block; printf 'management ssh\n!\nend\n'; } > "$RUNTIME/$1-flash/startup-config"
  printf 'DISABLE=True\n' > "$RUNTIME/$1-flash/zerotouch-config"
}

ceos() {  # ceos <node> <serial> <mac>
  printf 'SERIALNUMBER=%s\nSYSTEMMACADDR=%s\n' "$2" "$3" > "$RUNTIME/$1-flash/ceos-config"
  docker run -d --name "$P-$1" --privileged --network "container:$P-$1-ns" --restart unless-stopped "${CEOS_ENV[@]}" \
    -v "$RUNTIME/$1-flash:/mnt/flash" "$CEOS_IMAGE" "${CEOS_INIT[@]}" >/dev/null
}

up() {
  mkdir -p "$RUNTIME/keys"
  for k in fixture-admin nmas-svc; do
    [ -f "$RUNTIME/keys/$k" ] || ssh-keygen -q -t ed25519 -N '' -C "$k@nmas-p7-fixture" -f "$RUNTIME/keys/$k"
  done
  local body; body=$(mktemp -d)
  { router_body 1 1; p2p Ethernet1 10.254.80.1/24 2001:db8:254:80::1/64 "production LAN (HA)"
    p2p Ethernet2 10.254.81.0/31 2001:db8:254:81::0/127 "to T1"; p2p Ethernet3 10.254.82.0/31 2001:db8:254:82::0/127 "to T2" 100
    ospf 10.254.255.1 10.254.80.0/24 10.254.81.0/31 10.254.82.0/31 10.254.255.1/32; } > "$body/e1"
  { router_body 2 2; p2p Ethernet1 10.254.81.1/31 2001:db8:254:81::1/127 "to E1"; p2p Ethernet2 10.254.83.0/31 2001:db8:254:83::0/127 "to E2"
    ospf 10.254.255.2 10.254.81.0/31 10.254.83.0/31 10.254.255.2/32; } > "$body/t1"
  { router_body 3 3; p2p Ethernet1 10.254.82.1/31 2001:db8:254:82::1/127 "to E1" 100; p2p Ethernet2 10.254.84.0/31 2001:db8:254:84::0/127 "to E2" 100
    ospf 10.254.255.3 10.254.82.0/31 10.254.84.0/31 10.254.255.3/32; } > "$body/t2"
  { router_body 4 4; p2p Ethernet1 10.254.85.1/24 2001:db8:254:85::1/64 "production LAN (HB)"
    p2p Ethernet2 10.254.83.1/31 2001:db8:254:83::1/127 "to T1"; p2p Ethernet3 10.254.84.1/31 2001:db8:254:84::1/127 "to T2" 100
    p2p Ethernet4 10.254.86.0/31 2001:db8:254:86::0/127 "to STUB"
    ospf 10.254.255.4 10.254.85.0/24 10.254.83.0/31 10.254.84.0/31 10.254.86.0/31 10.254.255.4/32; } > "$body/e2"
  { router_body 5 5; p2p Ethernet1 10.254.86.1/31 2001:db8:254:86::1/127 "to E2"
    ospf 10.254.255.5 10.254.86.0/31 10.254.255.5/32; } > "$body/stub"
  # the OSPFv3 interface statements need the process; the IPv6 LAN interfaces join area 0 too
  local i=1
  for n in $NODES; do
    startup "$n" "P7$(echo "$n" | tr a-z A-Z)" "$body/$n"; holder "$P-$n-ns"; i=$((i + 1))
  done
  rm -rf "$body"
  holder "$P-ha"; holder "$P-hb"; holder "$P-nmas"
  veth "$P-ha" eth1 "$P-e1-ns" eth1
  veth "$P-e1-ns" eth2 "$P-t1-ns" eth1
  veth "$P-e1-ns" eth3 "$P-t2-ns" eth1
  veth "$P-t1-ns" eth2 "$P-e2-ns" eth2
  veth "$P-t2-ns" eth2 "$P-e2-ns" eth3
  veth "$P-e2-ns" eth4 "$P-stub-ns" eth1
  veth "$P-e2-ns" eth1 "$P-hb" eth1
  ns "$P-nmas" ip link add br0 type bridge
  ns "$P-nmas" ip link set br0 up
  ns "$P-nmas" ip addr add 10.254.70.100/24 dev br0
  for n in $NODES; do
    veth "$P-nmas" "m-$n" "$P-$n-ns" eth5
    ns "$P-nmas" ip link set "m-$n" master br0
  done
  ns "$P-ha" ip addr add 10.254.80.10/24 dev eth1
  ns "$P-ha" ip -6 addr add 2001:db8:254:80::10/64 dev eth1 nodad
  ns "$P-ha" ip route add default via 10.254.80.1
  ns "$P-ha" ip -6 route add default via 2001:db8:254:80::1
  ns "$P-hb" ip addr add 10.254.85.10/24 dev eth1
  ns "$P-hb" ip -6 addr add 2001:db8:254:85::10/64 dev eth1 nodad
  ns "$P-hb" ip route add default via 10.254.85.1
  ns "$P-hb" ip -6 route add default via 2001:db8:254:85::1
  local s=1
  for n in $NODES; do ceos "$n" "P7FX$(echo "$n" | tr a-z A-Z)" "02:5a:77:00:00:0$s"; s=$((s + 1)); done
  echo "fixture up: $P-{e1,t1,t2,e2,stub} (cEOS), hosts $P-ha / $P-hb, NMAS namespace $P-nmas (10.254.70.100)"
}

down() {
  docker rm -f $(docker ps -aq --filter "name=^$P-") >/dev/null 2>&1 || true
  sudo -n rm -rf "$RUNTIME"
  echo "fixture down"
}

status() { docker ps -a --filter "name=^$P-" --format '{{.Names}} {{.Status}} {{.Networks}}'; }
hostkey() { docker exec "$P-$1" Cli -A -p 15 -c "show management ssh hostkey ed25519 public" | awk '/ssh-ed25519/ {print $1" "$2}'; }
cli() { docker exec "$P-$1" Cli -A -p 15 -c "$2"; }
host() { local which=$1; shift; ns "$P-$which" "$@"; }

case "${1:-}" in
  up) up ;; down) down ;; status) status ;;
  nmas-pid) pid_of "$P-nmas" ;;
  cli) cli "${2:?}" "${3:?}" ;;
  hostkey) hostkey "${2:?}" ;;
  host) shift; host "$@" ;;
  mgmt) case "${3:-}" in up|down) ns "$P-nmas" ip link set "m-${2:?}" "$3" ;; *) echo "usage: $0 mgmt <node> up|down" >&2; exit 2 ;; esac ;;
  *) echo "usage: $0 up|down|status|nmas-pid|cli <node> <cmd>|hostkey <node>|host <ha|hb> <cmd...>|mgmt <node> up|down" >&2; exit 2 ;;
esac
