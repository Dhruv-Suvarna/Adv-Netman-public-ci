#!/usr/bin/env bash
# NMAS V2 Phases 5 + 6 -- disposable, isolated trusted-upstream isolation / commissioning / admission fixture.
#
#   [PROD alpine]                [CORE cEOS]                    [UP1 cEOS: trusted upstream]                 [NEW1 cEOS: factory default]
#   eth1 10.254.63.10/24 --- Et2 10.254.63.1/24                 Et1 10.254.60.1/24  (bootstrap port A) ===== Et1  (native ZTP)
#        2001:db8:254:63::10  Et1 10.254.62.2/30 ---------- Et3 10.254.62.1/30   ip helper 10.254.61.2      Et2 (bootstrap port B, after
#                               OSPF area 0                      OSPF area 0 (covers Et1: suppressed            commissioning) ===== Et1 [NEW2 cEOS]
#                                                                 by isolation until admission)
#                                                                Et2 10.254.61.1/30 --- eth1 [SVC: ISC dhcpd + NMAS bootstrap service;
#                                                                                                 the NMAS harness runs in this namespace]
#                                                                                               10.254.61.2/30
#
# Before a new device is attached, its bootstrap port is plugged into a PROBE namespace (alpine) that stands in for a hostile
# device: the isolation policy is verified against it (traffic to production, to the upstream's own services, routing hellos)
# BEFORE any untrusted device exists.  `attach new1|new2` then moves that very link into the new device's namespace and starts
# the factory-default cEOS (ZTP enabled; no startup-config, no user, no key).
#
# Every container uses Docker's "none" network: no Containerlab management bridge, no docker0, no route to the production lab,
# its VLAN 200 or the host.  Links are point-to-point veth pairs created here.  Fixture keys (fixture-admin for setup only,
# nmas-svc for NMAS) are generated into runtime/ (git-ignored) and destroyed by `down`.
#
# Usage: fixture.sh up | down | status | svc-pid | attach <new1|new2> | hostkey <up|new1|new2> | probe <a|b> <cmd...>
#        | prod <cmd...> | cli <up|core|new1|new2> <command> | capture-start <name> <ns> <if> | capture-stop <name>
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${NMAS_ISO_FX_RUNTIME:-$HERE/runtime}"
CEOS_IMAGE="${NMAS_ISO_FX_CEOS_IMAGE:-ceos:4.36.2F}"
SVC_IMAGE="${NMAS_ISO_FX_SVC_IMAGE:-nmas-ztp-svc:p3}"
P="nmas-iso-p56"
CEOS_ENV=(-e CEOS=1 -e EOS_PLATFORM=ceoslab -e container=docker -e INTFTYPE=eth -e ETBA=1
          -e SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 -e MAPETH0=0)
CEOS_INIT=(/sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1
           systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab systemd.setenv=container=docker systemd.setenv=MAPETH0=0)
NEW1_SERIAL=ISOP56NEW1; NEW1_MAC=02:5a:76:00:00:11
NEW2_SERIAL=ISOP56NEW2; NEW2_MAC=02:5a:76:00:00:12

pid_of() { docker inspect -f '{{.State.Pid}}' "$1"; }
ns() { local pid; pid=$(pid_of "$1"); shift; sudo -n nsenter -t "$pid" -n "$@"; }

veth() {  # veth <containerA> <ifA> <containerB> <ifB>
  local a b; a=$(pid_of "$1"); b=$(pid_of "$3")
  local ta="i${RANDOM}a" tb="i${RANDOM}b"
  sudo -n ip link add "$ta" type veth peer name "$tb"
  sudo -n ip link set "$ta" netns "$a"; sudo -n ip link set "$tb" netns "$b"
  sudo -n nsenter -t "$a" -n ip link set "$ta" name "$2"; sudo -n nsenter -t "$b" -n ip link set "$tb" name "$4"
  sudo -n nsenter -t "$a" -n ip link set "$2" up; sudo -n nsenter -t "$b" -n ip link set "$4" up
  # cEOS (ETBA) forwards in software and does not complete partial checksums (see labs/ztp-isolated/fixture.sh)
  sudo -n nsenter -t "$a" -n ethtool -K "$2" tx off >/dev/null; sudo -n nsenter -t "$b" -n ethtool -K "$4" tx off >/dev/null
}

holder() { docker run -d --name "$1" --network none --restart unless-stopped alpine:latest sleep infinity >/dev/null; }

users_block() {  # fixture-admin: fixture setup / out-of-band console stand-in only; nmas-svc: NMAS's machine identity
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

startup() {  # startup <name> <hostname> <body file>
  mkdir -p "$RUNTIME/$1-flash"
  { printf '! NMAS V2 Phases 5+6 isolated fixture -- %s (fixture infrastructure, not a device under test)\nhostname %s\n!\n' "$2" "$2"
    cat "$3"; users_block; printf 'end\n'; } > "$RUNTIME/$1-flash/startup-config"
  printf 'DISABLE=True\n' > "$RUNTIME/$1-flash/zerotouch-config"
}

ceos() {  # ceos <name> <serial> <mac>
  printf 'SERIALNUMBER=%s\nSYSTEMMACADDR=%s\n' "$2" "$3" > "$RUNTIME/$1-flash/ceos-config"
  docker run -d --name "$P-$1" --privileged --network "container:$P-$1-ns" --restart unless-stopped "${CEOS_ENV[@]}" \
    -v "$RUNTIME/$1-flash:/mnt/flash" "$CEOS_IMAGE" "${CEOS_INIT[@]}" >/dev/null
}

up() {
  mkdir -p "$RUNTIME/keys" "$RUNTIME/dhcp" "$RUNTIME/captures"
  for k in fixture-admin nmas-svc; do
    [ -f "$RUNTIME/keys/$k" ] || ssh-keygen -q -t ed25519 -N '' -C "$k@nmas-iso-fixture" -f "$RUNTIME/keys/$k"
  done
  local body; body=$(mktemp -d)
  cat > "$body/up" <<'EOF'
ip routing
ipv6 unicast-routing
!
OPTION82_LINE
interface Ethernet1
   description bootstrap port A (untrusted device side)
   no switchport
   ip address 10.254.60.1/24
   ipv6 address 2001:db8:254:60::1/64
   ip helper-address 10.254.61.2
!
interface Ethernet2
   description NMAS bootstrap service
   no switchport
   ip address 10.254.61.1/30
   ipv6 address 2001:db8:254:61::1/64
!
interface Ethernet3
   description production core
   no switchport
   ip address 10.254.62.1/30
   ipv6 address 2001:db8:254:62::1/64
!
interface Loopback0
   ip address 10.254.255.1/32
!
ipv6 route 2001:db8:254:63::/64 2001:db8:254:62::2
!
router ospf 1
   router-id 10.254.255.1
   passive-interface Ethernet2
   network 10.254.60.0/24 area 0.0.0.0
   network 10.254.61.0/30 area 0.0.0.0
   network 10.254.62.0/30 area 0.0.0.0
   network 10.254.255.1/32 area 0.0.0.0
!
EOF
  cat > "$body/core" <<'EOF'
ip routing
ipv6 unicast-routing
!
interface Ethernet1
   description trusted upstream UP1
   no switchport
   ip address 10.254.62.2/30
   ipv6 address 2001:db8:254:62::2/64
!
interface Ethernet2
   description production LAN
   no switchport
   ip address 10.254.63.1/24
   ipv6 address 2001:db8:254:63::1/64
!
interface Loopback0
   ip address 10.254.255.2/32
!
ipv6 route 2001:db8:254:60::/64 2001:db8:254:62::1
ipv6 route 2001:db8:254:61::/64 2001:db8:254:62::1
!
router ospf 1
   router-id 10.254.255.2
   passive-interface Ethernet2
   network 10.254.62.0/30 area 0.0.0.0
   network 10.254.63.0/24 area 0.0.0.0
   network 10.254.255.2/32 area 0.0.0.0
!
EOF
  # NMAS_ISO_FX_UP1_OPTION82=off: UP1 starts WITHOUT option 82, so NMAS applies it through a governed change (V2 Phase 9,
  # core/tests/live_option82_ztp_fixture.py).  Default "on" keeps the Phases 5+6 fixture exactly as it was.
  if [ "${NMAS_ISO_FX_UP1_OPTION82:-on}" = "off" ]; then sed -i '/^OPTION82_LINE$/d' "$body/up"
  else sed -i 's/^OPTION82_LINE$/ip dhcp relay information option\n!/' "$body/up"; fi
  # NMAS_ISO_FX_OSPF6=on (V2 Phase 9 IPv6 admission, core/tests/live_ipv6_admission_fixture.py): OSPFv3 in the cEOS form NMAS
  # renders on UP1 (bootstrap port A, the core link, its loopback) and CORE (the UP1 link, the production LAN passive), so the
  # bootstrap port carries OSPFv3 that isolation must suppress and admission must verify.  Default "off": the fixture as before.
  if [ "${NMAS_ISO_FX_OSPF6:-off}" = "on" ]; then
    cat >> "$body/up" <<'EOF'
interface Ethernet1
   ipv6 ospf 1 area 0.0.0.0
!
interface Ethernet3
   ipv6 ospf 1 area 0.0.0.0
!
interface Loopback0
   ipv6 address 2001:db8:254:255::1/128
   ipv6 ospf 1 area 0.0.0.0
!
ipv6 router ospf 1
   router-id 10.254.255.1
!
EOF
    cat >> "$body/core" <<'EOF'
interface Ethernet1
   ipv6 ospf 1 area 0.0.0.0
!
interface Ethernet2
   ipv6 ospf 1 area 0.0.0.0
!
interface Loopback0
   ipv6 address 2001:db8:254:255::2/128
   ipv6 ospf 1 area 0.0.0.0
!
ipv6 router ospf 1
   router-id 10.254.255.2
   passive-interface Ethernet2
!
EOF
  fi
  startup up ISOUP1 "$body/up"; startup core ISOCORE "$body/core"
  rm -rf "$body"
  holder "$P-up-ns"; holder "$P-core-ns"; holder "$P-new1-ns"; holder "$P-new2-ns"
  holder "$P-probe-a"; holder "$P-probe-b"; holder "$P-prod"
  docker run -d --name "$P-svc" --network none --restart unless-stopped -v "$RUNTIME/dhcp:/srv/dhcp" "$SVC_IMAGE" >/dev/null
  veth "$P-probe-a" eth1 "$P-up-ns" eth1            # bootstrap port A: the hostile probe first, NEW1 after `attach new1`
  veth "$P-up-ns" eth2 "$P-svc" eth1
  veth "$P-up-ns" eth3 "$P-core-ns" eth1
  veth "$P-core-ns" eth2 "$P-prod" eth1
  veth "$P-new1-ns" eth2 "$P-probe-b" eth1          # bootstrap port B (NEW1 Et2): the probe first, NEW2 after `attach new2`
  ns "$P-svc" ip addr add 10.254.61.2/30 dev eth1
  ns "$P-svc" ip -6 addr add 2001:db8:254:61::2/64 dev eth1 nodad
  ns "$P-svc" ip route add 10.254.0.0/16 via 10.254.61.1
  ns "$P-svc" ip -6 route add 2001:db8:254::/48 via 2001:db8:254:61::1
  ns "$P-prod" ip addr add 10.254.63.10/24 dev eth1
  ns "$P-prod" ip -6 addr add 2001:db8:254:63::10/64 dev eth1 nodad
  ns "$P-prod" ip route add default via 10.254.63.1
  ns "$P-prod" ip -6 route add default via 2001:db8:254:63::1
  ns "$P-probe-a" ip addr add 10.254.60.250/24 dev eth1
  ns "$P-probe-a" ip -6 addr add 2001:db8:254:60::250/64 dev eth1 nodad
  ns "$P-probe-a" ip route add default via 10.254.60.1
  ns "$P-probe-a" ip -6 route add default via 2001:db8:254:60::1
  ns "$P-probe-b" ip addr add 10.254.64.250/24 dev eth1
  ns "$P-probe-b" ip route add default via 10.254.64.1
  ceos up ISOP56UP1 02:5a:76:00:00:01
  ceos core ISOP56CORE 02:5a:76:00:00:02
  echo "fixture up: $P-{up,core} (cEOS), $P-svc (10.254.61.2), $P-prod (10.254.63.10), probes on bootstrap ports A and B"
}

attach() {  # attach new1|new2: move the bootstrap port from its probe namespace into the new device's namespace, boot factory default
  local probe serial mac
  case "$1" in
    new1) probe="$P-probe-a"; serial=$NEW1_SERIAL; mac=$NEW1_MAC ;;
    new2) probe="$P-probe-b"; serial=$NEW2_SERIAL; mac=$NEW2_MAC ;;
    *) echo "attach new1|new2" >&2; exit 2 ;;
  esac
  local target; target=$(pid_of "$P-$1-ns")
  ns "$probe" ip link set eth1 down
  ns "$probe" ip addr flush dev eth1
  ns "$probe" ip link set eth1 netns "$target"
  sudo -n nsenter -t "$target" -n ip link set eth1 up
  sudo -n nsenter -t "$target" -n ethtool -K eth1 tx off >/dev/null
  sudo -n rm -rf "$RUNTIME/$1-flash"; mkdir -p "$RUNTIME/$1-flash"
  ceos "$1" "$serial" "$mac"
  echo "$P-$1 started from factory default (serial $serial, mac $mac) on its bootstrap port"
}

down() {
  for c in new1 new2 up core svc; do docker rm -f "$P-$c" >/dev/null 2>&1 || true; done
  for c in up-ns core-ns new1-ns new2-ns probe-a probe-b prod; do docker rm -f "$P-$c" >/dev/null 2>&1 || true; done
  sudo -n rm -rf "$RUNTIME"
  echo "fixture removed"
}

status() { docker ps -a --filter "name=$P" --format '{{.Names}} {{.Status}} {{.Networks}}'; }

# The out-of-band host-key confirmation (stands in for reading the key on a physical console).  NMAS never uses this path.
hostkey() { docker exec "$P-$1" Cli -A -p 15 -c "show management ssh hostkey ed25519 public" | awk '/ssh-ed25519/ {print $1" "$2}'; }

# Fixture-side observation and hostile-actor emulation (the harness's independent vantage points; never an NMAS path).
probe() { local which=$1; shift; ns "$P-probe-$which" "$@"; }
prod() { ns "$P-prod" "$@"; }
# -A: the console stand-in does not go through AAA (a ZTP-bootstrapped device sets "aaa authorization exec default local")
cli() { docker exec "$P-$1" Cli -A -p 15 -c "$2"; }
capture_start() {  # capture-start <name> <container> <interface>: tcpdump (host binary) inside a fixture namespace
  local pid; pid=$(pid_of "$P-$2")
  sudo -n nsenter -t "$pid" -n timeout 600 tcpdump -nn -U -i "$3" -w "$RUNTIME/captures/$1.pcap" >/dev/null 2>&1 &
  echo $! > "$RUNTIME/captures/$1.pid"; sleep 1
}
capture_stop() {
  sudo -n pkill -INT -f "tcpdump -nn -U -i .* -w $RUNTIME/captures/$1.pcap" || true; sleep 1
  sudo -n tcpdump -nn -r "$RUNTIME/captures/$1.pcap" 2>/dev/null || true
}

case "${1:-}" in
  up) up ;; down) down ;; status) status ;;
  svc-pid) pid_of "$P-svc" ;;
  attach) attach "${2:?new1|new2}" ;;
  hostkey) hostkey "${2:?up|new1|new2}" ;;
  probe) shift; probe "$@" ;;
  prod) shift; prod "$@" ;;
  cli) cli "${2:?}" "${3:?}" ;;
  capture-start) capture_start "${2:?}" "${3:?}" "${4:?}" ;;
  capture-stop) capture_stop "${2:?}" ;;
  *) echo "usage: $0 up|down|status|svc-pid|attach <new1|new2>|hostkey <n>|probe <a|b> <cmd>|prod <cmd>|cli <n> <cmd>|capture-start|capture-stop" >&2; exit 2 ;;
esac
