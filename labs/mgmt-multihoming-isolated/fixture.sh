#!/usr/bin/env bash
# NMAS V2 Phase 4 -- disposable, isolated management-multihoming fixture.
#
#                         [MSW1 cEOS: fixture management switch, STP root]
#   NMAS eth1 ---- Ethernet1 (access 200)        Ethernet3 (trunk 200) ---- Ethernet1 [SW1 cEOS: adjacent switch]
#   10.254.40.10/24          Ethernet2 (access 200)                                   Ethernet2 (access 200)
#                                  |                                                         |
#                             Ethernet1 (access 200)                                Ethernet2 (access 200)
#                                  +----------------------- [DUT1 cEOS] -----------------------+
#                                     Vlan200 10.254.40.21/24 (class 1 direct OOB / class 2 via SW1)
#                                     Ethernet3 10.254.42.1/30 (class 3: routed, later VRF MGMT)
#                                                |
#   NMAS eth2 10.254.42.2/30 --------------------+   (a second NMAS attachment that does not touch MSW1)
#
# "NMAS" is a network namespace held by an alpine holder container: NMAS code runs in it with `nsenter -n`, so its two
# attachments are real interfaces it can observe (sysfs / iproute2) and bind probe sockets to.  Every container uses
# Docker's "none" network: no Containerlab management bridge, no docker0, no route to the production lab, its VLAN 200
# or the host.  VLAN 200 here is a fixture-local VLAN id on fixture veths; it is not the production management VLAN.
# Links are point-to-point veth pairs created here; `fail` / `restore` act only on the fixture switches MSW1 / SW1 (see link()).
#
# No DHCP runs anywhere in this fixture.  The fixture's own keys (fixture-admin for setup, nmas-svc for NMAS probes) are
# generated into runtime/ (git-ignored) and destroyed by `down`.
#
# Usage: fixture.sh up | down | status | reset-dut | hostkey <dut|msw|sw1> | nmas-pid | fail <oob|via-sw1|msw> | restore <oob|via-sw1|msw>
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${NMAS_MGMT_FX_RUNTIME:-$HERE/runtime}"
CEOS_IMAGE="${NMAS_MGMT_FX_CEOS_IMAGE:-ceos:4.36.2F}"
P="nmas-mgmt-p4"
CEOS_ENV=(-e CEOS=1 -e EOS_PLATFORM=ceoslab -e container=docker -e INTFTYPE=eth -e ETBA=1
          -e SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 -e MAPETH0=0)
CEOS_INIT=(/sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1
           systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab systemd.setenv=container=docker systemd.setenv=MAPETH0=0)

pid_of() { docker inspect -f '{{.State.Pid}}' "$1"; }
ns() { local pid; pid=$(pid_of "$1"); shift; sudo -n nsenter -t "$pid" -n "$@"; }

veth() {  # veth <containerA> <ifA> <containerB> <ifB>
  local a b; a=$(pid_of "$1"); b=$(pid_of "$3")
  local ta="m${RANDOM}a" tb="m${RANDOM}b"
  sudo -n ip link add "$ta" type veth peer name "$tb"
  sudo -n ip link set "$ta" netns "$a"; sudo -n ip link set "$tb" netns "$b"
  sudo -n nsenter -t "$a" -n ip link set "$ta" name "$2"; sudo -n nsenter -t "$b" -n ip link set "$tb" name "$4"
  sudo -n nsenter -t "$a" -n ip link set "$2" up; sudo -n nsenter -t "$b" -n ip link set "$4" up
  # cEOS (ETBA) forwards in software and does not complete partial checksums (see labs/ztp-isolated/fixture.sh)
  sudo -n nsenter -t "$a" -n ethtool -K "$2" tx off >/dev/null; sudo -n nsenter -t "$b" -n ethtool -K "$4" tx off >/dev/null
}

holder() { docker run -d --name "$1" --network none --restart unless-stopped alpine:latest sleep infinity >/dev/null; }

users_block() {
  local hash; hash=$(openssl passwd -6 "$(openssl rand -hex 24)")
  cat <<EOF
aaa authorization exec default local
!
username fixture-admin privilege 15 role network-admin secret sha512 $hash
username fixture-admin ssh-key $(cut -d' ' -f1-2 "$RUNTIME/keys/fixture-admin.pub") fixture-admin
username nmas-svc privilege 15 role network-admin secret sha512 $hash
username nmas-svc ssh-key $(cut -d' ' -f1-2 "$RUNTIME/keys/nmas-svc.pub") nmas-svc
!
management ssh
!
EOF
}

startup() {  # startup <name> <hostname> <body file>
  mkdir -p "$RUNTIME/$1-flash"
  { printf '! NMAS V2 Phase 4 isolated management fixture -- %s (fixture infrastructure)\nhostname %s\n!\nspanning-tree mode mstp\n' "$2" "$2"
    cat "$3"; users_block; printf 'end\n'; } > "$RUNTIME/$1-flash/startup-config"
  printf 'DISABLE=True\n' > "$RUNTIME/$1-flash/zerotouch-config"
}

ceos() {  # ceos <name> <serial> <mac>
  printf 'SERIALNUMBER=%s\nSYSTEMMACADDR=%s\n' "$2" "$3" > "$RUNTIME/$1-flash/ceos-config"
  docker run -d --name "$P-$1" --privileged --network "container:$P-$1-ns" --restart unless-stopped "${CEOS_ENV[@]}" \
    -v "$RUNTIME/$1-flash:/mnt/flash" "$CEOS_IMAGE" "${CEOS_INIT[@]}" >/dev/null
}

up() {
  mkdir -p "$RUNTIME/keys"
  for k in fixture-admin nmas-svc; do
    [ -f "$RUNTIME/keys/$k" ] || ssh-keygen -q -t ed25519 -N '' -C "$k@nmas-mgmt-fixture" -f "$RUNTIME/keys/$k"
  done
  local body; body=$(mktemp -d)
  cat > "$body/msw" <<'EOF'
spanning-tree mst 0 priority 4096
!
vlan 200
   name FIXTURE-MGMT
!
interface Ethernet1
   description NMAS fixture attachment eth1
   switchport access vlan 200
!
interface Ethernet2
   description DUT1 Ethernet1 (direct out-of-band)
   switchport access vlan 200
!
interface Ethernet3
   description SW1 Ethernet1 (management VLAN uplink)
   switchport mode trunk
   switchport trunk allowed vlan 200
!
interface Vlan200
   ip address 10.254.40.2/24
!
EOF
  cat > "$body/sw1" <<'EOF'
spanning-tree mst 0 priority 8192
!
vlan 200
   name FIXTURE-MGMT
!
interface Ethernet1
   description MSW1 Ethernet3 (management VLAN uplink)
   switchport mode trunk
   switchport trunk allowed vlan 200
!
interface Ethernet2
   description DUT1 Ethernet2
   switchport access vlan 200
!
interface Vlan200
   ip address 10.254.40.3/24
!
EOF
  cat > "$body/dut" <<'EOF'
vlan 200
   name FIXTURE-MGMT
!
interface Ethernet1
   description MSW1 Ethernet2 (direct out-of-band)
   switchport access vlan 200
!
interface Ethernet2
   description SW1 Ethernet2 (management VLAN via adjacent switch)
   switchport access vlan 200
!
interface Ethernet3
   description routed management link -> NMAS fixture eth2
   no switchport
   ip address 10.254.42.1/30
!
interface Vlan200
   ip address 10.254.40.21/24
!
EOF
  startup msw MSW1 "$body/msw"; startup sw1 SW1 "$body/sw1"; startup dut DUT1 "$body/dut"
  rm -rf "$body"
  holder "$P-nmas"; holder "$P-msw-ns"; holder "$P-sw1-ns"; holder "$P-dut-ns"
  veth "$P-nmas" eth1 "$P-msw-ns" eth1
  veth "$P-msw-ns" eth2 "$P-dut-ns" eth1
  veth "$P-msw-ns" eth3 "$P-sw1-ns" eth1
  veth "$P-sw1-ns" eth2 "$P-dut-ns" eth2
  veth "$P-nmas" eth2 "$P-dut-ns" eth3
  ns "$P-nmas" ip addr add 10.254.40.10/24 dev eth1
  ns "$P-nmas" ip addr add 10.254.42.2/30 dev eth2
  ceos msw MGMTP4MSW1 02:4d:47:00:00:01
  ceos sw1 MGMTP4SW1 02:4d:47:00:00:02
  ceos dut MGMTP4DUT1 02:4d:47:00:00:03
  echo "fixture up: $P-{msw,sw1,dut} (cEOS), $P-nmas (NMAS namespace: eth1 10.254.40.10/24, eth2 10.254.42.2/30)"
}

down() {
  docker rm -f "$P-msw" "$P-sw1" "$P-dut" "$P-nmas" "$P-msw-ns" "$P-sw1-ns" "$P-dut-ns" >/dev/null 2>&1 || true
  sudo -n rm -rf "$RUNTIME"
  echo "fixture removed"
}

reset_dut() {  # a disposable-fixture action only: reboot DUT1 into its unchanged startup-config (links live in the holder netns)
  docker restart "$P-dut" >/dev/null
  echo "$P-dut restarted from its startup-config"
}

status() { docker ps -a --filter "name=$P" --format '{{.Names}} {{.Status}} {{.Networks}}'; }

# The out-of-band host-key confirmation (stands in for reading the key on a physical console).  NMAS never uses this path.
hostkey() { docker exec "$P-$1" Cli -p 15 -c "show management ssh hostkey ed25519 public" | awk '/ssh-ed25519/ {print $1" "$2}'; }

port() {  # port <container> <interface> <shutdown|no shutdown>: a fixture switch's port facing DUT1 (fixture infrastructure only)
  docker exec "$P-$1" Cli -p 15 -c "$(printf 'configure\ninterface %s\n%s\nend' "$2" "$3")" >/dev/null
}

# Failure injection, on fixture infrastructure only (never on DUT1):
#   oob      MSW1 Ethernet2 shut: the carrier drops on the veth to DUT1 Ethernet1 (cEOS re-enables a kernel-downed veth, so the
#            switch port itself is shut)
#   via-sw1  SW1 Ethernet2 shut: the carrier drops on the veth to DUT1 Ethernet2
#   msw      the whole management switch frozen (docker pause): every link stays up but nothing is forwarded (a black hole)
link() {  # link <down|up> <oob|via-sw1|msw>
  case "$2:$1" in
    oob:down) port msw Ethernet2 shutdown ;;        oob:up) port msw Ethernet2 "no shutdown" ;;
    via-sw1:down) port sw1 Ethernet2 shutdown ;;    via-sw1:up) port sw1 Ethernet2 "no shutdown" ;;
    msw:down) docker pause "$P-msw" >/dev/null ;;   msw:up) docker unpause "$P-msw" >/dev/null ;;
    *) echo "unknown link $2" >&2; exit 2 ;;
  esac
  echo "link $2 $1"
}

case "${1:-}" in
  up) up ;; down) down ;; status) status ;;
  hostkey) hostkey "${2:?dut|msw|sw1}" ;;
  nmas-pid) pid_of "$P-nmas" ;;
  reset-dut) reset_dut ;;
  fail) link down "${2:?}" ;; restore) link up "${2:?}" ;;
  *) echo "usage: $0 up|down|status|reset-dut|hostkey <n>|nmas-pid|fail <link>|restore <link>" >&2; exit 2 ;;
esac
